//go:build linux

package sandbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/google/uuid"
	"github.com/launchdarkly/go-server-sdk/v7/testhelpers/ldtestdata"
	"github.com/stretchr/testify/require"

	"github.com/e2b-dev/infra/packages/clickhouse/pkg/hoststats"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/cfg"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/cgroup"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/fc"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/nbd"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/network"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/template"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/metadata"
	"github.com/e2b-dev/infra/packages/shared/pkg/featureflags"
	"github.com/e2b-dev/infra/packages/shared/pkg/grpc/orchestrator"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage"
)

// One opt-in, real Claude Code batch per process. The caller prepares a private
// copy of the snapshot dependency closure, evicts only those files, then starts
// this binary in a fresh, bounded systemd cgroup. NoopManager keeps FC and QEMU
// in that inherited aggregate cgroup. The production API is not used for A's
// synthetic team identities. The task snapshot contains no model credentials,
// reference solution, or grading patch. Grading runs separately after cleanup.
func TestEROFSAgentBenchmark(t *testing.T) { //nolint:paralleltest
	path := os.Getenv("E2B_EROFS_AGENT_CASE")
	if path == "" {
		t.Skip("E2B_EROFS_AGENT_CASE required")
	}
	require.Zero(t, os.Geteuid())
	var c agentBenchConfig
	require.NoError(t, json.Unmarshal(sharedBenchRead(t, path), &c))
	require.Contains(t, []string{"A", "D"}, c.Group)
	require.Greater(t, c.Count, 0)
	require.LessOrEqual(t, c.Count, 64)
	require.Greater(t, c.TimeoutSeconds, 0)
	require.NoError(t, os.MkdirAll(c.Dir, 0o700))
	var credentials struct {
		BaseURL string `json:"base_url"`
		APIKey  string `json:"api_key"`
		Model   string `json:"default_model"`
	}
	require.NoError(t, json.Unmarshal(sharedBenchRead(t, c.Credentials), &credentials))
	require.NotEmpty(t, credentials.APIKey)
	ctx, cancel := context.WithTimeout(t.Context(), time.Duration(c.TimeoutSeconds+300)*time.Second)
	defer cancel()
	report := map[string]any{"config": c, "started_at": time.Now().UTC(), "model": credentials.Model, "status": "incomplete"}
	agentInvestigationPhase(t, c, "case_start", nil)
	var vms []*Sandbox
	var vmReports []map[string]any
	var refs []*erofs.MountRef
	var factory *Factory
	var devices *nbd.DevicePool
	var flags *featureflags.Client
	var cancelPool context.CancelFunc
	netPool := &agentBenchNetwork{sharedBenchNetwork: sharedBenchNetwork{lifecycleNetworkPool: lifecycleNetworkPool{slots: map[string]*network.Slot{}}, servers: map[string]*http.Server{}}, upstream: credentials.BaseURL, dir: c.Dir, gateways: map[string]*http.Server{}}
	t.Cleanup(func() {
		var failures []string
		check := func(err error) {
			if err != nil {
				failures = append(failures, err.Error())
				t.Error(err)
			}
		}
		for i := len(vms) - 1; i >= 0; i-- {
			closeCtx, stop := context.WithTimeout(context.Background(), 45*time.Second)
			check(vms[i].Close(closeCtx))
			stop()
		}
		for _, ref := range refs {
			check(ref.Release())
		}
		if factory != nil {
			check(factory.CloseSharedMounts(context.Background()))
		}
		check(netPool.Close(context.Background()))
		if cancelPool != nil {
			cancelPool()
		}
		if devices != nil {
			check(devices.Close(context.Background()))
		}
		if flags != nil {
			check(flags.Close(context.Background()))
		}
		for _, vm := range vmReports {
			if id, ok := vm["fc_identity"].(erofs.ProcessIdentity); ok {
				check(erofs.ProcessTerminated(id))
			}
			if ov, ok := vm["overlay"].(erofs.OverlayRecovery); ok {
				check(erofs.ProcessTerminated(ov.Producer))
			}
		}
		after := sharedBenchHost(c.Dir, "after-cleanup")
		if after["owned_mount_count"] != 0 || after["owned_loop_count"] != 0 {
			check(fmt.Errorf("resources remain: mounts=%v loops=%v", after["owned_mount_count"], after["owned_loop_count"]))
		}
		report["after_cleanup"], report["cleanup_errors"], report["vms"] = after, failures, vmReports
		report["finished_at"] = time.Now().UTC()
		report["status"] = "completed"
		if t.Failed() {
			report["status"] = "failed"
		}
		sharedBenchJSON(t, filepath.Join(c.Dir, "report.json"), report)
	})
	config := cfg.BuilderConfig{EROFSSnapshotDir: filepath.Join(c.Dir, "snapshots"), EROFSNativeMemoryVerified: true, EROFSMkfsPath: c.Mkfs,
		FirecrackerVersionsDir: filepath.Join(c.Dir, "firecracker"), HostKernelsDir: filepath.Join(c.Dir, "kernels"),
		OrchestratorBaseDir: filepath.Join(c.Dir, "orchestrator"), SandboxDir: c.SandboxDir,
		StorageConfig: storage.Config{SandboxCacheDir: filepath.Join(c.Dir, "sandbox-cache"), TemplateCacheDir: filepath.Join(c.Dir, "template-cache")}}
	store, err := erofs.NewStore(config.EROFSSnapshotDir, erofs.Options{MkfsPath: c.Mkfs, FsckPath: c.Fsck})
	require.NoError(t, err)
	baseline, err := store.Load(c.Generation)
	require.NoError(t, err)
	nativeOnly := baseline.Manifest.Format == erofs.FormatV2
	if nativeOnly {
		require.NotNil(t, baseline.Manifest.Boot)
		require.Equal(t, erofs.LayoutPmem, baseline.Manifest.Boot.Layout)
		_, err := os.Stat("/sys/module/nbd")
		require.ErrorIs(t, err, os.ErrNotExist, "native Agent cases require no NBD module")
		config.EROFSNativeOnly, config.EROFSPmemVerified = true, true
	}
	report["native_only"] = nativeOnly
	report["manifest"] = baseline.Manifest
	meta, err := metadata.FromFile(baseline.MetadataPath())
	require.NoError(t, err)
	for target, source := range map[string]string{
		filepath.Join(config.FirecrackerVersionsDir, meta.Template.FirecrackerVersion, "firecracker"): c.FC,
		filepath.Join(config.HostKernelsDir, meta.Template.KernelVersion, "vmlinux.bin"):              c.Kernel,
		filepath.Join(c.Dir, "bin", "fsck.erofs"):                                                     c.Fsck,
	} {
		require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
		require.NoError(t, os.Symlink(source, target))
	}
	t.Setenv("PATH", filepath.Join(c.Dir, "bin")+":"+os.Getenv("PATH"))
	for _, p := range []string{config.StorageConfig.SandboxCacheDir, config.StorageConfig.TemplateCacheDir, c.SandboxDir} {
		require.NoError(t, os.MkdirAll(p, 0o755))
	}
	paths, err := (storage.Paths{BuildID: c.Generation}).Cache(config.StorageConfig)
	require.NoError(t, err)
	tmpl := template.NewEROFSTemplate(paths, baseline)
	flags, err = featureflags.NewClientWithDatasource(ldtestdata.DataSource())
	require.NoError(t, err)
	if nativeOnly {
		factory, err = NewFileFactory(ctx, config, netPool, flags, hoststats.NewNoopDelivery(), cgroup.NewNoopManager(), network.NewNoopEgressProxy(), nil, NewSandboxesMap())
		require.NoError(t, err)
	} else {
		devices, err = nbd.NewDevicePool(c.Count)
		require.NoError(t, err)
		poolCtx, stopPool := context.WithCancel(context.Background())
		cancelPool = stopPool
		go devices.Populate(poolCtx)
		factory = NewFactory(ctx, config, netPool, devices, flags, hoststats.NewNoopDelivery(), cgroup.NewNoopManager(), network.NewNoopEgressProxy(), nil, NewSandboxesMap())
	}
	report["before"] = sharedBenchHost(c.Dir, "before")
	team := uuid.NewString()
	memPaths := make([]string, c.Count)
	memIDs, diskIDs, lowerIDs, upperIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	lowerPaths := make([]string, c.Count)
	samples, err := os.OpenFile(filepath.Join(c.Dir, "samples.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	defer samples.Close()
	enc := json.NewEncoder(samples)
	activeAgents := 0
	sample := func(phase string) {
		row := map[string]any{"time": time.Now().UTC(), "phase": phase, "active_agents": activeAgents, "live_vms": len(vms)}
		measurements := []map[string]any{}
		for i, vm := range vmReports {
			pid := vm["fc_pid"].(int)
			data, e := os.ReadFile(fmt.Sprintf("/proc/%d/smaps", pid))
			if e != nil {
				row["error"] = e.Error()
				continue
			}
			mem, e := sharedBenchMemSmaps(string(data), sharedBenchIdentity(t, memPaths[i]))
			if e != nil {
				row["error"] = e.Error()
				continue
			}
			item := map[string]any{"index": i, "memfile_kib": mem, "fc_kib": sharedBenchCounters(string(data))}
			if nativeOnly {
				lower, e := sharedBenchFileSmaps(string(data), vm["lower_identity"].(string), "r--s")
				if e != nil {
					row["error"] = e.Error()
				} else {
					item["pmem_kib"] = lower
				}
			} else {
				q, _ := os.ReadFile(fmt.Sprintf("/proc/%d/smaps_rollup", vm["overlay"].(erofs.OverlayRecovery).Producer.PID))
				item["qemu_kib"] = sharedBenchCounters(string(q))
			}
			measurements = append(measurements, item)
		}
		row["vms"] = measurements
		for _, name := range []string{"memory.current", "memory.peak", "memory.stat", "memory.events", "cpu.stat", "cpu.pressure", "memory.pressure", "io.pressure", "cgroup.procs"} {
			data, e := os.ReadFile(filepath.Join(c.Cgroup, name))
			if e != nil {
				row[name+"_error"] = e.Error()
			} else {
				row[name] = string(data)
			}
		}
		require.NoError(t, enc.Encode(row))
	}
	sample("before_restore")
	for i := range c.Count {
		teamID := team
		if c.Group == "A" {
			teamID = uuid.NewString()
		}
		ref, err := factory.sharedMounts.Acquire(ctx, baseline, teamID)
		if ref != nil {
			refs = append(refs, ref)
		}
		require.NoError(t, err)
		memPaths[i] = ref.MemoryPath()
		agentInvestigationPhase(t, c, "memory_source_ready", map[string]any{"index": i, "path": ref.MemoryPath(), "identity": sharedBenchIdentity(t, ref.MemoryPath())})
		memIDs[sharedBenchIdentity(t, ref.MemoryPath())] = true
		diskIDs[sharedBenchIdentity(t, ref.DiskPath())] = true
		if nativeOnly {
			lower, err := factory.sharedMounts.AcquireLower(ctx, baseline.Manifest.Lower, teamID)
			require.NoError(t, err)
			refs = append(refs, lower)
			lowerPaths[i] = lower.LowerPath()
			lowerIDs[sharedBenchIdentity(t, lower.LowerPath())] = true
		}

		token, user := uuid.NewString()+uuid.NewString(), "user"
		vars := map[string]string{"ANTHROPIC_BASE_URL": "http://169.254.0.22:8317", "ANTHROPIC_AUTH_TOKEN": credentials.APIKey,
			"ANTHROPIC_MODEL": credentials.Model, "ANTHROPIC_DEFAULT_OPUS_MODEL": credentials.Model, "ANTHROPIC_DEFAULT_SONNET_MODEL": credentials.Model, "ANTHROPIC_DEFAULT_HAIKU_MODEL": credentials.Model,
			"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1"}
		conf := NewConfig(Config{Vcpu: c.VCPU, RamMB: baseline.Manifest.Memory.Size >> 20, TotalDiskSizeMB: baseline.Manifest.WritableDisk().Size >> 20,
			FirecrackerConfig: fc.Config{KernelVersion: meta.Template.KernelVersion, FirecrackerVersion: meta.Template.FirecrackerVersion, NativeMemory: true},
			Envd:              EnvdMetadata{Version: c.EnvdVersion, AccessToken: &token, DefaultUser: &user, Vars: vars}})
		rt := RuntimeMetadata{TemplateID: "agent-benchmark", SandboxID: "ab" + uuid.NewString()[:8], ExecutionID: uuid.NewString(), BuildID: c.Generation, TeamID: teamID, SandboxType: SandboxTypeBuild}
		start := time.Now()
		agentInvestigationPhase(t, c, "restore_start", map[string]any{"index": i})
		s, err := factory.ResumeSandbox(ctx, tmpl, conf, rt, start, start.Add(time.Hour), nil, WithoutLiveRegistration())
		if s != nil {
			vms = append(vms, s)
			vmReports = append(vmReports, map[string]any{"sandbox_id": rt.SandboxID, "index": i, "restore_ms": time.Since(start).Milliseconds()})
		}
		require.NoError(t, err)
		if !nativeOnly {
			lifecycleSharedMountIdentity(t, s, ref.MemoryPath(), ref.DiskPath(), factory.sharedMounts.Root())
		}
		pid, err := s.process.Pid()
		require.NoError(t, err)
		identity, err := erofs.IdentifyProcess(pid)
		require.NoError(t, err)
		vmReports[i]["fc_pid"], vmReports[i]["fc_identity"], vmReports[i]["netns"] = pid, identity, s.Slot.NamespaceID()
		processIDs := []int{pid}
		if nativeOnly {
			for name, source := range map[string]string{"memfile": ref.MemoryPath(), "lower.ext4": lowerPaths[i]} {
				bound := fmt.Sprintf("/proc/%d/root/run/e2b-devices/%s", pid, name)
				require.Equal(t, sharedBenchIdentity(t, source), sharedBenchIdentity(t, bound), "prepared and actual mappings differ")
			}
			upper, err := s.rootfs.Path()
			require.NoError(t, err)
			vmReports[i]["upper_identity"] = sharedBenchIdentity(t, upper)
			vmReports[i]["lower_identity"] = sharedBenchIdentity(t, lowerPaths[i])
			upperIDs[sharedBenchIdentity(t, upper)] = true
		} else {
			ov, err := s.rootfs.(*erofsRootfs).overlay.RecoveryInfo()
			require.NoError(t, err)
			vmReports[i]["overlay"] = ov
			processIDs = append(processIDs, ov.Producer.PID)
		}
		agentInvestigationPhase(t, c, "restore_returned", map[string]any{"index": i, "fc_pid": pid})
		vmReports[i]["mem_identity"] = sharedBenchIdentity(t, ref.MemoryPath())
		for _, processPID := range processIDs {
			membership := string(sharedBenchRead(t, fmt.Sprintf("/proc/%d/cgroup", processPID)))
			require.Equal(t, "0::"+strings.TrimPrefix(c.Cgroup, "/sys/fs/cgroup")+"\n", membership)
		}
		sample("restore_returned")
		// Readiness verifies CLI/repository without revealing grading material.
		agentInvestigationPhase(t, c, "readiness_start", map[string]any{"index": i})
		out, code, err := agentBenchShell(ctx, s, "cd /testbed && claude --version && git rev-parse HEAD && /opt/miniconda3/envs/testbed/bin/python -c 'import sympy; print(sympy.__version__)'", "user", 60*time.Second, nil)
		require.NoError(t, err)
		require.Zero(t, code, "%s", out)
		vmReports[i]["ready"] = out
		agentInvestigationPhase(t, c, "readiness_end", map[string]any{"index": i})
		agentInvestigationGuest(t, ctx, c, s, fmt.Sprintf("ready-%02d", i))
		sample("vm_ready")
	}
	want := c.Count
	if c.Group == "D" {
		want = 1
	}
	require.Len(t, memIDs, want)
	require.Len(t, diskIDs, want)
	report["memory_identities"], report["disk_identities"] = memIDs, diskIDs
	if nativeOnly {
		require.Len(t, lowerIDs, want)
		require.Len(t, upperIDs, c.Count)
		report["lower_identities"], report["upper_identities"] = lowerIDs, upperIDs
	}
	for _, ref := range refs {
		require.NoError(t, ref.Release())
	}
	refs = nil
	report["ready"] = sharedBenchHost(c.Dir, "ready")
	prompt := string(sharedBenchRead(t, c.Prompt))
	command := "cd /testbed && export PATH=/opt/miniconda3/envs/testbed/bin:/usr/local/bin:/usr/bin:/bin && printf %s '" + base64.StdEncoding.EncodeToString([]byte(prompt)) + "' | base64 -d | claude -p --verbose --output-format stream-json --max-turns 60 --allowedTools 'Bash,Read,Edit,Write,Glob,Grep' --tools 'Bash,Read,Edit,Write,Glob,Grep'"
	sample("ready")
	for i, s := range vms {
		if !nativeOnly {
			vmReports[i]["ready_metrics"] = sharedBenchVM(t, c.Dir, fmt.Sprintf("ready-%02d", i), s, memPaths[i])
		}
	}
	if c.DiagnosticScript != "" {
		args := []string{c.DiagnosticScript, "--out", filepath.Join(c.Dir, "pfn.json")}
		for i, s := range vms {
			require.NoError(t, s.process.Pause(ctx))
			args = append(args, fmt.Sprint(vmReports[i]["fc_pid"]))
		}
		lifecycleCommand(t, ctx, "python3", args...)
		for _, s := range vms {
			require.NoError(t, s.process.ResumeInPlace(ctx))
		}
		report["diagnostic_only"] = true
		return
	}
	type outcome struct {
		index   int
		code    int32
		err     error
		elapsed time.Duration
	}
	done := make(chan outcome, c.Count)
	start := time.Now()
	report["barrier_at"] = start.UTC()
	agentInvestigationPhase(t, c, "agent_start", nil)
	activeAgents = c.Count
	for i, s := range vms {
		go func() {
			f, e := os.OpenFile(filepath.Join(c.Dir, fmt.Sprintf("agent-%02d.jsonl", i)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if e != nil {
				done <- outcome{index: i, err: e}
				return
			}
			defer f.Close()
			_, code, e := agentBenchShell(ctx, s, command, "user", time.Duration(c.TimeoutSeconds)*time.Second, f)
			done <- outcome{i, code, e, time.Since(start)}
		}()
	}
	remaining := c.Count
	guestProbeTwo, guestProbeTen := false, false
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for remaining > 0 {
		select {
		case o := <-done:
			remaining--
			activeAgents--
			vmReports[o.index]["exit_code"], vmReports[o.index]["elapsed_seconds"] = o.code, o.elapsed.Seconds()
			if o.err != nil {
				vmReports[o.index]["agent_error"] = o.err.Error()
			}
		case <-ticker.C:
			sample("agent")
			if c.Investigation && !guestProbeTwo && time.Since(start) >= 2*time.Second {
				guestProbeTwo = true
				agentInvestigationGuest(t, ctx, c, vms[0], "agent-2s")
			}
			if c.Investigation && !guestProbeTen && time.Since(start) >= 10*time.Second {
				guestProbeTen = true
				agentInvestigationGuest(t, ctx, c, vms[0], "agent-10s")
			}
		}
	}
	report["agent_seconds"] = time.Since(start).Seconds()
	sample("completed")
	agentInvestigationPhase(t, c, "agent_end", nil)
	if c.Investigation {
		agentInvestigationGuest(t, ctx, c, vms[0], "agent-end")
	}
	for i, s := range vms {
		patch, code, e := agentBenchShell(ctx, s, "cd /testbed && git add -N . && git diff --binary 514579c655bf22e2af14f0743376ae1d7befe345", "user", 60*time.Second, nil)
		require.NoError(t, e)
		require.Zero(t, code)
		require.NoError(t, os.WriteFile(filepath.Join(c.Dir, fmt.Sprintf("patch-%02d.diff", i)), []byte(patch), 0o600))
	}
}

type agentBenchConfig struct {
	Dir, Group, Generation, FC, Kernel, Mkfs, Fsck, SandboxDir, EnvdVersion, Credentials, Prompt, Cgroup string
	Count, TimeoutSeconds                                                                                int
	VCPU                                                                                                 int64
	DiagnosticScript                                                                                     string
	Investigation                                                                                        bool
}

// The diagnostic observers never read guest memory contents or model credentials.
// Their time windows are recorded so their guest-side activity remains visible.
var agentInvestigationMu sync.Mutex

func agentInvestigationPhase(t *testing.T, c agentBenchConfig, phase string, fields map[string]any) {
	t.Helper()
	if !c.Investigation {
		return
	}
	agentInvestigationMu.Lock()
	defer agentInvestigationMu.Unlock()
	if fields == nil {
		fields = make(map[string]any)
	}
	now := time.Now()
	fields["time"], fields["unix_ns"], fields["phase"] = now.UTC(), now.UnixNano(), phase
	f, err := os.OpenFile(filepath.Join(c.Dir, "phases.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	require.NoError(t, json.NewEncoder(f).Encode(fields))
	require.NoError(t, f.Close())
}

func agentInvestigationGuest(t *testing.T, ctx context.Context, c agentBenchConfig, s *Sandbox, label string) {
	t.Helper()
	if !c.Investigation {
		return
	}
	require.Equal(t, 1, c.Count, "investigation is restricted to one VM")
	agentInvestigationPhase(t, c, "guest_observer_start", map[string]any{"label": label})
	command := `printf 'MEMINFO\n'; cat /proc/meminfo; for d in /proc/[0-9]*; do
IFS= read -r name < "$d/comm" 2>/dev/null || continue
case "$name" in claude|node|python*|envd)
printf '\nPROCESS %s %s\n' "${d##*/}" "$name"
cat "$d/status" "$d/smaps_rollup" 2>/dev/null || true
esac
done`
	out, code, err := agentBenchShell(ctx, s, command, "root", 20*time.Second, nil)
	require.NoError(t, os.WriteFile(filepath.Join(c.Dir, "guest-"+label+".txt"), []byte(out), 0o600))
	agentInvestigationPhase(t, c, "guest_observer_end", map[string]any{"label": label, "exit_code": code, "error": fmt.Sprint(err)})
	if err != nil || code != 0 {
		t.Logf("guest observer %s incomplete: exit %d, %v", label, code, err)
	}
}

func agentBenchShell(ctx context.Context, s *Sandbox, command, user string, timeout time.Duration, events io.Writer) (string, int32, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	stream, err := s.StartEnvdShell(ctx, "/bin/bash", []string{"-c", command}, user, timeout)
	if err != nil {
		return "", -1, err
	}
	defer stream.Close()
	var output strings.Builder
	code := int32(-1)
	for stream.Receive() {
		e := stream.Msg().GetEvent()
		if d := e.GetData(); d != nil {
			if events != nil {
				if err := json.NewEncoder(events).Encode(map[string]any{"time": time.Now().UTC(), "stdout": string(d.GetStdout()), "stderr": string(d.GetStderr())}); err != nil {
					return "", -1, err
				}
			} else {
				output.Write(d.GetStdout())
				output.Write(d.GetStderr())
			}
		}
		if end := e.GetEnd(); end != nil {
			code = end.GetExitCode()
		}
	}
	return output.String(), code, stream.Err()
}

// An HTTP listener on the tap gateway forwards only to the configured CPA.
// The listener is created in the VM netns; upstream sockets are opened in the
// host netns. No forwarding sysctl or host firewall change is necessary.
type agentBenchNetwork struct {
	sharedBenchNetwork
	upstream, dir string
	mu            sync.Mutex
	gateways      map[string]*http.Server
}

func (p *agentBenchNetwork) Get(ctx context.Context, conf *orchestrator.SandboxNetworkConfig, class network.EgressClass) (*network.Slot, error) {
	slot, err := p.sharedBenchNetwork.Get(ctx, conf, class)
	if err != nil {
		return nil, err
	}
	identity, err := os.Stat(filepath.Join("/var/run/netns", slot.NamespaceID()))
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	owned, err := os.OpenFile(filepath.Join(p.dir, "owned-netns.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err == nil {
		err = json.NewEncoder(owned).Encode(map[string]any{"name": slot.NamespaceID(), "inode": identity.Sys().(*syscall.Stat_t).Ino})
		err = errors.Join(err, owned.Close())
	}
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	netns, err := ns.GetNS(filepath.Join("/var/run/netns", slot.NamespaceID()))
	if err != nil {
		return nil, err
	}
	defer netns.Close()
	var listener net.Listener
	err = netns.Do(func(ns.NetNS) error {
		var e error
		listener, e = net.Listen("tcp4", net.JoinHostPort(slot.TapIPString(), "8317"))
		return e
	})
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(p.upstream)
	if err != nil {
		listener.Close()
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Transport = &http.Transport{Proxy: nil, ResponseHeaderTimeout: 10 * time.Minute}
	proxy.FlushInterval = -1
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		status := &agentBenchHTTPStatus{ResponseWriter: w, code: http.StatusOK}
		proxy.ServeHTTP(status, r)
		p.mu.Lock()
		defer p.mu.Unlock()
		f, e := os.OpenFile(filepath.Join(p.dir, "model-requests.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if e == nil {
			_ = json.NewEncoder(f).Encode(map[string]any{"netns": slot.NamespaceID(), "start": start.UTC(), "end": time.Now().UTC(), "path": r.URL.Path, "status": status.code})
			_ = f.Close()
		}
	})}
	p.mu.Lock()
	p.gateways[slot.NamespaceID()] = server
	p.mu.Unlock()
	go func() { _ = server.Serve(listener) }()
	return slot, nil
}

type agentBenchHTTPStatus struct {
	http.ResponseWriter
	code int
}

func (w *agentBenchHTTPStatus) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *agentBenchHTTPStatus) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (p *agentBenchNetwork) ReturnAsync(ctx context.Context, slot *network.Slot, released network.ReleaseNotify, after time.Duration) error {
	p.mu.Lock()
	server := p.gateways[slot.NamespaceID()]
	delete(p.gateways, slot.NamespaceID())
	p.mu.Unlock()
	var err error
	if server != nil {
		err = server.Close()
	}
	return errors.Join(err, p.sharedBenchNetwork.ReturnAsync(ctx, slot, released, after))
}

func (p *agentBenchNetwork) Close(ctx context.Context) error {
	p.mu.Lock()
	var err error
	for k, s := range p.gateways {
		err = errors.Join(err, s.Close())
		delete(p.gateways, k)
	}
	p.mu.Unlock()
	return errors.Join(err, p.sharedBenchNetwork.Close(ctx))
}
