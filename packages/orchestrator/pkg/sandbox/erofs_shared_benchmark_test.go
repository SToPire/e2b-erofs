//go:build linux

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/google/uuid"
	"github.com/launchdarkly/go-server-sdk/v7/testhelpers/ldtestdata"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

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

// TestEROFSSharedMountBenchmark is an opt-in topology A/B, NOT an old-binary
// comparison. All sixteen cases use the same real-envd G0, current Factory/FC,
// 256 MiB RAM and the lifecycle guest's three RAM/disk pages. Each VM reads
// state eight times, writes nonzero/zero pages, then a branch-specific RAM page
// and 512-byte disk range. This small correctness workload is not a general
// application-memory savings benchmark; physical PFN proof is a separate gate.
//
// E2B_EROFS_SHARED_BENCHMARK=1 plus E2B_EROFS_BASELINE_FACTORY_DIR, FC, KERNEL,
// MKFS, FSCK, ENVD and TEST_DIR (the latter six prefixed E2B_EROFS_) are required.
// Run a compiled test binary as root, with -test.timeout=30m. Ordinary tests skip.
// Cases retain reports even on assertion failure, never delete fixture evidence,
// and never change sysctls, host limits or global caches. No t.Parallel: real
// resources are owned by this process, while other workers may use the host.
func TestEROFSSharedMountBenchmark(t *testing.T) { //nolint:paralleltest
	if os.Getenv("E2B_EROFS_SHARED_BENCHMARK") != "1" {
		t.Skip("explicit E2B_EROFS_SHARED_BENCHMARK=1 required for real 1/2/4/8-VM topology A/B")
	}
	require.Zero(t, os.Geteuid())
	inputs := map[string]string{}
	for _, key := range []string{"BASELINE_FACTORY_DIR", "FC", "KERNEL", "MKFS", "FSCK", "ENVD", "TEST_DIR"} {
		value := os.Getenv("E2B_EROFS_" + key)
		require.NotEmpty(t, value, "missing E2B_EROFS_"+key)
		path, err := filepath.Abs(value)
		require.NoError(t, err)
		inputs[key] = path
	}
	require.NoError(t, os.MkdirAll(inputs["TEST_DIR"], 0o755))
	work, err := os.MkdirTemp(inputs["TEST_DIR"], "shared-benchmark-")
	require.NoError(t, err)
	t.Logf("retained benchmark: %s", work)
	report := map[string]any{
		"status": "incomplete", "inputs": inputs, "counts": []int{1, 2, 4, 8},
		"comparison":    "topology A/B using current binary: same TeamID versus distinct synthetic TeamIDs; same generation",
		"cache_method":  "fresh per-case image copies and mounts; fadvise DONTNEED on owned logical files after baseline hashing; warm additionally reads both logical files before any restore. Cold is advisory logical-file cold, NOT device/host cold: Store.Load hashes backing images and caches remain shared below EROFS. No global eviction; sequential guests can warm shared mounts.",
		"timing_method": "serial setup; acquire_ms includes mount/validation; restore_ms is Factory.ResumeSandbox including envd readiness on already-acquired mounts; create_total_ms adds these two and excludes cache conditioning. resume_in_place_ms measures a separate FC pause/resume. No cold boot measured.",
		"limitations":   []string{"three-page guest workload, not a large application working set", "host/node cache counters include other host activity", "PSS is attribution, not physical PFN proof", "userspace envd relay and test harness memory are reported separately; no forwarding sysctl changes"},
		"cases":         []map[string]any{},
	}
	t.Cleanup(func() {
		completed := 0
		for _, result := range report["cases"].([]map[string]any) {
			if result["status"] == "passed" {
				completed++
			}
		}
		report["completed_cases"] = completed
		report["status"] = "incomplete"
		if completed == 16 {
			report["status"] = "passed"
		}
		if t.Failed() {
			report["status"] = "failed"
		}
		sharedBenchJSON(t, filepath.Join(work, "report.json"), report)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Minute)
	defer cancel()
	baselineDir := inputs["BASELINE_FACTORY_DIR"]
	var provenance map[string]any
	require.NoError(t, json.Unmarshal(sharedBenchRead(t, filepath.Join(baselineDir, "report.json")), &provenance))
	require.Equal(t, "passed", provenance["status"])
	require.Equal(t, true, provenance["envd_enabled"])
	hashes := map[string]string{}
	for _, key := range []string{"FC", "KERNEL", "MKFS", "FSCK", "ENVD"} {
		hashes[key] = fmt.Sprintf("%x", lifecycleHash(t, inputs[key]))
	}
	for _, tool := range []string{"qemu-nbd", "qemu-img", "ip", "curl"} {
		path, err := exec.LookPath(tool)
		require.NoError(t, err)
		inputs[tool] = path
		hashes[tool] = fmt.Sprintf("%x", lifecycleHash(t, path))
	}
	executable, err := os.Executable()
	require.NoError(t, err)
	hashes["test_binary"] = fmt.Sprintf("%x", lifecycleHash(t, executable))
	_, sourcePath, _, _ := runtime.Caller(0)
	hashes["test_source"] = fmt.Sprintf("%x", lifecycleHash(t, sourcePath))
	report["sha256"] = hashes
	report["baseline_report"] = provenance
	report["uname"] = string(lifecycleCommand(t, ctx, "uname", "-a"))
	report["boot_id"] = string(sharedBenchRead(t, "/proc/sys/kernel/random/boot_id"))
	require.Equal(t, provenance["firecracker_sha256"], hashes["FC"])
	require.Equal(t, provenance["envd_sha256"], hashes["ENVD"])
	source, err := erofs.NewStore(filepath.Join(baselineDir, "snapshots"), erofs.Options{})
	require.NoError(t, err)
	entries, err := os.ReadDir(source.Root)
	require.NoError(t, err)
	var seed *erofs.Snapshot
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		candidate, err := source.Load(entry.Name())
		require.NoError(t, err)
		if candidate.Manifest.ParentID == "" {
			require.Nil(t, seed, "ambiguous generation zero")
			seed = candidate
		}
	}
	require.NotNil(t, seed)
	require.EqualValues(t, 256<<20, seed.Manifest.Memory.Size)
	require.EqualValues(t, 64<<20, seed.Manifest.Disk.Size)
	report["manifest"] = seed.Manifest // Includes exact image/vmstate/metadata hashes and device order.
	meta, err := metadata.FromFile(seed.MetadataPath())
	require.NoError(t, err)
	require.Equal(t, hashes["KERNEL"], fmt.Sprintf("%x", lifecycleHash(t,
		filepath.Join(baselineDir, "kernels", meta.Template.KernelVersion, "vmlinux.bin"))))
	envdVersion := strings.TrimSpace(string(lifecycleCommand(t, ctx, inputs["ENVD"], "-version")))
	// Real manager only when controllers are already provisioned: do not mutate
	// the shared cgroup parent or fall back to reporting our own cgroup as a VM.
	var manager cgroup.Manager = cgroup.NewNoopManager()
	controllers, cgErr := os.ReadFile(filepath.Join(cgroup.RootCgroupPath, "cgroup.subtree_control"))
	report["cgroup_method"] = "unavailable: existing /sys/fs/cgroup/e2b must have cpu+memory controllers; no host/controller changes made"
	if cgErr == nil && strings.Contains(string(controllers), "cpu") && strings.Contains(string(controllers), "memory") {
		manager, err = cgroup.NewManager()
		require.NoError(t, err)
		report["cgroup_method"] = "existing real cgroup manager; per-VM path, membership and memory.current/stat/peak recorded; no limits changed"
	} else {
		report["cgroup_preflight"] = fmt.Sprintf("subtree_control=%q error=%v", controllers, cgErr)
	}
	// Alternate order across counts to expose (not eliminate) temporal host noise.
	for _, count := range []int{1, 2, 4, 8} {
		for _, cache := range []string{"cold-advisory", "warm"} {
			topologies := []string{"shared", "isolated-teams"}
			if count == 2 || count == 8 {
				topologies[0], topologies[1] = topologies[1], topologies[0]
			}
			for _, topology := range topologies {
				name := fmt.Sprintf("%d-%s-%s", count, cache, topology)
				result := map[string]any{"name": name, "count": count, "cache": cache, "topology": topology, "status": "incomplete"}
				report["cases"] = append(report["cases"].([]map[string]any), result)
				if !t.Run(name, func(t *testing.T) {
					sharedBenchCase(t, ctx, work, inputs, seed, meta, envdVersion, manager, count, cache, topology, result)
				}) {
					return
				} // Do not contaminate subsequent cases after a failed cleanup/assertion.
			}
		}
	}
	_, err = source.Load(seed.Manifest.ID)
	require.NoError(t, err, "original fixture artifacts must remain unchanged")
}

func sharedBenchCase(t *testing.T, ctx context.Context, work string, inputs map[string]string, seed *erofs.Snapshot,
	meta metadata.Template, envdVersion string, manager cgroup.Manager, count int, cache, topology string, result map[string]any,
) {
	t.Helper()
	dir := filepath.Join(work, result["name"].(string))
	require.NoError(t, os.Mkdir(dir, 0o755))
	var vms []*Sandbox
	var refs []*erofs.MountRef
	var factory *Factory
	var devices *nbd.DevicePool
	var cancelPool context.CancelFunc
	var netPool *sharedBenchNetwork
	var flags *featureflags.Client
	vmReports := []map[string]any{}
	logStart := testLogObserver.Len()
	// One cleanup block preserves ordering on every require.FailNow path.
	t.Cleanup(func() {
		var cleanupErrors []string
		check := func(label string, err error) {
			if err != nil {
				cleanupErrors = append(cleanupErrors, label+": "+err.Error())
				t.Errorf("%s: %v", label, err)
			}
		}
		for i := len(vms) - 1; i >= 0; i-- {
			closeCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			start := time.Now()
			check("close VM", vms[i].Close(closeCtx))
			vmReports[i]["kill_ms"] = float64(time.Since(start).Microseconds()) / 1000
			cancel()
		}
		// Factory/nativeResources close FC before its private QEMU/NBD and mounts.
		for _, ref := range refs {
			check("release preparation reference", ref.Release())
		}
		if factory != nil {
			closeCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			check("shared mounts", factory.CloseSharedMounts(closeCtx))
			cancel()
		}
		if netPool != nil {
			check("network", netPool.Close(context.Background()))
		}
		if cancelPool != nil {
			cancelPool()
		}
		if devices != nil {
			closeCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			check("NBD pool", devices.Close(closeCtx))
			cancel()
		}
		if flags != nil {
			check("flags", flags.Close(context.Background()))
		}
		// Nonfatal diagnostics must not prevent report writing on cleanup failure.
		after := sharedBenchHost(dir, "after-cleanup")
		result["after_cleanup"] = after
		if after["owned_mount_count"] != 0 || after["owned_loop_count"] != 0 {
			check("owned resources", fmt.Errorf("mounts=%v loops=%v", after["owned_mount_count"], after["owned_loop_count"]))
		}
		for _, vm := range vmReports {
			if identity, ok := vm["fc_identity"].(erofs.ProcessIdentity); ok {
				check("FC termination", erofs.ProcessTerminated(identity))
			}
			if overlay, ok := vm["overlay"].(erofs.OverlayRecovery); ok {
				check("QEMU termination", erofs.ProcessTerminated(overlay.Producer))
			}
		}
		logs := []map[string]any{}
		for _, entry := range testLogObserver.All()[logStart:] {
			logs = append(logs, map[string]any{"time": entry.Time, "message": entry.Message, "fields": entry.ContextMap()})
			if t.Failed() {
				t.Log(entry.Message, entry.ContextMap())
			}
		}
		sharedBenchJSON(t, filepath.Join(dir, "factory-logs.json"), logs)
		result["cleanup_errors"] = cleanupErrors
		result["vms"] = vmReports
		result["status"] = "passed"
		if t.Failed() {
			result["status"] = "failed"
		}
		sharedBenchJSON(t, filepath.Join(dir, "report.json"), result)
	})
	config := cfg.BuilderConfig{
		EROFSSnapshotDir: filepath.Join(dir, "snapshots"), EROFSNativeMemoryVerified: true, EROFSMkfsPath: inputs["MKFS"],
		FirecrackerVersionsDir: filepath.Join(dir, "firecracker"), HostKernelsDir: filepath.Join(dir, "kernels"),
		OrchestratorBaseDir: filepath.Join(dir, "orchestrator"), SandboxDir: filepath.Join(inputs["BASELINE_FACTORY_DIR"], "fc-vm"),
		StorageConfig: storage.Config{SandboxCacheDir: filepath.Join(dir, "sandbox-cache"), TemplateCacheDir: filepath.Join(dir, "template-cache")},
	}
	for _, path := range []string{config.EROFSSnapshotDir, config.StorageConfig.SandboxCacheDir, config.StorageConfig.TemplateCacheDir,
		filepath.Join(config.FirecrackerVersionsDir, meta.Template.FirecrackerVersion), filepath.Join(config.HostKernelsDir, meta.Template.KernelVersion), filepath.Join(dir, "bin")} {
		require.NoError(t, os.MkdirAll(path, 0o755))
	}
	lifecycleCommand(t, ctx, "cp", "-a", "--reflink=never", seed.Dir, filepath.Join(config.EROFSSnapshotDir, seed.Manifest.ID))
	for target, source := range map[string]string{
		filepath.Join(config.FirecrackerVersionsDir, meta.Template.FirecrackerVersion, "firecracker"): inputs["FC"],
		filepath.Join(config.HostKernelsDir, meta.Template.KernelVersion, "vmlinux.bin"):              inputs["KERNEL"],
		filepath.Join(dir, "bin", "fsck.erofs"):                                                       inputs["FSCK"],
	} {
		require.NoError(t, os.Symlink(source, target))
	}
	t.Setenv("PATH", filepath.Join(dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	store, err := erofs.NewStore(config.EROFSSnapshotDir, erofs.Options{MkfsPath: inputs["MKFS"], FsckPath: inputs["FSCK"]})
	require.NoError(t, err)
	baseline, err := store.Load(seed.Manifest.ID)
	require.NoError(t, err)
	paths, err := (storage.Paths{BuildID: seed.Manifest.ID}).Cache(config.StorageConfig)
	require.NoError(t, err)
	tmpl := template.NewEROFSTemplate(paths, baseline)
	flags, err = featureflags.NewClientWithDatasource(ldtestdata.DataSource())
	require.NoError(t, err)
	devices, err = nbd.NewDevicePool(count)
	require.NoError(t, err)
	poolCtx, stopPool := context.WithCancel(context.Background())
	cancelPool = stopPool
	go devices.Populate(poolCtx)
	netPool = &sharedBenchNetwork{lifecycleNetworkPool: lifecycleNetworkPool{slots: make(map[string]*network.Slot)}, servers: make(map[string]*http.Server)}
	factory = NewFactory(ctx, config, netPool, devices, flags, hoststats.NewNoopDelivery(), manager, network.NewNoopEgressProxy(), nil, NewSandboxesMap())
	result["before"] = sharedBenchHost(dir, "before")
	teams := make([]string, count)
	memoryPaths, diskPaths := make([]string, count), make([]string, count)
	acquireMS := make([]float64, count)
	baselineHashes := map[string]string{}
	team := uuid.NewString()
	// Hold preparation references so warming uses precisely the runtime inode.
	// Isolated teams get independent file-backed mounts of identical copied artifacts.
	for i := range count {
		teams[i] = team
		if topology != "shared" {
			teams[i] = uuid.NewString()
		}
		start := time.Now()
		ref, err := factory.sharedMounts.Acquire(ctx, baseline, teams[i])
		if ref != nil {
			refs = append(refs, ref)
		}
		require.NoError(t, err)
		acquireMS[i] = float64(time.Since(start).Microseconds()) / 1000
		memoryPaths[i], diskPaths[i] = ref.MemoryPath(), ref.DiskPath()
		for _, path := range []string{ref.MemoryPath(), ref.DiskPath()} {
			if _, exists := baselineHashes[path]; !exists {
				baselineHashes[path] = fmt.Sprintf("%x", lifecycleHash(t, path))
			}
		}
	}
	result["baseline_sha256"] = baselineHashes
	result["before_conditioning"] = sharedBenchHost(dir, "before-conditioning")
	for path := range baselineHashes {
		file, err := os.Open(path)
		require.NoError(t, err)
		err = unix.Fadvise(int(file.Fd()), 0, 0, unix.FADV_DONTNEED)
		closeErr := file.Close()
		require.NoError(t, err)
		require.NoError(t, closeErr)
	}
	if cache == "warm" {
		for path := range baselineHashes {
			file, err := os.Open(path)
			require.NoError(t, err)
			_, err = io.Copy(io.Discard, file)
			closeErr := file.Close()
			require.NoError(t, err)
			require.NoError(t, closeErr)
		}
	}
	result["after_conditioning"] = sharedBenchHost(dir, "after-conditioning")
	for i := range count {
		token, user := strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", ""), "root"
		conf := NewConfig(Config{Vcpu: 1, RamMB: 256, TotalDiskSizeMB: 64,
			FirecrackerConfig: fc.Config{KernelVersion: meta.Template.KernelVersion, FirecrackerVersion: meta.Template.FirecrackerVersion, NativeMemory: true},
			Envd:              EnvdMetadata{Version: envdVersion, AccessToken: &token, DefaultUser: &user, Vars: map[string]string{"EROFS_LIFECYCLE": "ram-disk"}}})
		runtime := RuntimeMetadata{TemplateID: "erofs-benchmark", SandboxID: "bm" + uuid.NewString()[:8], ExecutionID: uuid.NewString(),
			BuildID: seed.Manifest.ID, TeamID: teams[i], SandboxType: SandboxTypeBuild}
		start := time.Now()
		s, err := factory.ResumeSandbox(ctx, tmpl, conf, runtime, start, start.Add(time.Hour), nil, WithoutLiveRegistration())
		elapsed := float64(time.Since(start).Microseconds()) / 1000
		if s != nil {
			vms = append(vms, s)
			vmReports = append(vmReports, map[string]any{"sandbox_id": runtime.SandboxID, "team_id": teams[i],
				"acquire_ms": acquireMS[i], "restore_ms": elapsed, "create_total_ms": acquireMS[i] + elapsed})
		}
		require.NoError(t, err)
		lifecycleEnvd(t, ctx, s)
		kernelBackend := lifecycleSharedMountIdentity(t, s, memoryPaths[i], diskPaths[i], factory.sharedMounts.Root())
		info, err := s.rootfs.(*erofsRootfs).overlay.RecoveryInfo()
		require.NoError(t, err)
		nbdPath, err := s.rootfs.Path()
		require.NoError(t, err)
		vmReports[i]["overlay"] = info
		vmReports[i]["nbd"] = nbdPath
		vmReports[i]["kernel_backend"] = kernelBackend
		pid, err := s.process.Pid()
		require.NoError(t, err)
		vmReports[i]["fc_pid"] = pid
		identity, err := erofs.IdentifyProcess(pid)
		require.NoError(t, err)
		vmReports[i]["fc_identity"] = identity
		vmReports[i]["qemu_pid"] = info.Producer.PID
		vmReports[i]["fc_sha256"] = fmt.Sprintf("%x", lifecycleHash(t, fmt.Sprintf("/proc/%d/exe", pid)))
		vmReports[i]["qemu_sha256"] = fmt.Sprintf("%x", lifecycleHash(t, fmt.Sprintf("/proc/%d/exe", info.Producer.PID)))
	}
	for _, ref := range refs {
		require.NoError(t, ref.Release())
	}
	refs = nil
	// Assert measured topology and per-runtime writable resources, including N=1.
	memIDs, diskIDs, qemus, nbds, overlays := map[string]bool{}, map[string]bool{}, map[any]bool{}, map[any]bool{}, map[string]bool{}
	for i, s := range vms {
		memIDs[sharedBenchIdentity(t, memoryPaths[i])] = true
		diskIDs[sharedBenchIdentity(t, diskPaths[i])] = true
		qemus[vmReports[i]["qemu_pid"]] = true
		nbds[vmReports[i]["nbd"]] = true
		info, err := s.rootfs.(*erofsRootfs).overlay.RecoveryInfo()
		require.NoError(t, err)
		overlays[sharedBenchIdentity(t, info.Path)] = true
	}
	wantMountPairs := count
	if topology == "shared" {
		wantMountPairs = 1
	}
	require.Len(t, memIDs, wantMountPairs)
	require.Len(t, diskIDs, wantMountPairs)
	require.Len(t, qemus, count)
	require.Len(t, nbds, count)
	require.Len(t, overlays, count)
	result["memory_identities"], result["disk_identities"] = memIDs, diskIDs
	baseState := lifecycleGuestState{Memory: [3]int{0x31, 0x42, 0x53}, Disk: [3]int{0x31, 0x42, 0x53}, Partial: 0x53}
	for _, s := range vms {
		for range 8 {
			lifecycleState(t, ctx, s, "/state", baseState)
		}
	}
	measure := func(phase string) {
		for _, s := range vms {
			require.NoError(t, s.process.Pause(ctx))
		}
		host := sharedBenchHost(dir, phase)
		result[phase+"_host"] = host
		require.Equal(t, 2*wantMountPairs, host["owned_mount_count"])
		require.Equal(t, 0, host["owned_loop_count"])
		totals := map[string]uint64{}
		for i, s := range vms {
			metrics := sharedBenchVM(t, dir, phase, s, memoryPaths[i])
			vmReports[i][phase] = metrics
			for _, group := range []string{"fc_memfile_kib", "fc_total_kib", "qemu_total_kib"} {
				for _, key := range []string{"Rss", "Pss", "Private_Dirty", "Shared_Clean", "Shared_Dirty"} {
					totals[group+"_"+key] += metrics[group].(map[string]uint64)[key]
				}
			}
		}
		result[phase+"_totals"] = totals
		for i, s := range vms {
			start := time.Now()
			require.NoError(t, s.process.ResumeInPlace(ctx))
			vmReports[i][phase+"_resume_in_place_ms"] = float64(time.Since(start).Microseconds()) / 1000
		}
	}
	measure("read")
	one := lifecycleGuestState{Generation: 1, Memory: [3]int{0xa6, 0, 0x53}, Disk: [3]int{0xa6, 0, 0x53}, Partial: 0x53}
	lifecycleState(t, ctx, vms[0], "/write/1", one)
	for _, s := range vms[1:] {
		lifecycleState(t, ctx, s, "/state", baseState)
	}
	for _, s := range vms[1:] {
		lifecycleState(t, ctx, s, "/write/1", one)
	}
	for i, s := range vms {
		want, path := one, "/write/2"
		want.Generation, want.Memory[2], want.Partial = 2, 0xb7, 0xb7
		if i%2 == 1 {
			want.Generation, want.Memory[2], want.Partial, path = 3, 0xc8, 0xc8, "/write/b"
		}
		lifecycleState(t, ctx, s, path, want)
	}
	for i, s := range vms {
		want := one
		want.Generation, want.Memory[2], want.Partial = 2, 0xb7, 0xb7
		if i%2 == 1 {
			want.Generation, want.Memory[2], want.Partial = 3, 0xc8, 0xc8
		}
		lifecycleState(t, ctx, s, "/state", want)
	}
	measure("write")
	// Hash only after sampling, so verification does not prime measured caches.
	for path, hash := range baselineHashes {
		require.Equal(t, hash, fmt.Sprintf("%x", lifecycleHash(t, path)), "baseline changed: %s", path)
	}
	_, err = store.Load(seed.Manifest.ID)
	require.NoError(t, err)
	result["cow_content_isolation"], result["baseline_unchanged"] = true, true
}

func sharedBenchRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

func sharedBenchJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err == nil {
		err = os.WriteFile(path, append(data, '\n'), 0o644)
	}
	if err != nil {
		t.Errorf("write evidence %s: %v", path, err)
	}
}

func sharedBenchIdentity(t *testing.T, path string) string {
	t.Helper()
	var st unix.Stat_t
	require.NoError(t, unix.Stat(path, &st))
	return fmt.Sprintf("%x:%x:%d", unix.Major(st.Dev), unix.Minor(st.Dev), st.Ino)
}

// Values remain in the source's units (smaps/meminfo: KiB; memory.stat: bytes).
func sharedBenchCounters(data string) map[string]uint64 {
	values := map[string]uint64{}
	for line := range strings.SplitSeq(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err == nil {
			values[strings.TrimSuffix(fields[0], ":")] += value
		}
	}
	return values
}

func sharedBenchMemSmaps(data, identity string) (map[string]uint64, error) {
	return sharedBenchFileSmaps(data, identity, "rw-p")
}

func sharedBenchFileSmaps(data, identity, permissions string) (map[string]uint64, error) {
	var selected strings.Builder
	active, found := false, false
	for line := range strings.SplitSeq(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && strings.Contains(fields[0], "-") {
			dev := strings.Split(fields[3], ":")
			if len(dev) != 2 {
				return nil, fmt.Errorf("invalid smaps device: %s", line)
			}
			major, e1 := strconv.ParseUint(dev[0], 16, 32)
			minor, e2 := strconv.ParseUint(dev[1], 16, 32)
			inode, e3 := strconv.ParseUint(fields[4], 10, 64)
			if err := errors.Join(e1, e2, e3); err != nil {
				return nil, err
			}
			active = fmt.Sprintf("%x:%x:%d", major, minor, inode) == identity
			if active {
				found = true
				if fields[1] != permissions {
					return nil, fmt.Errorf("mapping permissions must be %s: %s", permissions, line)
				}
			}
		} else if active {
			selected.WriteString(line + "\n")
		}
	}
	if !found {
		return nil, errors.New("shared memfile inode absent from FC smaps")
	}
	return sharedBenchCounters(selected.String()), nil
}

// Observational only: save errors instead of substituting zeros for missing
// host counters. Scope ownership by full case directory, not a global delta.
func sharedBenchHost(dir, phase string) map[string]any {
	result := map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano)}
	for name, path := range map[string]string{"meminfo": "/proc/meminfo", "mountinfo": "/proc/self/mountinfo",
		"vmstat": "/proc/vmstat", "memory_pressure": "/proc/pressure/memory", "harness_smaps_rollup": "/proc/self/smaps_rollup"} {
		data, err := os.ReadFile(path)
		if err != nil {
			result[name+"_error"] = err.Error()
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, phase+"-"+name+".txt"), data, 0o644); err != nil {
			result[name+"_save_error"] = err.Error()
		}
		if name == "meminfo" {
			counters := sharedBenchCounters(string(data))
			result["meminfo_kib"] = counters
			if total, ok := counters["MemTotal"]; ok {
				if available, ok := counters["MemAvailable"]; ok && total >= available {
					result["node_used_estimate_kib"] = total - available
				}
			}
		} else if name == "harness_smaps_rollup" {
			result["harness_kib"] = sharedBenchCounters(string(data))
		} else if name == "mountinfo" {
			mounts := []string{}
			for _, line := range strings.Split(string(data), "\n") {
				f := strings.Fields(line)
				if len(f) > 6 && strings.HasPrefix(f[4], dir+"/") {
					mounts = append(mounts, line)
				}
			}
			result["owned_mounts"], result["owned_mount_count"] = mounts, len(mounts)
		}
	}
	loops := map[string]string{}
	paths, err := filepath.Glob("/sys/block/loop*/loop/backing_file")
	if err != nil {
		result["loop_error"] = err.Error()
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		} // Unrelated loops may disappear concurrently.
		backing := strings.TrimSpace(string(data))
		if strings.HasPrefix(backing, dir+"/") {
			loops[filepath.Base(filepath.Dir(filepath.Dir(path)))] = backing
		}
	}
	result["owned_loops"], result["owned_loop_count"] = loops, len(loops)
	return result
}

func sharedBenchVM(t *testing.T, dir, phase string, s *Sandbox, memory string) map[string]any {
	t.Helper()
	pid, err := s.process.Pid()
	require.NoError(t, err)
	info, err := s.rootfs.(*erofsRootfs).overlay.RecoveryInfo()
	require.NoError(t, err)
	result := map[string]any{}
	for name, pid := range map[string]int{"fc": pid, "qemu": info.Producer.PID} {
		prefix := filepath.Join(dir, fmt.Sprintf("%s-%s-%d", phase, name, pid))
		for _, metric := range []string{"smaps", "smaps_rollup", "cgroup", "status", "mountinfo"} {
			data := sharedBenchRead(t, fmt.Sprintf("/proc/%d/%s", pid, metric))
			require.NoError(t, os.WriteFile(prefix+"-"+metric+".txt", data, 0o644))
			if metric == "smaps_rollup" {
				result[name+"_total_kib"] = sharedBenchCounters(string(data))
			}
			if name == "fc" && metric == "smaps" {
				metrics, err := sharedBenchMemSmaps(string(data), sharedBenchIdentity(t, memory))
				require.NoError(t, err)
				result["fc_memfile_kib"] = metrics
			}
		}
	}
	result["cgroup_unavailable"] = "Factory has no real per-sandbox cgroup handle; see preflight or Factory logs"
	if s.cgroupHandle != nil && s.cgroupHandle.Path() != "" {
		path := s.cgroupHandle.Path()
		result["cgroup_path"] = path
		cg := map[string]string{}
		for _, name := range []string{"memory.current", "memory.peak", "memory.stat", "memory.events", "cgroup.procs"} {
			data, err := os.ReadFile(filepath.Join(path, name))
			if err != nil {
				cg[name+"_error"] = err.Error()
			} else {
				cg[name] = string(data)
			}
		}
		result["cgroup"] = cg
		members := strings.Fields(cg["cgroup.procs"])
		require.Contains(t, members, strconv.Itoa(pid), "recorded cgroup must actually contain this FC")
		result["cgroup_scope"] = "sandbox FC cgroup; QEMU membership is recorded separately in its proc cgroup file"
		delete(result, "cgroup_unavailable")
	}
	return result
}

// Tap-only lifecycle networking plus an in-process relay to real envd. HostIP
// is a unique loopback address, so no host routes/addresses/sysctls are changed.
// ns.Do pins the dial to the VM netns; numeric tcp4 avoids DNS/happy-eyeballs
// helper goroutines opening a socket in the wrong namespace. No guest request
// or response is fabricated. Relay allocation belongs to harness RSS/PSS.
type sharedBenchNetwork struct {
	lifecycleNetworkPool
	serverMu sync.Mutex
	servers  map[string]*http.Server
}

func (p *sharedBenchNetwork) Get(ctx context.Context, conf *orchestrator.SandboxNetworkConfig, class network.EgressClass) (*network.Slot, error) {
	slot, err := p.lifecycleNetworkPool.Get(ctx, conf, class)
	if err != nil {
		return nil, err
	}
	slot.HostIP = net.IPv4(127, 77, byte(slot.Idx>>8), byte(slot.Idx))
	listener, err := net.Listen("tcp4", net.JoinHostPort(slot.HostIPString(), "49983"))
	if err != nil {
		return nil, errors.Join(err, p.lifecycleNetworkPool.ReturnAsync(context.WithoutCancel(ctx), slot, nil, 0))
	}
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		netns, err := ns.GetNS(filepath.Join("/var/run/netns", slot.NamespaceID()))
		if err != nil {
			return nil, err
		}
		defer netns.Close()
		var conn net.Conn
		err = netns.Do(func(ns.NetNS) error {
			var dialErr error
			conn, dialErr = (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(slot.NamespaceIP(), "49983"))
			return dialErr
		})
		if err != nil && conn != nil {
			_ = conn.Close()
			conn = nil
		}
		return conn, err
	}}
	proxy := &httputil.ReverseProxy{Director: func(r *http.Request) {
		r.URL.Scheme = "http"
		r.URL.Host = net.JoinHostPort(slot.NamespaceIP(), "49983")
	}, Transport: transport}
	server := &http.Server{Handler: proxy, ReadHeaderTimeout: 5 * time.Second}
	p.serverMu.Lock()
	p.servers[slot.NamespaceID()] = server
	p.serverMu.Unlock()
	go func() { _ = server.Serve(listener) }()
	return slot, nil
}

func (p *sharedBenchNetwork) ReturnAsync(ctx context.Context, slot *network.Slot, released network.ReleaseNotify, after time.Duration) error {
	p.serverMu.Lock()
	server := p.servers[slot.NamespaceID()]
	delete(p.servers, slot.NamespaceID())
	p.serverMu.Unlock()
	var err error
	if server != nil {
		err = server.Close()
	}
	return errors.Join(err, p.lifecycleNetworkPool.ReturnAsync(ctx, slot, released, after))
}

func (p *sharedBenchNetwork) Close(ctx context.Context) error {
	p.serverMu.Lock()
	var err error
	for key, server := range p.servers {
		err = errors.Join(err, server.Close())
		delete(p.servers, key)
	}
	p.serverMu.Unlock()
	return errors.Join(err, p.lifecycleNetworkPool.Close(ctx))
}

func TestEROFSSharedBenchmarkParsers(t *testing.T) {
	t.Parallel()
	smaps := "1000-2000 rw-p 00000000 08:01 42 /memfile\nPss: 4 kB\nPrivate_Dirty: 0 kB\n" +
		"2000-3000 rw-p 00001000 08:01 42 /memfile\nPss: 2 kB\nPrivate_Dirty: 4 kB\n" +
		"3000-4000 rw-p 00000000 08:02 42 /other\nPss: 99 kB\n"
	got, err := sharedBenchMemSmaps(smaps, "8:1:42")
	require.NoError(t, err)
	require.EqualValues(t, 6, got["Pss"])
	require.EqualValues(t, 4, got["Private_Dirty"])
	_, err = sharedBenchMemSmaps(smaps, "8:1:43")
	require.Error(t, err)
	_, err = sharedBenchMemSmaps(strings.ReplaceAll(smaps, "rw-p", "rw-s"), "8:1:42")
	require.Error(t, err)
	require.EqualValues(t, 42, sharedBenchCounters("MemAvailable: 42 kB\ninvalid: nope\n")["MemAvailable"])
	// Exercise host evidence without requiring privileged interfaces or VMs.
	dir := t.TempDir()
	host := sharedBenchHost(dir, "unprivileged")
	require.Equal(t, 0, host["owned_mount_count"])
	require.Equal(t, 0, host["owned_loop_count"])
	_, err = os.Stat(filepath.Join(dir, "unprivileged-meminfo.txt"))
	require.NoError(t, err)
}
