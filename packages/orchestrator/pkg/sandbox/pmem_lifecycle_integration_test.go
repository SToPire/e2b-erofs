//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/launchdarkly/go-server-sdk/v7/testhelpers/ldtestdata"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/e2b-dev/infra/packages/clickhouse/pkg/hoststats"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/cfg"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/block"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/cgroup"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/fc"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/network"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/template"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/build/core/pmem"
	"github.com/e2b-dev/infra/packages/shared/pkg/featureflags"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage"
)

// Exercises the real Factory, envd and kernel freeze/resume path. Run inside a
// private Host mount namespace with the pinned P0 kernel/FC/initramfs. The HTTP
// workload holds an open O_DIRECT file and independent RAM across generations.
func TestPmemFactoryLifecycle(t *testing.T) { //nolint:paralleltest // real VM/network/mount ownership
	if os.Getenv("E2B_PMEM_LIFECYCLE") != "1" {
		t.Skip("set E2B_PMEM_LIFECYCLE=1 and supply pinned runtime inputs")
	}
	require.Zero(t, os.Geteuid())
	_, err := os.Stat("/sys/module/nbd")
	require.ErrorIs(t, err, os.ErrNotExist, "NBD must be absent")
	if os.Getenv("E2B_PMEM_NO_LEGACY_TOOLS") == "1" {
		for _, name := range []string{"qemu-img", "qemu-nbd"} {
			_, err := exec.LookPath(name)
			require.ErrorIs(t, err, exec.ErrNotFound, "legacy tool must be unavailable: %s", name)
		}
	}
	inputs := make(map[string]string)
	for _, name := range []string{"FC", "KERNEL", "INITRD", "MKFS", "FSCK", "ENVD", "GUEST_SOURCE", "TEST_DIR"} {
		inputs[name] = os.Getenv("E2B_PMEM_" + name)
		require.NotEmpty(t, inputs[name], "missing E2B_PMEM_%s", name)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	require.NoError(t, os.MkdirAll(inputs["TEST_DIR"], 0755))
	work, err := os.MkdirTemp(inputs["TEST_DIR"], "lifecycle-pmem-")
	require.NoError(t, err)
	t.Logf("retained pmem lifecycle evidence: %s", work)
	config := cfg.BuilderConfig{EROFSSnapshotDir: filepath.Join(work, "store"), EROFSNativeMemoryVerified: true, EROFSPmemVerified: true, EROFSNativeOnly: true,
		EROFSMkfsPath: inputs["MKFS"], FirecrackerVersionsDir: filepath.Join(work, "fc"), HostKernelsDir: filepath.Join(work, "kernels"),
		OrchestratorBaseDir: filepath.Join(work, "orchestrator"), SandboxDir: filepath.Join(work, "fc-vm"),
		StorageConfig: storage.Config{SandboxCacheDir: filepath.Join(work, "cache"), TemplateCacheDir: filepath.Join(work, "templates")}}
	versions := fc.Config{KernelVersion: "kernel-pmem", FirecrackerVersion: "fc-pmem", NativeMemory: true}
	for target, source := range map[string]string{
		filepath.Join(config.HostKernelsDir, versions.KernelVersion, "vmlinux.bin"):              inputs["KERNEL"],
		filepath.Join(config.FirecrackerVersionsDir, versions.FirecrackerVersion, "firecracker"): inputs["FC"],
	} {
		require.NoError(t, os.MkdirAll(filepath.Dir(target), 0755))
		require.NoError(t, os.Symlink(source, target))
	}
	for _, p := range []string{config.StorageConfig.SandboxCacheDir, config.StorageConfig.TemplateCacheDir, filepath.Join(work, "bin")} {
		require.NoError(t, os.MkdirAll(p, 0755))
	}
	// Fail only publication, after the immutable lower was built successfully.
	failMarker := filepath.Join(work, "fail-publication")
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	config.EROFSMkfsPath = filepath.Join(work, "bin", "mkfs.erofs")
	require.NoError(t, os.WriteFile(config.EROFSMkfsPath, []byte("#!/bin/sh\nif [ -e "+quote(failMarker)+" ]; then exit 77; fi\nexec "+quote(inputs["MKFS"])+" \"$@\"\n"), 0755))
	require.NoError(t, os.Symlink(inputs["FSCK"], filepath.Join(work, "bin", "fsck.erofs")))
	t.Setenv("PATH", filepath.Join(work, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	const upperSize = int64(64 << 20)
	const lowerSize = int64(128 << 20)
	const ramMB = int64(256)
	tree := filepath.Join(work, "guest")
	for _, dir := range []string{"dev", "proc", "sys", "run", "etc", "root", "tmp", "sbin", "bin", "usr/bin"} {
		require.NoError(t, os.MkdirAll(filepath.Join(tree, dir), 0755))
	}
	lifecycleCommand(t, ctx, "cp", inputs["ENVD"], filepath.Join(tree, "envd"))
	envdVersion := strings.TrimSpace(string(lifecycleCommand(t, ctx, inputs["ENVD"], "-version")))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "etc/passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "etc/group"), []byte("root:x:0:\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "etc/hosts"), []byte("127.0.0.1 localhost\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tree, ".e2b"), []byte("BUILD_ID=parent\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "hard-a"), []byte("lower"), 0644))
	require.NoError(t, os.Link(filepath.Join(tree, "hard-a"), filepath.Join(tree, "hard-b")))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "remove-me"), []byte("whiteout me"), 0644))
	require.NoError(t, os.Mkdir(filepath.Join(tree, "dir-before"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "dir-before/child"), []byte("rename me"), 0644))

	lifecycleCommand(t, ctx, "gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-o", filepath.Join(tree, "sbin/init"), inputs["GUEST_SOURCE"])
	upperTree := filepath.Join(work, "upper-tree")
	for _, dir := range []string{"upper", "work"} {
		require.NoError(t, os.MkdirAll(filepath.Join(upperTree, dir), 0755))
	}
	rawImage := func(name, source string, size int64) string {
		t.Helper()
		path := filepath.Join(work, name)
		f, err := os.Create(path)
		require.NoError(t, err)
		require.NoError(t, f.Truncate(size))
		require.NoError(t, f.Close())
		lifecycleCommand(t, ctx, "mkfs.ext4", "-q", "-F", "-b", "4096", "-d", source, path)
		return path
	}
	lowerPath, upperPath := rawImage("lower.raw", tree, lowerSize), rawImage("upper-seed.raw", upperTree, upperSize)
	store, err := erofs.NewStore(config.EROFSSnapshotDir, erofs.Options{MkfsPath: config.EROFSMkfsPath, FsckPath: inputs["FSCK"]})
	require.NoError(t, err)
	lower, err := store.PublishLower(ctx, lowerPath, lowerSize)
	require.NoError(t, err)
	initrd, err := store.ImportInitramfs(ctx, inputs["INITRD"])
	require.NoError(t, err)
	digest := func(path string) string {
		t.Helper()
		d, e := runtimeBinaryDigest(ctx, path)
		require.NoError(t, e)
		return d
	}
	boot := erofs.BootLayout{Layout: erofs.LayoutPmem, KernelVersion: versions.KernelVersion, KernelSHA256: digest(inputs["KERNEL"]), FirecrackerVersion: versions.FirecrackerVersion, FirecrackerSHA256: digest(inputs["FC"]), Initramfs: initrd}
	flags, err := featureflags.NewClientWithDatasource(ldtestdata.DataSource())
	require.NoError(t, err)
	t.Cleanup(func() { flags.Close(context.Background()) })
	pool := &lifecycleNetworkPool{slots: make(map[string]*network.Slot), hostAccess: true}
	t.Cleanup(func() { require.NoError(t, pool.Close(context.Background())) })
	factory, err := NewFileFactory(ctx, config, pool, flags, hoststats.NewNoopDelivery(), cgroup.NewNoopManager(), network.NewNoopEgressProxy(), nil, NewSandboxesMap())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, factory.CloseSharedMounts(context.Background())) })
	team := uuid.NewString()
	runtimeFor := func(id string) RuntimeMetadata {
		return RuntimeMetadata{TemplateID: "pmem-lifecycle", SandboxID: "p" + uuid.NewString()[:8], ExecutionID: uuid.NewString(), BuildID: id, TeamID: team, SandboxType: SandboxTypeBuild}
	}
	newConfig := func() *Config {
		token, user := strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", ""), "root"
		return NewConfig(Config{Vcpu: 1, RamMB: ramMB, TotalDiskSizeMB: upperSize >> 20, FirecrackerConfig: versions, Envd: EnvdMetadata{Version: envdVersion, AccessToken: &token, DefaultUser: &user, Vars: map[string]string{"EROFS_LIFECYCLE": "ram-disk"}}})
	}
	own := func(s *Sandbox) {
		t.Helper()
		t.Cleanup(func() {
			c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			require.NoError(t, s.Close(c))
		})
	}
	if os.Getenv("E2B_PMEM_BUILD") == "1" {
		// First create a real raw-build snapshot, then run the same offline
		// finalizer used by Builder. No fabricated VM state is used as input.
		rawID := uuid.NewString()
		rawPaths, e := (storage.Paths{BuildID: rawID}).Cache(config.StorageConfig)
		require.NoError(t, e)
		device, e := block.NewLocal(lowerPath, 4096, uuid.MustParse(rawID))
		require.NoError(t, e)
		t.Cleanup(func() { require.NoError(t, device.Close()) })
		rawLog, e := os.Create(filepath.Join(work, "raw-build.log"))
		require.NoError(t, e)
		t.Cleanup(func() { require.NoError(t, rawLog.Close()) })
		rawConfig := newConfig()
		rawVM, e := factory.CreateSandbox(ctx, rawConfig, runtimeFor(rawID), &lifecycleTemplate{paths: rawPaths, rootfs: device, meta: lifecycleMetadata(rawID, versions)}, time.Hour, "",
			fc.ProcessOptions{InitScriptPath: "/sbin/init", KernelLogs: true, Stdout: rawLog, Stderr: rawLog, AccessToken: rawConfig.Envd.AccessToken}, nil, nil)
		require.NoError(t, e)
		own(rawVM)
		require.NoError(t, rawVM.WaitForEnvd(ctx, StartTypeCreate, 30*time.Second))
		lifecycleState(t, ctx, rawVM, "/write/1", lifecycleGuestState{Generation: 1, Memory: [3]int{0xa6, 0, 0x53}, Disk: [3]int{0xa6, 0, 0x53}, Partial: 0x53})
		rawSnapshot, e := rawVM.Pause(ctx, lifecycleMetadata(uuid.NewString(), versions), SnapshotUseCaseBuild)
		require.NoError(t, e)
		require.Equal(t, erofs.LayoutRawBuild, rawSnapshot.LocalEROFS.Manifest.Boot.Layout)
		require.NoError(t, rawVM.Close(ctx))
		baselines, e := os.ReadDir(filepath.Join(store.Root, ".raw-baselines"))
		require.NoError(t, e)
		require.Empty(t, baselines, "successful raw-build capture must release owned baseline files")
		prepared, e := pmem.Prepare(ctx, pmem.Inputs{Source: rawSnapshot.LocalEROFS, Store: store, Boot: boot})
		require.NoError(t, e)
		t.Cleanup(func() { require.NoError(t, prepared.Close()) })
		lower, upperPath = prepared.Lower, prepared.UpperPath
		require.Equal(t, upperSize, prepared.UpperSize)
		require.Less(t, prepared.Lower.Image.Size, lowerSize, "final lower should be compact")
		t.Logf("real raw-build snapshot converted to lower %s (%d bytes) and fresh upper", lower.ID, lower.Image.Size)
	}
	id := uuid.NewString()
	paths, err := (storage.Paths{BuildID: id}).Cache(config.StorageConfig)
	require.NoError(t, err)
	log, err := os.Create(filepath.Join(work, "cold-boot.log"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, log.Close()) })
	coldConfig := newConfig()
	initial, err := factory.CreateSandbox(ctx, coldConfig, runtimeFor(id), &lifecycleTemplate{paths: paths, meta: lifecycleMetadata(id, versions)}, time.Hour, "",
		fc.ProcessOptions{InitScriptPath: "/sbin/init", KernelLogs: true, Stdout: log, Stderr: log, AccessToken: coldConfig.Envd.AccessToken}, nil, nil,
		WithPmemBootstrap(PmemBootstrap{Boot: boot, Lower: lower, UpperPath: upperPath, UpperSize: upperSize, UpperContentSHA256: digest(upperPath)}))
	require.NoError(t, err)
	own(initial)
	lifecycleEnvd(t, ctx, initial)
	zero := lifecycleGuestState{Memory: [3]int{0x31, 0x42, 0x53}, Disk: [3]int{0x31, 0x42, 0x53}, Partial: 0x53}
	one := lifecycleGuestState{Generation: 1, Memory: [3]int{0xa6, 0, 0x53}, Disk: [3]int{0xa6, 0, 0x53}, Partial: 0x53}
	two := lifecycleGuestState{Generation: 2, Memory: [3]int{0xa6, 0, 0xb7}, Disk: [3]int{0xa6, 0, 0x53}, Partial: 0xb7}
	branchState := lifecycleGuestState{Generation: 3, Memory: [3]int{0xa6, 0, 0xc8}, Disk: [3]int{0xa6, 0, 0x53}, Partial: 0xc8}
	lifecycleState(t, ctx, initial, "/state", zero)
	checkpoint := func(s *Sandbox, parent string, fail bool) *Snapshot {
		t.Helper()
		meta := lifecycleMetadata(uuid.NewString(), versions)
		if fail {
			require.NoError(t, os.WriteFile(failMarker, nil, 0600))
		}
		snap, e := s.Pause(ctx, meta, SnapshotUseCasePause)
		if fail {
			require.Error(t, e)
			require.NotNil(t, s.nativeCapture)
			require.True(t, s.nativeCapture.memoryCaptured)
			require.True(t, s.nativeCapture.recoveryRecorded)
			hash := lifecycleHash(t, s.nativeCapture.request.MemoryPath)
			// Close may release parent mounts. Durable retry must reacquire the parent
			// without consuming another RAM Diff or discarding the captured upper.
			require.NoError(t, s.Close(ctx))
			require.NoError(t, os.Remove(failMarker))
			snap, e = s.Pause(ctx, meta, SnapshotUseCasePause)
			require.Equal(t, hash, lifecycleHash(t, s.nativeCapture.request.MemoryPath))
		}
		require.NoError(t, e)
		require.Equal(t, erofs.FormatV2, snap.LocalEROFS.Manifest.Format)
		require.Equal(t, parent, snap.LocalEROFS.Manifest.ParentID)
		require.Equal(t, ramMB<<20, snap.LocalEROFS.Manifest.Memory.Size)
		require.Equal(t, upperSize, snap.LocalEROFS.Manifest.Upper.Size)
		require.Equal(t, lower.ID, snap.LocalEROFS.Manifest.Lower.ID)
		require.Equal(t, 1, s.nativeCapture.memoryAttempts)
		require.NoError(t, s.Close(ctx))
		t.Logf("published generation %s parent=%s capture=%s", snap.BuildID, parent, snap.LocalEROFS.Manifest.MemoryCapture)
		return snap
	}
	resume := func(snap *Snapshot, deferred bool) *Sandbox {
		t.Helper()
		p, e := (storage.Paths{BuildID: snap.BuildID.String()}).Cache(config.StorageConfig)
		require.NoError(t, e)
		opts := []ResumeOption{WithoutLiveRegistration()}
		if deferred {
			opts = append(opts, WithDeferredLiveRegistration())
		}
		s, e := factory.ResumeSandbox(ctx, template.NewEROFSTemplate(p, snap.LocalEROFS), newConfig(), runtimeFor(snap.BuildID.String()), time.Now(), time.Now().Add(time.Hour), nil, opts...)
		require.NoError(t, e)
		own(s)
		require.IsType(t, &nativeRawRootfs{}, s.rootfs)
		if deferred {
			client := http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
			req, e := http.NewRequestWithContext(ctx, http.MethodGet, s.envdServerURL()+"/envs", nil)
			require.NoError(t, e)
			req.Header.Set("X-Access-Token", *s.Config.Envd.AccessToken)
			resp, e := client.Do(req)
			require.NoError(t, e)
			require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
			require.NoError(t, resp.Body.Close())
			out, e := exec.CommandContext(ctx, "ip", "netns", "exec", s.Slot.NamespaceID(), "curl", "-fsS", "--noproxy", "*", "--max-time", "1", "http://"+s.Slot.NamespaceIP()+":8080/state").CombinedOutput()
			require.Error(t, e, "workload answered before commit: %s", out)
			// Real same-PID exec while prepare holds the workload. The incoming
			// envd must retain the journal's hold through process handover and
			// another /init, then release it only at commit.
			confirmed, e := s.CallEnvdUpgrade(ctx, inputs["ENVD"], "", 30*time.Second)
			require.NoError(t, e)
			require.True(t, confirmed, "upgrade must complete an actual exec")
			require.NoError(t, s.WaitForEnvd(ctx, StartTypeResume, 30*time.Second))
			out, e = exec.CommandContext(ctx, "ip", "netns", "exec", s.Slot.NamespaceID(), "curl", "-fsS", "--noproxy", "*", "--max-time", "1", "http://"+s.Slot.NamespaceIP()+":8080/state").CombinedOutput()
			require.Error(t, e, "workload answered after upgrade but before commit: %s", out)
			require.NoError(t, s.CommitPmemResume(ctx))
			require.NoError(t, s.CommitPmemResume(ctx))
		}
		lifecycleEnvd(t, ctx, s)
		return s
	}
	g0 := checkpoint(initial, "", false)
	first, sibling := resume(g0, true), resume(g0, false)
	lifecycleState(t, ctx, first, "/write/1", one)
	lifecycleState(t, ctx, sibling, "/state", zero)
	fsCheck := func(vm *Sandbox, path string) {
		t.Helper()
		out := lifecycleCommand(t, ctx, "ip", "netns", "exec", vm.Slot.NamespaceID(), "curl", "-fsS", "--noproxy", "*", "--max-time", "10", "http://"+vm.Slot.NamespaceIP()+":8080"+path)
		require.Equal(t, "FS_OK\n", string(out))
	}
	if os.Getenv("E2B_PMEM_EXPORT") == "1" {
		fsCheck(first, "/fs/mutate")
	}
	g1 := checkpoint(first, g0.BuildID.String(), true)
	second := resume(g1, false)
	lifecycleState(t, ctx, second, "/state", one)
	require.NoError(t, sibling.Close(ctx))
	lifecycleState(t, ctx, second, "/write/2", two)
	g2 := checkpoint(second, g1.BuildID.String(), false)
	branch := resume(g1, false)
	lifecycleState(t, ctx, branch, "/write/b", branchState)
	gb := checkpoint(branch, g1.BuildID.String(), false)
	for _, v := range []struct {
		snap *Snapshot
		want lifecycleGuestState
	}{{g2, two}, {gb, branchState}, {g0, zero}} {
		s := resume(v.snap, false)
		lifecycleState(t, ctx, s, "/state", v.want)
		require.NoError(t, s.Close(ctx))
	}
	// An abrupt VMM exit must release only its private upper and references.
	// A sibling sharing the same immutable lower/RAM and the committed parent
	// must remain usable. Open a pidfd before checking the
	// command identity, so a reused numeric PID cannot be the kill target.
	healthy, victim := resume(g0, false), resume(g0, false)
	lifecycleState(t, ctx, victim, "/write/1", one)
	victimUpper, err := victim.rootfs.Path()
	require.NoError(t, err)
	victimPID, err := victim.process.Pid()
	require.NoError(t, err)
	victimFD, err := unix.PidfdOpen(victimPID, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(victimFD) })
	command, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", victimPID))
	require.NoError(t, err)
	require.Contains(t, string(command), victim.Runtime.SandboxID)
	require.NoError(t, unix.PidfdSendSignal(victimFD, unix.SIGKILL, nil, 0))
	select {
	case <-victim.process.Exit.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("killed Firecracker did not exit")
	}
	require.NoError(t, victim.Close(ctx))
	require.NoError(t, victim.Close(ctx))
	_, err = os.Stat(victimUpper)
	require.ErrorIs(t, err, os.ErrNotExist, "crashed VM leaked its private upper")
	lifecycleState(t, ctx, healthy, "/state", zero)
	require.NoError(t, healthy.Close(ctx))
	restoredAfterCrash := resume(g0, false)
	lifecycleState(t, ctx, restoredAfterCrash, "/state", zero)
	require.NoError(t, restoredAfterCrash.Close(ctx))
	t.Log("abrupt Firecracker exit: private upper cleaned, repeated Close safe, sibling and committed parent unchanged")
	if os.Getenv("E2B_PMEM_EXPORT") == "1" {
		p, e := (storage.Paths{BuildID: g1.BuildID.String()}).Cache(config.StorageConfig)
		require.NoError(t, e)
		sourceTemplate := template.NewEROFSTemplate(p, g1.LocalEROFS)
		merged, e := factory.ExportPmemRootfs(ctx, sourceTemplate, boot, team)
		require.NoError(t, e)
		t.Cleanup(func() { require.NoError(t, merged.Close()) })
		rawLog, e := os.Create(filepath.Join(work, "merged-raw-stage.log"))
		require.NoError(t, e)
		t.Cleanup(func() { require.NoError(t, rawLog.Close()) })
		rawConfig := newConfig()
		rawStage, e := factory.CreateSandbox(ctx, rawConfig, runtimeFor(g1.BuildID.String()), sourceTemplate, time.Hour, "", fc.ProcessOptions{InitScriptPath: "/sbin/init", KernelLogs: true, Stdout: rawLog, Stderr: rawLog, AccessToken: rawConfig.Envd.AccessToken}, nil, nil,
			WithRawBootstrap(RawBootstrap{Path: merged.Path, Size: merged.Size, SHA256: merged.SHA256}))
		require.NoError(t, e)
		own(rawStage)
		require.NoError(t, rawStage.WaitForEnvd(ctx, StartTypeCreate, 30*time.Second))
		fsCheck(rawStage, "/fs/check")
		staged, e := rawStage.Pause(ctx, lifecycleMetadata(uuid.NewString(), versions), SnapshotUseCaseBuild)
		require.NoError(t, e)
		require.Equal(t, erofs.LayoutRawBuild, staged.LocalEROFS.Manifest.Boot.Layout)
		require.NoError(t, rawStage.Close(ctx))
		final, e := pmem.Prepare(ctx, pmem.Inputs{Source: staged.LocalEROFS, Store: store, Boot: boot})
		require.NoError(t, e)
		t.Cleanup(func() { require.NoError(t, final.Close()) })
		nextConfig := newConfig()
		log, e := os.Create(filepath.Join(work, "derived-cold.log"))
		require.NoError(t, e)
		t.Cleanup(func() { require.NoError(t, log.Close()) })
		derived, e := factory.CreateSandbox(ctx, nextConfig, runtimeFor(g1.BuildID.String()), sourceTemplate, time.Hour, "", fc.ProcessOptions{InitScriptPath: "/sbin/init", KernelLogs: true, Stdout: log, Stderr: log, AccessToken: nextConfig.Envd.AccessToken}, nil, nil,
			WithPmemBootstrap(PmemBootstrap{Boot: boot, Lower: final.Lower, UpperPath: final.UpperPath, UpperSize: final.UpperSize, UpperContentSHA256: final.UpperSHA256}))
		require.NoError(t, e)
		own(derived)
		fsCheck(derived, "/fs/check")
		lifecycleState(t, ctx, derived, "/state", zero)
		require.NoError(t, derived.Close(ctx))
		original := resume(g1, false)
		fsCheck(original, "/fs/check")
		lifecycleState(t, ctx, original, "/state", one)
		require.NoError(t, original.Close(ctx))
		t.Log("merged export and new lower cold boot preserve whiteouts, renamed directories, hardlinks, capabilities, xattrs, device nodes and sparse data; original snapshot unchanged")
	}
	require.NoError(t, factory.CloseSharedMounts(ctx))
	require.NoError(t, pool.Close(ctx))
	_, err = os.Stat("/sys/module/nbd")
	require.ErrorIs(t, err, os.ErrNotExist)
	t.Log(fmt.Sprintf("pmem lifecycle passed: real envd %s, full + diff branches, deferred commit, publication retry after Close, no NBD", envdVersion))
}
