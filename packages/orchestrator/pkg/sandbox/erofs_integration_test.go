//go:build linux

package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/launchdarkly/go-server-sdk/v7/testhelpers/ldtestdata"
	"github.com/stretchr/testify/require"

	"github.com/e2b-dev/infra/packages/clickhouse/pkg/hoststats"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/cfg"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/block"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/cgroup"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/fc"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/nbd"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/network"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/rootfs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/template"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/metadata"
	"github.com/e2b-dev/infra/packages/shared/pkg/featureflags"
	"github.com/e2b-dev/infra/packages/shared/pkg/grpc/orchestrator"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage"
)

// TestEROFSFactoryLifecycle is opt-in because it launches real Firecracker
// processes and owns kernel EROFS mounts, NBD devices and isolated tap netns.
// It exercises the actual Factory and Pause implementation. E2B_EROFS_ENVD
// optionally installs real envd and exercises MMDS auth, /init and health after
// each restore. Without it the small guest is a RAM/disk fixture and uses the
// existing SkipEnvdWait debugger option. Public gRPC is outside this test.
//
// Build the package's test binary, then run as root with E2B_EROFS_FC,
// E2B_EROFS_KERNEL, E2B_EROFS_MKFS, E2B_EROFS_FSCK and E2B_EROFS_TEST_DIR set.
// The supplied binary must independently pass validate_native_memory.py. An
// upstream binary demonstrates this Go lifecycle but does not validate E2B's fork.
func TestEROFSFactoryLifecycle(t *testing.T) { //nolint:paralleltest // Owns privileged kernel resources and changes this test process's PATH.
	fcBinary := os.Getenv("E2B_EROFS_FC")
	envdBinary := os.Getenv("E2B_EROFS_ENVD")
	if fcBinary == "" {
		t.Skip("set E2B_EROFS_FC and kernel/EROFS tool paths to run the real lifecycle test")
	}
	require.Zero(t, os.Geteuid(), "requires root for mount, NBD and netns")
	inputs := map[string]string{"firecracker": fcBinary}
	for _, name := range []string{"KERNEL", "MKFS", "FSCK", "TEST_DIR"} {
		inputs[name] = os.Getenv("E2B_EROFS_" + name)
		require.NotEmpty(t, inputs[name], "missing E2B_EROFS_"+name)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	require.NoError(t, os.MkdirAll(inputs["TEST_DIR"], 0o755))
	work, err := os.MkdirTemp(inputs["TEST_DIR"], "factory-")
	require.NoError(t, err)
	t.Logf("retained lifecycle artifacts: %s", work)
	// Registered first so it runs only after all resource cleanups have passed.
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		report := map[string]any{
			"status": "passed", "firecracker": fcBinary, "firecracker_sha256": fmt.Sprintf("%x", lifecycleHash(t, fcBinary)),
			"kernel": inputs["KERNEL"], "ram_bytes": int64(256 << 20), "disk_bytes": int64(64 << 20),
			"envd_enabled": envdBinary != "", "retained_capture_retry": true, "concurrent_close": true, "qemu_failure_propagation": true,
			"baseline_capture_retained_on_close": true,
			"shared_memory_and_rootfs_mounts":    true, "shared_namespace_release": true,
		}
		if envdBinary != "" {
			report["envd_sha256"] = fmt.Sprintf("%x", lifecycleHash(t, envdBinary))
		}
		data, err := json.MarshalIndent(report, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(work, "report.json"), append(data, '\n'), 0o644))
	})
	defer func() {
		if t.Failed() {
			for _, entry := range testLogObserver.All() {
				t.Log(entry.Message, entry.ContextMap())
			}
		}
	}()
	config := cfg.BuilderConfig{
		EROFSSnapshotDir: filepath.Join(work, "snapshots"), EROFSNativeMemoryVerified: true,
		EROFSMkfsPath:          inputs["MKFS"],
		FirecrackerVersionsDir: filepath.Join(work, "firecracker"), HostKernelsDir: filepath.Join(work, "kernels"),
		OrchestratorBaseDir: filepath.Join(work, "orchestrator"), SandboxDir: filepath.Join(work, "fc-vm"),
		StorageConfig: storage.Config{SandboxCacheDir: filepath.Join(work, "sandbox-cache"), TemplateCacheDir: filepath.Join(work, "template-cache")},
	}
	versions := fc.Config{KernelVersion: "6.1.155", FirecrackerVersion: "v1.14-0.1.0", NativeMemory: true}
	if version := os.Getenv("E2B_EROFS_FC_VERSION"); version != "" {
		versions.FirecrackerVersion = version
	}
	if version := os.Getenv("E2B_EROFS_KERNEL_VERSION"); version != "" {
		versions.KernelVersion = version
	}
	for _, path := range []string{config.EROFSSnapshotDir, config.StorageConfig.SandboxCacheDir, config.StorageConfig.TemplateCacheDir,
		filepath.Join(config.FirecrackerVersionsDir, versions.FirecrackerVersion), filepath.Join(config.HostKernelsDir, versions.KernelVersion), filepath.Join(work, "bin")} {
		require.NoError(t, os.MkdirAll(path, 0o755))
	}
	require.NoError(t, os.Symlink(fcBinary, filepath.Join(config.FirecrackerVersionsDir, versions.FirecrackerVersion, "firecracker")))
	require.NoError(t, os.Symlink(inputs["KERNEL"], filepath.Join(config.HostKernelsDir, versions.KernelVersion, "vmlinux.bin")))
	require.NoError(t, os.Symlink(inputs["FSCK"], filepath.Join(work, "bin", "fsck.erofs")))
	failMarker := filepath.Join(work, "fail-mkfs")
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
	blockMarker, enteredMarker := filepath.Join(work, "block-mkfs"), filepath.Join(work, "entered-mkfs")
	config.EROFSMkfsPath = filepath.Join(work, "bin", "mkfs-wrapper")
	require.NoError(t, os.WriteFile(config.EROFSMkfsPath, []byte("#!/bin/sh\nif [ -e "+quote(failMarker)+" ]; then exit 77; fi\n"+
		"if [ -e "+quote(blockMarker)+" ]; then touch "+quote(enteredMarker)+"; while [ -e "+quote(blockMarker)+" ]; do sleep 0.02; done; fi\n"+
		"exec "+quote(inputs["MKFS"])+" \"$@\"\n"), 0o755))
	t.Setenv("PATH", filepath.Join(work, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))

	// Build an ext4 template with a static PID 1; it uses direct I/O for its
	// state file so restored page-cache contents cannot hide a stale disk.
	tree := filepath.Join(work, "guest")
	for _, dir := range []string{"dev", "proc", "sys", "run", "etc", "root", "tmp"} {
		require.NoError(t, os.MkdirAll(filepath.Join(tree, dir), 0o755))
	}
	envdVersion := ""
	if envdBinary != "" {
		lifecycleCommand(t, ctx, "cp", envdBinary, filepath.Join(tree, "envd"))
		envdVersion = strings.TrimSpace(string(lifecycleCommand(t, ctx, envdBinary, "-version")))
		require.NoError(t, os.WriteFile(filepath.Join(tree, "etc", "passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(tree, "etc", "group"), []byte("root:x:0:\n"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(tree, "etc", "hosts"), []byte("127.0.0.1 localhost\n"), 0o644))
	}
	guestSource, err := filepath.Abs("../../../../firecracker/fc-versions/scripts/erofs_lifecycle_guest.c")
	require.NoError(t, err)
	// A compiled Go test binary can run from any cwd if its caller supplies the source.
	if override := os.Getenv("E2B_EROFS_GUEST_SOURCE"); override != "" {
		guestSource = override
	}
	lifecycleCommand(t, ctx, "gcc", "-static", "-O2", "-Wall", "-Wextra", "-o", filepath.Join(tree, "init"), guestSource)
	const diskSize = int64(64 << 20)
	const ramMB = int64(256)
	rootfsPath := filepath.Join(work, "rootfs.ext4")
	file, err := os.Create(rootfsPath)
	require.NoError(t, err)
	require.NoError(t, file.Truncate(diskSize))
	require.NoError(t, file.Close())
	lifecycleCommand(t, ctx, "mkfs.ext4", "-q", "-F", "-b", "4096", "-d", tree, rootfsPath)
	buildID := uuid.New()
	rootfs, err := block.NewLocal(rootfsPath, 4096, buildID)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, rootfs.Close()) })
	paths, err := (storage.Paths{BuildID: buildID.String()}).Cache(config.StorageConfig)
	require.NoError(t, err)
	base := &lifecycleTemplate{paths: paths, rootfs: rootfs, meta: lifecycleMetadata(buildID.String(), versions)}
	guestLog, err := os.Create(filepath.Join(work, "cold-boot.log"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, guestLog.Close()) })
	flags, err := featureflags.NewClientWithDatasource(ldtestdata.DataSource())
	require.NoError(t, err)
	t.Cleanup(func() { flags.Close(context.WithoutCancel(ctx)) })
	devices, err := nbd.NewDevicePool(2)
	require.NoError(t, err)
	poolCtx, cancelPool := context.WithCancel(context.WithoutCancel(ctx))
	go devices.Populate(poolCtx)
	t.Cleanup(func() {
		cancelPool()
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		require.NoError(t, devices.Close(closeCtx))
	})
	netPool := &lifecycleNetworkPool{slots: make(map[string]*network.Slot), hostAccess: envdBinary != ""}
	t.Cleanup(func() { require.NoError(t, netPool.Close(context.WithoutCancel(ctx))) })
	factory := NewFactory(ctx, config, netPool, devices, flags, hoststats.NewNoopDelivery(), cgroup.NewNoopManager(), network.NewNoopEgressProxy(), nil, NewSandboxesMap())
	t.Cleanup(func() { require.NoError(t, factory.CloseSharedMounts(context.Background())) })
	newConfig := func() *Config {
		config := NewConfig(Config{Vcpu: 1, RamMB: ramMB, TotalDiskSizeMB: diskSize >> 20, FirecrackerConfig: versions, SkipEnvdWait: envdBinary == ""})
		if envdBinary != "" {
			// Every resume gets a new token, so /init must validate the refreshed
			// MMDS hash instead of taking envd's cached-token fast path.
			token, user := strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", ""), "root"
			config.Envd = EnvdMetadata{Version: envdVersion, AccessToken: &token, DefaultUser: &user, Vars: map[string]string{"EROFS_LIFECYCLE": "ram-disk"}}
		}
		return config
	}
	teamID := uuid.NewString()
	runtimeFor := func(id string) RuntimeMetadata {
		return RuntimeMetadata{TemplateID: "erofs-test", SandboxID: "e" + uuid.NewString()[:8], ExecutionID: uuid.NewString(), BuildID: id, TeamID: teamID, SandboxType: SandboxTypeBuild}
	}
	var sandboxes []*Sandbox
	t.Cleanup(func() {
		for _, s := range sandboxes {
			closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			err := s.Close(closeCtx)
			cancel()
			if err != nil {
				t.Errorf("close sandbox %s: %v", s.Runtime.SandboxID, err)
			}
		}
	})
	coldConfig := newConfig()
	initial, err := factory.CreateSandbox(ctx, coldConfig, runtimeFor(buildID.String()), base, time.Hour, rootfsPath,
		fc.ProcessOptions{InitScriptPath: "/init", KernelLogs: true, Stdout: guestLog, Stderr: guestLog, AccessToken: coldConfig.Envd.AccessToken}, nil, nil)
	require.NoError(t, err)
	sandboxes = append(sandboxes, initial)
	if envdBinary != "" {
		require.NoError(t, initial.WaitForEnvd(ctx, StartTypeCreate, 30*time.Second))
		lifecycleEnvd(t, ctx, initial)
	}
	lifecycleState(t, ctx, initial, "/state", lifecycleGuestState{Memory: [3]int{0x31, 0x42, 0x53}, Disk: [3]int{0x31, 0x42, 0x53}, Partial: 0x53})
	checkpoint := func(s *Sandbox, expectedParent string, failPublication bool) *Snapshot {
		t.Helper()
		pid, err := s.process.Pid()
		require.NoError(t, err)
		meta := lifecycleMetadata(uuid.NewString(), versions)
		if failPublication {
			require.NoError(t, os.WriteFile(failMarker, nil, 0o600))
		}
		snapshot, err := s.Pause(ctx, meta, SnapshotUseCasePause)
		if failPublication {
			require.Error(t, err)
			require.Nil(t, snapshot)
			require.True(t, s.nativeCapture.sealed, "capture must survive publication failure after FC exit")
			require.Equal(t, 1, s.nativeCapture.memoryAttempts)
			capturePath := s.nativeCapture.request.MemoryPath
			captureHash := lifecycleHash(t, capturePath)
			require.NoError(t, os.Remove(failMarker))
			snapshot, err = s.Pause(ctx, meta, SnapshotUseCasePause)
			require.NoError(t, err)
			require.Equal(t, capturePath, s.nativeCapture.request.MemoryPath)
			require.Equal(t, captureHash, lifecycleHash(t, capturePath))
			require.Equal(t, 1, s.nativeCapture.memoryAttempts, "retry must not request a second Diff")
		}
		require.NoError(t, err)
		require.NotNil(t, snapshot.LocalEROFS)
		require.Equal(t, expectedParent, snapshot.LocalEROFS.Manifest.ParentID)
		require.Equal(t, ramMB<<20, snapshot.LocalEROFS.Manifest.Memory.Size)
		require.Equal(t, diskSize, snapshot.LocalEROFS.Manifest.Disk.Size)
		select {
		case <-s.process.Exit.Done():
		default:
			t.Fatalf("snapshot returned before Firecracker %d exited", pid)
		}
		captureDir := s.nativeCapture.capture.Dir
		require.NoError(t, s.Close(ctx))
		_, statErr := os.Stat(captureDir)
		require.ErrorIs(t, statErr, os.ErrNotExist, "published sandbox-owned staging must be released")
		// The original cutoff remains retryable from committed artifacts even
		// after its transient RAM/qcow capture files have been discarded.
		retried, retryErr := s.Pause(ctx, meta, SnapshotUseCasePause)
		require.NoError(t, retryErr)
		require.Equal(t, snapshot.BuildID, retried.BuildID)
		require.Equal(t, 1, s.nativeCapture.memoryAttempts)
		return snapshot
	}
	resume := func(snapshot *Snapshot) *Sandbox {
		t.Helper()
		paths, err := (storage.Paths{BuildID: snapshot.BuildID.String()}).Cache(config.StorageConfig)
		require.NoError(t, err)
		tmpl := template.NewEROFSTemplate(paths, snapshot.LocalEROFS)
		s, err := factory.ResumeSandbox(ctx, tmpl, newConfig(), runtimeFor(snapshot.BuildID.String()), time.Now(), time.Now().Add(time.Hour), nil, WithoutLiveRegistration())
		require.NoError(t, err)
		sandboxes = append(sandboxes, s)
		require.True(t, s.UsesEROFS())
		require.IsType(t, &erofsRootfs{}, s.rootfs)
		if envdBinary != "" {
			lifecycleEnvd(t, ctx, s)
		}
		return s
	}
	// Fail the initial raw disk lookup after native RAM capture. Close must
	// retain that baseline before releasing the original direct provider.
	// Firecracker keeps its original provider; only the capture-side lookup
	// sees this one-shot failure.
	failingPath := &lifecycleFailRootfsPath{Provider: initial.rootfs}
	failingPath.fail.Store(true)
	initial.Resources.rootfs = failingPath
	baselineMeta := lifecycleMetadata(uuid.NewString(), versions)
	failedBaseline, err := initial.Pause(ctx, baselineMeta, SnapshotUseCaseBuild)
	require.ErrorContains(t, err, "injected baseline Path failure")
	require.Nil(t, failedBaseline)
	require.True(t, initial.nativeCapture.memoryCaptured)
	require.False(t, initial.nativeCapture.sealed)
	baselineRAMPath := initial.nativeCapture.request.MemoryPath
	baselineRAMHash := lifecycleHash(t, baselineRAMPath)
	require.NoError(t, initial.Close(ctx))
	require.True(t, initial.nativeCapture.sealed)
	require.Equal(t, 1, initial.nativeCapture.memoryAttempts)
	require.Equal(t, baselineRAMPath, initial.nativeCapture.request.MemoryPath)
	require.Equal(t, baselineRAMHash, lifecycleHash(t, baselineRAMPath))
	require.FileExists(t, filepath.Join(initial.nativeCapture.capture.Dir, "build-request.json"))
	committedBaseline, err := initial.nativeCapture.store.Build(ctx, initial.nativeCapture.request)
	require.NoError(t, err)
	snapshot0 := nativeSnapshot(committedBaseline, uuid.MustParse(baselineMeta.Template.BuildID))
	require.Empty(t, snapshot0.LocalEROFS.Manifest.ParentID)
	require.Equal(t, ramMB<<20, snapshot0.LocalEROFS.Manifest.Memory.Size)
	require.Equal(t, diskSize, snapshot0.LocalEROFS.Manifest.Disk.Size)
	baselineDisk := lifecycleHash(t, rootfsPath)
	first := resume(snapshot0)
	baselineSibling := resume(snapshot0)
	entries, err := os.ReadDir(factory.sharedMounts.Root())
	require.NoError(t, err)
	require.Len(t, entries, 1, "same-generation runtimes share one memory/disk mount pair")
	sharedBase := filepath.Join(factory.sharedMounts.Root(), entries[0].Name())
	memoryPath := filepath.Join(sharedBase, "memory", "memory", "memfile")
	diskPath := filepath.Join(sharedBase, "disk", "disk", "rootfs.ext4")
	for _, s := range []*Sandbox{first, baselineSibling} {
		lifecycleSharedMountIdentity(t, s, memoryPath, diskPath, factory.sharedMounts.Root())
	}
	firstDevice, err := first.rootfs.Path()
	require.NoError(t, err)
	siblingDevice, err := baselineSibling.rootfs.Path()
	require.NoError(t, err)
	require.NotEqual(t, firstDevice, siblingDevice, "writable NBD devices stay private")
	baseMemoryHash, baseDiskHash := lifecycleHash(t, memoryPath), lifecycleHash(t, diskPath)
	one := lifecycleGuestState{Generation: 1, Memory: [3]int{0xa6, 0, 0x53}, Disk: [3]int{0xa6, 0, 0x53}, Partial: 0x53}
	lifecycleState(t, ctx, first, "/write/1", one)
	lifecycleState(t, ctx, baselineSibling, "/state", lifecycleGuestState{Memory: [3]int{0x31, 0x42, 0x53}, Disk: [3]int{0x31, 0x42, 0x53}, Partial: 0x53})
	require.Equal(t, baseMemoryHash, lifecycleHash(t, memoryPath))
	require.Equal(t, baseDiskHash, lifecycleHash(t, diskPath))
	snapshot1 := checkpoint(first, snapshot0.BuildID.String(), true)
	require.FileExists(t, memoryPath, "sibling's reference retains old generation after checkpoint")
	second := resume(snapshot1)
	lifecycleState(t, ctx, second, "/state", one)
	// This newer FC was spawned while G0 was mounted. Its namespace must not
	// pin G0 after the last G0 runtime exits.
	require.NoError(t, baselineSibling.Close(ctx))
	_, err = os.Stat(sharedBase)
	require.ErrorIs(t, err, os.ErrNotExist)
	pid, err := second.process.Pid()
	require.NoError(t, err)
	mountinfo, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	require.NoError(t, err)
	require.NotContains(t, string(mountinfo), factory.sharedMounts.Root()+"/")
	lifecycleState(t, ctx, second, "/state", one)
	two := lifecycleGuestState{Generation: 2, Memory: [3]int{0xa6, 0, 0xb7}, Disk: [3]int{0xa6, 0, 0x53}, Partial: 0xb7}
	lifecycleState(t, ctx, second, "/write/2", two)
	snapshot2 := checkpoint(second, snapshot1.BuildID.String(), false)
	branch := resume(snapshot1)
	lifecycleState(t, ctx, branch, "/state", one)
	sibling := lifecycleGuestState{Generation: 3, Memory: [3]int{0xa6, 0, 0xc8}, Disk: [3]int{0xa6, 0, 0x53}, Partial: 0xc8}
	lifecycleState(t, ctx, branch, "/write/b", sibling)
	branchSnapshot := checkpoint(branch, snapshot1.BuildID.String(), false)
	for _, pair := range []struct {
		snapshot *Snapshot
		want     lifecycleGuestState
	}{{snapshot2, two}, {branchSnapshot, sibling}, {snapshot1, one}} {
		s := resume(pair.snapshot)
		lifecycleState(t, ctx, s, "/state", pair.want)
		require.NoError(t, s.Close(ctx))
	}
	require.Equal(t, baselineDisk, lifecycleHash(t, rootfsPath), "restoring branches must not modify the raw template")

	// Hold publication after RAM/disk capture and race Close against Pause.
	// Close must wait for the in-flight capture owner before releasing mounts.
	concurrent := resume(snapshot2)
	require.NoError(t, os.WriteFile(blockMarker, nil, 0o600))
	t.Cleanup(func() { _ = os.Remove(blockMarker) })
	type captureResult struct {
		snapshot *Snapshot
		err      error
	}
	pauseDone := make(chan captureResult, 1)
	go func() {
		snapshot, err := concurrent.Pause(ctx, lifecycleMetadata(uuid.NewString(), versions), SnapshotUseCasePause)
		pauseDone <- captureResult{snapshot: snapshot, err: err}
	}()
	require.Eventually(t, func() bool { _, err := os.Stat(enteredMarker); return err == nil }, 10*time.Second, 10*time.Millisecond)
	closeDone := make(chan error, 1)
	closeStarted := make(chan struct{})
	go func() { close(closeStarted); closeDone <- concurrent.Close(ctx) }()
	<-closeStarted
	select {
	case err := <-closeDone:
		t.Fatalf("Close finished while snapshot publication was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	require.NoError(t, os.Remove(blockMarker))
	var captured *Snapshot
	select {
	case result := <-pauseDone:
		require.NoError(t, result.err)
		captured = result.snapshot
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err := <-closeDone:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	afterClose := resume(captured)
	lifecycleState(t, ctx, afterClose, "/state", two)
	require.NoError(t, afterClose.Close(ctx))

	// A qemu-nbd crash must fail Sandbox.Wait and stop the live Firecracker.
	// Select only the one qemu-nbd whose image belongs to this test's directory.
	crashed := resume(snapshot2)
	lifecycleState(t, ctx, crashed, "/state", two)
	qemu := lifecycleQEMU(t, filepath.Join(config.EROFSSnapshotDir, ".overlays"))
	require.NoError(t, qemu.Kill())
	defer qemu.Release()
	waitCtx, stopWait := context.WithTimeout(ctx, 10*time.Second)
	defer stopWait()
	err = crashed.Wait(waitCtx)
	require.ErrorContains(t, err, "qemu-nbd exited unexpectedly")
	require.NotErrorIs(t, err, context.DeadlineExceeded)
	select {
	case <-crashed.process.Exit.Done():
	default:
		t.Fatal("QEMU death did not stop Firecracker")
	}
	require.NoError(t, crashed.Close(ctx))
	t.Log("Factory Create/Pause/Resume: two generations, branch isolation, retained capture retry, concurrent Close and QEMU crash propagation passed")
}

func lifecycleSharedMountIdentity(t *testing.T, s *Sandbox, memoryPath, diskPath, sharedRoot string) string {
	t.Helper()
	pid, err := s.process.Pid()
	require.NoError(t, err)
	boundPath := filepath.Join(s.config.SandboxDir, s.Config.FirecrackerConfig.SandboxKernelDir(), "memfile")
	memory, err := os.Stat(memoryPath)
	require.NoError(t, err)
	bound, err := os.Stat(fmt.Sprintf("/proc/%d/root%s", pid, boundPath))
	require.NoError(t, err)
	require.True(t, os.SameFile(memory, bound), "FC bind must preserve shared RAM inode")
	info, err := s.rootfs.(*erofsRootfs).overlay.RecoveryInfo()
	require.NoError(t, err)
	require.Equal(t, diskPath, info.BackingPath)
	nbdPath, err := s.rootfs.Path()
	require.NoError(t, err)
	backend, err := os.ReadFile(filepath.Join("/sys/class/block", filepath.Base(nbdPath), "backend"))
	require.NoError(t, err)
	// sysfs appends one newline; preserve all bytes of the qcow2 path itself.
	kernelBackend := strings.TrimSuffix(string(backend), "\n")
	require.Equal(t, info.Path, kernelBackend, "kernel NBD backend must identify this runtime's qcow2")
	mountinfo, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	require.NoError(t, err)
	require.NotContains(t, string(mountinfo), sharedRoot+"/", "FC retains only its private RAM bind")
	return kernelBackend
}

func lifecycleQEMU(t *testing.T, overlayRoot string) *os.Process {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	require.NoError(t, err)
	var matches []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
		if len(args) > 1 && filepath.Base(args[0]) == "qemu-nbd" && strings.HasPrefix(args[len(args)-1], overlayRoot+string(os.PathSeparator)) {
			matches = append(matches, pid)
		}
	}
	require.Len(t, matches, 1, "must identify exactly one owned QEMU process before killing it")
	p, err := os.FindProcess(matches[0])
	require.NoError(t, err)
	return p
}

func lifecycleMetadata(id string, versions fc.Config) metadata.Template {
	return metadata.Template{Version: metadata.CurrentVersion, Template: metadata.TemplateMetadata{BuildID: id, KernelVersion: versions.KernelVersion, FirecrackerVersion: versions.FirecrackerVersion}}
}

func lifecycleEnvd(t *testing.T, ctx context.Context, s *Sandbox) {
	t.Helper()
	// The production WaitForEnvd call already authenticated /init. Health is
	// intentionally public; /envs proves auth and configuration delivery.
	// A prior VM may have snapshotted one side of an old keepalive connection.
	// Match the production sandbox transport and establish a fresh connection.
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	for _, check := range []struct {
		path       string
		authorized bool
		status     int
	}{
		{"/health", false, http.StatusNoContent}, {"/envs", true, http.StatusOK}, {"/envs", false, http.StatusUnauthorized},
	} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.envdServerURL()+check.path, nil)
		require.NoError(t, err)
		if check.authorized {
			request.Header.Set("X-Access-Token", *s.Config.Envd.AccessToken)
		}
		response, err := client.Do(request)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, response.Body.Close())
		require.NoError(t, err)
		require.Equal(t, check.status, response.StatusCode, "%s", body)
		if check.path == "/envs" && check.authorized {
			var envs map[string]string
			require.NoError(t, json.Unmarshal(body, &envs))
			require.Equal(t, "ram-disk", envs["EROFS_LIFECYCLE"])
		}
	}
}

func lifecycleCommand(t *testing.T, ctx context.Context, command string, args ...string) []byte {
	t.Helper()
	out, err := exec.CommandContext(ctx, command, args...).CombinedOutput()
	require.NoError(t, err, "%s %v: %s", command, args, out)
	return out
}

func lifecycleHash(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	hash := sha256.New()
	_, err = io.Copy(hash, f)
	require.NoError(t, err)
	return hash.Sum(nil)
}

type lifecycleGuestState struct {
	Generation int    `json:"generation"`
	Memory     [3]int `json:"memory"`
	Disk       [3]int `json:"disk"`
	Partial    int    `json:"partial"`
}

func lifecycleState(t *testing.T, ctx context.Context, s *Sandbox, path string, want lifecycleGuestState) {
	t.Helper()
	var got lifecycleGuestState
	var last []byte
	require.Eventually(t, func() bool {
		var err error
		last, err = exec.CommandContext(ctx, "ip", "netns", "exec", s.Slot.NamespaceID(), "curl", "-fsS", "--noproxy", "*", "--connect-timeout", "1", "--max-time", "2", "http://"+s.Slot.NamespaceIP()+":8080"+path).CombinedOutput()
		return err == nil && json.Unmarshal(last, &got) == nil
	}, 30*time.Second, 100*time.Millisecond, "guest did not respond: %s", last)
	require.Equal(t, want, got)
}

type lifecycleTemplate struct {
	paths  storage.CachePaths
	rootfs block.ReadonlyDevice
	meta   metadata.Template
}

type lifecycleFailRootfsPath struct {
	rootfs.Provider
	fail atomic.Bool
}

func (p *lifecycleFailRootfsPath) Path() (string, error) {
	if p.fail.Swap(false) {
		return "", errors.New("injected baseline Path failure")
	}
	return p.Provider.Path()
}

func (t *lifecycleTemplate) Files() storage.CachePaths { return t.paths }
func (*lifecycleTemplate) Memfile(context.Context) (block.ReadonlyDevice, error) {
	return nil, errors.New("native cold boot must not request a header memory device")
}
func (t *lifecycleTemplate) Rootfs() (block.ReadonlyDevice, error)       { return t.rootfs, nil }
func (*lifecycleTemplate) Snapfile() (template.File, error)              { return &template.NoopFile{}, nil }
func (t *lifecycleTemplate) Metadata() (metadata.Template, error)        { return t.meta, nil }
func (t *lifecycleTemplate) UpdateMetadata(meta metadata.Template) error { t.meta = meta; return nil }
func (*lifecycleTemplate) Close(context.Context) error                   { return nil }

// A real tap and netns, optionally with a veth route for host envd requests.
// Firewall rules stay inside the namespace; the Factory acquires/releases real
// Slot values through its normal pool API.
type lifecycleNetworkPool struct {
	mu         sync.Mutex
	slots      map[string]*network.Slot
	hostAccess bool
	closed     bool
}

func (p *lifecycleNetworkPool) Get(ctx context.Context, _ *orchestrator.SandboxNetworkConfig, _ network.EgressClass) (*network.Slot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, errors.New("lifecycle network pool is closed")
	}
	for idx := 20000 + os.Getpid()%8000; idx < 32767; idx++ {
		slot, err := network.NewSlot("erofs-lifecycle-"+strconv.Itoa(idx), idx, network.Config{}, network.NewNoopEgressProxy())
		if err != nil {
			return nil, err
		}
		if out, err := exec.CommandContext(ctx, "ip", "netns", "add", slot.NamespaceID()).CombinedOutput(); err != nil {
			if _, statErr := os.Stat(filepath.Join("/var/run/netns", slot.NamespaceID())); statErr == nil {
				continue
			}
			return nil, fmt.Errorf("create test netns: %w: %s", err, out)
		}
		p.slots[slot.NamespaceID()] = slot
		commands := [][]string{
			{"-n", slot.NamespaceID(), "tuntap", "add", "dev", slot.TapName(), "mode", "tap"},
			// Match the stable host tap MAC used by the production pool so the
			// guest's restored ARP cache stays valid across fresh namespaces.
			{"-n", slot.NamespaceID(), "link", "set", "dev", slot.TapName(), "address", "02:fc:00:00:00:06"},
			{"-n", slot.NamespaceID(), "address", "add", slot.TapIPString() + "/30", "dev", slot.TapName()},
			{"-n", slot.NamespaceID(), "link", "set", "dev", slot.TapName(), "up"},
			{"-n", slot.NamespaceID(), "link", "set", "lo", "up"},
		}
		if p.hostAccess {
			host, peer := "ev"+strconv.Itoa(idx), "ep"+strconv.Itoa(idx)
			commands = append(commands,
				[]string{"link", "add", host, "type", "veth", "peer", "name", peer, "netns", slot.NamespaceID()},
				[]string{"address", "add", slot.VethIP().String() + "/31", "dev", host},
				[]string{"link", "set", host, "up"},
				[]string{"-n", slot.NamespaceID(), "address", "add", slot.VpeerIP().String() + "/31", "dev", peer},
				[]string{"-n", slot.NamespaceID(), "link", "set", peer, "up"},
				[]string{"route", "add", slot.HostCIDR(), "via", slot.VpeerIP().String(), "dev", host},
				[]string{"netns", "exec", slot.NamespaceID(), "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"},
				[]string{"netns", "exec", slot.NamespaceID(), "iptables", "-t", "nat", "-A", "PREROUTING", "-d", slot.HostIPString(), "-j", "DNAT", "--to-destination", slot.NamespaceIP()},
				[]string{"netns", "exec", slot.NamespaceID(), "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", slot.TapName(), "-j", "SNAT", "--to-source", slot.TapIPString()},
			)
		}
		for _, args := range commands {
			if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
				return nil, fmt.Errorf("configure test tap: %w: %s", err, out)
			}
		}
		return slot, nil
	}
	return nil, errors.New("no unused test network namespace")
}

func (p *lifecycleNetworkPool) ReturnAsync(ctx context.Context, slot *network.Slot, released network.ReleaseNotify, _ time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.slots[slot.NamespaceID()]; !ok {
		return nil
	}
	if out, err := exec.CommandContext(ctx, "ip", "netns", "delete", slot.NamespaceID()).CombinedOutput(); err != nil {
		return fmt.Errorf("delete test netns: %w: %s", err, out)
	}
	delete(p.slots, slot.NamespaceID())
	if released != nil {
		released(ctx, slot.HostIPString())
	}
	return nil
}

func (p *lifecycleNetworkPool) Close(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	slots := make([]*network.Slot, 0, len(p.slots))
	for _, slot := range p.slots {
		slots = append(slots, slot)
	}
	p.mu.Unlock()
	var result error
	for _, slot := range slots {
		result = errors.Join(result, p.ReturnAsync(ctx, slot, nil, 0))
	}
	return result
}
