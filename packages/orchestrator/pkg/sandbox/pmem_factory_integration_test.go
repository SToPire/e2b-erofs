//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/launchdarkly/go-server-sdk/v7/testhelpers/ldtestdata"
	"github.com/stretchr/testify/require"

	"github.com/e2b-dev/infra/packages/clickhouse/pkg/hoststats"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/cfg"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/cgroup"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/fc"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/network"
	"github.com/e2b-dev/infra/packages/shared/pkg/featureflags"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage"
)

// Tests the real Go Factory cold-bootstrap and close path with the P0 fixture
// images. Capture/resume and envd are separate gates; this never publishes a
// fabricated VM snapshot merely to make a cold-boot API accept a template.
func TestPmemFactoryColdBootstrap(t *testing.T) { //nolint:paralleltest // owns mount/network namespaces
	if os.Getenv("E2B_PMEM_FACTORY") != "1" {
		t.Skip("set E2B_PMEM_FACTORY=1 and supply the verified P0 inputs")
	}
	require.Zero(t, os.Geteuid())
	_, err := os.Stat("/sys/module/nbd")
	require.True(t, os.IsNotExist(err), "NBD must be absent")
	inputs := make(map[string]string)
	for _, name := range []string{"FC", "KERNEL", "MKFS", "FSCK", "LOWER", "UPPER", "INITRD", "TEST_DIR"} {
		inputs[name] = os.Getenv("E2B_PMEM_" + name)
		require.NotEmpty(t, inputs[name], "missing E2B_PMEM_%s", name)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	require.NoError(t, os.MkdirAll(inputs["TEST_DIR"], 0755))
	work, err := os.MkdirTemp(inputs["TEST_DIR"], "factory-pmem-")
	require.NoError(t, err)
	t.Logf("retained Factory evidence: %s", work)
	config := cfg.BuilderConfig{EROFSSnapshotDir: filepath.Join(work, "store"), EROFSNativeMemoryVerified: true,
		EROFSPmemVerified: true, EROFSNativeOnly: true, EROFSMkfsPath: inputs["MKFS"],
		FirecrackerVersionsDir: filepath.Join(work, "fc"), HostKernelsDir: filepath.Join(work, "kernels"),
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
	for _, path := range []string{config.StorageConfig.SandboxCacheDir, config.StorageConfig.TemplateCacheDir} {
		require.NoError(t, os.MkdirAll(path, 0755))
	}
	store, err := erofs.NewStore(config.EROFSSnapshotDir, erofs.Options{MkfsPath: inputs["MKFS"], FsckPath: inputs["FSCK"]})
	require.NoError(t, err)
	lowerInfo, err := os.Stat(inputs["LOWER"])
	require.NoError(t, err)
	upperInfo, err := os.Stat(inputs["UPPER"])
	require.NoError(t, err)
	lower, err := store.PublishLower(ctx, inputs["LOWER"], lowerInfo.Size())
	require.NoError(t, err)
	initrd, err := store.ImportInitramfs(ctx, inputs["INITRD"])
	require.NoError(t, err)
	kernelHash, err := runtimeBinaryDigest(ctx, inputs["KERNEL"])
	require.NoError(t, err)
	fcHash, err := runtimeBinaryDigest(ctx, inputs["FC"])
	require.NoError(t, err)
	upperHash, err := runtimeBinaryDigest(ctx, inputs["UPPER"])
	require.NoError(t, err)
	boot := erofs.BootLayout{Layout: erofs.LayoutPmem, KernelVersion: versions.KernelVersion, KernelSHA256: kernelHash,
		FirecrackerVersion: versions.FirecrackerVersion, FirecrackerSHA256: fcHash, Initramfs: initrd}
	flags, err := featureflags.NewClientWithDatasource(ldtestdata.DataSource())
	require.NoError(t, err)
	t.Cleanup(func() { flags.Close(context.Background()) })
	networkPool := &lifecycleNetworkPool{slots: make(map[string]*network.Slot)}
	t.Cleanup(func() { require.NoError(t, networkPool.Close(context.Background())) })
	factory, err := NewFileFactory(ctx, config, networkPool, flags, hoststats.NewNoopDelivery(), cgroup.NewNoopManager(), network.NewNoopEgressProxy(), nil, NewSandboxesMap())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, factory.CloseSharedMounts(context.Background())) })
	var firstLower, firstUpper os.FileInfo
	team := uuid.NewString()
	for i := 0; i < 2; i++ {
		id := uuid.NewString()
		paths, err := (storage.Paths{BuildID: id}).Cache(config.StorageConfig)
		require.NoError(t, err)
		base := &lifecycleTemplate{paths: paths, meta: lifecycleMetadata(id, versions)}
		logPath := filepath.Join(work, fmt.Sprintf("guest-%d.log", i))
		log, err := os.Create(logPath)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, log.Close()) })
		runtime := RuntimeMetadata{TemplateID: "pmem-test", SandboxID: "p" + uuid.NewString()[:8], ExecutionID: uuid.NewString(), BuildID: id, TeamID: team, SandboxType: SandboxTypeBuild}
		guestConfig := NewConfig(Config{Vcpu: 1, RamMB: 256, TotalDiskSizeMB: upperInfo.Size() >> 20, FirecrackerConfig: versions, SkipEnvdWait: true})
		vm, err := factory.CreateSandbox(ctx, guestConfig, runtime, base, time.Hour, "", fc.ProcessOptions{InitScriptPath: "/sbin/init", KernelLogs: true, Stdout: log, Stderr: log}, nil, nil,
			WithPmemBootstrap(PmemBootstrap{Boot: boot, Lower: lower, UpperPath: inputs["UPPER"], UpperSize: upperInfo.Size(), UpperContentSHA256: upperHash}))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, vm.Close(context.Background())) })
		require.Eventually(t, func() bool { data, _ := os.ReadFile(logPath); return strings.Contains(string(data), "P0_EXEC_OK") }, 30*time.Second, 20*time.Millisecond)
		pid, err := vm.process.Pid()
		require.NoError(t, err)
		boundLower, err := os.Stat(fmt.Sprintf("/proc/%d/root/run/e2b-devices/lower.ext4", pid))
		require.NoError(t, err)
		boundUpper, err := os.Stat(fmt.Sprintf("/proc/%d/root/run/e2b-devices/upper.ext4", pid))
		require.NoError(t, err)
		if i == 0 {
			firstLower, firstUpper = boundLower, boundUpper
		} else {
			require.True(t, os.SameFile(firstLower, boundLower), "lower must share one inode")
			require.False(t, os.SameFile(firstUpper, boundUpper), "upper must have an independent inode")
		}
	}
}
