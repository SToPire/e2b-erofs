//go:build linux

package fc

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/cfg"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/rootfs"
)

func TestPmemAPIUsesSeparateReadonlyAndWritableDevices(t *testing.T) {
	t.Parallel()
	type request struct {
		path string
		body map[string]any
	}
	requests := make(chan request, 3)
	c := nativeAPIStub(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- request{r.URL.Path, body}
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.setBootSource(t.Context(), "rdinit=/init", "/kernel", "/initrd"))
	require.NoError(t, c.setPmemRootfs(t.Context(), "/lower", "/upper", nil))
	boot, lower, upper := <-requests, <-requests, <-requests
	require.Equal(t, "/boot-source", boot.path)
	require.Equal(t, "/initrd", boot.body["initrd_path"])
	require.Equal(t, "/pmem/lower", lower.path)
	require.Equal(t, true, lower.body["read_only"])
	require.NotEqual(t, true, lower.body["root_device"])
	require.Equal(t, "/drives/upper", upper.path)
	require.Equal(t, false, upper.body["is_root_device"])
	require.NotEqual(t, true, upper.body["is_read_only"])
	require.Equal(t, "Sync", upper.body["io_engine"])
	require.Equal(t, "Writeback", upper.body["cache_type"])
	require.Equal(t, "/upper", upper.body["path_on_host"])
}

func TestPmemKernelArgsCannotBeReplacedByExtraArguments(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"rdinit", "e2b.lower_bytes", "e2b.rootfs_layout", "e2b.init"} {
		require.Error(t, ValidateCmdlineArgs(map[string]string{name: "wrong"}))
	}
	p := &preparedPmemRootfs{source: PmemRootfsSource{LowerSize: 2 << 20, UpperSize: 4 << 20}}
	args, err := p.kernelArgs(buildKernelArgs("network", ProcessOptions{InitScriptPath: "/sbin/init"}), "/sbin/init")
	require.NoError(t, err)
	require.NotContains(t, args, "init")
	require.NotContains(t, args, "root")
	require.NotContains(t, args, "rootflags")
	require.Equal(t, "/init", args["rdinit"])
	require.Equal(t, PmemRootfsLayout, args["e2b.rootfs_layout"])
	require.Equal(t, "2097152", args["e2b.lower_bytes"])
	require.Equal(t, "4194304", args["e2b.upper_bytes"])
	_, err = p.kernelArgs(KernelArgs{}, "/sbin/init e2b.upper_bytes=1")
	require.Error(t, err)
}

func pmemTestInputs(t *testing.T) (cfg.BuilderConfig, Config, RuntimeSources) {
	t.Helper()
	dir := t.TempDir()
	config := cfg.BuilderConfig{EROFSSnapshotDir: filepath.Join(dir, "store"), EROFSPmemVerified: true,
		HostKernelsDir: filepath.Join(dir, "kernels"), FirecrackerVersionsDir: filepath.Join(dir, "fc")}
	versions := Config{KernelVersion: "kernel", FirecrackerVersion: "fc", NativeMemory: true}
	sources := RuntimeSources{MemoryPath: filepath.Join(dir, "memfile"), Rootfs: &PmemRootfsSource{
		LowerPath: filepath.Join(dir, "lower ' with spaces"), LowerSize: 2 << 20,
		UpperPath: filepath.Join(dir, "upper"), UpperSize: 4 << 20, InitramfsPath: filepath.Join(dir, "initrd"),
	}}
	for path, size := range map[string]int64{sources.Rootfs.LowerPath: sources.Rootfs.LowerSize,
		sources.Rootfs.UpperPath: sources.Rootfs.UpperSize, sources.Rootfs.InitramfsPath: 1,
		sources.MemoryPath: 4096, versions.HostKernelPath(config): 1} {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		f, err := os.Create(path)
		require.NoError(t, err)
		require.NoError(t, f.Truncate(size))
		require.NoError(t, f.Close())
	}
	return config, versions, sources
}

func TestPmemSourcesAreBoundBeforeInheritedMountCleanup(t *testing.T) {
	t.Parallel()
	config, versions, sources := pmemTestInputs(t)
	result, err := NewStartScriptBuilder(config).Build(versions, createTestSandboxFiles("sbx", "exec"),
		ConstantRootfsPaths, "ns-test", sources)
	require.NoError(t, err)
	require.Equal(t, "/run/e2b-devices/upper.ext4", result.RootfsPath)
	require.Equal(t, "/run/e2b-devices/memfile", result.MemoryPath)
	require.Contains(t, result.Value, shellPath(sources.Rootfs.LowerPath))
	require.Less(t, strings.LastIndex(result.Value, "mount --bind"), strings.Index(result.Value, "umount --"))
	require.NotContains(t, result.Value, "/dev/nbd")
	command := exec.Command("bash", "-n")
	command.Stdin = strings.NewReader(result.Value)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)
	// A caller cannot change the expected path/size after preparation.
	expected := result.pmem.source.UpperPath
	sources.Rootfs.UpperPath = "/different"
	require.Equal(t, expected, result.pmem.source.UpperPath)
	config.EROFSPmemVerified = false
	_, err = NewStartScriptBuilder(config).Build(versions, createTestSandboxFiles("sbx", "exec"), ConstantRootfsPaths, "ns-test", sources)
	require.ErrorContains(t, err, "EROFS_PMEM_VERIFIED")
}

func TestPmemRejectsAliasedOrSymlinkInputs(t *testing.T) {
	t.Parallel()
	config, versions, sources := pmemTestInputs(t)
	initrd := sources.Rootfs.InitramfsPath
	require.NoError(t, os.Remove(initrd))
	require.NoError(t, os.Link(sources.Rootfs.LowerPath, initrd))
	_, err := NewStartScriptBuilder(config).Build(versions, createTestSandboxFiles("sbx", "exec"), ConstantRootfsPaths, "ns-test", sources)
	require.ErrorContains(t, err, "alias")
	require.NoError(t, os.Remove(initrd))
	require.NoError(t, os.Symlink(sources.Rootfs.LowerPath, initrd))
	_, err = NewStartScriptBuilder(config).Build(versions, createTestSandboxFiles("sbx", "exec"), ConstantRootfsPaths, "ns-test", sources)
	require.ErrorContains(t, err, "type or size")
}

func TestPmemAcceptsPinnedKernelCacheSymlink(t *testing.T) {
	t.Parallel()
	config, versions, sources := pmemTestInputs(t)
	path := versions.HostKernelPath(config)
	require.NoError(t, os.Rename(path, path+".actual"))
	require.NoError(t, os.Symlink(path+".actual", path))
	result, err := NewStartScriptBuilder(config).Build(versions, createTestSandboxFiles("sbx", "exec"), ConstantRootfsPaths, "ns-test", sources)
	require.NoError(t, err)
	require.NotNil(t, result.pmem)
}

type pmemProviderPath struct {
	rootfs.Provider
	path string
}

func (p pmemProviderPath) Path() (string, error) { return p.path, nil }

func TestPmemBindMustKeepPreparedInode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	host, alias := filepath.Join(dir, "host"), filepath.Join(dir, "alias")
	require.NoError(t, os.WriteFile(host, []byte("data"), 0o600))
	require.NoError(t, os.Link(host, alias))
	info, err := os.Stat(host)
	require.NoError(t, err)
	process, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	defer process.Release()
	p := &Process{cmd: &exec.Cmd{Process: process}, rootfsProvider: pmemProviderPath{path: host},
		pmem: &preparedPmemRootfs{source: PmemRootfsSource{UpperPath: host},
			binds: []runtimeFileBind{{host: host, target: alias, info: info}}}}
	require.NoError(t, p.validatePmemBindings())
	require.NoError(t, os.Remove(alias))
	require.NoError(t, os.WriteFile(alias, []byte("data"), 0o600))
	require.ErrorContains(t, p.validatePmemBindings(), "prepared inode")
}
