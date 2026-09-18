//go:build linux

package fc

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/cfg"
)

func TestSharedMountScriptPaths(t *testing.T) {
	t.Parallel()
	root := "/store with ' quotes/$()/back\\slash/.shared-mounts"
	script, err := sharedMountScript(root, root+"/g0/memory/memory/memfile", "/fc-vm/kernel/memfile")
	require.NoError(t, err)
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	require.Contains(t, script, shellPath(root))
	for _, bad := range []struct{ root, host, target string }{
		{"/", "", ""},
		{"relative/.shared-mounts", "", ""},
		{root, "/foreign/memfile", "/fc-vm/memfile"},
		{root, root + "/../escape", "/fc-vm/memfile"},
		{root, root + "/g0/memfile", root + "/alias"},
		{root, root + "/g0/memfile", "/fc-vm/a\nb"},
	} {
		_, err := sharedMountScript(bad.root, bad.host, bad.target)
		require.Error(t, err)
	}
}

func TestSharedMountStartScript(t *testing.T) {
	t.Parallel()
	config := cfg.BuilderConfig{EROFSSnapshotDir: "/store", SandboxDir: "/fc-vm"}
	builder := NewStartScriptBuilder(config)
	for _, version := range []uint64{1, 2} {
		t.Run(strconv.FormatUint(version, 10), func(t *testing.T) {
			result, err := builder.Build(Config{NativeMemory: true, KernelVersion: "kernel", FirecrackerVersion: "v1.14"},
				createTestSandboxFiles("sbx", "execution"), RootfsPaths{TemplateVersion: version}, "ns-1",
				RuntimeSources{MemoryPath: "/store/.shared-mounts/g0/memory/memory/memfile"})
			require.NoError(t, err)
			require.Equal(t, "/fc-vm/kernel/memfile", result.MemoryPath)
			require.Less(t, strings.Index(result.Value, "mount --make-rprivate"), strings.Index(result.Value, "mount --bind"))
			require.Less(t, strings.Index(result.Value, "mount --bind"), strings.Index(result.Value, "umount --"))
			require.Less(t, strings.Index(result.Value, "umount --"), strings.Index(result.Value, "ip netns exec"))
			cmd := exec.Command("bash", "-n")
			cmd.Stdin = strings.NewReader(result.Value)
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "%s", output)
		})
	}
	result, err := builder.Build(Config{KernelVersion: "kernel"}, createTestSandboxFiles("sbx", "execution"), ConstantRootfsPaths, "ns-1")
	require.NoError(t, err)
	require.Contains(t, result.Value, "umount --", "cold/legacy FC must discard inherited shared mounts too")
	require.NotContains(t, result.Value, "mount --bind")
	require.Empty(t, result.MemoryPath)
}

func TestSharedMountScriptEnumeration(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), ".shared-mounts")
	script, err := sharedMountScript(root, "", "")
	require.NoError(t, err)
	output, err := exec.Command("bash", "-c", script).CombinedOutput()
	require.NoError(t, err, "%s", output)
	// Every namespace has a root mount, so enumeration errors must fail closed.
	bin := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bin, "findmnt"), []byte("#!/bin/sh\nexit 1\n"), 0700))
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	require.Error(t, cmd.Run())
}

func TestNativeMemoryBindIdentity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	host, bound := filepath.Join(dir, "host"), filepath.Join(dir, "bound")
	require.NoError(t, os.WriteFile(host, []byte("memory"), 0600))
	require.NoError(t, os.Link(host, bound))
	process, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	defer process.Release()
	p := &Process{cmd: &exec.Cmd{Process: process}, nativeMemoryHost: host, nativeMemoryPath: bound}
	path, err := p.memoryPathInNamespace(host)
	require.NoError(t, err)
	require.Equal(t, bound, path)
	require.NoError(t, os.Remove(bound))
	require.NoError(t, os.WriteFile(bound, []byte("memory"), 0600))
	_, err = p.memoryPathInNamespace(host)
	require.ErrorContains(t, err, "verified inode")
	_, err = p.memoryPathInNamespace(bound)
	require.ErrorContains(t, err, "differs")
}
