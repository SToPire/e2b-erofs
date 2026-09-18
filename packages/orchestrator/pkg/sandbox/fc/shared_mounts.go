//go:build linux

package fc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RuntimeSources supplies prepared host files before creating the private namespace.
// The caller retains their mounts and ownership through Firecracker exit.
type RuntimeSources struct {
	MemoryPath  string
	Rootfs      *PmemRootfsSource
	RawDisk     bool // Standalone raw build disk; honor Guest flush requests.
	LifecycleID string
}

func shellPath(path string) string {
	return "'" + strings.ReplaceAll(path, "'", "'\"'\"'") + "'"
}

// Shared mounts are inherited by every new FC namespace, including cold boots.
// Keep just the current RAM bind there; qemu-nbd reads disk backing in the host
// namespace. Otherwise a sibling FC can keep unused generations' image references alive.
func sharedMountScript(root, hostMemory, memoryPath string) (string, error) {
	if root == "" {
		if hostMemory != "" {
			return "", fmt.Errorf("native memory source requires a shared mount root")
		}
		return "", nil
	}
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) || filepath.Base(root) != ".shared-mounts" || strings.ContainsAny(root, "\x00\r\n") {
		return "", fmt.Errorf("invalid shared mount root %q", root)
	}
	bind := ""
	if hostMemory != "" {
		if !filepath.IsAbs(hostMemory) || !strings.HasPrefix(filepath.Clean(hostMemory), root+string(os.PathSeparator)) ||
			!filepath.IsAbs(memoryPath) || strings.HasPrefix(filepath.Clean(memoryPath), root+string(os.PathSeparator)) ||
			strings.ContainsAny(hostMemory+memoryPath, "\x00\r\n") {
			return "", fmt.Errorf("invalid shared memory bind paths")
		}
		bind = fmt.Sprintf("test ! -e %s\ntouch -- %s\nmount --bind -- %s %s\nmount -o remount,bind,ro,nosuid,nodev,noexec -- %s\n",
			shellPath(memoryPath), shellPath(memoryPath), shellPath(hostMemory), shellPath(memoryPath), shellPath(memoryPath))
	}
	return fmt.Sprintf(`(
set -e
%sshared_root=%s
# findmnt raw output escapes whitespace/backslashes. Decode as data, never eval.
shared_mounts=$(findmnt --kernel --raw --noheadings --output TARGET,FSTYPE)
while read -r encoded_mount filesystem; do
  test "$filesystem" = erofs || continue
  mount_path=$(printf '%%b' "$encoded_mount")
  case "$mount_path" in
    "$shared_root"/*) umount -- "$mount_path" ;;
  esac
done <<< "$shared_mounts"
)`, bind, shellPath(root)), nil
}

func (p *Process) memoryPathInNamespace(hostPath string) (string, error) {
	if p.nativeMemoryPath == "" {
		return hostPath, nil
	}
	if hostPath != p.nativeMemoryHost {
		return "", fmt.Errorf("File restore source differs from the prepared memory bind")
	}
	host, err := os.Stat(hostPath)
	if err != nil {
		return "", err
	}
	pid, err := p.Pid()
	if err != nil {
		return "", err
	}
	bound, err := os.Stat(fmt.Sprintf("/proc/%d/root%s", pid, p.nativeMemoryPath))
	if err != nil {
		return "", fmt.Errorf("inspect FC memory bind: %w", err)
	}
	if !os.SameFile(host, bound) {
		return "", fmt.Errorf("FC memory bind does not reference the verified inode")
	}
	return p.nativeMemoryPath, nil
}
