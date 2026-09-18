//go:build linux

package erofs

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Run the opt-in test as root in a private mount namespace. It needs the
// file-delta EROFS tools and qemu-img/qemu-io, but no KVM or reserved NBD device.
// Set TMPDIR to a disk filesystem: tmpfs cannot back these EROFS mounts.
func TestKernelFileBackedMounts(t *testing.T) {
	if os.Getenv("EROFS_TEST_FILE_MOUNTS") != "1" {
		t.Skip("set EROFS_TEST_FILE_MOUNTS=1 and run as root in a private mount namespace")
	}
	require.Zero(t, os.Geteuid())
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "store"), Options{
		MkfsPath: os.Getenv("EROFS_MKFS"), FsckPath: os.Getenv("EROFS_FSCK"),
	})
	require.NoError(t, err)
	shared := NewSharedMounts(store.Root)
	t.Cleanup(func() { require.NoError(t, shared.Close(context.Background())) })
	const size = 16 * BlockSize
	memory, disk := bytes.Repeat([]byte{0x17}, size), bytes.Repeat([]byte{0x35}, size)
	vmstate, metadata := filepath.Join(dir, "vmstate"), filepath.Join(dir, "metadata.json")
	require.NoError(t, os.WriteFile(vmstate, []byte("test-vmstate"), 0600))
	require.NoError(t, os.WriteFile(metadata, []byte(`{}`), 0600))
	var refs []*MountRef
	acquire := func(s *Snapshot) *MountRef {
		t.Helper()
		ref, err := shared.Acquire(ctx, s, "test-team")
		require.NoError(t, err)
		refs = append(refs, ref)
		t.Cleanup(func() { require.NoError(t, ref.Release()) })
		return ref
	}
	assertContents := func(ref *MountRef, mem, disk []byte) {
		t.Helper()
		for path, want := range map[string][]byte{ref.MemoryPath(): mem, ref.DiskPath(): disk} {
			got, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, want, got)
		}
	}
	assertFileSources := func(ref *MountRef, s *Snapshot) {
		t.Helper()
		data, err := os.ReadFile("/proc/self/mountinfo")
		require.NoError(t, err)
		for path, artifact := range map[string]Artifact{ref.MemoryPath(): s.Manifest.Memory.Artifact, ref.DiskPath(): s.Manifest.Disk.Artifact} {
			target := filepath.Dir(filepath.Dir(path))
			found := false
			for _, line := range strings.Split(string(data), "\n") {
				left, right, ok := strings.Cut(line, " - ")
				if !ok || strings.Fields(left)[4] != target {
					continue
				}
				fields := strings.Fields(right)
				require.Equal(t, "erofs", fields[0])
				require.Equal(t, filepath.Join(store.Root, artifact.File), fields[1])
				require.Contains(t, strings.Split(strings.Fields(left)[5], ","), "ro")
				found = true
			}
			require.True(t, found, "file-backed mount absent: %s", target)
		}
	}
	build := func(id string, parent *Snapshot, backing *MountRef, wantMemory, wantDisk []byte, block int) *Snapshot {
		t.Helper()
		memPath, diskPath := filepath.Join(dir, id+".memory"), filepath.Join(dir, id+".disk")
		r := BuildRequest{ID: id, MemoryPath: memPath, DiskPath: diskPath,
			MemorySize: size, DiskSize: size, VMStatePath: vmstate, MetadataPath: metadata}
		if parent == nil {
			require.NoError(t, os.WriteFile(memPath, wantMemory, 0600))
			require.NoError(t, os.WriteFile(diskPath, wantDisk, 0600))
		} else {
			r.ParentID = parent.Manifest.ID
			f, err := os.OpenFile(memPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			require.NoError(t, err)
			t.Cleanup(func() { _ = f.Close() })
			require.NoError(t, f.Truncate(size))
			page := bytes.Repeat([]byte{byte(0x80 + block)}, BlockSize)
			_, err = f.WriteAt(page, int64(block*BlockSize))
			require.NoError(t, err)
			copy(wantMemory[block*BlockSize:], page)
			_, err = f.WriteAt(make([]byte, BlockSize), 4*BlockSize)
			require.NoError(t, err)
			clear(wantMemory[4*BlockSize : 5*BlockSize])
			require.NoError(t, f.Sync())
			require.NoError(t, f.Close())
			require.NoError(t, command(ctx, "qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", backing.DiskPath(),
				"-o", "cluster_size=4096,lazy_refcounts=off", diskPath, fmt.Sprint(size)))
			require.NoError(t, command(ctx, "qemu-io", "-f", "qcow2", "-c", fmt.Sprintf("write -P %d %d 512", 0xa0+block, block*BlockSize+512),
				"-c", fmt.Sprintf("write -z %d %d", 5*BlockSize, BlockSize), diskPath))
			copy(wantDisk[block*BlockSize+512:], bytes.Repeat([]byte{byte(0xa0 + block)}, 512))
			clear(wantDisk[5*BlockSize : 6*BlockSize])
			require.NoError(t, writeDiskSeal(diskPath, parent.Manifest.ID, backing.DiskPath(), size))
		}
		snapshot, err := store.Build(ctx, r)
		require.NoError(t, err)
		return snapshot
	}
	base := build("g0", nil, nil, memory, disk, 0)
	baseRef, sibling := acquire(base), acquire(base)
	require.Equal(t, baseRef.MemoryPath(), sibling.MemoryPath())
	require.NoError(t, baseRef.Release())
	assertContents(sibling, memory, disk)
	assertFileSources(sibling, base)

	parent, parentRef := base, sibling
	wantMemory, wantDisk := bytes.Clone(memory), bytes.Clone(disk)
	for generation, block := range []int{2, 7} {
		parent = build(fmt.Sprintf("g%d", generation+1), parent, parentRef, wantMemory, wantDisk, block)
		parentRef = acquire(parent)
		assertContents(parentRef, wantMemory, wantDisk)
		assertFileSources(parentRef, parent)
	}
	branchMemory, branchDisk := bytes.Clone(memory), bytes.Clone(disk)
	branch := build("branch", base, sibling, branchMemory, branchDisk, 10)
	branchRef := acquire(branch)
	assertContents(branchRef, branchMemory, branchDisk)
	assertContents(parentRef, wantMemory, wantDisk)
	assertContents(sibling, memory, disk)

	// Private RAM writes do not change either the shared inode or its sibling.
	f, err := os.Open(parentRef.MemoryPath())
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	private, err := unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
	require.NoError(t, err)
	private[0] ^= 0xff
	require.NoError(t, unix.Munmap(private))
	require.NoError(t, f.Close())
	assertContents(parentRef, wantMemory, wantDisk)

	// A busy memory consumer retains the partially closed mount for a retry.
	mounted, err := parent.Mount(ctx, filepath.Join(dir, "busy"))
	if mounted != nil {
		t.Cleanup(func() { require.NoError(t, mounted.Close()) })
	}
	require.NoError(t, err)
	busyFile, err := os.Open(mounted.MemoryPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = busyFile.Close() })
	require.ErrorIs(t, mounted.Close(), unix.EBUSY)
	require.NoError(t, busyFile.Close())
	require.NoError(t, mounted.Close())
	require.NoError(t, mounted.Close())
	for _, ref := range refs {
		require.NoError(t, ref.Release())
	}
	entries, err := os.ReadDir(shared.Root())
	require.NoError(t, err)
	require.Empty(t, entries)
	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	require.NoError(t, err)
	require.NotContains(t, string(mountinfo), dir)
	loops, err := filepath.Glob("/sys/class/block/loop*/loop/backing_file")
	require.NoError(t, err)
	for _, path := range loops {
		backing, err := os.ReadFile(path)
		if os.IsNotExist(err) { // Unrelated loop devices can disappear.
			continue
		}
		require.NoError(t, err)
		require.NotContains(t, string(backing), dir)
	}
}
