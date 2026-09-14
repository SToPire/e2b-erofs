//go:build linux

package erofs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSparseCaptureFilesystem(t *testing.T) {
	if err := ProbeSparseFilesystem(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

// EROFS_TEST_DEVICE must be an exclusively reserved NBD device. The explicit
// opt-in avoids touching host devices during ordinary unit test runs.
func TestKernelSnapshotChain(t *testing.T) {
	device := os.Getenv("EROFS_TEST_DEVICE")
	if device == "" {
		t.Skip("set EROFS_TEST_DEVICE to an exclusively reserved NBD device and run as root")
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel EROFS/NBD integration requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "store"), Options{MkfsPath: os.Getenv("EROFS_MKFS"), FsckPath: os.Getenv("EROFS_FSCK")})
	if err != nil {
		t.Fatal(err)
	}
	if err := ProbeSparseFilesystem(store.Root); err != nil {
		t.Fatal(err)
	}
	const size = 16 * BlockSize
	memory := bytes.Repeat([]byte{0x17}, size)
	disk := bytes.Repeat([]byte{0x35}, size)
	rawMemory, rawDisk := filepath.Join(dir, "memory.raw"), filepath.Join(dir, "disk.raw")
	vmstate, metadata := filepath.Join(dir, "vmstate"), filepath.Join(dir, "metadata.json")
	write := func(path string, b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(rawMemory, memory)
	write(rawDisk, disk)
	write(vmstate, []byte("state-0"))
	write(metadata, []byte(`{"generation":0}`))
	baseline, err := store.Build(ctx, BuildRequest{ID: "g0", MemoryPath: rawMemory, DiskPath: rawDisk, VMStatePath: vmstate, MetadataPath: metadata, MemorySize: size, DiskSize: size})
	if err != nil {
		t.Fatal(err)
	}
	baseMount, err := baseline.Mount(ctx, filepath.Join(dir, "mounts"))
	if err != nil {
		t.Fatal(err)
	}
	defer baseMount.Close()
	assertBytes := func(path string, want []byte) {
		t.Helper()
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("bytes mismatch: %s", path)
		}
	}
	assertBytes(baseMount.MemoryPath, memory)
	assertBytes(baseMount.DiskPath, disk)
	// Firecracker's File backend uses a private mapping: writes must never
	// modify the read-only baseline, including an untouched nonzero page.
	f, err := os.Open(baseMount.MemoryPath)
	if err != nil {
		t.Fatal(err)
	}
	private, err := unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	private[0] = 0x66
	if private[9*BlockSize] != 0x17 {
		t.Fatal("untouched nonzero page lost")
	}
	unix.Munmap(private)
	f.Close()
	assertBytes(baseMount.MemoryPath, memory)

	makeGeneration := func(id string, parent *Snapshot, mounted *Mounted, wantMemory, wantDisk []byte, dirtyBlock int, failFirst bool) *Snapshot {
		t.Helper()
		capture, err := store.Begin(id)
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(capture.MemoryPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(size); err != nil {
			t.Fatal(err)
		}
		page := bytes.Repeat([]byte{byte(0x80 + dirtyBlock)}, BlockSize)
		if _, err := f.WriteAt(page, int64(dirtyBlock*BlockSize)); err != nil {
			t.Fatal(err)
		}
		copy(wantMemory[dirtyBlock*BlockSize:], page)
		if _, err := f.WriteAt(make([]byte, BlockSize), 4*BlockSize); err != nil {
			t.Fatal(err)
		}
		clear(wantMemory[4*BlockSize : 5*BlockSize])
		f.Sync()
		f.Close()
		write(capture.VMStatePath, []byte("state-"+id))
		overlay, err := NewOverlay(ctx, OverlayOptions{Directory: filepath.Join(capture.Dir, "runtime"), BackingPath: mounted.DiskPath, Size: size, DevicePath: device, ParentID: parent.Manifest.ID, Tools: store.Options})
		if err != nil {
			if overlay != nil {
				overlay.Close(ctx)
			}
			t.Fatal(err)
		}
		defer overlay.Close(ctx)
		blk, err := os.OpenFile(overlay.Path(), os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		partial := bytes.Repeat([]byte{byte(0xa0 + dirtyBlock)}, 512)
		start := dirtyBlock*BlockSize + 512
		if _, err := blk.WriteAt(partial, int64(start)); err != nil {
			t.Fatal(err)
		}
		copy(wantDisk[start:], partial)
		if _, err := blk.WriteAt(make([]byte, BlockSize), 5*BlockSize); err != nil {
			t.Fatal(err)
		}
		clear(wantDisk[5*BlockSize : 6*BlockSize])
		if err := blk.Sync(); err != nil {
			t.Fatal(err)
		}
		blk.Close()
		sealed, err := overlay.Seal(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := overlay.Err(); err != nil {
			t.Fatalf("intentional QEMU disconnect reported as failure: %v", err)
		}
		r := BuildRequest{ID: id, ParentID: parent.Manifest.ID, MemoryPath: capture.MemoryPath, DiskPath: sealed, VMStatePath: capture.VMStatePath, MetadataPath: metadata, MemorySize: size, DiskSize: size}
		if failFirst {
			original := store.Options.FsckPath
			store.Options.FsckPath = "false"
			_, err := store.Build(ctx, r)
			store.Options.FsckPath = original
			if err == nil {
				t.Fatal("validation failure published snapshot")
			}
			if _, err := store.Load(id); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial generation visible: %v", err)
			}
			if err := ValidateSparseDiff(capture.MemoryPath, size); err != nil {
				t.Fatal(err)
			}
			if err := validateDiskSeal(sealed, parent.Manifest.ID, size); err != nil {
				t.Fatal(err)
			}
		}
		next, err := store.Build(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(id); err != nil {
			t.Fatal(err)
		}
		if retried, err := store.Build(ctx, r); err != nil || retried.Dir != next.Dir {
			t.Fatalf("repeat publication did not recover its committed capture: %v", err)
		}
		if r.ParentID != "g0" {
			changedParent := r
			changedParent.ParentID = "g0"
			if _, err := store.Build(ctx, changedParent); !errors.Is(err, ErrSnapshotConflict) {
				t.Fatalf("different parent accepted as same capture: %v", err)
			}
		}
		// The native Diff's untouched zero bytes must not become zero DATA on
		// retry: those layouts mean inherit parent and overwrite parent.
		dataBefore, err := os.ReadFile(capture.MemoryPath)
		if err != nil {
			t.Fatal(err)
		}
		changed, err := os.OpenFile(capture.MemoryPath, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := changed.WriteAt(make([]byte, BlockSize), 0); err != nil {
			t.Fatal(err)
		}
		if err := changed.Sync(); err != nil {
			t.Fatal(err)
		}
		dataAfter, err := os.ReadFile(capture.MemoryPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dataBefore, dataAfter) {
			t.Fatal("zero DATA test changed logical bytes")
		}
		if _, err := store.Build(ctx, r); !errors.Is(err, ErrSnapshotConflict) {
			t.Fatalf("changed Diff layout accepted as same capture: %v", err)
		}
		if err := unix.Fallocate(int(changed.Fd()), unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, 0, BlockSize); err != nil {
			t.Fatal(err)
		}
		if err := errors.Join(changed.Sync(), changed.Close()); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Build(ctx, r); err != nil {
			t.Fatalf("restored capture failed retry: %v", err)
		}
		return next
	}
	memory1, disk1 := bytes.Clone(memory), bytes.Clone(disk)
	g1 := makeGeneration("g1", baseline, baseMount, memory1, disk1, 2, true)
	g1Mount, err := g1.Mount(ctx, filepath.Join(dir, "mounts"))
	if err != nil {
		t.Fatal(err)
	}
	defer g1Mount.Close()
	assertBytes(g1Mount.MemoryPath, memory1)
	assertBytes(g1Mount.DiskPath, disk1)
	assertBytes(baseMount.MemoryPath, memory)
	assertBytes(baseMount.DiskPath, disk)
	memory2, disk2 := bytes.Clone(memory1), bytes.Clone(disk1)
	g2 := makeGeneration("g2", g1, g1Mount, memory2, disk2, 7, false)
	g2Mount, err := g2.Mount(ctx, filepath.Join(dir, "mounts"))
	if err != nil {
		t.Fatal(err)
	}
	defer g2Mount.Close()
	assertBytes(g2Mount.MemoryPath, memory2)
	assertBytes(g2Mount.DiskPath, disk2)
	if len(g2.Manifest.Memory.Devices) != 2 || g2.Manifest.Memory.Devices[0].File != "g1/memory.erofs" || g2.Manifest.Memory.Devices[1].File != "g0/memory.erofs" {
		t.Fatal("device order mismatch")
	}
	branchMemory, branchDisk := bytes.Clone(memory), bytes.Clone(disk)
	branch := makeGeneration("branch", baseline, baseMount, branchMemory, branchDisk, 10, false)
	branchMount, err := branch.Mount(ctx, filepath.Join(dir, "mounts"))
	if err != nil {
		t.Fatal(err)
	}
	defer branchMount.Close()
	assertBytes(branchMount.MemoryPath, branchMemory)
	assertBytes(branchMount.DiskPath, branchDisk)
	assertBytes(g2Mount.MemoryPath, memory2)
	assertBytes(g2Mount.DiskPath, disk2)
	// Unexpected QEMU exit must fail capture, but cleanup must still release the
	// kernel device so a dead backend does not pin its pool slot and EROFS mounts.
	crashed, err := NewOverlay(ctx, OverlayOptions{Directory: filepath.Join(dir, "crash"), BackingPath: baseMount.DiskPath, Size: size, DevicePath: device, ParentID: "g0", Tools: store.Options})
	if err != nil {
		t.Fatal(err)
	}
	if err := crashed.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-crashed.Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if crashed.Err() == nil {
		t.Fatal("unexpected QEMU exit not reported")
	}
	if _, err := crashed.Seal(ctx); err == nil {
		t.Fatal("crashed qcow2 was sealed")
	}
	if err := crashed.Close(ctx); err != nil {
		t.Fatalf("crashed QEMU cleanup: %v", err)
	}
	if crashed.Err() == nil {
		t.Fatal("Close erased QEMU crash reported to exit watcher")
	}
	if _, err := os.Stat(crashed.file + ".sealed.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("crashed capture has seal: %v", err)
	}
	// QEMU handles SIGTERM gracefully and exits with status zero. That is
	// still unexpected while the VM owns its disk, even if cleanup runs first.
	terminated, err := NewOverlay(ctx, OverlayOptions{Directory: filepath.Join(dir, "terminated"), BackingPath: baseMount.DiskPath, Size: size, DevicePath: device, ParentID: "g0", Tools: store.Options})
	if err != nil {
		t.Fatal(err)
	}
	if err := terminated.cmd.Process.Signal(unix.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-terminated.Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if terminated.waitErr != nil {
		t.Fatalf("SIGTERM did not exercise a normal QEMU exit: %v", terminated.waitErr)
	}
	if err := terminated.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if terminated.Err() == nil {
		t.Fatal("unexpected normal QEMU exit was erased by cleanup")
	}
	// The manifest cannot silently reorder external block devices.
	m := g2.Manifest
	m.Memory.Devices[0], m.Memory.Devices[1] = m.Memory.Devices[1], m.Memory.Devices[0]
	bad, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(g2.Dir, ManifestName), bad)
	if _, err := store.Load("g2"); err == nil {
		t.Fatal("reordered device binding accepted")
	}
}
