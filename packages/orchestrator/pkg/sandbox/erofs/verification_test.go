//go:build linux

package erofs

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestVerifyCommittedRetriesDirectoryDurability(t *testing.T) {
	store, request := publicationFixture(t)
	committed, err := store.Build(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(committed.Dir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	// Verification requires only the committed chain, not capture files or
	// mkfs/QEMU. A status RPC must never restart publication as a side effect.
	for _, path := range []string{request.MemoryPath, request.DiskPath, request.VMStatePath, request.MetadataPath} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	store.Options = Options{MkfsPath: "/missing/mkfs", FsckPath: "/missing/fsck", QemuImgPath: "/missing/qemu"}
	var synced []string
	failRoot := true
	syncDir := func(path string) error {
		synced = append(synced, path)
		if path == store.Root && failRoot {
			failRoot = false
			return unix.EIO
		}
		return syncPath(path)
	}
	snapshot, err := store.verifyCommitted(t.Context(), request.ID, syncDir)
	if snapshot == nil || snapshot.Dir != committed.Dir || !errors.Is(err, unix.EIO) {
		t.Fatalf("valid snapshot must survive durability error: snapshot=%v err=%v", snapshot, err)
	}
	if len(synced) != 2 || synced[0] != committed.Dir || synced[1] != store.Root {
		t.Fatalf("directory sync order: %v", synced)
	}
	snapshot, err = store.verifyCommitted(t.Context(), request.ID, syncDir)
	if snapshot == nil || err != nil {
		t.Fatalf("retry directory fsync: %v", err)
	}
	if _, err := store.VerifyCommitted(t.Context(), request.ID); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(committed.Dir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifest, after) {
		t.Fatal("verification rewrote the manifest")
	}
}

func TestVerifyCommittedMissingOrCorruptReturnsNoSnapshot(t *testing.T) {
	store, request := publicationFixture(t)
	if snapshot, err := store.VerifyCommitted(t.Context(), request.ID); snapshot != nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing snapshot: %v %v", snapshot, err)
	}
	committed, err := store.Build(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(committed.Dir, "vmstate")
	if err := os.Chmod(state, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte("corrupted-state"), 0600); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := store.VerifyCommitted(t.Context(), request.ID); snapshot != nil || err == nil {
		t.Fatalf("corrupt snapshot: %v %v", snapshot, err)
	}
}

func TestVerifyCommittedValidatesParentArtifacts(t *testing.T) {
	mkfs := os.Getenv("EROFS_MKFS")
	if mkfs == "" {
		t.Skip("set EROFS_MKFS to mkfs.erofs with file-delta support")
	}
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img required")
	}
	store, r := publicationFixture(t)
	store.Options.MkfsPath = mkfs
	if fsck := os.Getenv("EROFS_FSCK"); fsck != "" {
		store.Options.FsckPath = fsck
	}
	parent, err := store.Build(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	parentDisk := r.DiskPath
	capture, err := store.Begin("child")
	if err != nil {
		t.Fatal(err)
	}
	r.ID, r.ParentID = "child", parent.Manifest.ID
	r.MemoryPath, r.DiskPath = capture.MemoryPath, capture.DiskPath
	f, err := os.Create(r.MemoryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(r.MemorySize); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bytes.Repeat([]byte{0x71}, BlockSize), BlockSize); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		t.Fatal(err)
	}
	if err := command(t.Context(), "qemu-img", "create", "-q", "-f", "qcow2", "-F", "raw", "-b", parentDisk, "-o", "compat=1.1,cluster_size=4096,lazy_refcounts=off", r.DiskPath, strconv.FormatInt(r.DiskSize, 10)); err != nil {
		t.Fatal(err)
	}
	if err := writeDiskSeal(r.DiskPath, r.ParentID, parentDisk, r.DiskSize); err != nil {
		t.Fatal(err)
	}
	child, err := store.Build(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if verified, err := store.VerifyCommitted(t.Context(), child.Manifest.ID); verified == nil || err != nil {
		t.Fatalf("valid child failed verification: %v", err)
	}
	ancestorImage := filepath.Join(parent.Dir, "memory.erofs")
	if err := os.Chmod(ancestorImage, 0600); err != nil {
		t.Fatal(err)
	}
	f, err = os.OpenFile(ancestorImage, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{0x1c}, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if verified, err := store.VerifyCommitted(t.Context(), child.Manifest.ID); verified != nil || err == nil {
		t.Fatalf("corrupt parent accepted: %v", err)
	}
}

func TestVerifyCommittedRespectsContextAcrossDurability(t *testing.T) {
	store, r := publicationFixture(t)
	if _, err := store.Build(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if snapshot, err := store.VerifyCommitted(ctx, r.ID); snapshot != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled: %v %v", snapshot, err)
	}
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	snapshot, err := store.verifyCommitted(ctx, r.ID, func(path string) error { calls++; err := syncPath(path); cancel(); return err })
	if snapshot == nil || !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("cancel after validation: snapshot=%v err=%v syncs=%d", snapshot, err, calls)
	}
}

type cancelWhileReadingContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *cancelWhileReadingContext) Err() error {
	c.remaining--
	if c.remaining == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestCommittedArtifactHashingCanBeCanceled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large-artifact")
	if err := os.WriteFile(path, make([]byte, 8*1024*1024), 0600); err != nil {
		t.Fatal(err)
	}
	base, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &cancelWhileReadingContext{Context: base, cancel: cancel, remaining: 4}
	if _, err := describeContext(ctx, path, "artifact"); !errors.Is(err, context.Canceled) {
		t.Fatalf("hash ignored cancellation: %v", err)
	}
}
