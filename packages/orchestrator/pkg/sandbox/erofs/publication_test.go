//go:build linux

package erofs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

func publicationFixture(t *testing.T) (*Store, BuildRequest) {
	t.Helper()
	for _, tool := range []string{"mkfs.erofs", "fsck.erofs"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("real publication test requires %s", tool)
		}
	}
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "store"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := BuildRequest{ID: "baseline", MemoryPath: filepath.Join(dir, "memory"), DiskPath: filepath.Join(dir, "disk"), VMStatePath: filepath.Join(dir, "vmstate"), MetadataPath: filepath.Join(dir, "metadata"), MemorySize: 8 * BlockSize, DiskSize: 8 * BlockSize}
	for _, item := range []struct {
		path string
		data []byte
	}{
		{r.MemoryPath, bytes.Repeat([]byte{0x19}, int(r.MemorySize))},
		{r.DiskPath, bytes.Repeat([]byte{0x23}, int(r.DiskSize))},
		{r.VMStatePath, []byte("cutoff-000")},
		{r.MetadataPath, []byte(`{"generation":0}`)},
	} {
		if err := os.WriteFile(item.path, item.data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return store, r
}

func TestPublicationRetryUsesCommittedCapture(t *testing.T) {
	store, r := publicationFixture(t)
	first, err := store.Build(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(first.Dir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if first.Manifest.Capture == nil {
		t.Fatal("capture identity missing from committed manifest")
	}
	// Publication recovery must work even if external build tools are no
	// longer installed: it validates inputs/artifacts and retries directory fsync.
	store.Options = Options{MkfsPath: "/missing/mkfs", FsckPath: "/missing/fsck", QemuImgPath: "/missing/qemu-img"}
	for range 2 {
		retried, err := store.Build(t.Context(), r)
		if err != nil {
			t.Fatal(err)
		}
		if retried.Dir != first.Dir {
			t.Fatal("retry changed committed directory")
		}
	}
	after, err := os.ReadFile(filepath.Join(first.Dir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("retry rewrote manifest")
	}
	// Removing the optional metadata is a different cutoff, too.
	withoutMetadata := r
	withoutMetadata.MetadataPath = ""
	if _, err := store.Build(t.Context(), withoutMetadata); !errors.Is(err, ErrSnapshotConflict) {
		t.Fatalf("missing metadata accepted: %v", err)
	}
	for name, path := range map[string]string{"RAM": r.MemoryPath, "disk": r.DiskPath, "vmstate": r.VMStatePath, "metadata": r.MetadataPath} {
		t.Run(name, func(t *testing.T) {
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := bytes.Clone(original)
			changed[0] ^= 0x5a
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			defer os.WriteFile(path, original, 0600)
			if _, err := store.Build(t.Context(), r); !errors.Is(err, ErrSnapshotConflict) {
				t.Fatalf("different %s capture accepted: %v", name, err)
			}
		})
	}
	if _, err := store.Build(t.Context(), r); err != nil {
		t.Fatal(err)
	}
}

func TestPublicationRetryValidatesCommittedArtifacts(t *testing.T) {
	store, r := publicationFixture(t)
	snapshot, err := store.Build(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(snapshot.Dir, "vmstate")
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corruption"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Build(t.Context(), r); err == nil {
		t.Fatal("corrupt output accepted as successful retry")
	}
}

func TestPublicationWithoutInputBindingCannotClaimRetry(t *testing.T) {
	store, r := publicationFixture(t)
	snapshot, err := store.Build(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	m := snapshot.Manifest
	m.Capture = nil
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(snapshot.Dir, ManifestName)
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(r.ID); err != nil {
		t.Fatalf("older manifest can still restore: %v", err)
	}
	if _, err := store.Build(t.Context(), r); !errors.Is(err, ErrSnapshotConflict) {
		t.Fatalf("unbound snapshot accepted as a retry: %v", err)
	}
}

func TestConcurrentPublicationOfSameCapture(t *testing.T) {
	store, r := publicationFixture(t)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() { _, err := store.Build(t.Context(), r); errs <- err })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Load(r.ID); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentPublicationRejectsDifferentCapture(t *testing.T) {
	store, r := publicationFixture(t)
	other := r
	other.VMStatePath = filepath.Join(filepath.Dir(r.VMStatePath), "different-vmstate")
	if err := os.WriteFile(other.VMStatePath, []byte("different cutoff"), 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, request := range []BuildRequest{r, other} {
		wg.Go(func() { _, err := store.Build(t.Context(), request); errs <- err })
	}
	wg.Wait()
	close(errs)
	successes, conflicts := 0, 0
	for err := range errs {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrSnapshotConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestPublicationRefusesCaptureChangedWhileBuilding(t *testing.T) {
	store, r := publicationFixture(t)
	mkfs, err := exec.LookPath(store.Options.MkfsPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("EROFS_TEST_REAL_MKFS", mkfs)
	t.Setenv("EROFS_TEST_CAPTURE_MUTATE", r.MetadataPath)
	wrapper := filepath.Join(filepath.Dir(r.MetadataPath), "mkfs-wrapper")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nprintf changed > \"$EROFS_TEST_CAPTURE_MUTATE\"\nexec \"$EROFS_TEST_REAL_MKFS\" \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	store.Options.MkfsPath = wrapper
	if _, err := store.Build(t.Context(), r); err == nil {
		t.Fatal("published artifacts from a changing capture")
	}
	if _, err := store.Load(r.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("changed capture published: %v", err)
	}
	if _, err := os.Stat(r.MemoryPath); err != nil {
		t.Fatal("failed build removed retained RAM")
	}
}

func TestSparseCaptureIdentityIncludesZeroDataAllocation(t *testing.T) {
	store, r := publicationFixture(t)
	parent, err := store.Build(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	r.ID, r.ParentID = "next", parent.Manifest.ID
	if err := os.Truncate(r.MemoryPath, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(r.MemoryPath, r.MemorySize); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.DiskPath+".sealed.json", []byte("test seal identity"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := captureRequest(t.Context(), r, parent)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(r.MemoryPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(make([]byte, BlockSize), BlockSize); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		t.Fatal(err)
	}
	after, err := captureRequest(t.Context(), r, parent)
	if err != nil {
		t.Fatal(err)
	}
	var a, b captureIdentity
	if err := json.Unmarshal(before, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(after, &b); err != nil {
		t.Fatal(err)
	}
	if a.Memory.SHA256 != b.Memory.SHA256 {
		t.Fatal("test did not preserve logical zero bytes")
	}
	if a.Memory.SparseLayoutSHA256 == b.Memory.SparseLayoutSHA256 {
		t.Fatal("HOLE and zero DATA have the same capture identity")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := captureRequest(ctx, r, parent); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled fingerprint: %v", err)
	}
}
