//go:build linux

package erofs

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRawDeltaZeroOverridesAndUnchangedInherits(t *testing.T) {
	dir := t.TempDir()
	const size = 6 * BlockSize
	parent := bytes.Repeat([]byte{0x71}, size)
	current := append([]byte(nil), parent...)
	clear(current[BlockSize : 2*BlockSize])
	current[4*BlockSize+123] = 0x29
	parentPath, currentPath, delta := filepath.Join(dir, "parent"), filepath.Join(dir, "current"), filepath.Join(dir, "delta")
	if err := os.WriteFile(parentPath, parent, 0o600); err != nil {
		t.Fatal(err)
	}
	// Materialize writes nonzero blocks only: the zero replacement is a genuine
	// raw hole, which the delta must turn into explicit DATA.
	if err := os.WriteFile(filepath.Join(dir, "source"), current, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MaterializeRawFile(t.Context(), filepath.Join(dir, "source"), currentPath, size); err != nil {
		t.Fatal(err)
	}
	stats, err := CreateRawDelta(t.Context(), parentPath, currentPath, delta, size)
	if err != nil {
		t.Fatal(err)
	}
	if stats.ReadBytes != 2*size || stats.WrittenBytes != 2*BlockSize {
		t.Fatalf("unexpected delta work: %+v", stats)
	}
	extents, err := SparseExtents(delta, size)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(extents, []Extent{{BlockSize, BlockSize}, {4 * BlockSize, BlockSize}}) {
		t.Fatalf("wrong override extents: %+v", extents)
	}
	data, err := os.ReadFile(delta)
	if err != nil {
		t.Fatal(err)
	}
	restored := append([]byte(nil), parent...)
	for _, extent := range extents {
		copy(restored[extent.Offset:extent.Offset+extent.Length], data[extent.Offset:extent.Offset+extent.Length])
	}
	if !bytes.Equal(restored, current) {
		t.Fatal("applying delta did not reproduce the current disk")
	}
}

// Run in a private user/mount namespace: unshare -Urnm env E2B_RAW_ENOSPC=1
// <test-binary> -test.run '^TestRawENOSPCCleansPartialOutput$' -test.v.
func TestRawENOSPCCleansPartialOutput(t *testing.T) { //nolint:paralleltest // private mount namespace
	if os.Getenv("E2B_RAW_ENOSPC") != "1" {
		t.Skip("requires an isolated mount namespace and E2B_RAW_ENOSPC=1")
	}
	dir := t.TempDir()
	limited := filepath.Join(dir, "limited")
	if err := os.Mkdir(limited, 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", limited, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC, "size=1m"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(limited, 0); err != nil {
			t.Error(err)
		}
	})
	const size = 4 << 20
	parent := filepath.Join(dir, "parent.raw")
	current := filepath.Join(dir, "current.raw")
	inputs := map[string][]byte{parent: bytes.Repeat([]byte{0x35}, size), current: bytes.Repeat([]byte{0x76}, size)}
	for path, data := range inputs {
		if err := os.WriteFile(path, data, 0400); err != nil {
			t.Fatal(err)
		}
	}
	for _, delta := range []bool{false, true} {
		name := "materialize"
		if delta {
			name = "delta"
		}
		t.Run(name, func(t *testing.T) {
			output := filepath.Join(limited, name+".raw")
			var stats RawCopyStats
			var err error
			if delta {
				stats, err = CreateRawDelta(t.Context(), parent, current, output, size)
			} else {
				stats, err = MaterializeRawFile(t.Context(), current, output, size)
			}
			if !errors.Is(err, unix.ENOSPC) || stats.WrittenBytes == 0 || stats.WrittenBytes >= size {
				t.Fatalf("expected ENOSPC after partial output, got stats=%+v err=%v", stats, err)
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial output was retained: %v", err)
			}
			for path, expected := range inputs {
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatalf("ENOSPC changed a retained source: %s, %v", path, err)
				}
			}
		})
	}
}

func TestRawCopyAndDeltaAcrossBatchBoundary(t *testing.T) {
	dir := t.TempDir()
	const size = 1024*1024 + 3*BlockSize
	data := make([]byte, size)
	for i := 1024*1024 - BlockSize; i < len(data); i++ {
		data[i] = byte(i%255 + 1)
	}
	source, copyPath, delta := filepath.Join(dir, "source"), filepath.Join(dir, "copy"), filepath.Join(dir, "delta")
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}
	stats, err := MaterializeRawFile(t.Context(), source, copyPath, size)
	if err != nil {
		t.Fatal(err)
	}
	if stats.WrittenBytes != 4*BlockSize {
		t.Fatalf("full copy did not preserve sparse allocation: %+v", stats)
	}
	got, err := os.ReadFile(copyPath)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("copy differs: %v", err)
	}
	a, _ := os.Stat(source)
	b, _ := os.Stat(copyPath)
	if os.SameFile(a, b) {
		t.Fatal("writable copy reused the source inode")
	}
	stats, err = CreateRawDelta(t.Context(), source, copyPath, delta, size)
	if err != nil || stats.WrittenBytes != 0 {
		t.Fatalf("identical disk must produce an empty delta: %+v %v", stats, err)
	}
	extents, err := SparseExtents(delta, size)
	if err != nil || len(extents) != 0 {
		t.Fatalf("empty delta must inherit every block: %+v %v", extents, err)
	}
}

func TestRawOutputOwnershipAndCancellation(t *testing.T) {
	dir := t.TempDir()
	source, destination := filepath.Join(dir, "source"), filepath.Join(dir, "destination")
	data := bytes.Repeat([]byte{0x39}, BlockSize)
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MaterializeRawFile(t.Context(), source, destination, BlockSize); !errors.Is(err, os.ErrExist) {
		t.Fatalf("must not overwrite an existing output: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil || string(got) != "existing" {
		t.Fatal("failed operation changed an existing output")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	cancelled := filepath.Join(dir, "cancelled")
	if _, err := CreateRawDelta(ctx, source, source, cancelled, BlockSize); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled operation: %v", err)
	}
	if _, err := os.Lstat(cancelled); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled operation left an output")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if _, err := MaterializeRawFile(t.Context(), link, cancelled, BlockSize); err == nil {
		t.Fatal("accepted a symlink as sealed input")
	}
	if _, err := MaterializeRawFile(t.Context(), source, cancelled, 2*BlockSize); err == nil {
		t.Fatal("accepted an input with the wrong size")
	}
}

func TestRawRejectsFIFOWithoutWaitingForWriter(t *testing.T) {
	dir := t.TempDir()
	fifo, output := filepath.Join(dir, "fifo"), filepath.Join(dir, "output")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := MaterializeRawFile(t.Context(), fifo, output, BlockSize)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted a FIFO input")
		}
	case <-time.After(2 * time.Second):
		// Release a regressed blocking open so the test does not leave a
		// goroutine waiting forever after reporting the failure.
		fd, err := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if err == nil {
			unix.Close(fd)
		}
		t.Fatal("raw input validation blocked waiting for a FIFO writer")
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid input left a destination file")
	}
}
