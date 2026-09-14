//go:build linux

package erofs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func recordedProducer(t *testing.T) (ProcessIdentity, func()) {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }) }
	t.Cleanup(stop)
	identity, err := IdentifyProcess(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	return identity, stop
}

func TestRecoveryProducerIdentity(t *testing.T) {
	producer, stop := recordedProducer(t)
	if err := processTerminated(producer); err == nil {
		t.Fatal("live original producer accepted")
	}
	reused := producer
	reused.StartTime++
	if err := processTerminated(reused); err != nil {
		t.Fatalf("different start time should identify a different process: %v", err)
	}
	if err := processTerminated(ProcessIdentity{}); err == nil {
		t.Fatal("missing producer identity accepted")
	}
	stop()
	if err := processTerminated(producer); err != nil {
		t.Fatal(err)
	}
}

func TestKernelCaptureRecovery(t *testing.T) {
	device := os.Getenv("EROFS_TEST_DEVICE")
	if device == "" {
		t.Skip("set EROFS_TEST_DEVICE to an exclusively reserved NBD device and run as root")
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel recovery test requires root")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	store, base := publicationFixture(t)
	if mkfs := os.Getenv("EROFS_MKFS"); mkfs != "" {
		store.Options.MkfsPath = mkfs
	}
	if fsck := os.Getenv("EROFS_FSCK"); fsck != "" {
		store.Options.FsckPath = fsck
	}
	parent, err := store.Build(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	for _, full := range []bool{false, true} {
		name := "delta"
		if full {
			name = "full-from-erofs"
		}
		t.Run(name, func(t *testing.T) {
			capture, err := store.Begin(name)
			if err != nil {
				t.Fatal(err)
			}
			mounted, err := parent.Mount(ctx, filepath.Join(store.Root, "mounts"))
			if err != nil {
				t.Fatal(err)
			}
			defer mounted.Close()
			r := BuildRequest{ID: name, ParentID: parent.Manifest.ID, MemoryPath: capture.MemoryPath, DiskPath: capture.DiskPath, VMStatePath: capture.VMStatePath, MetadataPath: base.MetadataPath, MemorySize: base.MemorySize, DiskSize: base.DiskSize}
			if full {
				r.ParentID = ""
			}
			mem, err := os.OpenFile(r.MemoryPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if full {
				data, err := os.ReadFile(base.MemoryPath)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := mem.Write(data); err != nil {
					t.Fatal(err)
				}
			} else if err := mem.Truncate(r.MemorySize); err != nil {
				t.Fatal(err)
			}
			if _, err := mem.WriteAt(bytes.Repeat([]byte{0x88}, BlockSize), 2*BlockSize); err != nil {
				t.Fatal(err)
			}
			if err := errors.Join(mem.Sync(), mem.Close()); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(r.VMStatePath, []byte("captured native vmstate"), 0600); err != nil {
				t.Fatal(err)
			}
			overlay, err := NewOverlay(ctx, OverlayOptions{Directory: filepath.Join(capture.Dir, "runtime"), BackingPath: mounted.DiskPath, ParentID: parent.Manifest.ID, Size: r.DiskSize, DevicePath: device, Tools: store.Options})
			if err != nil {
				t.Fatal(err)
			}
			defer overlay.Close(ctx)
			disk, err := os.OpenFile(overlay.Path(), os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := disk.WriteAt(bytes.Repeat([]byte{0xa7}, 512), 3*BlockSize+512); err != nil {
				t.Fatal(err)
			}
			if err := errors.Join(disk.Sync(), disk.Close()); err != nil {
				t.Fatal(err)
			}
			producer, stopFC := recordedProducer(t)
			info, err := overlay.RecoveryInfo()
			if err != nil {
				t.Fatal(err)
			}
			recordPath := filepath.Join(capture.Dir, "recovery.json")
			if err := store.RecordRecovery(ctx, filepath.Join(capture.Dir, "missing", "recovery.json"), r, info, producer); err == nil {
				t.Fatal("record write fault ignored")
			}
			if _, err := os.Stat(r.MemoryPath); err != nil {
				t.Fatal("record failure discarded captured RAM")
			}
			if err := store.RecordRecovery(ctx, recordPath, r, info, producer); err != nil {
				t.Fatal(err)
			}
			if err := store.RecordRecovery(ctx, recordPath, r, info, producer); err != nil {
				t.Fatalf("same recovery record retry: %v", err)
			}
			if _, err := store.Recover(ctx, recordPath); err == nil || !strings.Contains(err.Error(), "Firecracker") {
				t.Fatalf("live FC accepted: %v", err)
			}
			stopFC()
			if _, err := store.Recover(ctx, recordPath); err == nil || !strings.Contains(err.Error(), "QEMU") {
				t.Fatalf("live QEMU accepted: %v", err)
			}
			// Stop the backend normally without producing any seal record. This
			// models teardown after capture succeeded but sealing/persistence failed.
			if err := overlay.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(info.Path + ".sealed.json"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("test already had a seal: %v", err)
			}
			if err := mounted.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(info.BackingPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("old runtime backing remains mounted: %v", err)
			}
			// Replacing an inode with identical container bytes cannot substitute
			// a different producer's disk in this captured cutoff.
			original := info.Path + ".original"
			if err := os.Rename(info.Path, original); err != nil {
				t.Fatal(err)
			}
			if err := copyFile(original, info.Path); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Recover(ctx, recordPath); err == nil || !strings.Contains(err.Error(), "inode") {
				t.Fatalf("substituted qcow inode accepted: %v", err)
			}
			if err := os.Remove(info.Path); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(original, info.Path); err != nil {
				t.Fatal(err)
			}
			if !full {
				changed, err := os.OpenFile(r.MemoryPath, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := changed.WriteAt(make([]byte, BlockSize), 0); err != nil {
					t.Fatal(err)
				}
				changed.Sync()
				if _, err := store.Recover(ctx, recordPath); err == nil || !strings.Contains(err.Error(), "RAM") {
					t.Fatalf("changed native sparse layout accepted: %v", err)
				}
				if err := unix.Fallocate(int(changed.Fd()), unix.FALLOC_FL_KEEP_SIZE|unix.FALLOC_FL_PUNCH_HOLE, 0, BlockSize); err != nil {
					t.Fatal(err)
				}
				if err := errors.Join(changed.Sync(), changed.Close()); err != nil {
					t.Fatal(err)
				}
			}
			// Refuse a dirty QCOW header even though the original process is dead.
			qcow, err := os.OpenFile(info.Path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			var dirty [8]byte
			binary.BigEndian.PutUint64(dirty[:], 1)
			if _, err := qcow.WriteAt(dirty[:], 72); err != nil {
				t.Fatal(err)
			}
			qcow.Sync()
			if _, err := store.Recover(ctx, recordPath); err == nil || !strings.Contains(err.Error(), "clean closed image") {
				t.Fatalf("dirty qcow accepted: %v", err)
			}
			clear(dirty[:])
			if _, err := qcow.WriteAt(dirty[:], 72); err != nil {
				t.Fatal(err)
			}
			if err := errors.Join(qcow.Sync(), qcow.Close()); err != nil {
				t.Fatal(err)
			}
			// Failed seal record publication leaves the durable RAM cutoff and
			// QCOW available; the same recovery record can finish after the fault.
			if err := os.Mkdir(info.Path+".sealed.json", 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Recover(ctx, recordPath); err == nil {
				t.Fatal("seal publication fault ignored")
			}
			if err := os.Remove(info.Path + ".sealed.json"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(recordPath+".build-request.json", 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Recover(ctx, recordPath); err == nil {
				t.Fatal("build request publication fault ignored")
			}
			if err := os.Remove(recordPath + ".build-request.json"); err != nil {
				t.Fatal(err)
			}
			fsck := store.Options.FsckPath
			store.Options.FsckPath = "false"
			_, err = store.Recover(ctx, recordPath)
			store.Options.FsckPath = fsck
			if err == nil {
				t.Fatal("failed EROFS validation published recovery")
			}
			if _, err := store.Load(r.ID); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial recovery was visible: %v", err)
			}
			recovered, err := store.Recover(ctx, recordPath)
			if err != nil {
				t.Fatal(err)
			}
			again, err := store.Recover(ctx, recordPath)
			if err != nil || again.Dir != recovered.Dir {
				t.Fatalf("repeat recovery: %v", err)
			}
			view, err := recovered.Mount(ctx, filepath.Join(store.Root, "verify"))
			if err != nil {
				t.Fatal(err)
			}
			defer view.Close()
			actual, err := os.ReadFile(view.MemoryPath)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := os.ReadFile(base.MemoryPath)
			if err != nil {
				t.Fatal(err)
			}
			copy(expected[2*BlockSize:], bytes.Repeat([]byte{0x88}, BlockSize))
			if !bytes.Equal(actual, expected) {
				t.Fatal("recovery changed captured RAM")
			}
			actual, err = os.ReadFile(view.DiskPath)
			if err != nil {
				t.Fatal(err)
			}
			expected, err = os.ReadFile(base.DiskPath)
			if err != nil {
				t.Fatal(err)
			}
			copy(expected[3*BlockSize+512:], bytes.Repeat([]byte{0xa7}, 512))
			if !bytes.Equal(actual, expected) {
				t.Fatal("recovery changed captured disk")
			}
			// The RAM fingerprint persists across process exit and rejects later
			// input changes instead of rebuilding the same ID from another cutoff.
			if err := os.WriteFile(r.VMStatePath, []byte("different state"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Recover(ctx, recordPath); err == nil {
				t.Fatal("modified captured state accepted")
			}
		})
	}
}
