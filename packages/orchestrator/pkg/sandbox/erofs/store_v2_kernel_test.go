//go:build linux

package erofs

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Run in a private mount namespace with real sparse file-delta EROFS tools.
// This tests storage bytes and dependencies; vmstate is opaque fixture data,
// not a claim that a complete Factory/Guest lifecycle has been exercised.
func TestKernelV2SnapshotChain(t *testing.T) {
	if os.Getenv("EROFS_TEST_V2") != "1" {
		t.Skip("set EROFS_TEST_V2=1 and use file-delta EROFS tools as root")
	}
	require.Zero(t, os.Geteuid())
	_, err := os.Stat("/sys/module/nbd")
	require.True(t, os.IsNotExist(err), "NBD must not be loaded for this test")
	store, r := v2Fixture(t)
	store.Options.QemuImgPath, store.Options.QemuNBDPath = "/not-used/qemu-img", "/not-used/qemu-nbd"
	lower := makeLowerFixture(t, store)
	initFile := filepath.Join(t.TempDir(), "initrd")
	require.NoError(t, os.WriteFile(initFile, []byte("storage test initrd"), 0600))
	initrd, err := store.ImportInitramfs(t.Context(), initFile)
	require.NoError(t, err)
	r.Boot.Layout, r.Boot.Initramfs, r.Lower = LayoutPmem, initrd, lower
	memory, err := os.ReadFile(r.MemoryPath)
	require.NoError(t, err)
	upper, err := os.ReadFile(r.UpperPath)
	require.NoError(t, err)
	registry := NewSharedMounts(store.Root)
	t.Cleanup(func() { require.NoError(t, registry.Close(context.Background())) })
	var previous *Snapshot
	var previousRef *MountRef
	var firstLower os.FileInfo
	for generation := 0; generation < 4; generation++ {
		if previous != nil {
			r.ID, r.ParentID = fmt.Sprintf("v2-%d", generation), previous.Manifest.ID
			r.ParentUpperPath = previousRef.DiskPath()
			r.UpperPath = filepath.Join(filepath.Dir(r.UpperPath), fmt.Sprintf("upper-%d.raw", generation))
			r.MemoryPath = filepath.Join(filepath.Dir(r.MemoryPath), fmt.Sprintf("mem-%d", generation))
			clear(upper[generation*BlockSize : (generation+1)*BlockSize])
			upper[0] = byte(generation)
			require.NoError(t, os.WriteFile(r.UpperPath, upper, 0600))
			clear(memory[generation*BlockSize : (generation+1)*BlockSize])
			if generation == 2 {
				r.MemoryCapture = "full"
				require.NoError(t, os.WriteFile(r.MemoryPath, memory, 0600))
			} else {
				r.MemoryCapture = "diff"
				f, err := os.Create(r.MemoryPath)
				require.NoError(t, err)
				require.NoError(t, f.Truncate(r.MemorySize))
				_, err = f.WriteAt(make([]byte, BlockSize), int64(generation*BlockSize))
				require.NoError(t, err)
				require.NoError(t, f.Sync())
				require.NoError(t, f.Close())
			}
		}
		snapshot, err := store.BuildV2(t.Context(), r)
		require.NoError(t, err)
		retried, err := store.BuildV2(t.Context(), r)
		require.NoError(t, err)
		require.Equal(t, snapshot.Manifest, retried.Manifest)
		ref, err := registry.Acquire(t.Context(), snapshot, "team")
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, ref.Release()) })
		gotMemory, err := os.ReadFile(ref.MemoryPath())
		require.NoError(t, err)
		require.True(t, bytes.Equal(memory, gotMemory), "generation %d RAM", generation)
		gotUpper, err := os.ReadFile(ref.DiskPath())
		require.NoError(t, err)
		require.Equal(t, upper, gotUpper, "generation %d upper", generation)
		lowerRef, err := registry.AcquireLower(t.Context(), snapshot.Manifest.Lower, "team")
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, lowerRef.Release()) })
		info, err := os.Stat(lowerRef.LowerPath())
		require.NoError(t, err)
		if firstLower == nil {
			firstLower = info
		} else {
			require.True(t, os.SameFile(firstLower, info), "lower must share its inode across generations")
		}
		if r.MemoryCapture == "full" {
			require.Empty(t, snapshot.Manifest.Memory.Devices)
		}
		if previous != nil {
			require.NotEmpty(t, snapshot.Manifest.Upper.Devices)
		}
		previous, previousRef = snapshot, ref
	}
}
