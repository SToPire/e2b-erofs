//go:build linux

package erofs

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func v2Fixture(t *testing.T) (*Store, BuildV2Request) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "store"), Options{MkfsPath: os.Getenv("EROFS_MKFS"), FsckPath: os.Getenv("EROFS_FSCK")})
	require.NoError(t, err)
	for _, tool := range []string{store.Options.MkfsPath, store.Options.FsckPath} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("EROFS_TEST_V2") == "1" {
				require.NoError(t, err, "explicit v2 integration must not skip its tools")
			}
			t.Skipf("real publication requires %s", tool)
		}
	}
	boot := BootLayout{Layout: LayoutRawBuild, KernelVersion: "kernel", FirecrackerVersion: "fc",
		KernelSHA256: strings64('1'), FirecrackerSHA256: strings64('2')}
	r := BuildV2Request{ID: "v2-base", MemoryPath: filepath.Join(dir, "memory"), UpperPath: filepath.Join(dir, "upper"),
		MemorySize: 8 * BlockSize, UpperSize: 8 * BlockSize, VMStatePath: filepath.Join(dir, "vmstate"),
		MetadataPath: filepath.Join(dir, "metadata"), Boot: boot, MemoryCapture: "full"}
	for path, contents := range map[string][]byte{r.MemoryPath: bytes.Repeat([]byte{0x19}, int(r.MemorySize)),
		r.UpperPath: bytes.Repeat([]byte{0x23}, int(r.UpperSize)), r.VMStatePath: []byte("cutoff-000"), r.MetadataPath: []byte(`{}`)} {
		require.NoError(t, os.WriteFile(path, contents, 0600))
	}
	return store, r
}

func strings64(value byte) string { return string(bytes.Repeat([]byte{value}, 64)) }

func TestV2PublicationAndRetry(t *testing.T) {
	store, r := v2Fixture(t)
	first, err := store.BuildV2(t.Context(), r)
	require.NoError(t, err)
	require.Equal(t, FormatV2, first.Manifest.Format)
	require.Equal(t, LayoutRawBuild, first.Manifest.Boot.Layout)
	require.Equal(t, r.UpperSize, first.Manifest.WritableDisk().Size)
	store.Options.MkfsPath, store.Options.FsckPath = "/missing/mkfs", "/missing/fsck"
	retried, err := store.BuildV2(t.Context(), r)
	require.NoError(t, err)
	require.Equal(t, first.Manifest, retried.Manifest)
	require.NoError(t, os.WriteFile(r.VMStatePath, []byte("different cutoff"), 0600))
	_, err = store.BuildV2(t.Context(), r)
	require.ErrorIs(t, err, ErrSnapshotConflict)
}

func TestV2RejectsMixedLayoutAndBadParent(t *testing.T) {
	store, r := v2Fixture(t)
	base, err := store.BuildV2(t.Context(), r)
	require.NoError(t, err)
	r.ID, r.ParentID, r.ParentUpperPath = "v2-child", base.Manifest.ID, r.UpperPath
	r.MemoryCapture = "diff"
	r.Boot.KernelSHA256 = strings64('3')
	_, err = store.BuildV2(t.Context(), r)
	require.ErrorContains(t, err, "layout, binaries")
	r.Boot = *base.Manifest.Boot
	badParent := filepath.Join(filepath.Dir(r.UpperPath), "bad-parent")
	require.NoError(t, os.WriteFile(badParent, make([]byte, r.UpperSize), 0600))
	r.ParentUpperPath = badParent
	_, err = store.BuildV2(t.Context(), r)
	require.ErrorContains(t, err, "parent upper content")
	m := base.Manifest
	m.Disk = Image{Size: 4096}
	data, err := json.Marshal(m)
	require.NoError(t, err)
	manifestPath := filepath.Join(base.Dir, ManifestName)
	require.NoError(t, os.Chmod(manifestPath, 0600))
	require.NoError(t, os.WriteFile(manifestPath, data, 0600))
	_, err = store.Load(base.Manifest.ID)
	require.ErrorContains(t, err, "invalid v2")
}

func makeLowerFixture(t *testing.T, store *Store) *Lower {
	t.Helper()
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 required")
	}
	path := filepath.Join(t.TempDir(), "lower.ext4")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(32<<20))
	require.NoError(t, f.Close())
	output, err := exec.Command("mkfs.ext4", "-q", "-F", "-b", "4096", "-E", "lazy_itable_init=0,lazy_journal_init=0", path).CombinedOutput()
	require.NoError(t, err, "%s", output)
	lower, err := store.PublishLower(t.Context(), path, 32<<20)
	require.NoError(t, err)
	again, err := store.PublishLower(t.Context(), path, 32<<20)
	require.NoError(t, err)
	require.Equal(t, lower, again)
	return lower
}

func TestPmemManifestAndLowerReferences(t *testing.T) {
	store, r := v2Fixture(t)
	lower := makeLowerFixture(t, store)
	initPath := filepath.Join(t.TempDir(), "initrd")
	require.NoError(t, os.WriteFile(initPath, []byte("immutable initramfs test artifact"), 0600))
	initrd, err := store.ImportInitramfs(t.Context(), initPath)
	require.NoError(t, err)
	r.Boot.Layout, r.Boot.Initramfs, r.Lower = LayoutPmem, initrd, lower
	snapshot, err := store.BuildV2(t.Context(), r)
	require.NoError(t, err)
	loaded, err := store.Load(snapshot.Manifest.ID)
	require.NoError(t, err)
	require.True(t, loaded.Manifest.UsesPmem())
	registry := NewSharedMounts(store.Root)
	var mounts, unmounts atomic.Int32
	registry.mountLower = func(_ context.Context, _ *Store, got *Lower, _ string) (*Mounted, error) {
		require.Equal(t, lower.ID, got.ID)
		mounts.Add(1)
		return &Mounted{LowerPath: "/shared/lower"}, nil
	}
	registry.unmount = func(_ *Mounted) error { unmounts.Add(1); return nil }
	a, err := registry.AcquireLower(t.Context(), snapshot.Manifest.Lower, "team")
	require.NoError(t, err)
	b, err := registry.AcquireLower(t.Context(), loaded.Manifest.Lower, "team")
	require.NoError(t, err)
	require.Equal(t, int32(1), mounts.Load())
	require.Equal(t, a.LowerPath(), b.LowerPath())
	require.NoError(t, a.Release())
	require.Zero(t, unmounts.Load())
	require.NoError(t, b.Release())
	require.Equal(t, int32(1), unmounts.Load())
	require.NoError(t, registry.Close(t.Context()))
	bad := *lower
	bad.ContentSHA256 = strings64('5')
	_, err = store.BuildV2(t.Context(), BuildV2Request{ID: "bad", MemoryPath: r.MemoryPath, UpperPath: r.UpperPath,
		MemorySize: r.MemorySize, UpperSize: r.UpperSize, VMStatePath: r.VMStatePath, Boot: r.Boot, Lower: &bad, MemoryCapture: "full"})
	require.ErrorContains(t, err, "lower descriptor")
}

func TestLowerRejectsTruncatedFilesystem(t *testing.T) {
	store, _ := v2Fixture(t)
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 required")
	}
	path := filepath.Join(t.TempDir(), "lower.ext4")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(32<<20))
	require.NoError(t, f.Close())
	output, err := exec.Command("mkfs.ext4", "-q", "-F", "-b", "4096", path).CombinedOutput()
	require.NoError(t, err, "%s", output)
	require.NoError(t, os.Truncate(path, 2<<20))
	_, err = store.PublishLower(t.Context(), path, 2<<20)
	require.ErrorContains(t, err, "backing file capacity")
}
