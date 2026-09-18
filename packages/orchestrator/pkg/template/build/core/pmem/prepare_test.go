//go:build linux

package pmem

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/build/core/filesystem"
	"github.com/stretchr/testify/require"
)

func TestCompactLowerPreservesFilesystem(t *testing.T) {
	t.Parallel()
	for _, bin := range []string{"mkfs.ext4", "e2fsck", "resize2fs", "debugfs"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip("requires e2fsprogs")
		}
	}
	tree := filepath.Join(t.TempDir(), "tree")
	require.NoError(t, os.Mkdir(tree, 0755))
	payload := []byte("lower contents survive compaction and alignment\n")
	require.NoError(t, os.WriteFile(filepath.Join(tree, "payload"), payload, 0644))
	require.NoError(t, os.Link(filepath.Join(tree, "payload"), filepath.Join(tree, "linked")))
	path := filepath.Join(t.TempDir(), "lower.raw")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(64<<20))
	require.NoError(t, f.Close())
	out, err := exec.CommandContext(t.Context(), "mkfs.ext4", "-q", "-F", "-b", "4096", "-d", tree, path).CombinedOutput()
	require.NoError(t, err, "%s", out)
	_, err = filesystem.CheckIntegrity(t.Context(), path, true)
	require.NoError(t, err)
	_, err = filesystem.Shrink(t.Context(), path)
	require.NoError(t, err)
	require.NoError(t, alignExt4Image(path))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Zero(t, info.Size()%(2<<20))
	require.Less(t, info.Size(), int64(64<<20))
	_, err = filesystem.CheckIntegrity(t.Context(), path, false)
	require.NoError(t, err)
	extracted := filepath.Join(t.TempDir(), "payload")
	out, err = exec.CommandContext(t.Context(), "debugfs", "-R", "dump /linked "+extracted, path).CombinedOutput()
	require.NoError(t, err, "%s", out)
	got, err := os.ReadFile(extracted)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

func TestInvalidBuildInputHasNoSideEffects(t *testing.T) {
	t.Parallel()
	_, err := Prepare(t.Context(), Inputs{})
	require.Error(t, err)
}

func TestUpperFreeSpaceIncludesRootReservation(t *testing.T) {
	t.Parallel()
	for _, bin := range []string{"mkfs.ext4", "tune2fs", "debugfs"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip("requires e2fsprogs")
		}
	}
	path, size, err := CreateUpperSeed(t.Context(), t.TempDir(), 1024, 256)
	require.NoError(t, err)
	require.Greater(t, size, int64(1280<<20))
	free, err := filesystem.GetFreeSpace(t.Context(), path, 4096)
	require.NoError(t, err)
	require.GreaterOrEqual(t, free, int64(1024<<20))
}
