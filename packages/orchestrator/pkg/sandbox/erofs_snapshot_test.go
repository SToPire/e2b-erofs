//go:build linux

package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNativeRawCaptureKeepsSourceAndRemovesIncompleteCopy(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, "runtime.raw"), filepath.Join(dir, "capture.raw")
	data := bytes.Repeat([]byte{0x61}, 4096)
	require.NoError(t, os.WriteFile(source, data, 0600))
	// A short device read cannot leave a partial file that a later retry
	// mistakes for a complete baseline or that consumes staging space.
	require.Error(t, captureRawDisk(source, target, 8192))
	_, err := os.Stat(target)
	require.ErrorIs(t, err, os.ErrNotExist)
	got, err := os.ReadFile(source)
	require.NoError(t, err)
	require.Equal(t, data, got)

	data = append(data, make([]byte, 4096)...)
	require.NoError(t, os.WriteFile(source, data, 0600))
	require.NoError(t, captureRawDisk(source, target, int64(len(data))))
	got, err = os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, data, got, "an explicit zero sector remains in the full baseline")
}

func TestNativeRawCaptureNeverReplacesExistingArtifact(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, "runtime.raw"), filepath.Join(dir, "capture.raw")
	require.NoError(t, os.WriteFile(source, bytes.Repeat([]byte{0x11}, 4096), 0600))
	prior := bytes.Repeat([]byte{0x22}, 4096)
	require.NoError(t, os.WriteFile(target, prior, 0600))
	require.ErrorIs(t, captureRawDisk(source, target, 4096), os.ErrExist)
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, prior, got)
}

func TestNativeBuildRequestCreatesThenReplacesCompleteDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "build-request.json")
	for _, data := range [][]byte{[]byte(`{"ID":"first"}`), []byte(`{"ID":"retry"}`)} {
		require.NoError(t, writeNativeBuildRequest(path, data))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, data, got)
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1)
}
