//go:build linux

package erofs

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestV2RecoveryRequiresStoppedWriterAndPreservesCutoff(t *testing.T) {
	store, r := v2Fixture(t)
	r.ID = "recover-v2"
	capture, err := store.Begin(r.ID)
	require.NoError(t, err)
	raw := r.UpperPath
	for source, target := range map[string]string{r.MemoryPath: capture.MemoryPath, r.VMStatePath: capture.VMStatePath, r.MetadataPath: filepath.Join(capture.Dir, "metadata.json")} {
		require.NoError(t, copyFile(source, target))
	}
	r.MemoryPath, r.VMStatePath, r.MetadataPath = capture.MemoryPath, capture.VMStatePath, filepath.Join(capture.Dir, "metadata.json")
	target := filepath.Join(capture.Dir, "upper.sealed.raw")
	r.UpperPath = target
	writer := exec.Command("sleep", "60")
	require.NoError(t, writer.Start())
	t.Cleanup(func() { _ = writer.Process.Kill(); _ = writer.Wait() })
	identity, err := IdentifyProcess(writer.Process.Pid)
	require.NoError(t, err)
	record := filepath.Join(capture.Dir, "recovery.json")
	require.NoError(t, store.RecordV2Recovery(t.Context(), record, r, raw, target, identity))
	_, err = store.Recover(t.Context(), record)
	require.ErrorContains(t, err, "still alive")
	require.NoError(t, writer.Process.Kill())
	_ = writer.Wait()
	before, err := os.ReadFile(raw)
	require.NoError(t, err)
	changed := append([]byte(nil), before...)
	changed[0] ^= 1
	require.NoError(t, os.WriteFile(raw, changed, 0600))
	_, err = store.Recover(t.Context(), record)
	require.ErrorContains(t, err, "bytes changed")
	require.NoError(t, os.WriteFile(raw, before, 0600))
	snapshot, err := store.Recover(t.Context(), record)
	require.NoError(t, err)
	require.Equal(t, FormatV2, snapshot.Manifest.Format)
	actual, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, before, actual)
	require.NoError(t, os.Remove(raw))
	store.Options.MkfsPath, store.Options.FsckPath = "/missing/mkfs", "/missing/fsck"
	again, err := store.Recover(t.Context(), record)
	require.NoError(t, err)
	require.Equal(t, snapshot.Manifest, again.Manifest)
	memory, err := os.ReadFile(r.MemoryPath)
	require.NoError(t, err)
	memory[0] ^= 1
	require.NoError(t, os.WriteFile(r.MemoryPath, memory, 0600))
	_, err = store.Recover(t.Context(), record)
	require.ErrorContains(t, err, "RAM or vmstate changed")
}
