//go:build linux

package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/metadata"
)

// These fixtures exercise index publication against the same authenticated
// manifest loader used by restores. EROFS image construction is tested by the
// store's integration tests, independently of recipe indexing.
func indexSnapshot(t *testing.T, root, id string) {
	t.Helper()
	dir := filepath.Join(root, id)
	require.NoError(t, os.Mkdir(dir, 0o700))
	artifact := func(name string, data []byte) erofs.Artifact {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o600))
		digest := sha256.Sum256(data)
		return erofs.Artifact{File: filepath.Join(id, name), SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(data))}
	}
	meta, err := json.Marshal(metadata.Template{Version: metadata.CurrentVersion, Template: metadata.TemplateMetadata{BuildID: id}})
	require.NoError(t, err)
	metaArtifact := artifact("metadata.json", meta)
	manifest := erofs.Manifest{
		Format: erofs.Format, ID: id,
		Memory:  erofs.Image{Artifact: artifact("memory.erofs", []byte("memory-image")), Size: 4096},
		Disk:    erofs.Image{Artifact: artifact("disk.erofs", []byte("disk-image")), Size: 4096},
		VMState: artifact("vmstate", []byte("vm-state")), Metadata: &metaArtifact,
	}
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, erofs.ManifestName), data, 0o600))
}

func TestEROFSIndexPublicationAndScope(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	index, err := NewEROFSIndex(root, "team/../scope")
	require.NoError(t, err)
	const id = "valid-build"
	layer := LayerMetadata{Template: Template{BuildID: id}}
	require.Error(t, index.SaveLayerMeta(t.Context(), "recipe", layer))
	_, err = index.LayerMetaFromHash(t.Context(), "recipe")
	require.Error(t, err)

	indexSnapshot(t, root, id)
	require.NoError(t, index.SaveLayerMeta(t.Context(), "recipe", layer))
	// Cache survives a process restart without any remote object store.
	reopened, err := NewEROFSIndex(root, "team/../scope")
	require.NoError(t, err)
	got, err := reopened.LayerMetaFromHash(t.Context(), "recipe")
	require.NoError(t, err)
	require.Equal(t, layer, got)
	otherScope, err := NewEROFSIndex(root, "other-team")
	require.NoError(t, err)
	_, err = otherScope.LayerMetaFromHash(t.Context(), "recipe")
	require.Error(t, err)

	// A stale recipe must not conceal loss or corruption of its artifacts.
	require.NoError(t, os.WriteFile(filepath.Join(root, id, "disk.erofs"), []byte("corrupt"), 0o600))
	_, err = reopened.LayerMetaFromHash(t.Context(), "recipe")
	require.Error(t, err)
}
