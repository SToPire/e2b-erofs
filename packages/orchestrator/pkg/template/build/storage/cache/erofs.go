//go:build linux

package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/metadata"
)

// EROFSIndex publishes recipes only on the node holding their complete snapshot
// chain. A shared object-store index would advertise artifacts other nodes
// cannot restore. Cache entries are hints; committed manifests are authoritative.
type EROFSIndex struct {
	store *erofs.Store
	dir   string
}

func NewEROFSIndex(root, scope string) (*EROFSIndex, error) {
	store, err := erofs.NewStore(root, erofs.Options{})
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(store.Root, ".build-cache", HashKeys(scope))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	return &EROFSIndex{store: store, dir: dir}, nil
}

func (*EROFSIndex) Version() string { return hashingVersion + ":" + erofs.Format }

func (h *EROFSIndex) LayerMetaFromHash(ctx context.Context, hash string) (LayerMetadata, error) {
	if err := ctx.Err(); err != nil {
		return LayerMetadata{}, err
	}
	data, err := os.ReadFile(filepath.Join(h.dir, HashKeys(hash)))
	if err != nil {
		return LayerMetadata{}, err
	}
	var layer LayerMetadata
	if err := json.Unmarshal(data, &layer); err != nil {
		return LayerMetadata{}, err
	}
	if _, err := h.Cached(ctx, layer.Template.BuildID); err != nil {
		return LayerMetadata{}, err
	}

	return layer, nil
}

func (h *EROFSIndex) SaveLayerMeta(ctx context.Context, hash string, layer LayerMetadata) error {
	// Never make an incomplete or corrupt generation discoverable by recipe.
	if _, err := h.Cached(ctx, layer.Template.BuildID); err != nil {
		return err
	}
	data, err := json.Marshal(layer)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(h.dir, ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(h.dir, HashKeys(hash))); err != nil {
		return err
	}
	dir, err := os.Open(h.dir)
	if err != nil {
		return err
	}

	return errors.Join(dir.Sync(), dir.Close())
}

func (h *EROFSIndex) Cached(ctx context.Context, buildID string) (metadata.Template, error) {
	if err := ctx.Err(); err != nil {
		return metadata.Template{}, err
	}
	snapshot, err := h.store.Load(buildID)
	if err != nil {
		return metadata.Template{}, fmt.Errorf("load local EROFS template %s: %w", buildID, err)
	}
	t, err := metadata.FromFile(snapshot.MetadataPath())
	if err != nil {
		return metadata.Template{}, err
	}
	if t.Template.BuildID != buildID || t.Version < minimalCachedTemplateVersion || t.Version <= metadata.DeprecatedVersion {
		return metadata.Template{}, errors.New("invalid EROFS template metadata")
	}

	return t, nil
}
