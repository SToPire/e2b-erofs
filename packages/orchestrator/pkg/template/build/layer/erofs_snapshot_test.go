//go:build linux

package layer

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/cfg"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/build/buildcontext"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/build/storage/cache"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/metadata"
	"github.com/e2b-dev/infra/packages/shared/pkg/logger"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage"
)

type recordingLocalIndex struct {
	validationErr error
	saved         bool
}

func (*recordingLocalIndex) Version() string { return "test" }
func (*recordingLocalIndex) LayerMetaFromHash(context.Context, string) (cache.LayerMetadata, error) {
	return cache.LayerMetadata{}, errors.New("unused")
}
func (i *recordingLocalIndex) Cached(context.Context, string) (metadata.Template, error) {
	return metadata.Template{}, i.validationErr
}
func (i *recordingLocalIndex) SaveLayerMeta(context.Context, string, cache.LayerMetadata) error {
	i.saved = true
	return nil
}

func TestUploadEROFSUsesOnlyCommittedLocalIndex(t *testing.T) {
	t.Parallel()
	for _, valid := range []bool{true, false} {
		t.Run(map[bool]string{true: "committed", false: "uncommitted"}[valid], func(t *testing.T) {
			t.Parallel()
			index := &recordingLocalIndex{}
			if !valid {
				index.validationErr = errors.New("missing committed generation")
			}
			// No legacy cache, upload group, or object storage is provided: this
			// branch must not touch any of them or dereference legacy headers.
			executor := &LayerExecutor{
				BuildContext: buildcontext.BuildContext{BuilderConfig: cfg.BuilderConfig{EROFSSnapshotDir: t.TempDir()}},
				index:        index,
			}
			snapshot := &sandbox.Snapshot{LocalEROFS: &erofs.Snapshot{Manifest: erofs.Manifest{ID: "build"}}}
			err := executor.UploadSnapshot(t.Context(), logger.L(), snapshot, "recipe", metadata.Template{
				Template: metadata.TemplateMetadata{BuildID: "build"},
			}, storage.ObjectOriginTemplateBuild)
			if valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.Equal(t, valid, index.saved)
		})
	}
}

func TestEROFSBuildRejectsLegacySnapshot(t *testing.T) {
	t.Parallel()
	executor := &LayerExecutor{BuildContext: buildcontext.BuildContext{BuilderConfig: cfg.BuilderConfig{EROFSSnapshotDir: t.TempDir()}}}
	err := executor.UploadSnapshot(t.Context(), logger.L(), &sandbox.Snapshot{}, "recipe", metadata.Template{}, storage.ObjectOriginTemplateBuild)
	require.ErrorContains(t, err, "legacy snapshot")
}
