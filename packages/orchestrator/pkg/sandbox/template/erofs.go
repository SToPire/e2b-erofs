//go:build linux

package template

import (
	"context"
	"errors"
	"fmt"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/block"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/metadata"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage"
)

// EROFSTemplate holds a committed local snapshot. Each sandbox acquires its own
// mounts, so template-cache eviction cannot unmount RAM or a qcow2 backing file
// that a running Firecracker still uses. Committed generations are retained.
type EROFSTemplate struct {
	paths    storage.CachePaths
	snapshot *erofs.Snapshot
}

func NewEROFSTemplate(paths storage.CachePaths, snapshot *erofs.Snapshot) *EROFSTemplate {
	return &EROFSTemplate{paths: paths, snapshot: snapshot}
}

func EROFS(t Template) (*erofs.Snapshot, bool) {
	switch t := t.(type) {
	case *EROFSTemplate:
		return t.snapshot, true
	case *MaskTemplate:
		return EROFS(t.template)
	default:
		return nil, false
	}
}

var ErrEROFSDevice = errors.New("EROFS template requires mounted file access, not a header device")

func (t *EROFSTemplate) Files() storage.CachePaths { return t.paths }
func (*EROFSTemplate) Close(context.Context) error { return nil }
func (*EROFSTemplate) Memfile(context.Context) (block.ReadonlyDevice, error) {
	return nil, ErrEROFSDevice
}
func (*EROFSTemplate) Rootfs() (block.ReadonlyDevice, error) { return nil, ErrEROFSDevice }
func (t *EROFSTemplate) Snapfile() (File, error) {
	return retainedFile(t.snapshot.VMStatePath()), nil
}
func (t *EROFSTemplate) Metadata() (metadata.Template, error) {
	return metadata.FromFile(t.snapshot.MetadataPath())
}
func (*EROFSTemplate) UpdateMetadata(metadata.Template) error {
	return fmt.Errorf("committed EROFS snapshot metadata is immutable")
}

type retainedFile string

func (f retainedFile) Path() string { return string(f) }
func (retainedFile) Close() error   { return nil }
