//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/block"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/nbd"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/rootfs"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage/header"
)

// erofsRootfs reserves devices through the same pool as legacy NBD overlays.
// The VM accesses the raw NBD device; qemu-nbd alone interprets qcow2 metadata.
type erofsRootfs struct {
	overlay    *erofs.Overlay
	pool       *nbd.DevicePool
	slot       nbd.DeviceSlot
	mu         sync.Mutex
	released   bool
	runtimeDir string
	discarded  bool
}

var _ rootfs.Provider = (*erofsRootfs)(nil)

func newEROFSRootfs(ctx context.Context, pool *nbd.DevicePool, backing string, size int64, storeRoot, parentID string) (*erofsRootfs, error) {
	slot, err := pool.GetDevice(ctx)
	if err != nil {
		return nil, err
	}
	base := filepath.Join(storeRoot, ".overlays")
	if err := os.MkdirAll(base, 0700); err != nil {
		return nil, errors.Join(err, pool.ReleaseDevice(context.WithoutCancel(ctx), slot))
	}
	dir, err := os.MkdirTemp(base, "runtime-")
	if err != nil {
		return nil, errors.Join(err, pool.ReleaseDevice(context.WithoutCancel(ctx), slot))
	}
	overlay, err := erofs.NewOverlay(ctx, erofs.OverlayOptions{
		Directory: dir, BackingPath: backing, Size: size,
		DevicePath: nbd.GetDevicePath(slot), ParentID: parentID,
	})
	if err != nil {
		if overlay != nil {
			// Return ownership even on partial startup. The caller must close
			// this provider before releasing its backing mounts.
			return &erofsRootfs{overlay: overlay, pool: pool, slot: slot, runtimeDir: dir}, err
		}
		releaseErr := pool.ReleaseDevice(context.WithoutCancel(ctx), slot)
		if releaseErr != nil {
			return &erofsRootfs{pool: pool, slot: slot, runtimeDir: dir}, errors.Join(err, releaseErr)
		}
		provider := &erofsRootfs{pool: pool, slot: slot, runtimeDir: dir, released: true}
		if discardErr := provider.discard(); discardErr != nil {
			return provider, errors.Join(err, discardErr)
		}
		return nil, err
	}
	return &erofsRootfs{overlay: overlay, pool: pool, slot: slot, runtimeDir: dir}, nil
}

func (*erofsRootfs) Start(context.Context) error { return nil }
func (p *erofsRootfs) Path() (string, error)     { return p.overlay.Path(), nil }
func (p *erofsRootfs) Done() <-chan struct{}     { return p.overlay.Done() }
func (p *erofsRootfs) Err() error                { return p.overlay.Err() }

func rootfsExit(provider rootfs.Provider) (<-chan struct{}, func() error) {
	if backend, ok := provider.(interface {
		Done() <-chan struct{}
		Err() error
	}); ok {
		return backend.Done(), backend.Err
	}
	return nil, func() error { return nil }
}

func (p *erofsRootfs) Close(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.released {
		return nil
	}
	if p.overlay != nil {
		if err := p.overlay.Close(ctx); err != nil {
			return err
		}
	}
	if err := p.pool.ReleaseDevice(ctx, p.slot); err != nil {
		return err
	}
	p.released = true
	return nil
}

func (p *erofsRootfs) seal(ctx context.Context) (string, error) { return p.overlay.Seal(ctx) }

// discard removes only this runtime's private files after all QEMU/NBD
// ownership has been released. The caller decides whether captured inputs may
// be discarded; Close alone must retain them for failed snapshot recovery.
func (p *erofsRootfs) discard() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.discarded {
		return nil
	}
	if !p.released {
		return errors.New("cannot discard an unreleased EROFS disk runtime")
	}
	if p.runtimeDir == "" {
		return errors.New("EROFS disk runtime directory ownership is missing")
	}
	if err := os.RemoveAll(p.runtimeDir); err != nil {
		return err
	}
	p.discarded = true
	return nil
}

var errEROFSExport = errors.New("EROFS rootfs requires sealed qcow2 capture and resume-fresh checkpoint")

func (*erofsRootfs) ExportDiff(context.Context, *os.File, func(context.Context) error) (*header.DiffMetadata, error) {
	return nil, errEROFSExport
}
func (*erofsRootfs) ExportDiffInPlace(context.Context, *os.File) (*header.DiffMetadata, error) {
	return nil, errEROFSExport
}
func (*erofsRootfs) PrepareExportDiff(context.Context, func(context.Context) error) (*block.Cache, error) {
	return nil, rootfs.ErrDeferredExportNotSupported
}
func (*erofsRootfs) SwapForBackgroundSeal(context.Context) (*block.Cache, error) {
	return nil, rootfs.ErrDeferredExportNotSupported
}
func (*erofsRootfs) FoldSealed(context.Context) (*block.Cache, error) { return nil, errEROFSExport }
