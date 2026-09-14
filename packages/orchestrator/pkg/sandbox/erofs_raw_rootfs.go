//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/block"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/rootfs"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage/header"
)

type nativeRawFile interface {
	Sync() error
	Close() error
}

// nativeRawRootfs serves the first native baseline directly as complete raw
// bytes. It has no COW cache or export handoff: captureRawDisk retains the full
// cutoff before nativeResources closes this provider. Supplied files remain
// caller-owned; only private files materialized here are removed on close.
type nativeRawRootfs struct {
	mu     sync.Mutex
	path   string
	file   nativeRawFile
	owned  bool
	synced bool
	closed bool
}

var _ rootfs.Provider = (*nativeRawRootfs)(nil)

func newNativeRawRootfs(ctx context.Context, source block.ReadonlyDevice, suppliedPath, storeRoot string) (*nativeRawRootfs, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	size, err := source.Size(ctx)
	if err != nil {
		return nil, err
	}
	if size <= 0 || size%erofs.BlockSize != 0 {
		return nil, errors.New("native raw disk size must be a positive multiple of 4096")
	}
	if suppliedPath != "" {
		path, err := filepath.Abs(suppliedPath)
		if err != nil {
			return nil, err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() != size {
			return nil, errors.New("supplied native raw disk must be a regular file of the expected full size")
		}
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		return &nativeRawRootfs{path: path, file: file}, nil
	}
	if storeRoot == "" {
		return nil, errors.New("native raw materialization requires a persistent store")
	}
	dir, err := filepath.Abs(filepath.Join(storeRoot, ".raw-baselines"))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(dir, "baseline-*.raw")
	if err != nil {
		return nil, err
	}
	if err := materializeNativeRaw(ctx, source, file, size); err != nil {
		return nil, errors.Join(err, file.Close(), os.Remove(file.Name()))
	}
	return &nativeRawRootfs{path: file.Name(), file: file, owned: true}, nil
}

func materializeNativeRaw(ctx context.Context, source block.ReadonlyDevice, out *os.File, size int64) error {
	buffer := make([]byte, min(size, 1024*1024))
	for offset := int64(0); offset < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := buffer[:min(int64(len(buffer)), size-offset)]
		n, err := source.ReadAt(ctx, chunk, offset)
		if err != nil && !(errors.Is(err, io.EOF) && n == len(chunk)) {
			return fmt.Errorf("read native raw source at %d: %w", offset, err)
		}
		if n != len(chunk) {
			return fmt.Errorf("read native raw source at %d: %w", offset, io.ErrUnexpectedEOF)
		}
		if _, err := out.Write(chunk); err != nil {
			return err
		}
		offset += int64(n)
	}
	return out.Sync()
}

func (p *nativeRawRootfs) Start(ctx context.Context) error { return ctx.Err() }

func (p *nativeRawRootfs) Path() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return "", os.ErrClosed
	}
	return p.path, nil
}

func (p *nativeRawRootfs) Close(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !p.synced {
		if err := p.file.Sync(); err != nil {
			return fmt.Errorf("sync native raw disk: %w", err)
		}
		p.synced = true
	}
	if p.file != nil {
		// os.File.Close consumes the descriptor even if it reports an error.
		// A retry continues with path cleanup instead of closing it again.
		err := p.file.Close()
		p.file = nil
		if err != nil {
			return fmt.Errorf("close native raw disk: %w", err)
		}
	}
	if p.owned {
		if err := os.Remove(p.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove private native raw disk: %w", err)
		}
	}
	p.closed = true
	return nil
}

var errNativeRawExport = errors.New("native raw rootfs requires complete disk capture")

func (*nativeRawRootfs) ExportDiff(context.Context, *os.File, func(context.Context) error) (*header.DiffMetadata, error) {
	return nil, errNativeRawExport
}
func (*nativeRawRootfs) ExportDiffInPlace(context.Context, *os.File) (*header.DiffMetadata, error) {
	return nil, errNativeRawExport
}
func (*nativeRawRootfs) PrepareExportDiff(context.Context, func(context.Context) error) (*block.Cache, error) {
	return nil, rootfs.ErrDeferredExportNotSupported
}
func (*nativeRawRootfs) SwapForBackgroundSeal(context.Context) (*block.Cache, error) {
	return nil, rootfs.ErrDeferredExportNotSupported
}
func (*nativeRawRootfs) FoldSealed(context.Context) (*block.Cache, error) {
	return nil, errNativeRawExport
}
