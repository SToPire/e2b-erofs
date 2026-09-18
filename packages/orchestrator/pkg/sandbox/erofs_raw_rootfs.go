//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

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
	mu            sync.Mutex
	path          string
	file          nativeRawFile
	owned         bool
	synced        bool
	closed        bool
	privateDir    string
	storeRoot     string
	identity      os.FileInfo
	sealTarget    string
	retainCapture bool
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
	info, err := file.Stat()
	if err != nil {
		return nil, errors.Join(err, file.Close(), os.Remove(file.Name()))
	}
	return &nativeRawRootfs{path: file.Name(), file: file, owned: true, identity: info}, nil
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
	if p.closed || p.sealTarget != "" {
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
	if p.owned && !p.retainCapture {
		if err := os.Remove(p.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove private native raw disk: %w", err)
		}
	}
	if p.privateDir != "" && !(p.owned && p.retainCapture) {
		if err := os.Remove(p.privateDir); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	p.closed = true
	return nil
}

func (p *nativeRawRootfs) retainForCapture() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.retainCapture = true
}
func (p *nativeRawRootfs) isClosed() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.closed }

func (p *nativeRawRootfs) discardRetainedCapture() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		return errors.New("raw capture cleanup requires a closed runtime")
	}
	if p.owned && p.retainCapture {
		info, err := os.Lstat(p.path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil {
			if !info.Mode().IsRegular() || !os.SameFile(info, p.identity) {
				return errors.New("retained raw inode changed before cleanup")
			}
			if err := os.Remove(p.path); err != nil {
				return err
			}
		}
		if p.privateDir != "" {
			if err := os.Remove(p.privateDir); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		p.owned, p.retainCapture = false, false
	}
	return nil
}

// newV2RawRootfs materializes a generation's complete upper view into a unique
// writable inode. The digest is calculated while copying, before FC can attach it.
func newV2RawRootfs(ctx context.Context, source, expectedSHA string, size int64, storeRoot string) (*nativeRawRootfs, error) {
	root, err := filepath.Abs(storeRoot)
	if err != nil || storeRoot == "" {
		return nil, errors.New("raw upper requires a persistent store")
	}
	base := filepath.Join(root, ".runtimes")
	if err := os.MkdirAll(base, 0700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(base, "upper-")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "upper.ext4")
	stats, err := erofs.MaterializeRawFile(ctx, source, path, size)
	if err != nil {
		return nil, errors.Join(err, os.RemoveAll(dir))
	}
	if stats.SourceSHA256 != expectedSHA {
		return nil, errors.Join(errors.New("materialized raw upper differs from committed content"), os.RemoveAll(dir))
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, errors.Join(err, os.RemoveAll(dir))
	}
	info, err := file.Stat()
	if err != nil {
		return nil, errors.Join(err, file.Close(), os.RemoveAll(dir))
	}
	return &nativeRawRootfs{path: path, file: file, owned: true, privateDir: dir, storeRoot: root, identity: info}, nil
}

// seal transfers this runtime's upper to capture ownership. The caller must
// first stop and wait for Firecracker; no writer may remain. Even a failure
// after rename must never allow Close to delete the retained capture.
func (p *nativeRawRootfs) seal(ctx context.Context, target string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return p.sealTarget, err
	}
	if p.privateDir == "" || p.identity == nil {
		return "", errors.New("raw provider does not own a v2 upper")
	}
	if !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return "", errors.New("capture target must be canonical and absolute")
	}
	rel, err := filepath.Rel(filepath.Join(p.storeRoot, ".captures"), target)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", errors.New("raw capture target is outside the capture store")
	}
	if p.sealTarget != "" && p.sealTarget != target {
		return p.sealTarget, errors.New("raw upper already belongs to another capture")
	}
	if p.closed && p.sealTarget == "" {
		return "", os.ErrClosed
	}
	info, err := os.Lstat(p.path)
	if err != nil {
		return p.sealTarget, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(info, p.identity) || info.Size() != p.identity.Size() {
		return p.sealTarget, errors.New("raw upper identity or capacity changed")
	}
	if !p.synced {
		if err := p.file.Sync(); err != nil {
			return p.sealTarget, err
		}
		p.synced = true
	}
	if p.sealTarget == "" {
		if err := unix.Renameat2(unix.AT_FDCWD, p.path, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE); err != nil {
			return "", err
		}
		p.path, p.sealTarget, p.owned = target, target, false
	}
	if p.file != nil {
		err := p.file.Close()
		p.file = nil
		if err != nil {
			return target, err
		}
	}
	if err := os.Chmod(target, 0400); err != nil {
		return target, err
	}
	sourceDir := p.privateDir
	if p.closed {
		sourceDir = filepath.Dir(p.privateDir)
	}
	for _, path := range []string{target, filepath.Dir(target), sourceDir} {
		f, err := os.Open(path)
		if err != nil {
			return target, err
		}
		if err := errors.Join(f.Sync(), f.Close()); err != nil {
			return target, err
		}
	}
	return target, nil
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
