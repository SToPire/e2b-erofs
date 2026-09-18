//go:build linux

package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/fc"
)

type v2Runtime struct {
	parent       *erofs.Snapshot
	parentUpper  string
	boot         erofs.BootLayout
	lower        *erofs.Lower
	upper        *nativeRawRootfs
	exportHelper bool
}

func (f *Factory) prepareV2Runtime(ctx context.Context, snapshot *erofs.Snapshot, mounted *erofs.MountRef,
	resources *nativeResources, versions fc.Config, teamID string) (*v2Runtime, fc.RuntimeSources, error) {
	m := snapshot.Manifest
	var sources fc.RuntimeSources
	if m.Format != erofs.FormatV2 || m.Boot == nil || m.Upper == nil {
		return nil, sources, errors.New("missing v2 runtime layout")
	}
	state, sources, err := f.prepareV2Files(ctx, *m.Boot, m.Lower, mounted.DiskPath(), m.UpperContentSHA256, m.Upper.Size, resources, versions, teamID)
	if err != nil {
		return nil, sources, err
	}
	state.parent, state.parentUpper = snapshot, mounted.DiskPath()
	sources.MemoryPath = mounted.MemoryPath()
	return state, sources, nil
}

// PmemBootstrap is a cold-build input, not a committed VM snapshot. Its upper
// seed is copied to a private inode before the first Guest starts.
type PmemBootstrap struct {
	Boot               erofs.BootLayout
	Lower              *erofs.Lower
	UpperPath          string
	UpperContentSHA256 string
	UpperSize          int64
	Export             *fc.PmemExportSource
}

func WithPmemBootstrap(bootstrap PmemBootstrap) CreateOption {
	return func(options *createOptions) { options.pmemBootstrap = &bootstrap }
}

// RawBootstrap is a sealed complete filesystem for a new cold build VM. It
// carries no RAM and cannot turn a runtime checkpoint into a different layout.
type RawBootstrap struct {
	Path   string
	Size   int64
	SHA256 string
}

func WithRawBootstrap(bootstrap RawBootstrap) CreateOption {
	return func(options *createOptions) { options.rawBootstrap = &bootstrap }
}

func (f *Factory) prepareV2Files(ctx context.Context, boot erofs.BootLayout, lowerDescriptor *erofs.Lower,
	upperSource, upperDigest string, upperSize int64, resources *nativeResources, versions fc.Config, teamID string) (*v2Runtime, fc.RuntimeSources, error) {
	var sources fc.RuntimeSources
	store, err := erofs.NewStore(f.config.EROFSSnapshotDir, erofs.Options{})
	if err != nil {
		return nil, sources, err
	}
	if err := store.ValidateBoot(ctx, boot, lowerDescriptor); err != nil {
		return nil, sources, err
	}
	if versions.KernelVersion != boot.KernelVersion || versions.FirecrackerVersion != boot.FirecrackerVersion {
		return nil, sources, errors.New("requested binaries differ from the v2 boot layout")
	}
	for path, expected := range map[string]string{versions.HostKernelPath(f.config): boot.KernelSHA256,
		versions.FirecrackerPath(f.config): boot.FirecrackerSHA256} {
		actual, err := runtimeBinaryDigest(ctx, path)
		if err != nil {
			return nil, sources, err
		}
		if actual != expected {
			return nil, sources, fmt.Errorf("runtime binary digest differs from v2 snapshot: %s", path)
		}
	}
	var lowerPath string
	if boot.Layout == erofs.LayoutPmem {
		if !f.config.EROFSPmemVerified {
			return nil, sources, errors.New("pmem runtime requires EROFS_PMEM_VERIFIED")
		}
		lower, err := f.sharedMounts.AcquireLower(ctx, lowerDescriptor, teamID)
		if lower != nil {
			previous := resources.closeMount
			resources.closeMount = func() error {
				err := lower.Release()
				if previous != nil {
					err = errors.Join(err, previous())
				}
				return err
			}
		}
		if err != nil {
			return nil, sources, err
		}
		lowerPath = lower.LowerPath()
	}
	upper, err := newV2RawRootfs(ctx, upperSource, upperDigest, upperSize, f.config.EROFSSnapshotDir)
	if err != nil {
		return nil, sources, err
	}
	resources.closeDisk = upper.Close
	upperPath, err := upper.Path()
	if err != nil {
		return nil, sources, err
	}
	sources.RawDisk = boot.Layout == erofs.LayoutRawBuild
	if boot.Layout == erofs.LayoutPmem {
		sources.Rootfs = &fc.PmemRootfsSource{LowerPath: lowerPath, LowerSize: lowerDescriptor.Image.Size,
			UpperPath: upperPath, UpperSize: upperSize, InitramfsPath: filepath.Join(f.config.EROFSSnapshotDir, boot.Initramfs.File)}
	}
	return &v2Runtime{boot: boot, lower: lowerDescriptor, upper: upper}, sources, nil
}

func runtimeBinaryDigest(ctx context.Context, path string) (string, error) {
	// Artifact caches may use symlinks. Validate the opened target and digest;
	// O_NONBLOCK still prevents a symlink to a FIFO from stalling validation.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return "", errors.New("runtime binary must be a nonempty regular file")
	}
	digest := sha256.New()
	buffer := make([]byte, 128*1024)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := f.Read(buffer)
		digest.Write(buffer[:n])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func (f *Factory) rawBuildRuntime(ctx context.Context, versions fc.Config, upper *nativeRawRootfs) (*v2Runtime, error) {
	kernel, err := runtimeBinaryDigest(ctx, versions.HostKernelPath(f.config))
	if err != nil {
		return nil, err
	}
	binary, err := runtimeBinaryDigest(ctx, versions.FirecrackerPath(f.config))
	if err != nil {
		return nil, err
	}
	return &v2Runtime{upper: upper, boot: erofs.BootLayout{Layout: erofs.LayoutRawBuild, KernelVersion: versions.KernelVersion,
		KernelSHA256: kernel, FirecrackerVersion: versions.FirecrackerVersion, FirecrackerSHA256: binary}}, nil
}
