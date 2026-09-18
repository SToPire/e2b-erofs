//go:build linux

// Package pmem converts a sealed build disk into inputs for a fresh pmem boot.
// It never edits an image paired with running or restorable Guest RAM.
package pmem

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/build/core/filesystem"
)

const BuildContract = "pmem-overlay-raw-v1:ext4-4k-no-inline:index=on,metacopy=off,redirect_dir=on,xino=on,nfs_export=off:upper-i4096-reserved-v4-root-metadata-flags:state=.e2b-rootfs"

type RawInput struct {
	Path   string
	Size   int64
	SHA256 string
}

type Inputs struct {
	Raw        *RawInput
	Source     *erofs.Snapshot
	Store      *erofs.Store
	Boot       erofs.BootLayout
	FreeDiskMB int64
	ReservedMB int64
}

type Prepared struct {
	Boot        erofs.BootLayout
	Lower       *erofs.Lower
	UpperPath   string
	UpperSize   int64
	UpperSHA256 string
	dir         string
}

func (p *Prepared) Close() error { return os.RemoveAll(p.dir) }

// DigestBinary follows trusted node artifact-cache symlinks but refuses special
// files, so a bad configuration cannot hang while computing a build cache key.
func DigestBinary(ctx context.Context, path string) (string, error) {
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
		return "", errors.New("boot artifact must be a nonempty regular file")
	}
	h := sha256.New()
	buf := make([]byte, 128*1024)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, e := f.Read(buf)
		h.Write(buf[:n])
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func Prepare(ctx context.Context, in Inputs) (_ *Prepared, resultErr error) {
	if in.Store == nil || (in.Source == nil) == (in.Raw == nil) {
		return nil, errors.New("finalization requires one sealed raw input")
	}
	if in.Source != nil && (in.Source.Manifest.Format != erofs.FormatV2 || in.Source.Manifest.Boot == nil || in.Source.Manifest.Upper == nil || in.Source.Manifest.Boot.Layout != erofs.LayoutRawBuild) {
		return nil, errors.New("pmem finalization requires a sealed v2 raw build disk")
	}
	if in.Boot.Layout != erofs.LayoutPmem {
		return nil, errors.New("pmem finalization requires pinned pmem boot artifacts")
	}
	if err := validateCapacity(in.FreeDiskMB, in.ReservedMB); err != nil {
		return nil, errors.New("invalid upper free-space target")
	}
	root := filepath.Join(in.Store.Root, ".build-rootfs")
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(root, "finalize-")
	if err != nil {
		return nil, err
	}
	p := &Prepared{Boot: in.Boot, dir: dir}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, p.Close())
		}
	}()
	// Release source mounts before spawning a new FC namespace. Only the full
	// private working copy below is checked, journal-replayed or compacted.
	var sourcePath, expectedSHA string
	var sourceSize int64
	var mounted *erofs.Mounted
	if in.Raw != nil {
		sourcePath, expectedSHA, sourceSize = in.Raw.Path, in.Raw.SHA256, in.Raw.Size
	} else {
		mounted, err = in.Source.Mount(ctx, filepath.Join(dir, "source"))
		if err != nil {
			return nil, err
		}
		sourcePath, expectedSHA, sourceSize = mounted.DiskPath, in.Source.Manifest.UpperContentSHA256, in.Source.Manifest.Upper.Size
	}
	lowerPath := filepath.Join(dir, "lower.raw")
	stats, copyErr := erofs.MaterializeRawFile(ctx, sourcePath, lowerPath, sourceSize)
	var closeErr error
	if mounted != nil {
		closeErr = mounted.Close()
	}
	if err := errors.Join(copyErr, closeErr); err != nil {
		return nil, err
	}
	if stats.SourceSHA256 != expectedSHA {
		return nil, errors.New("build disk differs from its sealed digest")
	}
	if _, err := filesystem.CheckIntegrity(ctx, lowerPath, true); err != nil {
		return nil, err
	}
	if _, err := filesystem.Shrink(ctx, lowerPath); err != nil {
		return nil, err
	}
	if err := alignExt4Image(lowerPath); err != nil {
		return nil, err
	}
	if _, err := filesystem.CheckIntegrity(ctx, lowerPath, false); err != nil {
		return nil, err
	}
	info, err := os.Stat(lowerPath)
	if err != nil {
		return nil, err
	}
	p.Lower, err = in.Store.PublishLower(ctx, lowerPath, info.Size())
	if err != nil {
		return nil, err
	}
	p.UpperPath, p.UpperSize, err = CreateUpperSeed(ctx, dir, in.FreeDiskMB, in.ReservedMB)
	if err != nil {
		return nil, err
	}
	p.UpperSHA256, err = DigestBinary(ctx, p.UpperPath)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// resize2fs may leave padding in the regular file. Read ext4's actual block
// count before choosing the pmem region length; never trim filesystem blocks.
func alignExt4Image(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	sb := make([]byte, 1024)
	if _, err := f.ReadAt(sb, 1024); err != nil {
		return err
	}
	if binary.LittleEndian.Uint16(sb[0x38:]) != 0xef53 || binary.LittleEndian.Uint32(sb[0x18:]) != 2 {
		return errors.New("lower requires ext4 with 4 KiB blocks")
	}
	blocks := uint64(binary.LittleEndian.Uint32(sb[4:]))
	if binary.LittleEndian.Uint32(sb[0x60:])&0x80 != 0 {
		blocks |= uint64(binary.LittleEndian.Uint32(sb[0x150:])) << 32
	}
	if blocks == 0 || blocks > uint64(math.MaxInt64-(2<<20))/4096 {
		return errors.New("invalid compacted ext4 block count")
	}
	bytes := int64(blocks) * 4096
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if bytes > info.Size() {
		return errors.New("compacted ext4 exceeds backing file")
	}
	size := ((bytes + (2 << 20) - 1) / (2 << 20)) * (2 << 20)
	if err := f.Truncate(size); err != nil {
		return err
	}
	return f.Sync()
}

func validateCapacity(freeMB, reservedMB int64) error {
	const limit = (math.MaxInt64 >> 20) / 2
	if freeMB < 0 || reservedMB < 0 || reservedMB > limit || freeMB > limit-reservedMB {
		return errors.New("invalid upper capacity/reservation")
	}
	return nil
}

// CreateUpperSeed includes root-reserved blocks in its capacity and verifies
// the non-root free-space promise after applying that reservation.
func CreateUpperSeed(ctx context.Context, dir string, freeMB, reservedMB int64) (string, int64, error) {
	if err := validateCapacity(freeMB, reservedMB); err != nil {
		return "", 0, err
	}
	// Leave enough space for inode tables, journal and initial overlay metadata;
	// verify actual free blocks rather than treating file capacity as free space.
	seedTree := filepath.Join(dir, "seed")
	for _, name := range []string{"upper", "work"} {
		if err := os.MkdirAll(filepath.Join(seedTree, name), 0755); err != nil {
			return "", 0, err
		}
	}
	if err := os.WriteFile(filepath.Join(seedTree, ".e2b-new-upper"), []byte("root-metadata-v1\n"), 0600); err != nil {
		return "", 0, err
	}
	target := (freeMB + reservedMB) << 20
	size := ((max(int64(64<<20), target+target/8+(32<<20)) + (2 << 20) - 1) / (2 << 20)) * (2 << 20)
	path := filepath.Join(dir, "upper.raw")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return "", 0, err
	}
	if err := errors.Join(f.Truncate(size), f.Close()); err != nil {
		return "", 0, err
	}
	cmd := exec.CommandContext(ctx, "mkfs.ext4", "-q", "-F", "-b", "4096", "-i", "4096", "-m", "0", "-O", "^orphan_file,^inline_data", "-d", seedTree, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", 0, fmt.Errorf("create upper seed: %w: %s", err, out)
	}
	if reservedMB > 0 {
		if err := filesystem.SetReservedBlocksOnHost(ctx, path, reservedMB, 4096); err != nil {
			return "", 0, err
		}
	}
	target = freeMB << 20
	free, err := filesystem.GetFreeSpace(ctx, path, 4096)
	if err != nil {
		return "", 0, err
	}
	if free < target {
		return "", 0, fmt.Errorf("upper seed has %d free bytes; required %d", free, target)
	}
	return path, size, nil
}
