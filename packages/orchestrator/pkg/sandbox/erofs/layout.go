//go:build linux

package erofs

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	FormatV2       = "erofs-v2"
	LayoutPmem     = "pmem-overlay-raw-v1"
	LayoutRawBuild = "raw-build-v1"
)

// Lower is shared across runtime generations. Its ID binds the complete ext4
// content, capacity and filesystem identity, not a per-VM writable upper.
type Lower struct {
	ID             string `json:"id"`
	FilesystemUUID string `json:"filesystem_uuid"`
	ContentSHA256  string `json:"content_sha256"`
	Image          Image  `json:"image"`
}

// BootLayout binds the immutable executable and guest layout inputs. The
// versioned layout fixes device order, IDs and OverlayFS mount options.
type BootLayout struct {
	Layout             string    `json:"layout"`
	KernelVersion      string    `json:"kernel_version"`
	KernelSHA256       string    `json:"kernel_sha256"`
	FirecrackerVersion string    `json:"firecracker_version"`
	FirecrackerSHA256  string    `json:"firecracker_sha256"`
	Initramfs          *Artifact `json:"initramfs,omitempty"`
}

func (m Manifest) WritableDisk() Image {
	if m.Format == FormatV2 && m.Upper != nil {
		return *m.Upper
	}
	return m.Disk
}

func (m Manifest) UsesPmem() bool {
	return m.Format == FormatV2 && m.Boot != nil && m.Boot.Layout == LayoutPmem
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func validVersion(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value && !strings.ContainsAny(value, "\\\x00\r\n")
}

func lowerID(content string, size int64, filesystemUUID string) string {
	data, _ := json.Marshal(struct {
		Layout, Content, UUID string
		Size                  int64
	}{LayoutPmem, content, filesystemUUID, size})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func descriptorDigest(value any) [32]byte {
	data, _ := json.Marshal(value)
	return sha256.Sum256(data)
}

// PublishLower accepts a sealed clean ext4 image and publishes one reusable
// lower. It never replays a journal or modifies the supplied image.
func (s *Store) PublishLower(ctx context.Context, source string, size int64) (*Lower, error) {
	if size <= 0 || size%(2<<20) != 0 {
		return nil, errors.New("pmem lower capacity must be a positive multiple of 2 MiB")
	}
	f, err := openRawInput(source, size)
	if err != nil {
		return nil, err
	}
	var super [1024]byte
	_, readErr := f.ReadAt(super[:], 1024)
	if err := errors.Join(readErr, f.Close()); err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint16(super[56:58]) != 0xef53 || binary.LittleEndian.Uint32(super[24:28]) != 2 {
		return nil, errors.New("pmem lower must contain a 4 KiB ext4 filesystem")
	}
	if binary.LittleEndian.Uint32(super[96:100])&0x8000 != 0 {
		return nil, errors.New("pmem lower cannot enable ext4 inline_data; rebuild with DAX-compatible mkfs options")
	}
	blocks := uint64(binary.LittleEndian.Uint32(super[4:8]))
	if binary.LittleEndian.Uint32(super[96:100])&0x80 != 0 {
		blocks |= uint64(binary.LittleEndian.Uint32(super[336:340])) << 32
	}
	if blocks == 0 || blocks > uint64(size/BlockSize) {
		return nil, errors.New("lower ext4 filesystem exceeds its backing file capacity")
	}
	if binary.LittleEndian.Uint16(super[58:60]) != 1 || binary.LittleEndian.Uint32(super[96:100])&4 != 0 {
		return nil, errors.New("pmem lower must be clean and require no journal recovery")
	}
	fsID, err := uuid.FromBytes(super[104:120])
	if err != nil || fsID == uuid.Nil {
		return nil, errors.New("pmem lower requires a filesystem UUID")
	}
	input, err := describeContext(ctx, source, "")
	if err != nil {
		return nil, err
	}
	id := lowerID(input.SHA256, size, fsID.String())
	if _, err := os.Lstat(filepath.Join(s.Root, "lowers", id)); err == nil {
		return s.loadDurableLower(ctx, id)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	base := filepath.Join(s.Root, "lowers")
	if err := os.MkdirAll(base, 0700); err != nil {
		return nil, err
	}
	pending, err := os.MkdirTemp(base, ".pending-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(pending)
	image, err := s.buildFileImage(ctx, pending, filepath.Join("lowers", id), "lower.erofs", "/lower/rootfs.ext4", source, size, nil)
	if err != nil {
		return nil, err
	}
	after, err := describeContext(ctx, source, "")
	if err != nil {
		return nil, err
	}
	if input != after {
		return nil, errors.New("lower input changed during publication")
	}
	lower := &Lower{ID: id, FilesystemUUID: fsID.String(), ContentSHA256: input.SHA256, Image: image}
	data, err := json.MarshalIndent(lower, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(pending, ManifestName), append(data, '\n'), 0400); err != nil {
		return nil, err
	}
	if err := sealDirectory(pending); err != nil {
		return nil, err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, pending, unix.AT_FDCWD, filepath.Join(base, id), unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return s.loadDurableLower(ctx, id)
		}
		return nil, err
	}
	if err := syncPath(base); err != nil {
		return nil, err
	}
	if err := syncPath(s.Root); err != nil {
		return nil, err
	}
	return lower, nil
}

func (s *Store) LoadLower(ctx context.Context, id string) (*Lower, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validDigest(id) {
		return nil, errors.New("invalid lower ID")
	}
	data, err := trackedMetadata(ctx, filepath.Join(s.Root, "lowers", id, ManifestName))
	if err != nil {
		return nil, err
	}
	var lower Lower
	if err := json.Unmarshal(data, &lower); err != nil {
		return nil, err
	}
	fsID, err := uuid.Parse(lower.FilesystemUUID)
	if err != nil || fsID == uuid.Nil || fsID.String() != lower.FilesystemUUID || lower.ID != id ||
		!validDigest(lower.ContentSHA256) || lower.Image.Size <= 0 || lower.Image.Size%(2<<20) != 0 ||
		len(lower.Image.Devices) != 0 || lower.Image.File != filepath.Join("lowers", id, "lower.erofs") ||
		lowerID(lower.ContentSHA256, lower.Image.Size, lower.FilesystemUUID) != id {
		return nil, errors.New("invalid lower descriptor")
	}
	if err := s.verifyArtifact(ctx, lower.Image.Artifact); err != nil {
		return nil, err
	}
	return &lower, nil
}

func (s *Store) loadDurableLower(ctx context.Context, id string) (*Lower, error) {
	lower, err := s.LoadLower(ctx, id)
	if err != nil {
		return nil, err
	}
	for _, path := range []string{filepath.Join(s.Root, "lowers", id), filepath.Join(s.Root, "lowers"), s.Root} {
		if err := syncPath(path); err != nil {
			return nil, err
		}
	}
	return lower, nil
}

// ImportInitramfs copies a boot artifact to an immutable content-addressed path.
func (s *Store) ImportInitramfs(ctx context.Context, source string) (*Artifact, error) {
	input, err := describeContext(ctx, source, "")
	if err != nil {
		return nil, err
	}
	if input.Bytes == 0 {
		return nil, errors.New("empty initramfs")
	}
	base := filepath.Join(s.Root, "boot")
	if err := os.MkdirAll(base, 0700); err != nil {
		return nil, err
	}
	a := Artifact{File: filepath.Join("boot", input.SHA256, "initramfs.cpio.gz"), SHA256: input.SHA256, Bytes: input.Bytes}
	if _, err := os.Lstat(filepath.Join(s.Root, a.File)); err == nil {
		if err := s.verifyArtifact(ctx, a); err != nil {
			return nil, err
		}
		return &a, errors.Join(syncPath(filepath.Dir(filepath.Join(s.Root, a.File))), syncPath(base), syncPath(s.Root))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	pending, err := os.MkdirTemp(base, ".pending-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(pending)
	path := filepath.Join(pending, "initramfs.cpio.gz")
	if err := copyFile(source, path); err != nil {
		return nil, err
	}
	actual, err := describeContext(ctx, path, a.File)
	if err != nil {
		return nil, err
	}
	if actual != a {
		return nil, errors.New("initramfs changed while copying")
	}
	if err := sealDirectory(pending); err != nil {
		return nil, err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, pending, unix.AT_FDCWD, filepath.Join(base, a.SHA256), unix.RENAME_NOREPLACE); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	if err := s.verifyArtifact(ctx, a); err != nil {
		return nil, err
	}
	return &a, errors.Join(syncPath(base), syncPath(s.Root))
}

func (s *Store) verifyArtifact(ctx context.Context, a Artifact) error {
	if a.File == "" || filepath.IsAbs(a.File) || filepath.Clean(a.File) != a.File || a.File == ".." || strings.HasPrefix(a.File, "../") || !validDigest(a.SHA256) || a.Bytes <= 0 {
		return errors.New("invalid artifact reference")
	}
	return s.verifyArtifactBytes(ctx, a)
}

func (s *Store) validateBoot(ctx context.Context, boot BootLayout, lower *Lower) error {
	if !validVersion(boot.KernelVersion) || !validVersion(boot.FirecrackerVersion) || !validDigest(boot.KernelSHA256) || !validDigest(boot.FirecrackerSHA256) {
		return errors.New("invalid pinned runtime binaries")
	}
	switch boot.Layout {
	case LayoutRawBuild:
		if lower != nil || boot.Initramfs != nil {
			return errors.New("raw build layout cannot contain pmem inputs")
		}
	case LayoutPmem:
		if lower == nil || boot.Initramfs == nil {
			return errors.New("pmem layout requires lower and initramfs")
		}
		if boot.Initramfs.File != filepath.Join("boot", boot.Initramfs.SHA256, "initramfs.cpio.gz") {
			return errors.New("invalid initramfs path")
		}
		if err := s.verifyArtifact(ctx, *boot.Initramfs); err != nil {
			return err
		}
		actual, err := s.LoadLower(ctx, lower.ID)
		if err != nil {
			return err
		}
		if descriptorDigest(actual) != descriptorDigest(lower) {
			return errors.New("lower descriptor differs from committed lower")
		}
	default:
		return errors.New("unsupported rootfs layout")
	}
	return nil
}

// ValidateBoot verifies the pinned layout and all locally committed boot inputs
// before a cold bootstrap exists as a complete VM snapshot.
func (s *Store) ValidateBoot(ctx context.Context, boot BootLayout, lower *Lower) error {
	return s.validateBoot(ctx, boot, lower)
}

func sealDirectory(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return errors.New("unexpected entry in publication directory")
		}
		path := filepath.Join(dir, entry.Name())
		if err := os.Chmod(path, 0400); err != nil {
			return err
		}
		if err := syncPath(path); err != nil {
			return err
		}
	}
	return syncPath(dir)
}
