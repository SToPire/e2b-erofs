//go:build linux

package erofs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Mounted owns both file-backed EROFS mounts. The kernel holds references to
// the primary and historical image files until the mounts are released.
// Close must follow Firecracker exit and overlay seal, after all consumers have
// closed their files. Failed unmounts retain ownership for retry.
type Mounted struct {
	MemoryPath  string
	DiskPath    string
	LowerPath   string
	VMStatePath string
	mu          sync.Mutex
	dir         string
	mounts      []*imageMount
}

type imageMount struct {
	path    string
	mounted bool
}

func (s *Snapshot) Mount(ctx context.Context, mountRoot string) (*Mounted, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	verified, err := s.store.LoadContext(ctx, s.Manifest.ID)
	if err != nil {
		return nil, err
	}
	if sharedManifestDigest(verified.Manifest) != sharedManifestDigest(s.Manifest) {
		return nil, ErrSnapshotConflict
	}
	// Mount precisely the descriptor just verified, rather than a stale or
	// caller-modified copy of the exported Manifest field.
	s = verified
	if err := os.MkdirAll(mountRoot, 0700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(mountRoot, s.Manifest.ID+"-")
	if err != nil {
		return nil, err
	}
	m := &Mounted{dir: dir, VMStatePath: s.VMStatePath()}
	writableName, writableTarget := "disk", "disk/rootfs.ext4"
	if s.Manifest.Format == FormatV2 {
		writableName, writableTarget = "upper", "upper/upper.ext4"
	}
	for _, item := range []struct {
		name, target string
		image        Image
		dest         *string
	}{
		{"memory", "memory/memfile", s.Manifest.Memory, &m.MemoryPath},
		{writableName, writableTarget, s.Manifest.WritableDisk(), &m.DiskPath},
	} {
		if err := m.mountView(ctx, s.store.Root, item.name, item.target, item.image, item.dest); err != nil {
			return m, errors.Join(err, m.Close())
		}
	}
	return m, nil
}

func (s *Store) MountLower(ctx context.Context, lower *Lower, mountRoot string) (*Mounted, error) {
	if lower == nil {
		return nil, errors.New("missing lower")
	}
	verified, err := s.LoadLower(ctx, lower.ID)
	if err != nil {
		return nil, err
	}
	if descriptorDigest(verified) != descriptorDigest(lower) {
		return nil, ErrSnapshotConflict
	}
	if err := os.MkdirAll(mountRoot, 0700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(mountRoot, "lower-"+lower.ID+"-")
	if err != nil {
		return nil, err
	}
	m := &Mounted{dir: dir}
	if err := m.mountView(ctx, s.Root, "lower", "lower/rootfs.ext4", verified.Image, &m.LowerPath); err != nil {
		return m, errors.Join(err, m.Close())
	}
	return m, nil
}

func (m *Mounted) mountView(ctx context.Context, storeRoot, name, target string, image Image, dest *string) error {
	im := &imageMount{path: filepath.Join(m.dir, name)}
	m.mounts = append(m.mounts, im)
	if err := os.Mkdir(im.path, 0700); err != nil {
		return err
	}
	var devices []string
	for _, a := range append([]Artifact{image.Artifact}, image.Devices...) {
		if err := ctx.Err(); err != nil {
			return err
		}
		devices = append(devices, filepath.Join(storeRoot, a.File))
	}
	var opts []string
	for _, device := range devices[1:] {
		opts = append(opts, "device="+device)
	}
	data := strings.Join(opts, ",")
	// mount(2) copies at most one page of options. File paths are longer
	// than loop names; reject oversized chains before the kernel truncates them.
	if len(data) >= os.Getpagesize() {
		return errors.New("EROFS history mount options exceed the kernel page limit")
	}
	// Call mount(2) directly: mount(8) may silently allocate a loop device
	// for a regular-file source on older util-linux versions.
	if err := unix.Mount(devices[0], im.path, "erofs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, data); err != nil {
		return fmt.Errorf("mount file-backed EROFS (requires CONFIG_EROFS_FS_BACKED_BY_FILE and a supported backing filesystem): %w", err)
	}
	im.mounted = true
	*dest = filepath.Join(im.path, target)
	return regularSize(*dest, image.Size)
}

func (m *Mounted) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var result error
	for i := len(m.mounts) - 1; i >= 0; i-- {
		im := m.mounts[i]
		if im.mounted {
			if err := unix.Unmount(im.path, 0); err != nil {
				result = errors.Join(result, err)
				continue
			}
			im.mounted = false
		}
	}
	if result == nil {
		result = os.RemoveAll(m.dir)
	}
	return result
}
