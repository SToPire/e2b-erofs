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

// Mounted owns the primary and every historical loop device, and both mounts.
// Close must follow Firecracker exit and overlay seal, after all consumers have
// closed their files. Failed unmounts retain the loop ownership for retry.
type Mounted struct {
	MemoryPath  string
	DiskPath    string
	VMStatePath string
	mu          sync.Mutex
	dir         string
	mounts      []*imageMount
}

type imageMount struct {
	path    string
	mounted bool
	loops   []*os.File
}

func (s *Snapshot) Mount(ctx context.Context, mountRoot string) (*Mounted, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	verified, err := s.store.Load(s.Manifest.ID)
	if err != nil {
		return nil, err
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
	for _, item := range []struct {
		name, target string
		image        Image
		dest         *string
	}{
		{"memory", "memory/memfile", s.Manifest.Memory, &m.MemoryPath},
		{"disk", "disk/rootfs.ext4", s.Manifest.Disk, &m.DiskPath},
	} {
		im := &imageMount{path: filepath.Join(dir, item.name)}
		m.mounts = append(m.mounts, im)
		if err := os.Mkdir(im.path, 0700); err != nil {
			return m, errors.Join(err, m.Close())
		}
		var devices []string
		for _, a := range append([]Artifact{item.image.Artifact}, item.image.Devices...) {
			if err := ctx.Err(); err != nil {
				return m, errors.Join(err, m.Close())
			}
			loop, err := attachLoop(filepath.Join(s.store.Root, a.File))
			if err != nil {
				return m, errors.Join(err, m.Close())
			}
			im.loops = append(im.loops, loop)
			devices = append(devices, loop.Name())
		}
		var opts []string
		for _, device := range devices[1:] {
			opts = append(opts, "device="+device)
		}
		if err := unix.Mount(devices[0], im.path, "erofs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, strings.Join(opts, ",")); err != nil {
			return m, errors.Join(fmt.Errorf("mount EROFS: %w", err), m.Close())
		}
		im.mounted = true
		*item.dest = filepath.Join(im.path, item.target)
		if err := regularSize(*item.dest, item.image.Size); err != nil {
			return m, errors.Join(err, m.Close())
		}
	}
	return m, nil
}

func attachLoop(path string) (*os.File, error) {
	image, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer image.Close()
	control, err := os.OpenFile("/dev/loop-control", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer control.Close()
	for range 32 {
		n, err := unix.IoctlRetInt(int(control.Fd()), unix.LOOP_CTL_GET_FREE)
		if err != nil {
			return nil, err
		}
		loop, err := os.OpenFile(fmt.Sprintf("/dev/loop%d", n), os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		config := &unix.LoopConfig{Fd: uint32(image.Fd()), Info: unix.LoopInfo64{Flags: unix.LO_FLAGS_READ_ONLY | unix.LO_FLAGS_AUTOCLEAR}}
		if err := unix.IoctlLoopConfigure(int(loop.Fd()), config); err != nil {
			loop.Close()
			if errors.Is(err, unix.EBUSY) {
				continue
			}
			return nil, err
		}
		return loop, nil
	}
	return nil, errors.New("unable to reserve a loop device")
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
		for _, loop := range im.loops {
			result = errors.Join(result, loop.Close())
		}
		im.loops = nil
	}
	if result == nil {
		result = os.RemoveAll(m.dir)
	}
	return result
}
