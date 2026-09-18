//go:build linux

// Package pmemstate owns the Guest's pmem-rootfs resume state. Its small journal
// lives on the initramfs tmpfs, so it survives both VM snapshots and envd execve
// without requiring a write to a potentially frozen upper filesystem.
package pmemstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

const (
	Layout     = "pmem-overlay-raw-v1"
	StateDir   = "/.e2b-rootfs"
	UpperMount = StateDir + "/upperfs"
	LowerMount = StateDir + "/lower"
)

type State struct {
	LifecycleID string `json:"lifecycle_id"`
	Phase       string `json:"phase"`
	Frozen      bool   `json:"frozen"`
}

type Controller struct {
	mu         sync.Mutex
	dir, upper *os.File
	state      State
	permitThaw atomic.Bool
	closed     bool
}

// Open returns nil for a legacy root. A present but invalid marker is an error,
// never a reason to fall back to freezing the OverlayFS root by mistake.
func Open() (*Controller, error) {
	c, err := openLayout(StateDir, false)
	if c != nil || err != nil {
		return c, err
	}
	// Existing experimental snapshots retain their original initramfs mount
	// tree across RAM restore and envd exec. New boots reserve a separate path
	// so the established /.e2b template metadata file remains a regular file.
	return openLayout("/.e2b/rootfs", true)
}

func openLayout(stateDir string, legacy bool) (*Controller, error) {
	marker, err := os.OpenFile(stateDir+"/layout.json", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if legacy && errors.Is(err, unix.ENOTDIR) {
		return nil, nil // /.e2b is a normal metadata file on a legacy raw root.
	}
	if err != nil {
		return nil, err
	}
	var layout struct {
		Layout string `json:"layout"`
		Upper  string `json:"upper_mount"`
		Lower  string `json:"lower_mount"`
	}
	decoder := json.NewDecoder(io.LimitReader(marker, 4096))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&layout)
	closeErr := marker.Close()
	if err := errors.Join(err, closeErr); err != nil {
		return nil, err
	}
	if layout.Layout != Layout || layout.Upper != stateDir+"/upperfs" || layout.Lower != stateDir+"/lower" {
		return nil, errors.New("invalid pmem rootfs layout marker")
	}
	dir, err := os.OpenFile(stateDir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	upper, err := os.OpenFile(layout.Upper, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.Join(err, dir.Close())
	}
	fail := func(err error) (*Controller, error) { return nil, errors.Join(err, dir.Close(), upper.Close()) }
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(dir.Fd()), &st); err != nil {
		return fail(err)
	}
	if st.Type != unix.TMPFS_MAGIC {
		return fail(errors.New("pmem control state must be on tmpfs"))
	}
	if err := unix.Fstatfs(int(upper.Fd()), &st); err != nil {
		return fail(err)
	}
	if st.Type != unix.EXT4_SUPER_MAGIC || st.Flags&unix.ST_RDONLY != 0 {
		return fail(errors.New("pmem upper must be writable ext4"))
	}
	var device, mounted unix.Stat_t
	if err := unix.Stat("/dev/vda", &device); err != nil {
		return fail(err)
	}
	if err := unix.Fstat(int(upper.Fd()), &mounted); err != nil {
		return fail(err)
	}
	if device.Mode&unix.S_IFMT != unix.S_IFBLK || mounted.Dev != device.Rdev {
		return fail(errors.New("pmem upper does not reference /dev/vda"))
	}
	if err := unix.Statfs("/", &st); err != nil {
		return fail(err)
	}
	if st.Type != unix.OVERLAYFS_SUPER_MAGIC {
		return fail(errors.New("pmem root must be OverlayFS"))
	}
	c, err := openController(dir, upper)
	if err != nil {
		return fail(err)
	}
	return c, nil
}

func openController(dir, upper *os.File) (*Controller, error) {
	c := &Controller{dir: dir, upper: upper}
	f, err := os.OpenFile(c.journal(), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c.state); err != nil {
		return nil, err
	}
	switch c.state.Phase {
	case "", "preparing", "prepared", "committed":
	default:
		return nil, errors.New("invalid persisted resume phase")
	}
	if len(c.state.LifecycleID) > 128 || (c.state.Phase != "" && c.state.LifecycleID == "") {
		return nil, errors.New("invalid persisted resume identity")
	}
	return c, nil
}

func (c *Controller) journal() string { return fmt.Sprintf("/proc/self/fd/%d/resume.json", c.dir.Fd()) }

func (c *Controller) Mountpoint() string { return fmt.Sprintf("/proc/self/fd/%d", c.upper.Fd()) }

func (c *Controller) Snapshot() State { c.mu.Lock(); defer c.mu.Unlock(); return c.state }

// CanThaw is also the single guard used by the cgroup watchdog and handover
// failure paths. Only the authenticated commit handler can grant a temporary
// permit while it performs the actual thaw.
func (c *Controller) CanThaw() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closed && !c.state.Frozen && (c.permitThaw.Load() || c.state.Phase == "" || c.state.Phase == "committed")
}

func (c *Controller) Ready() bool { s := c.Snapshot(); return s.Phase == "committed" && !s.Frozen }

func (c *Controller) saveLocked(next State) error {
	if c.closed {
		return os.ErrClosed
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(c.journal()), ".resume-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err := errors.Join(err, f.Sync(), f.Close()); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), c.journal()); err != nil {
		return err
	}
	// Update memory after rename even if directory fsync fails: a retry and an
	// execve must not disagree about the phase already visible in the journal.
	c.state = next
	return c.dir.Sync()
}

func (c *Controller) BeginPrepare(lifecycle string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if lifecycle == "" || len(lifecycle) > 128 {
		return false, errors.New("invalid resume identity")
	}
	if c.state.LifecycleID == lifecycle && c.state.Phase == "committed" && !c.state.Frozen {
		return true, nil
	}
	next := c.state
	next.LifecycleID, next.Phase = lifecycle, "preparing"
	return false, c.saveLocked(next)
}

func (c *Controller) Prepared(lifecycle string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.LifecycleID != lifecycle || c.state.Frozen {
		return errors.New("resume identity or upper state changed")
	}
	next := c.state
	next.Phase = "prepared"
	return c.saveLocked(next)
}

func (c *Controller) SetFrozen(frozen bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	next := c.state
	next.Frozen = frozen
	return c.saveLocked(next)
}

func (c *Controller) Commit(lifecycle string, thaw func() error) error {
	c.mu.Lock()
	if c.state.LifecycleID != lifecycle || c.state.Frozen || (c.state.Phase != "prepared" && c.state.Phase != "committed") {
		c.mu.Unlock()
		return errors.New("resume was not prepared for this lifecycle")
	}
	if c.state.Phase == "committed" {
		c.mu.Unlock()
		return nil
	}
	c.permitThaw.Store(true)
	c.mu.Unlock()
	defer c.permitThaw.Store(false)
	if err := thaw(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	next := c.state
	next.Phase = "committed"
	return c.saveLocked(next)
}

// HoldUpgrade is called with the API init lock held until execve. The rollback
// restores the prior thaw policy if the outgoing upgrade fails.
func (c *Controller) HoldUpgrade() (func() error, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	previous := c.state
	if previous.LifecycleID == "" || previous.Frozen {
		return nil, errors.New("cannot upgrade before upper thaw and authentication")
	}
	next := previous
	next.Phase = "prepared"
	if err := c.saveLocked(next); err != nil {
		return nil, err
	}
	return func() error { c.mu.Lock(); defer c.mu.Unlock(); return c.saveLocked(previous) }, nil
}

func (c *Controller) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return errors.Join(c.upper.Close(), c.dir.Close())
}
