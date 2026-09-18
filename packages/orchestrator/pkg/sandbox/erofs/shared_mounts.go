//go:build linux

package erofs

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrSharedMountsClosed = errors.New("shared EROFS mounts are closed")
	ErrSharedMountsInUse  = errors.New("shared EROFS mounts still have runtime references")
)

// SharedMounts owns one store's active memory/disk mount pairs. Callers must
// authorize teamID before Acquire and release only after all consumers exit.
// There is no idle cache: the last reference starts cleanup immediately.
type SharedMounts struct {
	mu              sync.Mutex
	storeRoot, root string
	initErr         error
	closed          bool
	stopped         chan struct{}
	entries         map[sharedMountKey]*sharedMountEntry
	// Set only before use, to exercise ownership without privileged mounts.
	mount      func(context.Context, *Snapshot, string) (*Mounted, error)
	mountLower func(context.Context, *Store, *Lower, string) (*Mounted, error)
	unmount    func(*Mounted) error
}

type sharedMountKey struct{ team, generation, kind string }

type sharedMountEntry struct {
	key                  sharedMountKey
	digest               [sha256.Size]byte
	mounted              *Mounted
	refs, waiters        int
	busy                 chan struct{}
	cancel               context.CancelFunc // nonnil only while mounting
	abandoned            bool
	mountErr, cleanupErr error
}

// MountRef is a single runtime's reference. Do not copy it. Paths remain valid
// until Release; Release may be retried after a cleanup error.
type MountRef struct {
	owner                             *SharedMounts
	entry                             *sharedMountEntry
	memoryPath, diskPath, vmStatePath string
	lowerPath                         string
	released                          bool // protected by owner.mu
}

// NewSharedMounts does not touch the filesystem. Create one per Factory/store.
func NewSharedMounts(storeRoot string) *SharedMounts {
	root, err := filepath.Abs(storeRoot)
	return &SharedMounts{
		storeRoot: root, root: filepath.Join(root, ".shared-mounts"), initErr: err,
		entries: make(map[sharedMountKey]*sharedMountEntry), stopped: make(chan struct{}),
		mount: func(ctx context.Context, snapshot *Snapshot, root string) (*Mounted, error) {
			return snapshot.Mount(ctx, root)
		},
		unmount: (*Mounted).Close,
		mountLower: func(ctx context.Context, store *Store, lower *Lower, root string) (*Mounted, error) {
			return store.MountLower(ctx, lower, root)
		},
	}
}

func (s *SharedMounts) Root() string    { return s.root }
func (r *MountRef) MemoryPath() string  { return r.memoryPath }
func (r *MountRef) DiskPath() string    { return r.diskPath }
func (r *MountRef) LowerPath() string   { return r.lowerPath }
func (r *MountRef) VMStatePath() string { return r.vmStatePath }

// LoadContext verifies the full manifest and ordered dependency chain, with
// cancellation during artifact hashing, just like Load's internal loader.
func (s *Store) LoadContext(ctx context.Context, id string) (*Snapshot, error) {
	return s.load(ctx, id, make(map[string]bool))
}

func sharedManifestDigest(m Manifest) [sha256.Size]byte {
	data, _ := json.Marshal(m) // Manifest contains only JSON-supported fields.
	return sha256.Sum256(data)
}

// Acquire verifies even cache hits. The caller must not mutate snapshot during
// this call; the registry retains only its own verified descriptor and digest.
// A request cancellation drops its reservation, not another request's mount.
func (s *SharedMounts) Acquire(ctx context.Context, snapshot *Snapshot, teamID string) (*MountRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, ErrSharedMountsClosed
	}
	if s.initErr != nil {
		return nil, s.initErr
	}
	if snapshot == nil || snapshot.store == nil || teamID == "" {
		return nil, errors.New("snapshot, store and authorized team ID are required")
	}
	root, err := filepath.Abs(snapshot.store.Root)
	if err != nil {
		return nil, err
	}
	if root != s.storeRoot {
		return nil, errors.New("snapshot belongs to a different EROFS store")
	}
	// Copy the store as well: no caller-owned mutable descriptor survives into
	// the asynchronous mount operation.
	store := *snapshot.store
	store.Root = s.storeRoot
	expected := sharedManifestDigest(snapshot.Manifest)
	verified, err := store.LoadContext(ctx, snapshot.Manifest.ID)
	if err != nil {
		return nil, err
	}
	digest := sharedManifestDigest(verified.Manifest)
	if expected != digest {
		return nil, ErrSnapshotConflict
	}
	key := sharedMountKey{team: teamID, generation: verified.Manifest.ID}
	return s.acquireVerified(ctx, key, digest, func(ctx context.Context) (*Mounted, error) {
		return s.mount(ctx, verified, s.root)
	})
}

// AcquireLower shares one immutable lower across distinct memory/upper generations.
// A separate key kind prevents a generation ID from colliding with a lower ID.
func (s *SharedMounts) AcquireLower(ctx context.Context, lower *Lower, teamID string) (*MountRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.initErr != nil {
		return nil, s.initErr
	}
	if lower == nil || teamID == "" {
		return nil, errors.New("lower and authorized team ID are required")
	}
	store := &Store{Root: s.storeRoot}
	verified, err := store.LoadLower(ctx, lower.ID)
	if err != nil {
		return nil, err
	}
	digest := descriptorDigest(verified)
	if digest != descriptorDigest(lower) {
		return nil, ErrSnapshotConflict
	}
	return s.acquireVerified(ctx, sharedMountKey{team: teamID, generation: verified.ID, kind: "lower"}, digest,
		func(ctx context.Context) (*Mounted, error) { return s.mountLower(ctx, store, verified, s.root) })
}

func (s *SharedMounts) acquireVerified(ctx context.Context, key sharedMountKey, digest [32]byte, mount func(context.Context) (*Mounted, error)) (*MountRef, error) {
	for {
		s.mu.Lock()
		if err := ctx.Err(); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		if s.closed {
			s.mu.Unlock()
			return nil, ErrSharedMountsClosed
		}
		e := s.entries[key]
		if e == nil {
			mountCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
			e = &sharedMountEntry{key: key, digest: digest, busy: make(chan struct{}), cancel: cancel}
			s.entries[key] = e
			go s.mountEntry(mountCtx, mount, e)
		}
		if e.digest != digest {
			s.mu.Unlock()
			return nil, ErrSnapshotConflict
		}
		if e.cancel != nil && !e.abandoned {
			e.waiters++
			done := e.busy
			s.mu.Unlock()
			select {
			case <-done:
			case <-ctx.Done():
			case <-s.stopped:
			}
			s.mu.Lock()
			e.waiters--
			err := ctx.Err()
			if err == nil && s.closed {
				err = ErrSharedMountsClosed
			}
			if err == nil {
				err = e.mountErr
			}
			if err == nil {
				ref := s.reference(e)
				s.mu.Unlock()
				return ref, nil
			}
			s.cleanupUnused(e)
			s.mu.Unlock()
			return nil, err
		}
		if e.busy == nil && e.cleanupErr != nil {
			// A previous failed cleanup owns this key until a retry succeeds.
			s.startCleanup(e, false)
		}
		if e.busy != nil {
			done := e.busy
			s.mu.Unlock()
			select {
			case <-done:
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-s.stopped:
				return nil, ErrSharedMountsClosed
			}
			s.mu.Lock()
			// An abandoned mount may hand cleanup to a new worker before we
			// wake. Wait for that operation instead of returning its old error.
			if e.busy != nil {
				s.mu.Unlock()
				continue
			}
			err := e.cleanupErr
			s.mu.Unlock()
			if err != nil {
				return nil, err
			}
			continue
		}
		ref := s.reference(e)
		s.mu.Unlock()
		return ref, nil
	}
}

// The following state helpers require s.mu. Only mount/cleanup workers perform
// filesystem operations, always outside that lock.
func (s *SharedMounts) reference(e *sharedMountEntry) *MountRef {
	e.refs++
	return &MountRef{owner: s, entry: e, memoryPath: e.mounted.MemoryPath,
		diskPath: e.mounted.DiskPath, vmStatePath: e.mounted.VMStatePath, lowerPath: e.mounted.LowerPath}
}

func (s *SharedMounts) cleanupUnused(e *sharedMountEntry) {
	if e.refs != 0 || e.waiters != 0 || e.cleanupErr != nil {
		return
	}
	if e.cancel != nil {
		e.abandoned = true
		e.cancel()
	} else if e.busy == nil && s.entries[e.key] == e {
		s.startCleanup(e, true)
	}
}

func (s *SharedMounts) mountEntry(ctx context.Context, mount func(context.Context) (*Mounted, error), e *sharedMountEntry) {
	mounted, err := mount(ctx)
	if err == nil && mounted == nil {
		err = errors.New("EROFS mount returned no resources")
	}
	s.mu.Lock()
	e.cancel()
	e.cancel = nil
	e.mounted, e.mountErr = mounted, err
	if err != nil || e.waiters == 0 || s.closed {
		// Retain even a partial Mounted until cleanup succeeds. This worker also
		// owns cleanup when every waiter has already returned on cancellation.
		s.mu.Unlock()
		cleanupErr := s.closeMounted(mounted)
		s.mu.Lock()
		e.cleanupErr = cleanupErr
		e.mountErr = errors.Join(err, cleanupErr)
		if cleanupErr == nil {
			delete(s.entries, e.key)
		}
	}
	close(e.busy)
	e.busy = nil
	if e.cleanupErr != nil && !s.closed {
		s.startCleanup(e, true)
	}
	s.mu.Unlock()
}

func (s *SharedMounts) closeMounted(m *Mounted) error {
	if m == nil {
		return nil
	}
	return s.unmount(m)
}

// retry is used only when no MountRef was delivered, so nativeResources has
// no handle to retry. The same worker owns busy across attempts, preventing a
// new Acquire or Close from overlapping cleanup or replacing the entry.
func (s *SharedMounts) startCleanup(e *sharedMountEntry, retry bool) {
	e.busy = make(chan struct{})
	go func() {
		for {
			// Pace retries after the initial mount cleanup failure as well.
			if retry && e.cleanupErr != nil {
				timer := time.NewTimer(100 * time.Millisecond)
				select {
				case <-timer.C:
				case <-s.stopped:
				}
				timer.Stop()
			}
			err := s.closeMounted(e.mounted)
			s.mu.Lock()
			e.cleanupErr = err
			if err == nil {
				delete(s.entries, e.key)
			}
			if err == nil || !retry || s.closed {
				close(e.busy)
				e.busy = nil
				s.mu.Unlock()
				return
			}
			s.mu.Unlock()
		}
	}()
}

// Release decrements exactly once, even when cleanup fails. Retrying this same
// handle retries cleanup only for its own entry, never a replacement generation.
func (r *MountRef) Release() error {
	if r == nil {
		return nil
	}
	s, e := r.owner, r.entry
	s.mu.Lock()
	if !r.released {
		r.released = true
		e.refs--
	}
	if e.refs != 0 || e.waiters != 0 || s.entries[e.key] != e {
		s.mu.Unlock()
		return nil
	}
	if e.busy == nil {
		s.startCleanup(e, false)
	}
	done := e.busy
	s.mu.Unlock()
	<-done
	s.mu.Lock()
	defer s.mu.Unlock()
	return e.cleanupErr
}

// Close permanently rejects new acquisitions and cancels outstanding mounts.
// Call it after runtime teardown. Live references are never forcibly unmounted:
// ErrSharedMountsInUse requires releasing them and retrying Close. Cleanup errors
// are likewise retryable. Shutdown wakes automatic retries for a final attempt;
// persistent failures remain owned by the table for a later Close, without an
// idle retry goroutine. ctx bounds waiting, not an in-flight filesystem operation.
// Workers retain ownership even if it expires. No filesystem operation runs
// under the table lock.
func (s *SharedMounts) Close(ctx context.Context) error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.stopped)
	}
	entries := make([]*sharedMountEntry, 0, len(s.entries))
	waits := make([]<-chan struct{}, 0, len(s.entries))
	var result error
	for _, e := range s.entries {
		entries = append(entries, e)
		if e.refs != 0 {
			// Remember this observation even if Release starts cleanup before
			// the final check: that cleanup was not included in waits.
			result = errors.Join(result, fmt.Errorf("%w: team %q generation %q", ErrSharedMountsInUse, e.key.team, e.key.generation))
		}
		if e.cancel != nil {
			e.abandoned = true
			e.cancel()
		}
		if e.busy == nil && e.refs == 0 {
			s.startCleanup(e, false)
		}
		if e.busy != nil {
			waits = append(waits, e.busy)
		}
	}
	s.mu.Unlock()
	for _, done := range waits {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range entries {
		result = errors.Join(result, e.cleanupErr)
	}
	return errors.Join(result, ctx.Err())
}
