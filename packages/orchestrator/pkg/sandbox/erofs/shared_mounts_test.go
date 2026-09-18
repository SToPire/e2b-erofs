//go:build linux

package erofs

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// These fixtures exercise the real manifest/dependency/hash verifier. Only the
// privileged mount and unmount operations are replaced; no EROFS tools are needed.
func sharedSnapshot(t *testing.T, store *Store, id string, parent *Snapshot) *Snapshot {
	t.Helper()
	dir := filepath.Join(store.Root, id)
	require.NoError(t, os.MkdirAll(dir, 0700))
	artifact := func(name string) Artifact {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(id+"/"+name), 0600))
		a, err := describe(path, filepath.Join(id, name))
		require.NoError(t, err)
		return a
	}
	m := Manifest{Format: Format, ID: id,
		Memory:  Image{Artifact: artifact("memory.erofs"), Size: BlockSize},
		Disk:    Image{Artifact: artifact("disk.erofs"), Size: BlockSize},
		VMState: artifact("vmstate")}
	metadata := artifact("metadata.json")
	m.Metadata = &metadata
	if parent != nil {
		m.ParentID = parent.Manifest.ID
		m.Memory.Devices = append([]Artifact{parent.Manifest.Memory.Artifact}, parent.Manifest.Memory.Devices...)
		m.Disk.Devices = append([]Artifact{parent.Manifest.Disk.Artifact}, parent.Manifest.Disk.Devices...)
	}
	sharedWriteManifest(t, dir, m)
	snapshot, err := store.LoadContext(t.Context(), id)
	require.NoError(t, err)
	return snapshot
}

func sharedWriteManifest(t *testing.T, dir string, m Manifest) {
	t.Helper()
	data, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, ManifestName), data, 0600))
}

type sharedFixture struct {
	registry       *SharedMounts
	store          *Store
	snapshot       *Snapshot
	mounts, closes atomic.Int32
}

func newSharedFixture(t *testing.T) *sharedFixture {
	t.Helper()
	store, err := NewStore(t.TempDir(), Options{})
	require.NoError(t, err)
	f := &sharedFixture{store: store, registry: NewSharedMounts(store.Root)}
	f.snapshot = sharedSnapshot(t, store, "g0", nil)
	f.registry.mount = func(_ context.Context, snapshot *Snapshot, root string) (*Mounted, error) {
		f.mounts.Add(1)
		if err := os.MkdirAll(root, 0700); err != nil {
			return nil, err
		}
		dir, err := os.MkdirTemp(root, snapshot.Manifest.ID+"-")
		if err != nil {
			return nil, err
		}
		return &Mounted{dir: dir, MemoryPath: filepath.Join(dir, "memory", "memfile"),
			DiskPath: filepath.Join(dir, "disk", "rootfs.ext4"), VMStatePath: snapshot.VMStatePath()}, nil
	}
	f.registry.unmount = func(m *Mounted) error { f.closes.Add(1); return m.Close() }
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, f.registry.Close(ctx))
	})
	return f
}

type sharedResult struct {
	ref *MountRef
	err error
}

func sharedAcquire(ctx context.Context, s *SharedMounts, snapshot *Snapshot, team string) <-chan sharedResult {
	out := make(chan sharedResult, 1)
	go func() { ref, err := s.Acquire(ctx, snapshot, team); out <- sharedResult{ref, err} }()
	return out
}
func sharedReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("shared mount operation stalled")
		var zero T
		return zero
	}
}
func sharedWaiters(t *testing.T, s *SharedMounts, n int) {
	t.Helper()
	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		count := 0
		for _, e := range s.entries {
			count += e.waiters
		}
		return count == n
	}, 5*time.Second, time.Millisecond)
}
func sharedEmpty(t *testing.T, s *SharedMounts) {
	t.Helper()
	require.Eventually(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.entries) == 0 }, 5*time.Second, time.Millisecond)
}

func TestSharedMountsConstructorIsLazy(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent-store")
	s := NewSharedMounts(root)
	require.Equal(t, filepath.Join(root, ".shared-mounts"), s.Root())
	require.NoError(t, s.Close(t.Context()))
	_, err := os.Stat(root)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestSharedMountsConcurrentFirstAcquireAndDoubleRelease(t *testing.T) {
	f := newSharedFixture(t)
	original := f.registry.mount
	gate := make(chan struct{})
	f.registry.mount = func(ctx context.Context, s *Snapshot, root string) (*Mounted, error) {
		<-gate
		return original(ctx, s, root)
	}
	const count = 24
	results := make([]<-chan sharedResult, count)
	for i := range results {
		results[i] = sharedAcquire(t.Context(), f.registry, f.snapshot, "team")
	}
	sharedWaiters(t, f.registry, count)
	close(gate)
	refs := make([]*MountRef, count)
	for i, result := range results {
		r := sharedReceive(t, result)
		require.NoError(t, r.err)
		refs[i] = r.ref
		require.Equal(t, refs[0].MemoryPath(), r.ref.MemoryPath())
		require.Equal(t, refs[0].DiskPath(), r.ref.DiskPath())
		require.Equal(t, f.snapshot.VMStatePath(), r.ref.VMStatePath())
		require.True(t, filepath.IsLocal(mustSharedRel(t, f.registry.Root(), r.ref.MemoryPath())))
	}
	require.EqualValues(t, 1, f.mounts.Load())
	require.NoError(t, refs[0].Release())
	require.NoError(t, refs[0].Release())
	require.Zero(t, f.closes.Load())
	var wg sync.WaitGroup
	for _, ref := range refs[1:] {
		for range 2 {
			wg.Go(func() {
				if err := ref.Release(); err != nil {
					t.Error(err)
				}
			})
		}
	}
	wg.Wait()
	require.EqualValues(t, 1, f.closes.Load())
	sharedEmpty(t, f.registry)
	next, err := f.registry.Acquire(t.Context(), f.snapshot, "team")
	require.NoError(t, err)
	require.NotEqual(t, refs[0].MemoryPath(), next.MemoryPath())
	require.NoError(t, refs[count-1].Release()) // cannot decrement the replacement
	require.EqualValues(t, 1, f.closes.Load())
	require.NoError(t, next.Release())
	require.EqualValues(t, 2, f.mounts.Load())
}

func mustSharedRel(t *testing.T, root, path string) string {
	t.Helper()
	rel, err := filepath.Rel(root, path)
	require.NoError(t, err)
	return rel
}

func TestSharedMountsDifferentTeamsAndGenerationsMountConcurrently(t *testing.T) {
	f := newSharedFixture(t)
	child := sharedSnapshot(t, f.store, "g1", f.snapshot)
	grandchild := sharedSnapshot(t, f.store, "g2", child)
	original := f.registry.mount
	started := make(chan Manifest, 3)
	gate := make(chan struct{})
	f.registry.mount = func(ctx context.Context, s *Snapshot, root string) (*Mounted, error) {
		started <- s.Manifest
		<-gate
		return original(ctx, s, root)
	}
	a := sharedAcquire(t.Context(), f.registry, f.snapshot, "team-a")
	b := sharedAcquire(t.Context(), f.registry, f.snapshot, "team-b")
	c := sharedAcquire(t.Context(), f.registry, grandchild, "team-a")
	for range 3 {
		m := sharedReceive(t, started)
		if m.ID == "g2" {
			require.Equal(t, []Artifact{child.Manifest.Memory.Artifact, f.snapshot.Manifest.Memory.Artifact}, m.Memory.Devices)
			require.Equal(t, []Artifact{child.Manifest.Disk.Artifact, f.snapshot.Manifest.Disk.Artifact}, m.Disk.Devices)
		}
	}
	close(gate)
	paths := make(map[string]bool)
	for _, result := range []<-chan sharedResult{a, b, c} {
		r := sharedReceive(t, result)
		require.NoError(t, r.err)
		require.False(t, paths[r.ref.MemoryPath()])
		paths[r.ref.MemoryPath()] = true
		require.NoError(t, r.ref.Release())
	}
	require.EqualValues(t, 3, f.mounts.Load())
}

func TestSharedMountsCanceledLeaderDoesNotCancelWaiter(t *testing.T) {
	f := newSharedFixture(t)
	original := f.registry.mount
	started := make(chan context.Context, 1)
	gate := make(chan struct{})
	f.registry.mount = func(ctx context.Context, s *Snapshot, root string) (*Mounted, error) {
		started <- ctx
		<-gate
		return original(ctx, s, root)
	}
	ctx, cancel := context.WithCancel(t.Context())
	a := sharedAcquire(ctx, f.registry, f.snapshot, "team")
	mountCtx := sharedReceive(t, started)
	b := sharedAcquire(t.Context(), f.registry, f.snapshot, "team")
	sharedWaiters(t, f.registry, 2)
	cancel()
	require.ErrorIs(t, sharedReceive(t, a).err, context.Canceled)
	require.NoError(t, mountCtx.Err())
	close(gate)
	r := sharedReceive(t, b)
	require.NoError(t, r.err)
	require.NoError(t, r.ref.Release())
	require.EqualValues(t, 1, f.mounts.Load())
	require.EqualValues(t, 1, f.closes.Load())
}

func TestSharedMountsAllWaitersCancelPartialMountCleanupRetry(t *testing.T) {
	f := newSharedFixture(t)
	original := f.registry.mount
	started := make(chan struct{})
	gate := make(chan struct{})
	var partial *Mounted
	f.registry.mount = func(ctx context.Context, s *Snapshot, root string) (*Mounted, error) {
		var err error
		partial, err = original(ctx, s, root)
		if err != nil {
			return partial, err
		}
		close(started)
		<-ctx.Done()
		<-gate
		return partial, ctx.Err()
	}
	cleaned := make(chan struct{}, 1)
	f.registry.unmount = func(m *Mounted) error {
		require.Same(t, partial, m)
		if f.closes.Add(1) == 1 {
			cleaned <- struct{}{}
			return unix.EBUSY
		}
		return m.Close()
	}
	ctx, cancel := context.WithCancel(t.Context())
	a := sharedAcquire(ctx, f.registry, f.snapshot, "team")
	sharedReceive(t, started)
	b := sharedAcquire(ctx, f.registry, f.snapshot, "team")
	sharedWaiters(t, f.registry, 2)
	cancel()
	require.ErrorIs(t, sharedReceive(t, a).err, context.Canceled)
	require.ErrorIs(t, sharedReceive(t, b).err, context.Canceled)
	close(gate)
	sharedReceive(t, cleaned)
	// No Acquire or Close drives the retry after both callers have returned.
	sharedEmpty(t, f.registry)
	require.EqualValues(t, 2, f.closes.Load())
	_, err := os.Stat(partial.dir)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestSharedMountsFailureOwnsPartialAndRetriesBeforeRemount(t *testing.T) {
	f := newSharedFixture(t)
	original := f.registry.mount
	mountFailure := errors.New("disk mount failed")
	f.registry.mount = func(ctx context.Context, s *Snapshot, root string) (*Mounted, error) {
		m, err := original(ctx, s, root)
		if err != nil {
			return m, err
		}
		if f.mounts.Load() == 1 {
			return m, mountFailure
		}
		return m, nil
	}
	var fail atomic.Bool
	fail.Store(true)
	f.registry.unmount = func(m *Mounted) error {
		f.closes.Add(1)
		if fail.Load() {
			return unix.EBUSY
		}
		return m.Close()
	}
	ref, err := f.registry.Acquire(t.Context(), f.snapshot, "team")
	require.Nil(t, ref)
	require.ErrorIs(t, err, mountFailure)
	require.ErrorIs(t, err, unix.EBUSY)
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	ref, err = f.registry.Acquire(ctx, f.snapshot, "team")
	require.Nil(t, ref)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.EqualValues(t, 1, f.mounts.Load())
	fail.Store(false)
	ref, err = f.registry.Acquire(t.Context(), f.snapshot, "team")
	require.NoError(t, err)
	require.EqualValues(t, 2, f.mounts.Load())
	require.NoError(t, ref.Release())
}

func TestSharedMountsReleaseRetryDoesNotDecrementTwice(t *testing.T) {
	f := newSharedFixture(t)
	f.registry.unmount = func(m *Mounted) error {
		if f.closes.Add(1) == 1 {
			return unix.EBUSY
		}
		return m.Close()
	}
	ref, err := f.registry.Acquire(t.Context(), f.snapshot, "team")
	require.NoError(t, err)
	require.ErrorIs(t, ref.Release(), unix.EBUSY)
	require.NoError(t, ref.Release())
	require.NoError(t, ref.Release())
	require.EqualValues(t, 2, f.closes.Load())
	sharedEmpty(t, f.registry)
}

func TestSharedMountsLastReleaseSerializesWithAcquire(t *testing.T) {
	f := newSharedFixture(t)
	started := make(chan struct{})
	gate := make(chan struct{})
	f.registry.unmount = func(m *Mounted) error {
		if f.closes.Add(1) == 1 {
			close(started)
			<-gate
		}
		return m.Close()
	}
	ref, err := f.registry.Acquire(t.Context(), f.snapshot, "team")
	require.NoError(t, err)
	released := make(chan error, 1)
	go func() { released <- ref.Release() }()
	sharedReceive(t, started)
	ctx, cancel := context.WithCancel(t.Context())
	canceled := sharedAcquire(ctx, f.registry, f.snapshot, "team")
	next := sharedAcquire(t.Context(), f.registry, f.snapshot, "team")
	// Another key can finish while this key's unmount is blocked.
	other, err := f.registry.Acquire(t.Context(), f.snapshot, "other")
	require.NoError(t, err)
	require.NoError(t, other.Release())
	require.EqualValues(t, 2, f.mounts.Load())
	cancel()
	require.ErrorIs(t, sharedReceive(t, canceled).err, context.Canceled)
	close(gate)
	require.NoError(t, sharedReceive(t, released))
	r := sharedReceive(t, next)
	require.NoError(t, r.err)
	require.NotEqual(t, ref.MemoryPath(), r.ref.MemoryPath())
	require.EqualValues(t, 3, f.mounts.Load())
	require.NoError(t, ref.Release())
	require.NoError(t, r.ref.Release())
}

func TestSharedMountsManifestAndStoreVerification(t *testing.T) {
	f := newSharedFixture(t)
	ref, err := f.registry.Acquire(t.Context(), f.snapshot, "team")
	require.NoError(t, err)
	defer func() { require.NoError(t, ref.Release()) }()
	original := f.snapshot.Manifest
	f.snapshot.Manifest.Metadata.File = "wrong"
	_, err = f.registry.Acquire(t.Context(), f.snapshot, "team")
	require.ErrorIs(t, err, ErrSnapshotConflict)
	// Restore from disk; the caller's pointer mutation did not change the entry.
	f.snapshot, err = f.store.LoadContext(t.Context(), "g0")
	require.NoError(t, err)
	again, err := f.registry.Acquire(t.Context(), f.snapshot, "team")
	require.NoError(t, err)
	require.Equal(t, ref.MemoryPath(), again.MemoryPath())
	require.NoError(t, again.Release())
	for _, invalid := range []*Snapshot{nil, {}, {Manifest: original}, {Manifest: original, store: &Store{Root: t.TempDir()}}} {
		_, err := f.registry.Acquire(t.Context(), invalid, "team")
		require.Error(t, err)
	}
	_, err = f.registry.Acquire(t.Context(), f.snapshot, "")
	require.Error(t, err)
	// A valid but different full manifest for an already active key conflicts.
	changed := f.snapshot.Manifest
	changed.Memory.Size *= 2
	sharedWriteManifest(t, f.snapshot.Dir, changed)
	changedSnapshot, err := f.store.LoadContext(t.Context(), "g0")
	require.NoError(t, err)
	_, err = f.registry.Acquire(t.Context(), changedSnapshot, "team")
	require.ErrorIs(t, err, ErrSnapshotConflict)
	// Cache hits still verify artifact contents.
	require.NoError(t, os.WriteFile(f.snapshot.VMStatePath(), []byte("corrupt"), 0600))
	_, err = f.registry.Acquire(t.Context(), f.snapshot, "team")
	require.Error(t, err)
	require.EqualValues(t, 1, f.mounts.Load())
}

func TestSharedMountsCallerDevicesAreNotRetained(t *testing.T) {
	f := newSharedFixture(t)
	child := sharedSnapshot(t, f.store, "g1", f.snapshot)
	original := f.registry.mount
	var owned *Snapshot
	f.registry.mount = func(ctx context.Context, s *Snapshot, root string) (*Mounted, error) {
		owned = s
		return original(ctx, s, root)
	}
	ref, err := f.registry.Acquire(t.Context(), child, "team")
	require.NoError(t, err)
	before := sharedManifestDigest(owned.Manifest)
	child.Manifest.Memory.Devices[0].SHA256 = "modified"
	child.Manifest.Disk.Devices[0].File = "modified"
	child.Manifest.Metadata.Bytes++
	require.Equal(t, before, sharedManifestDigest(owned.Manifest))
	require.NoError(t, ref.Release())
}

func TestSharedMountsClosePreservesLiveReferencesAndIsTerminal(t *testing.T) {
	f := newSharedFixture(t)
	ref, err := f.registry.Acquire(t.Context(), f.snapshot, "team")
	require.NoError(t, err)
	require.ErrorIs(t, f.registry.Close(t.Context()), ErrSharedMountsInUse)
	require.Zero(t, f.closes.Load())
	_, err = f.registry.Acquire(t.Context(), f.snapshot, "team")
	require.ErrorIs(t, err, ErrSharedMountsClosed)
	require.NoError(t, ref.Release())
	require.NoError(t, f.registry.Close(t.Context()))
	require.NoError(t, f.registry.Close(t.Context()))
	require.EqualValues(t, 1, f.closes.Load())
}

func TestSharedMountsCloseCancellationDuringMountRetainsOwnership(t *testing.T) {
	f := newSharedFixture(t)
	original := f.registry.mount
	started := make(chan struct{})
	gate := make(chan struct{})
	f.registry.mount = func(ctx context.Context, s *Snapshot, root string) (*Mounted, error) {
		m, err := original(ctx, s, root)
		if err != nil {
			return m, err
		}
		close(started)
		<-ctx.Done()
		<-gate
		return m, nil // even a mount ignoring cancellation must be cleaned
	}
	result := sharedAcquire(t.Context(), f.registry, f.snapshot, "team")
	sharedReceive(t, started)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, f.registry.Close(ctx), context.Canceled)
	r := sharedReceive(t, result)
	require.Nil(t, r.ref)
	require.ErrorIs(t, r.err, ErrSharedMountsClosed)
	close(gate)
	require.NoError(t, f.registry.Close(t.Context()))
	require.EqualValues(t, 1, f.closes.Load())
	sharedEmpty(t, f.registry)
}

func TestSharedMountsAlreadyCanceledAcquireDoesNoWork(t *testing.T) {
	f := newSharedFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	ref, err := f.registry.Acquire(ctx, f.snapshot, "team")
	require.Nil(t, ref)
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, f.mounts.Load())
	sharedEmpty(t, f.registry)
}

func TestSharedMountsCanceledAtSuccessfulMountCompletion(t *testing.T) {
	f := newSharedFixture(t)
	original := f.registry.mount
	ctx, cancel := context.WithCancel(t.Context())
	f.registry.mount = func(ctx context.Context, s *Snapshot, root string) (*Mounted, error) {
		m, err := original(ctx, s, root)
		cancel() // caller cancels after resources exist, before receiving a handle
		return m, err
	}
	ref, err := f.registry.Acquire(ctx, f.snapshot, "team")
	require.Nil(t, ref)
	require.ErrorIs(t, err, context.Canceled)
	sharedEmpty(t, f.registry)
	require.EqualValues(t, 1, f.mounts.Load())
	require.EqualValues(t, 1, f.closes.Load())
}

func TestSharedMountsCloseRetriesCleanupFailure(t *testing.T) {
	f := newSharedFixture(t)
	f.registry.unmount = func(m *Mounted) error {
		if f.closes.Add(1) <= 2 {
			return unix.EBUSY
		}
		return m.Close()
	}
	ref, err := f.registry.Acquire(t.Context(), f.snapshot, "team")
	require.NoError(t, err)
	require.ErrorIs(t, ref.Release(), unix.EBUSY)
	require.ErrorIs(t, f.registry.Close(t.Context()), unix.EBUSY)
	require.NoError(t, f.registry.Close(t.Context()))
	require.NoError(t, ref.Release())
	require.EqualValues(t, 3, f.closes.Load())
}

func TestSharedMountsMountFailureWithoutResourcesAllowsRetry(t *testing.T) {
	for _, nilSuccess := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "nil-success"}[nilSuccess], func(t *testing.T) {
			f := newSharedFixture(t)
			original := f.registry.mount
			var attempts atomic.Int32
			f.registry.mount = func(ctx context.Context, s *Snapshot, root string) (*Mounted, error) {
				if attempts.Add(1) == 1 {
					if nilSuccess {
						return nil, nil
					}
					return nil, unix.ENOMEM
				}
				return original(ctx, s, root)
			}
			ref, err := f.registry.Acquire(t.Context(), f.snapshot, "team")
			require.Nil(t, ref)
			require.Error(t, err)
			require.Zero(t, f.closes.Load())
			ref, err = f.registry.Acquire(t.Context(), f.snapshot, "team")
			require.NoError(t, err)
			require.NoError(t, ref.Release())
		})
	}
}

func TestSharedMountsRejectsCorruptDependencyOnReuse(t *testing.T) {
	f := newSharedFixture(t)
	child := sharedSnapshot(t, f.store, "g1", f.snapshot)
	ref, err := f.registry.Acquire(t.Context(), child, "team")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(f.snapshot.Dir, "memory.erofs"), []byte("corrupt parent"), 0600))
	_, err = f.registry.Acquire(t.Context(), child, "team")
	require.Error(t, err)
	require.EqualValues(t, 1, f.mounts.Load())
	require.NoError(t, ref.Release())
}

func TestSharedMountsFailedAcquireCleansWithoutAnotherCaller(t *testing.T) {
	f := newSharedFixture(t)
	original := f.registry.mount
	var partial *Mounted
	f.registry.mount = func(ctx context.Context, s *Snapshot, root string) (*Mounted, error) {
		var err error
		partial, err = original(ctx, s, root)
		return partial, errors.Join(err, unix.ENOMEM)
	}
	f.registry.unmount = func(m *Mounted) error {
		if m != partial {
			t.Error("cleanup lost partial mount ownership")
		}
		if f.closes.Add(1) == 1 {
			return unix.EBUSY
		}
		return m.Close()
	}
	ref, err := f.registry.Acquire(t.Context(), f.snapshot, "team")
	require.Nil(t, ref)
	require.ErrorIs(t, err, unix.ENOMEM)
	require.ErrorIs(t, err, unix.EBUSY)
	sharedEmpty(t, f.registry)
	require.EqualValues(t, 2, f.closes.Load())
	_, err = os.Stat(partial.dir)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestSharedMountsOrphanRetryCloseRetainsPersistentFailure(t *testing.T) {
	for _, cancelClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "wait", true: "cancel"}[cancelClose], func(t *testing.T) {
			f := newSharedFixture(t)
			original := f.registry.mount
			var partial *Mounted
			f.registry.mount = func(ctx context.Context, s *Snapshot, root string) (*Mounted, error) {
				var err error
				partial, err = original(ctx, s, root)
				return partial, errors.Join(err, unix.ENOMEM)
			}
			started := make(chan struct{})
			gate := make(chan struct{})
			var unblock sync.Once
			defer unblock.Do(func() { close(gate) })
			var fail atomic.Bool
			fail.Store(true)
			defer fail.Store(false)
			var active atomic.Int32
			f.registry.unmount = func(m *Mounted) error {
				if active.Add(1) != 1 {
					t.Error("overlapping cleanup attempts")
				}
				defer active.Add(-1)
				if m != partial {
					t.Error("cleanup lost partial mount ownership")
				}
				if f.closes.Add(1) == 2 {
					close(started)
					<-gate
				}
				if fail.Load() {
					return unix.EBUSY
				}
				return m.Close()
			}
			ref, err := f.registry.Acquire(t.Context(), f.snapshot, "team")
			require.Nil(t, ref)
			require.ErrorIs(t, err, unix.ENOMEM)
			sharedReceive(t, started) // autonomous second attempt is in flight
			f.registry.mu.Lock()
			e := f.registry.entries[sharedMountKey{team: "team", generation: "g0"}]
			done := e.busy
			f.registry.mu.Unlock()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if cancelClose {
				cancel()
			}
			closed := make(chan error, 1)
			go func() { closed <- f.registry.Close(ctx) }()
			sharedReceive(t, f.registry.stopped)
			if cancelClose {
				require.ErrorIs(t, sharedReceive(t, closed), context.Canceled)
			} else {
				select {
				case err := <-closed:
					t.Fatalf("Close returned before cleanup finished: %v", err)
				default:
				}
			}
			unblock.Do(func() { close(gate) })
			sharedReceive(t, done) // the retry worker exits despite persistent failure
			if !cancelClose {
				require.ErrorIs(t, sharedReceive(t, closed), unix.EBUSY)
			}
			f.registry.mu.Lock()
			retained := f.registry.entries[e.key] == e && e.mounted == partial && e.busy == nil && errors.Is(e.cleanupErr, unix.EBUSY)
			f.registry.mu.Unlock()
			require.True(t, retained)
			require.EqualValues(t, 2, f.closes.Load())
			require.Zero(t, active.Load())
			_, err = os.Stat(partial.dir)
			require.NoError(t, err)
			fail.Store(false)
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					if err := f.registry.Close(t.Context()); err != nil {
						t.Error(err)
					}
				})
			}
			wg.Wait()
			sharedEmpty(t, f.registry)
			require.EqualValues(t, 3, f.closes.Load())
		})
	}
}

// Observe each busy-select enrollment without blocking the caller. Verification
// uses Err(), so Done() identifies the Acquire waits in these tests.
type sharedObservedContext struct {
	context.Context
	entered chan struct{}
}

func (c *sharedObservedContext) Done() <-chan struct{} {
	select {
	case c.entered <- struct{}{}:
	default:
	}
	return c.Context.Done()
}

func TestSharedMountsAcquireWaitsForReplacementCleanup(t *testing.T) {
	f := newSharedFixture(t)
	original := f.registry.mount
	mountStarted := make(chan struct{})
	mountGate := make(chan struct{})
	retryStarted := make(chan struct{})
	retryGate := make(chan struct{})
	var openMount, openRetry sync.Once
	defer openMount.Do(func() { close(mountGate) })
	defer openRetry.Do(func() { close(retryGate) })
	f.registry.mount = func(ctx context.Context, s *Snapshot, root string) (*Mounted, error) {
		m, err := original(ctx, s, root)
		if f.mounts.Load() == 1 {
			close(mountStarted)
			<-ctx.Done()
			<-mountGate
			return m, errors.Join(err, ctx.Err())
		}
		return m, err
	}
	f.registry.unmount = func(m *Mounted) error {
		switch f.closes.Add(1) {
		case 1:
			return unix.EBUSY
		case 2:
			close(retryStarted)
			<-retryGate
		}
		return m.Close()
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	leader := sharedAcquire(ctx, f.registry, f.snapshot, "team")
	sharedReceive(t, mountStarted)
	cancel()
	require.ErrorIs(t, sharedReceive(t, leader).err, context.Canceled)
	f.registry.mu.Lock()
	entry := f.registry.entries[sharedMountKey{team: "team", generation: "g0"}]
	oldBusy := entry.busy
	abandoned := entry.abandoned
	f.registry.mu.Unlock()
	require.True(t, abandoned)
	newcomerCtx := &sharedObservedContext{Context: t.Context(), entered: make(chan struct{}, 1)}
	newcomer := sharedAcquire(newcomerCtx, f.registry, f.snapshot, "team")
	sharedReceive(t, newcomerCtx.entered) // enrolled on abandoned mount's channel
	openMount.Do(func() { close(mountGate) })
	select {
	case <-newcomerCtx.entered: // re-enrolled on replacement cleanup's channel
	case r := <-newcomer:
		if r.ref != nil {
			require.NoError(t, r.ref.Release())
		}
		t.Fatalf("Acquire returned before replacement cleanup completed: %v", r.err)
	case <-time.After(5 * time.Second):
		t.Fatal("Acquire did not re-wait for replacement cleanup")
	}
	sharedReceive(t, retryStarted)
	f.registry.mu.Lock()
	active := entry.busy != nil && entry.busy != oldBusy && f.registry.entries[entry.key] == entry
	f.registry.mu.Unlock()
	require.True(t, active)
	require.NoError(t, newcomerCtx.Err())
	require.EqualValues(t, 1, f.mounts.Load())
	select {
	case r := <-newcomer:
		if r.ref != nil {
			require.NoError(t, r.ref.Release())
		}
		t.Fatalf("Acquire returned while cleanup was blocked: %v", r.err)
	default:
	}
	openRetry.Do(func() { close(retryGate) })
	r := sharedReceive(t, newcomer)
	require.NoError(t, r.err)
	require.NotNil(t, r.ref)
	require.EqualValues(t, 2, f.mounts.Load())
	require.EqualValues(t, 2, f.closes.Load())
	require.NoError(t, r.ref.Release())
	sharedEmpty(t, f.registry)
	require.EqualValues(t, 3, f.closes.Load())
}

func TestSharedMountsAcquireReturnsTerminalReleaseCleanupError(t *testing.T) {
	f := newSharedFixture(t)
	var fail atomic.Bool
	fail.Store(true)
	defer fail.Store(false)
	f.registry.unmount = func(m *Mounted) error {
		f.closes.Add(1)
		if fail.Load() {
			return unix.EBUSY
		}
		return m.Close()
	}
	ref, err := f.registry.Acquire(t.Context(), f.snapshot, "team")
	require.NoError(t, err)
	require.ErrorIs(t, ref.Release(), unix.EBUSY)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	newcomer, err := f.registry.Acquire(ctx, f.snapshot, "team")
	require.Nil(t, newcomer)
	require.ErrorIs(t, err, unix.EBUSY)
	require.EqualValues(t, 2, f.closes.Load())
	f.registry.mu.Lock()
	terminal := ref.entry.busy == nil && errors.Is(ref.entry.cleanupErr, unix.EBUSY)
	f.registry.mu.Unlock()
	require.True(t, terminal)
	fail.Store(false)
	require.NoError(t, ref.Release())
	sharedEmpty(t, f.registry)
	require.EqualValues(t, 3, f.closes.Load())
}
