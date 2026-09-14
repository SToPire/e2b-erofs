//go:build linux

package sandbox

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/rootfs"
)

func TestNativeResourcesCloseDiskBeforeMountAndOnlyOnce(t *testing.T) {
	t.Parallel()
	var calls []string
	r := &nativeResources{
		closeDisk:  func(context.Context) error { calls = append(calls, "disk"); return nil },
		closeMount: func() error { calls = append(calls, "mount"); return nil },
	}
	require.NoError(t, r.close(t.Context()))
	require.NoError(t, r.close(t.Context()))
	require.NoError(t, r.closeUntilDone(t.Context()))
	require.Equal(t, []string{"disk", "mount"}, calls)
}

func TestNativeResourcesDiskFailureRetainsMountForRetry(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("NBD disconnect temporarily unavailable")
	var calls []string
	diskAttempts := 0
	r := &nativeResources{
		closeDisk: func(context.Context) error {
			calls = append(calls, "disk")
			diskAttempts++
			if diskAttempts == 1 {
				return wantErr
			}
			return nil
		},
		closeMount: func() error { calls = append(calls, "mount"); return nil },
	}
	require.ErrorIs(t, r.close(t.Context()), wantErr)
	require.Equal(t, []string{"disk"}, calls, "backing mounts must stay alive while NBD still owns them")
	require.NoError(t, r.close(t.Context()))
	require.Equal(t, []string{"disk", "disk", "mount"}, calls)
}

func TestNativeResourcesMountFailureRetriesOnlyMount(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("mount temporarily busy")
	var calls []string
	mountAttempts := 0
	r := &nativeResources{
		closeDisk: func(context.Context) error { calls = append(calls, "disk"); return nil },
		closeMount: func() error {
			calls = append(calls, "mount")
			mountAttempts++
			if mountAttempts == 1 {
				return wantErr
			}
			return nil
		},
	}
	require.ErrorIs(t, r.close(t.Context()), wantErr)
	require.NoError(t, r.close(t.Context()))
	require.NoError(t, r.close(t.Context()))
	require.Equal(t, []string{"disk", "mount", "mount"}, calls)
}

func TestNativeResourcesCloseUntilDoneRetriesTransientFailure(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		attempts, mounts := 0, 0
		r := &nativeResources{
			closeDisk: func(context.Context) error {
				attempts++
				if attempts < 3 {
					return errors.New("transient failure")
				}
				return nil
			},
			closeMount: func() error { mounts++; return nil },
		}
		require.NoError(t, r.closeUntilDone(t.Context()))
		require.Equal(t, 3, attempts)
		require.Equal(t, 1, mounts)
	})
}

func TestNativeResourcesCanceledCloseRetainsCallbacks(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	transient := errors.New("disk still attached")
	disks, mounts := 0, 0
	r := &nativeResources{
		closeDisk: func(context.Context) error {
			disks++
			if disks == 1 {
				cancel()
				return transient
			}
			return nil
		},
		closeMount: func() error { mounts++; return nil },
	}
	err := r.closeUntilDone(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, transient)
	require.Equal(t, 1, disks)
	require.Zero(t, mounts)
	// A fresh lifecycle close continues from the failed disk step on the same
	// owner; the canceled attempt must not discard either resource callback.
	require.NoError(t, r.closeUntilDone(t.Context()))
	require.Equal(t, 2, disks)
	require.Equal(t, 1, mounts)
}

func TestNativeResourcesConcurrentCloseSerializesCallbacks(t *testing.T) {
	t.Parallel()
	var disks, mounts atomic.Int32
	r := &nativeResources{
		closeDisk: func(context.Context) error {
			disks.Add(1)
			// Let competing callers reach close while disk teardown is active.
			runtime.Gosched()
			return nil
		},
		closeMount: func() error { mounts.Add(1); return nil },
	}
	const callers = 32
	start := make(chan struct{})
	errors := make(chan error, callers)
	var ready, done sync.WaitGroup
	ready.Add(callers)
	done.Add(callers)
	for range callers {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			errors <- r.close(t.Context())
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	require.Equal(t, int32(1), disks.Load())
	require.Equal(t, int32(1), mounts.Load())
}

type watchedTestRootfs struct {
	rootfs.Provider
	done chan struct{}
	err  error
}

func (p *watchedTestRootfs) Done() <-chan struct{} { return p.done }
func (p *watchedTestRootfs) Err() error            { return p.err }

func TestRootfsExitWatchesNativeBackendsAndDisablesLegacyArm(t *testing.T) {
	t.Parallel()
	backend := &watchedTestRootfs{done: make(chan struct{})}
	done, exitErr := rootfsExit(backend)
	require.Equal(t, (<-chan struct{})(backend.done), done)
	require.NoError(t, exitErr())
	backend.err = errors.New("qemu-nbd exited")
	close(backend.done)
	<-done
	require.ErrorIs(t, exitErr(), backend.err)

	legacy := struct{ rootfs.Provider }{}
	done, exitErr = rootfsExit(legacy)
	require.Nil(t, done, "nil channel keeps the watcher select arm disabled")
	require.NoError(t, exitErr())
}
