//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
)

func nativeInputFixture(t *testing.T) (*Sandbox, *erofsRootfs, string) {
	t.Helper()
	store, err := erofs.NewStore(t.TempDir(), erofs.Options{})
	require.NoError(t, err)
	id := uuid.NewString()
	capture, err := store.Begin(id)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(capture.MemoryPath, []byte("captured RAM"), 0600))
	require.NoError(t, os.WriteFile(capture.VMStatePath, []byte("captured vmstate"), 0600))
	runtimeBase := filepath.Join(store.Root, ".overlays")
	require.NoError(t, os.MkdirAll(runtimeBase, 0700))
	runtimeDir, err := os.MkdirTemp(runtimeBase, "runtime-")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(runtimeDir, "disk.qcow2"), []byte("captured disk"), 0600))
	provider := &erofsRootfs{runtimeDir: runtimeDir, released: true}
	s := &Sandbox{Resources: &Resources{rootfs: provider}, nativeCapture: &nativeCapture{store: store, capture: capture, request: erofs.BuildRequest{ID: id}}}
	committed := filepath.Join(store.Root, id)
	require.NoError(t, os.Mkdir(committed, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(committed, "memory.erofs"), []byte("immutable generation"), 0400))
	return s, provider, committed
}

func TestNativeInputCleanupRetainsFailedAndUncertainCapture(t *testing.T) {
	t.Parallel()
	s, provider, _ := nativeInputFixture(t)
	for _, state := range []string{"capturing", "sealed", "uncertain commit"} {
		t.Run(state, func(t *testing.T) {
			s.nativeCapture.sealed = state != "capturing"
			if state == "uncertain commit" {
				s.nativeCapture.committed = &erofs.Snapshot{}
			}
			require.NoError(t, s.cleanupNativeInputs(t.Context()))
			require.FileExists(t, s.nativeCapture.capture.MemoryPath)
			require.FileExists(t, filepath.Join(provider.runtimeDir, "disk.qcow2"))
			require.False(t, s.nativeCapture.inputsCleaned)
		})
	}
}

func TestNativeInputCleanupRemovesOnlyPublishedOperationInputs(t *testing.T) {
	t.Parallel()
	s, provider, committed := nativeInputFixture(t)
	external := filepath.Join(t.TempDir(), "generic-store-caller.raw")
	require.NoError(t, os.WriteFile(external, []byte("caller owns this"), 0600))
	s.nativeCapture.request.DiskPath = external
	s.nativeCapture.published = true
	require.NoError(t, s.cleanupNativeInputs(t.Context()))
	require.NoDirExists(t, s.nativeCapture.capture.Dir)
	require.NoDirExists(t, provider.runtimeDir)
	require.FileExists(t, filepath.Join(committed, "memory.erofs"))
	require.FileExists(t, external)
	require.True(t, s.nativeCapture.inputsCleaned)
	// A duplicate lifecycle callback must not remove a newly reused pathname.
	require.NoError(t, os.Mkdir(s.nativeCapture.capture.Dir, 0700))
	require.NoError(t, os.Mkdir(provider.runtimeDir, 0700))
	require.NoError(t, s.cleanupNativeInputs(t.Context()))
	require.DirExists(t, s.nativeCapture.capture.Dir)
	require.DirExists(t, provider.runtimeDir)
}

func TestNativeInputCleanupWithoutCaptureDiscardsOnlyReleasedRuntime(t *testing.T) {
	t.Parallel()
	s, provider, _ := nativeInputFixture(t)
	capture := s.nativeCapture.capture
	s.nativeCapture = nil
	provider.released = false
	require.ErrorContains(t, s.cleanupNativeInputs(t.Context()), "unreleased")
	require.DirExists(t, provider.runtimeDir)
	provider.released = true
	require.NoError(t, s.cleanupNativeInputs(t.Context()))
	require.NoDirExists(t, provider.runtimeDir)
	require.FileExists(t, capture.MemoryPath, "an unrelated capture must not be swept")
	require.NoError(t, os.Mkdir(provider.runtimeDir, 0700))
	require.NoError(t, s.cleanupNativeInputs(t.Context()))
	require.DirExists(t, provider.runtimeDir)
}

type cancelAfterRuntimeCleanup struct {
	context.Context
	cancel context.CancelFunc
	calls  int
}

func (c *cancelAfterRuntimeCleanup) Err() error {
	c.calls++
	if c.calls == 2 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestNativeInputCleanupRetriesAfterPartialCleanupCancellation(t *testing.T) {
	t.Parallel()
	s, provider, _ := nativeInputFixture(t)
	s.nativeCapture.published = true
	base, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &cancelAfterRuntimeCleanup{Context: base, cancel: cancel}
	err := s.cleanupNativeInputs(ctx)
	require.True(t, errors.Is(err, context.Canceled))
	require.NoDirExists(t, provider.runtimeDir)
	require.FileExists(t, s.nativeCapture.capture.MemoryPath)
	require.False(t, s.nativeCapture.inputsCleaned)
	require.NoError(t, s.cleanupNativeInputs(t.Context()))
	require.NoDirExists(t, s.nativeCapture.capture.Dir)
	require.True(t, s.nativeCapture.inputsCleaned)
}

func TestNativeInputCleanupRejectsUnownedCaptureDirectory(t *testing.T) {
	t.Parallel()
	s, provider, committed := nativeInputFixture(t)
	s.nativeCapture.published = true
	s.nativeCapture.capture.Dir = committed
	require.ErrorContains(t, s.cleanupNativeInputs(t.Context()), "outside this native capture")
	require.FileExists(t, filepath.Join(committed, "memory.erofs"))
	require.DirExists(t, provider.runtimeDir)
}
