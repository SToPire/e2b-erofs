//go:build linux

package layer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPreBootHooksPreserveOrderAndStopOnError(t *testing.T) {
	t.Parallel()
	var called []int
	opts := &createSandboxOptions{}
	wantErr := errors.New("first hook failed")
	WithPreBootFn(func(context.Context, string) error { called = append(called, 1); return wantErr })(opts)
	WithPreBootFn(func(context.Context, string) error { called = append(called, 2); return nil })(opts)
	require.ErrorIs(t, opts.preBootFn(t.Context(), "disk"), wantErr)
	require.Equal(t, []int{1}, called)
}

func TestMinimumFreeDiskRejectsInsufficientReservedAdjustedSpace(t *testing.T) {
	// e2fsck/debugfs are injected to cover the cold-boot boundary without
	// mounting a filesystem; production uses the existing ext4 helpers.
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "e2fsck"), []byte("#!/bin/sh\nexit 0\n"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "debugfs"), []byte("#!/bin/sh\nprintf 'Reserved block count: 256\\nGroup 0:\\n 1024 free blocks, 512 free inodes\\n'\n"), 0o700))
	opts := &createSandboxOptions{}
	var reservedHookRan bool
	WithPreBootFn(func(context.Context, string) error { reservedHookRan = true; return nil })(opts)
	WithMinimumFreeDisk(4, 4096)(opts)
	var spaceErr *InsufficientFreeDiskError
	require.ErrorAs(t, opts.preBootFn(t.Context(), "private-disk"), &spaceErr)
	require.True(t, reservedHookRan)
	require.Equal(t, int64(3), spaceErr.FreeMB)
	adequate := &createSandboxOptions{}
	WithMinimumFreeDisk(3, 4096)(adequate)
	require.NoError(t, adequate.preBootFn(t.Context(), "private-disk"))
}
