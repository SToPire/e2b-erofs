//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/block"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
)

func nativeRawSource(t *testing.T, size int) (*block.Local, []byte) {
	t.Helper()
	data := bytes.Repeat([]byte{0x46}, size)
	clear(data[erofs.BlockSize : 2*erofs.BlockSize])
	path := filepath.Join(t.TempDir(), "source.raw")
	require.NoError(t, os.WriteFile(path, data, 0600))
	source, err := block.NewLocal(path, erofs.BlockSize, uuid.New())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, source.Close()) })
	return source, data
}

func TestV2RawUpperOwnershipAndSeal(t *testing.T) {
	t.Parallel()
	store := t.TempDir()
	parent := filepath.Join(store, "parent.raw")
	data := bytes.Repeat([]byte{0x35}, 4*erofs.BlockSize)
	require.NoError(t, os.WriteFile(parent, data, 0600))
	provider, err := newV2RawRootfs(t.Context(), parent, fmt.Sprintf("%x", sha256.Sum256(data)), int64(len(data)), store)
	require.NoError(t, err)
	path, err := provider.Path()
	require.NoError(t, err)
	a, err := os.Stat(parent)
	require.NoError(t, err)
	b, err := os.Stat(path)
	require.NoError(t, err)
	require.False(t, os.SameFile(a, b))
	changed := bytes.Clone(data)
	clear(changed[erofs.BlockSize : 2*erofs.BlockSize])
	require.NoError(t, os.WriteFile(path, changed, 0600))
	dir := filepath.Join(store, ".captures", "cutoff")
	require.NoError(t, os.MkdirAll(dir, 0700))
	target := filepath.Join(dir, "upper.sealed.raw")
	sealed, err := provider.seal(t.Context(), target)
	require.NoError(t, err)
	require.Equal(t, target, sealed)
	require.NoFileExists(t, path)
	require.NoError(t, provider.Close(t.Context()))
	require.NoDirExists(t, filepath.Dir(path))
	sealed, err = provider.seal(t.Context(), target)
	require.NoError(t, err)
	require.Equal(t, target, sealed)
	actual, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, changed, actual)
	actual, err = os.ReadFile(parent)
	require.NoError(t, err)
	require.Equal(t, data, actual)
	_, err = newV2RawRootfs(t.Context(), parent, "wrong digest", int64(len(data)), store)
	require.ErrorContains(t, err, "committed content")
}

func TestV2RawRecoveryPinSurvivesRuntimeClose(t *testing.T) {
	store := t.TempDir()
	data := bytes.Repeat([]byte{0x24}, 4*erofs.BlockSize)
	parent := filepath.Join(store, "parent.raw")
	require.NoError(t, os.WriteFile(parent, data, 0600))
	provider, err := newV2RawRootfs(t.Context(), parent, fmt.Sprintf("%x", sha256.Sum256(data)), int64(len(data)), store)
	require.NoError(t, err)
	path, err := provider.Path()
	require.NoError(t, err)
	provider.retainForCapture()
	require.NoError(t, provider.Close(t.Context()))
	require.FileExists(t, path, "durable recovery must retain the raw source")
	require.NoError(t, provider.discardRetainedCapture())
	require.NoFileExists(t, path)
	require.FileExists(t, parent)
}

func TestNativeRawSuppliedDiskRemainsCallerOwned(t *testing.T) {
	t.Parallel()
	source, data := nativeRawSource(t, 4*erofs.BlockSize)
	provided := filepath.Join(t.TempDir(), "provision.raw")
	changed := bytes.Repeat([]byte{0x31}, len(data))
	require.NoError(t, os.WriteFile(provided, changed, 0600))
	provider, err := newNativeRawRootfs(t.Context(), source, provided, "")
	require.NoError(t, err)
	path, err := provider.Path()
	require.NoError(t, err)
	require.Equal(t, provided, path)
	actual, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, changed, actual, "supplied full raw must not be overwritten from source")
	require.NoError(t, provider.Close(t.Context()))
	require.NoError(t, provider.Close(t.Context()))
	actual, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, changed, actual)
	_, err = newNativeRawRootfs(t.Context(), source, filepath.Dir(provided), "")
	require.Error(t, err, "directory is not a valid raw image")
	require.NoError(t, os.Truncate(provided, erofs.BlockSize))
	_, err = newNativeRawRootfs(t.Context(), source, provided, "")
	require.Error(t, err, "a partial raw file must not silently zero-fill missing source bytes")
}

func TestNativeRawMaterializedDiskIsolatedAndRetainedBeforeClose(t *testing.T) {
	t.Parallel()
	source, data := nativeRawSource(t, 3*1024*1024)
	store := t.TempDir()
	provider, err := newNativeRawRootfs(t.Context(), source, "", store)
	require.NoError(t, err)
	path, err := provider.Path()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(store, ".raw-baselines"), filepath.Dir(path))
	actual, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, data, actual)
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	guestWrite := bytes.Repeat([]byte{0x91}, 512)
	_, err = file.WriteAt(guestWrite, 2*erofs.BlockSize+512)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	copy(data[2*erofs.BlockSize+512:], guestWrite)
	retained := filepath.Join(t.TempDir(), "captured.raw")
	require.NoError(t, captureRawDisk(path, retained, int64(len(data))))
	require.NoError(t, provider.Close(t.Context()))
	require.NoFileExists(t, path)
	actual, err = os.ReadFile(retained)
	require.NoError(t, err)
	require.Equal(t, data, actual, "closing private runtime must not discard the captured cutoff")
	actual, err = os.ReadFile(source.Path())
	require.NoError(t, err)
	require.Equal(t, byte(0x46), actual[2*erofs.BlockSize+512], "runtime writes must not modify source")
	_, err = provider.Path()
	require.ErrorIs(t, err, os.ErrClosed)
}

type failingNativeRawFile struct {
	nativeRawFile
	failSync   bool
	failClose  bool
	syncCalls  int
	closeCalls int
}

func (f *failingNativeRawFile) Sync() error {
	f.syncCalls++
	if f.failSync {
		f.failSync = false
		return unix.EIO
	}
	return f.nativeRawFile.Sync()
}

func (f *failingNativeRawFile) Close() error {
	f.closeCalls++
	err := f.nativeRawFile.Close()
	if f.failClose {
		f.failClose = false
		return errors.Join(err, unix.EIO)
	}
	return err
}

func TestNativeRawCloseRetriesOnlyRemainingStages(t *testing.T) {
	for _, stage := range []string{"sync", "close", "remove"} {
		t.Run(stage, func(t *testing.T) {
			source, _ := nativeRawSource(t, 4*erofs.BlockSize)
			provider, err := newNativeRawRootfs(t.Context(), source, "", t.TempDir())
			require.NoError(t, err)
			path, err := provider.Path()
			require.NoError(t, err)
			file := &failingNativeRawFile{nativeRawFile: provider.file, failSync: stage == "sync", failClose: stage == "close"}
			provider.file = file
			if stage == "remove" {
				require.NoError(t, os.Rename(path, path+".saved"))
				require.NoError(t, os.Mkdir(path, 0700))
				require.NoError(t, os.WriteFile(filepath.Join(path, "blocker"), []byte("retain"), 0600))
			}
			require.Error(t, provider.Close(t.Context()))
			require.False(t, provider.closed)
			if stage == "sync" {
				require.Equal(t, 0, file.closeCalls, "failed sync must retain the open backing descriptor")
			}
			if stage == "remove" {
				require.NoError(t, os.Remove(filepath.Join(path, "blocker")))
				require.NoError(t, os.Remove(path))
				require.NoError(t, os.Rename(path+".saved", path))
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			var wg sync.WaitGroup
			errs := make(chan error, 2)
			for range 2 {
				wg.Go(func() { errs <- provider.Close(ctx) })
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				require.NoError(t, err)
			}
			require.Equal(t, 1, file.closeCalls, "the consumed descriptor must never be closed twice")
			require.NoFileExists(t, path)
			require.NoError(t, provider.Close(t.Context()))
		})
	}
}

type interruptedNativeRawSource struct {
	block.ReadonlyDevice
	short   bool
	cancel  context.CancelFunc
	maxRead int
}

func (s *interruptedNativeRawSource) ReadAt(ctx context.Context, p []byte, off int64) (int, error) {
	s.maxRead = max(s.maxRead, len(p))
	if s.short {
		return len(p) - 1, nil
	}
	n, err := s.ReadonlyDevice.ReadAt(ctx, p, off)
	s.cancel()
	return n, err
}

func TestNativeRawFailedMaterializationRemovesOnlyIncompletePrivateFile(t *testing.T) {
	for _, short := range []bool{true, false} {
		source, data := nativeRawSource(t, 3*1024*1024)
		ctx, cancel := context.WithCancel(t.Context())
		input := &interruptedNativeRawSource{ReadonlyDevice: source, short: short, cancel: cancel}
		store := t.TempDir()
		provider, err := newNativeRawRootfs(ctx, input, "", store)
		cancel()
		require.Nil(t, provider)
		if short {
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		} else {
			require.ErrorIs(t, err, context.Canceled)
		}
		require.LessOrEqual(t, input.maxRead, 1024*1024)
		entries, err := os.ReadDir(filepath.Join(store, ".raw-baselines"))
		require.NoError(t, err)
		require.Empty(t, entries)
		actual, err := os.ReadFile(source.Path())
		require.NoError(t, err)
		require.Equal(t, data, actual)
	}
}

func TestNativeRawRetainedBaselineCleanup(t *testing.T) {
	t.Parallel()
	source, _ := nativeRawSource(t, 8192)
	p, err := newNativeRawRootfs(t.Context(), source, "", t.TempDir())
	require.NoError(t, err)
	path, err := p.Path()
	require.NoError(t, err)
	p.retainForCapture()
	require.NoError(t, p.Close(t.Context()))
	require.FileExists(t, path)
	require.NoError(t, p.discardRetainedCapture())
	require.NoFileExists(t, path)
	require.NoError(t, p.discardRetainedCapture())
	require.FileExists(t, source.Path())
}
