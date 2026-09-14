//go:build linux

package fc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/e2b-dev/infra/packages/shared/pkg/fc/client/operations"
	"github.com/e2b-dev/infra/packages/shared/pkg/fc/models"
)

// NativeSnapshotType selects Firecracker's own guest-memory serialization.
type NativeSnapshotType string

const (
	NativeSnapshotFull NativeSnapshotType = "Full"
	NativeSnapshotDiff NativeSnapshotType = "Diff"
	nativePageSize                        = 4096
)

var ErrNativeMemoryUnsupported = errors.New("operation is unsupported for native File memory")

func (c *apiClient) loadFileSnapshot(ctx context.Context, memfilePath, snapfilePath string) error {
	backendType := models.MemoryBackendBackendTypeFile
	_, err := c.client.Operations.LoadSnapshot(&operations.LoadSnapshotParams{
		Context: ctx,
		Body: &models.SnapshotLoadParams{
			SnapshotPath:    &snapfilePath,
			TrackDirtyPages: true,
			ResumeVM:        false,
			MemBackend: &models.MemoryBackend{
				BackendPath: &memfilePath,
				BackendType: &backendType,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("load native File snapshot: %w", err)
	}

	return nil
}

// validateNativeMemory checks snapshot-persisted configuration before any vCPU
// resumes. Ordinary-page templates must be rebuilt instead of converting an old
// hugepage or balloon-enabled snapshot on restore.
func (c *apiClient) validateNativeMemory(ctx context.Context) error {
	machine, err := c.client.Operations.GetMachineConfiguration(&operations.GetMachineConfigurationParams{Context: ctx})
	if err != nil {
		return fmt.Errorf("inspect native memory configuration: %w", err)
	}
	if machine.Payload == nil || (machine.Payload.HugePages != "" && machine.Payload.HugePages != "None") ||
		machine.Payload.TrackDirtyPages == nil || !*machine.Payload.TrackDirtyPages {
		return errors.New("File snapshots require ordinary pages and dirty tracking")
	}
	_, err = c.client.Operations.DescribeBalloonConfig(&operations.DescribeBalloonConfigParams{Context: ctx})
	if err == nil {
		return errors.New("File snapshots require a template without a balloon device")
	}
	var noBalloon *operations.DescribeBalloonConfigBadRequest
	if !errors.As(err, &noBalloon) {
		return fmt.Errorf("inspect native memory balloon configuration: %w", err)
	}

	return nil
}

func (c *apiClient) createNativeSnapshot(ctx context.Context, snapfilePath, memfilePath string, snapshotType NativeSnapshotType) error {
	_, err := c.client.Operations.CreateSnapshot(&operations.CreateSnapshotParams{
		Context: ctx,
		Body: &models.SnapshotCreateParams{
			SnapshotPath: &snapfilePath,
			MemFilePath:  memfilePath,
			SnapshotType: string(snapshotType),
		},
	})
	if err != nil {
		return fmt.Errorf("create native %s snapshot: %w", snapshotType, err)
	}

	return nil
}

// CreateNativeSnapshot captures a paused VM's state and its actual private RAM
// mappings. Both output paths must be absent in caller-owned staging directories.
// A Diff file is consumed locally with its DATA/HOLE layout intact; zero DATA is
// an update, whereas a HOLE inherits the parent. Never copy it as a byte stream,
// preallocate it, or punch holes according to byte content.
//
// An error after the request starts may have consumed the native dirty bitmap.
// Output files are deliberately retained: keep the VM paused and retry with a
// Full capture at fresh paths, or use an already successful sealed capture.
func (p *Process) CreateNativeSnapshot(ctx context.Context, snapfilePath, memfilePath string, snapshotType NativeSnapshotType) error {
	if !p.Versions.NativeMemory {
		return errors.New("native snapshot requires native memory configuration")
	}
	if snapshotType != NativeSnapshotFull && snapshotType != NativeSnapshotDiff {
		return fmt.Errorf("invalid native snapshot type %q", snapshotType)
	}
	if snapfilePath == "" || memfilePath == "" {
		return errors.New("native snapshot requires state and memory paths")
	}
	if err := ValidateSparseStaging(filepath.Dir(memfilePath)); err != nil {
		return err
	}
	memfile, err := os.OpenFile(memfilePath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("reserve fresh native memfile: %w", err)
	}
	defer memfile.Close()
	state, err := os.OpenFile(snapfilePath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.Join(fmt.Errorf("reserve fresh native vmstate: %w", err), os.Remove(memfilePath))
	}
	defer state.Close()
	if err := p.client.createNativeSnapshot(ctx, snapfilePath, memfilePath, snapshotType); err != nil {
		return err
	}
	if err := errors.Join(memfile.Sync(), state.Sync()); err != nil {
		return fmt.Errorf("seal native snapshot files: %w", err)
	}
	info, err := memfile.Stat()
	if err != nil {
		return fmt.Errorf("inspect native memfile: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size()%nativePageSize != 0 ||
		(p.nativeMemorySize != 0 && info.Size() != p.nativeMemorySize) {
		return fmt.Errorf("invalid native memfile size %d (expected %d)", info.Size(), p.nativeMemorySize)
	}
	info, err = state.Stat()
	if err != nil {
		return fmt.Errorf("inspect native vmstate: %w", err)
	}
	if info.Size() == 0 {
		return errors.New("native vmstate is empty")
	}

	return nil
}

// ValidateSparseStaging verifies the local filesystem contract required by
// Firecracker Diff -> EROFS: untouched 4 KiB pages are HOLE and explicitly written
// pages, including zero pages, are DATA. Merely supporting SEEK_DATA is not enough.
func ValidateSparseStaging(dir string) error {
	f, err := os.CreateTemp(dir, ".native-sparse-probe-*")
	if err != nil {
		return fmt.Errorf("create sparse staging probe: %w", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Truncate(8 * nativePageSize); err != nil {
		return fmt.Errorf("size sparse staging probe: %w", err)
	}
	data := make([]byte, nativePageSize)
	for _, page := range []int64{1, 3, 6} {
		// Page 3 is explicitly zero; the other two pages contain nonzero data.
		if page == 3 {
			clear(data)
		} else {
			data[0] = 0xa5
		}
		if _, err := f.WriteAt(data, page*nativePageSize); err != nil {
			return fmt.Errorf("write sparse staging probe: %w", err)
		}
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync sparse staging probe: %w", err)
	}
	for _, page := range []int64{1, 3, 6} {
		start := page * nativePageSize
		for _, check := range []struct {
			from, want int64
			whence     int
		}{
			{start - nativePageSize, start, unix.SEEK_DATA},
			{start, start, unix.SEEK_DATA},
			{start, start + nativePageSize, unix.SEEK_HOLE},
			{start - nativePageSize, start - nativePageSize, unix.SEEK_HOLE},
		} {
			got, err := unix.Seek(int(f.Fd()), check.from, check.whence)
			if err != nil {
				return fmt.Errorf("probe staging DATA/HOLE semantics: %w", err)
			}
			if got != check.want {
				return fmt.Errorf("staging filesystem lacks exact 4 KiB DATA/HOLE semantics: seek(%d, %d) = %d, want %d",
					check.from, check.whence, got, check.want)
			}
		}
	}
	_, err = unix.Seek(int(f.Fd()), 7*nativePageSize, unix.SEEK_DATA)
	if !errors.Is(err, unix.ENXIO) {
		return fmt.Errorf("staging filesystem reports DATA for an unwritten trailing page: %v", err)
	}

	return nil
}
