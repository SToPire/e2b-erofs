//go:build linux

package erofs

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type Extent struct{ Offset, Length int64 }

// SparseExtents enumerates allocation, never inferring changes from byte values.
// Explicit zero DATA must override the parent just like nonzero DATA.
func SparseExtents(path string, size int64) ([]Extent, error) {
	if size <= 0 || size%BlockSize != 0 {
		return nil, errors.New("invalid sparse capture size")
	}
	if err := regularSize(path, size); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Resolve delayed allocation before inspecting the on-disk extent layout.
	if err := f.Sync(); err != nil {
		return nil, err
	}
	var extents []Extent
	for offset := int64(0); offset < size; {
		data, err := unix.Seek(int(f.Fd()), offset, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("seek sparse DATA: %w", err)
		}
		hole, err := unix.Seek(int(f.Fd()), data, unix.SEEK_HOLE)
		if err != nil {
			return nil, fmt.Errorf("seek sparse HOLE: %w", err)
		}
		if data < offset || data >= size || hole <= data || hole > size || data%BlockSize != 0 || hole%BlockSize != 0 {
			return nil, errors.New("sparse capture DATA/HOLE boundaries must be ordered 4 KiB blocks")
		}
		extents = append(extents, Extent{Offset: data, Length: hole - data})
		offset = hole
	}
	return extents, nil
}

func ValidateSparseDiff(path string, size int64) error {
	_, err := SparseExtents(path, size)
	return err
}

// ProbeSparseFilesystem must succeed on the actual capture filesystem before
// enabling native Diff export. SEEK_DATA support alone does not suffice: Linux
// permits filesystems to report every byte as DATA.
func ProbeSparseFilesystem(dir string) error {
	f, err := os.CreateTemp(dir, ".sparse-probe-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Truncate(6 * BlockSize); err != nil {
		return err
	}
	data := make([]byte, BlockSize)
	data[0] = 0x7f
	if _, err := f.WriteAt(data, BlockSize); err != nil {
		return err
	}
	clear(data)
	if _, err := f.WriteAt(data, 3*BlockSize); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	extents, err := SparseExtents(f.Name(), 6*BlockSize)
	if err != nil {
		return err
	}
	if len(extents) != 2 || extents[0] != (Extent{BlockSize, BlockSize}) || extents[1] != (Extent{3 * BlockSize, BlockSize}) {
		return fmt.Errorf("capture filesystem does not preserve 4 KiB DATA/HOLE semantics: %v", extents)
	}
	return nil
}
