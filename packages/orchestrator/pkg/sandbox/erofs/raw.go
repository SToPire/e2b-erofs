//go:build linux

package erofs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/sys/unix"
)

// RawCopyStats describes work performed on a complete raw image. WrittenBytes
// includes explicit zero blocks in a delta, but excludes holes in a full copy.
type RawCopyStats struct {
	ReadBytes    int64  `json:"read_bytes"`
	WrittenBytes int64  `json:"written_bytes"`
	SourceSHA256 string `json:"source_sha256"`
}

// MaterializeRawFile creates an independent writable inode containing the exact
// logical bytes of an immutable raw image. Zero blocks may become holes: unlike
// a delta, a complete raw image never interprets a hole as parent inheritance.
// The destination must not exist. A failed operation removes only its new file.
func MaterializeRawFile(ctx context.Context, source, destination string, size int64) (stats RawCopyStats, resultErr error) {
	if err := ctx.Err(); err != nil {
		return stats, err
	}
	in, err := openRawInput(source, size)
	if err != nil {
		return stats, err
	}
	defer in.Close()
	out, err := createRawOutput(destination, size)
	if err != nil {
		return stats, err
	}
	defer finishRawOutput(out, destination, &resultErr)
	stats, _, err = writeRawBlocks(ctx, nil, in, out, size)
	if err != nil {
		return stats, err
	}
	return stats, out.Sync()
}

// CreateRawDelta compares two sealed, equal-sized raw images and emits a sparse
// file-delta: DATA overrides the parent, HOLE inherits it. In particular, a hole
// in current that replaces nonzero parent data is emitted as allocated zero DATA.
// Callers must seal both inputs before calling; this is not a live-disk snapshot.
func CreateRawDelta(ctx context.Context, parent, current, destination string, size int64) (stats RawCopyStats, resultErr error) {
	if err := ctx.Err(); err != nil {
		return stats, err
	}
	previous, err := openRawInput(parent, size)
	if err != nil {
		return stats, err
	}
	defer previous.Close()
	in, err := openRawInput(current, size)
	if err != nil {
		return stats, err
	}
	defer in.Close()
	if err := ProbeSparseFilesystem(filepath.Dir(destination)); err != nil {
		return stats, err
	}
	out, err := createRawOutput(destination, size)
	if err != nil {
		return stats, err
	}
	defer finishRawOutput(out, destination, &resultErr)
	stats, expected, err := writeRawBlocks(ctx, previous, in, out, size)
	if err != nil {
		return stats, err
	}
	// SparseExtents syncs before inspecting allocation. Check this actual delta,
	// not only a small filesystem probe: extra DATA would overwrite parent bytes
	// with unwritten zeros, and missing zero DATA would resurrect parent bytes.
	actual, err := SparseExtents(destination, size)
	if err != nil {
		return stats, err
	}
	if !slices.Equal(actual, expected) {
		return stats, errors.New("raw delta allocation differs from changed blocks")
	}
	return stats, nil
}

func openRawInput(path string, size int64) (*os.File, error) {
	if size <= 0 || size%BlockSize != 0 {
		return nil, errors.New("raw image size must be a positive multiple of 4096")
	}
	// Reject FIFOs and other special files without waiting for an external
	// writer before f.Stat can validate the descriptor. O_NONBLOCK is ignored
	// for the regular files accepted below.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if !info.Mode().IsRegular() || info.Size() != size {
		return nil, errors.Join(fmt.Errorf("raw input %s is not a regular file of size %d", path, size), f.Close())
	}
	return f, nil
}

func createRawOutput(path string, size int64) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(size); err != nil {
		return nil, errors.Join(err, f.Close(), os.Remove(path))
	}
	return f, nil
}

func finishRawOutput(f *os.File, path string, resultErr *error) {
	*resultErr = errors.Join(*resultErr, f.Close())
	if *resultErr != nil {
		*resultErr = errors.Join(*resultErr, os.Remove(path))
	}
}

func writeRawBlocks(ctx context.Context, parent, current, out *os.File, size int64) (RawCopyStats, []Extent, error) {
	const batchSize = 1024 * 1024
	buffer := make([]byte, min(size, batchSize))
	var previous []byte
	if parent != nil {
		previous = make([]byte, len(buffer))
	}
	zero := make([]byte, BlockSize)
	var stats RawCopyStats
	digest := sha256.New()
	var extents []Extent
	for offset := int64(0); offset < size; {
		if err := ctx.Err(); err != nil {
			return stats, extents, err
		}
		chunk := buffer[:min(int64(len(buffer)), size-offset)]
		if _, err := current.ReadAt(chunk, offset); err != nil {
			return stats, extents, fmt.Errorf("read current raw at %d: %w", offset, err)
		}
		stats.ReadBytes += int64(len(chunk))
		digest.Write(chunk)
		if parent != nil {
			if _, err := parent.ReadAt(previous[:len(chunk)], offset); err != nil {
				return stats, extents, fmt.Errorf("read parent raw at %d: %w", offset, err)
			}
			stats.ReadBytes += int64(len(chunk))
		}
		for start := 0; start < len(chunk); {
			selected := func(index int) bool {
				base := zero
				if parent != nil {
					base = previous[index : index+BlockSize]
				}
				return !bytes.Equal(chunk[index:index+BlockSize], base)
			}
			if !selected(start) {
				start += BlockSize
				continue
			}
			end := start + BlockSize
			for end < len(chunk) && selected(end) {
				end += BlockSize
			}
			position := offset + int64(start)
			n, err := out.WriteAt(chunk[start:end], position)
			if err != nil {
				return stats, extents, err
			}
			if n != end-start {
				return stats, extents, io.ErrShortWrite
			}
			stats.WrittenBytes += int64(n)
			if len(extents) != 0 && extents[len(extents)-1].Offset+extents[len(extents)-1].Length == position {
				extents[len(extents)-1].Length += int64(n)
			} else {
				extents = append(extents, Extent{Offset: position, Length: int64(n)})
			}
			start = end
		}
		offset += int64(len(chunk))
	}
	stats.SourceSHA256 = hex.EncodeToString(digest.Sum(nil))
	return stats, extents, ctx.Err()
}
