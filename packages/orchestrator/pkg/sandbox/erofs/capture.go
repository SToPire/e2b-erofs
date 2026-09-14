//go:build linux

package erofs

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const captureName = "capture.json"

var ErrSnapshotConflict = errors.New("snapshot ID is already committed for a different capture")

// captureIdentity binds a published generation to its sealed input cutoff.
// Host paths are deliberately excluded: a retained capture can be relocated if
// its content and native Diff allocation layout are preserved exactly.
type captureIdentity struct {
	Version              int            `json:"version"`
	ID                   string         `json:"id"`
	ParentID             string         `json:"parent_id,omitempty"`
	ParentManifestSHA256 string         `json:"parent_manifest_sha256,omitempty"`
	MemorySize           int64          `json:"memory_size"`
	DiskSize             int64          `json:"disk_size"`
	Memory               inputIdentity  `json:"memory"`
	Disk                 inputIdentity  `json:"disk"`
	DiskSeal             *inputIdentity `json:"disk_seal,omitempty"`
	VMState              inputIdentity  `json:"vmstate"`
	Metadata             *inputIdentity `json:"metadata,omitempty"`
}

type inputIdentity struct {
	Bytes              int64  `json:"bytes"`
	SHA256             string `json:"sha256"`
	SparseLayoutSHA256 string `json:"sparse_layout_sha256,omitempty"`
}

func captureRequest(ctx context.Context, r BuildRequest, parent *Snapshot) ([]byte, error) {
	c := captureIdentity{Version: 1, ID: r.ID, ParentID: r.ParentID, MemorySize: r.MemorySize, DiskSize: r.DiskSize}
	if parent != nil {
		data, err := json.Marshal(parent.Manifest)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(data)
		c.ParentManifestSHA256 = hex.EncodeToString(digest[:])
	}
	for _, item := range []struct {
		path string
		out  *inputIdentity
	}{
		{r.DiskPath, &c.Disk}, {r.VMStatePath, &c.VMState},
	} {
		identity, err := fingerprintInput(ctx, item.path)
		if err != nil {
			return nil, fmt.Errorf("fingerprint capture: %w", err)
		}
		*item.out = identity
	}
	var err error
	c.Memory, err = fingerprintMemory(ctx, r.MemoryPath, r.MemorySize, parent != nil)
	if err != nil {
		return nil, err
	}
	if c.VMState.Bytes == 0 {
		return nil, errors.New("empty captured vmstate")
	}
	if r.MetadataPath != "" {
		identity, err := fingerprintInput(ctx, r.MetadataPath)
		if err != nil {
			return nil, err
		}
		if identity.Bytes == 0 {
			return nil, errors.New("empty captured metadata")
		}
		c.Metadata = &identity
	}
	if parent != nil {
		identity, err := fingerprintInput(ctx, r.DiskPath+".sealed.json")
		if err != nil {
			return nil, err
		}
		c.DiskSeal = &identity
	}
	return json.MarshalIndent(c, "", "  ")
}

func fingerprintMemory(ctx context.Context, path string, size int64, sparse bool) (inputIdentity, error) {
	if err := regularSize(path, size); err != nil {
		return inputIdentity{}, err
	}
	identity, err := fingerprintInput(ctx, path)
	if err != nil {
		return inputIdentity{}, err
	}
	if !sparse {
		return identity, nil
	}
	// A zero DATA page and an unwritten HOLE have identical byte hashes but
	// opposite inheritance semantics. Allocation is part of input identity.
	extents, err := SparseExtents(path, size)
	if err != nil {
		return inputIdentity{}, err
	}
	h := sha256.New()
	for _, extent := range extents {
		var entry [16]byte
		binary.BigEndian.PutUint64(entry[:8], uint64(extent.Offset))
		binary.BigEndian.PutUint64(entry[8:], uint64(extent.Length))
		h.Write(entry[:])
	}
	identity.SparseLayoutSHA256 = hex.EncodeToString(h.Sum(nil))
	return identity, nil
}

func fingerprintInput(ctx context.Context, path string) (inputIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return inputIdentity{}, err
	}
	if !info.Mode().IsRegular() {
		return inputIdentity{}, fmt.Errorf("not a regular capture: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return inputIdentity{}, err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return inputIdentity{}, err
	}
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx: ctx, reader: f})
	if err != nil {
		return inputIdentity{}, err
	}
	return inputIdentity{Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// committedCapture is also used after losing a concurrent RENAME_NOREPLACE
// race. The winner is accepted only if it published these same sealed inputs.
func (s *Store) committedCapture(id string, identity []byte) (*Snapshot, error) {
	snapshot, err := s.Load(id)
	if err != nil {
		return nil, err
	}
	if snapshot.Manifest.Capture == nil {
		return nil, ErrSnapshotConflict
	}
	digest := sha256.Sum256(identity)
	if snapshot.Manifest.Capture.Bytes != int64(len(identity)) || snapshot.Manifest.Capture.SHA256 != hex.EncodeToString(digest[:]) {
		return nil, ErrSnapshotConflict
	}
	// Load has verified capture.json bytes against this digest, together with
	// the output artifacts and complete parent chain. Retry directory durability
	// even when the first caller saw rename succeed and root fsync fail.
	return snapshot, syncPath(s.Root)
}

func (s *Store) writeCapture(pending, id string, identity []byte) (*Artifact, error) {
	path := filepath.Join(pending, captureName)
	if err := os.WriteFile(path, identity, 0400); err != nil {
		return nil, err
	}
	a, err := describe(path, filepath.Join(id, captureName))
	if err != nil {
		return nil, err
	}
	return &a, nil
}
