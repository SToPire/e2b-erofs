//go:build linux

// Package erofs implements the node-local, immutable EROFS snapshot format.
package erofs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	Format       = "erofs-v1"
	BlockSize    = 4096
	ManifestName = "manifest.json"
)

var validID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)

type Options struct {
	MkfsPath    string
	FsckPath    string
	QemuImgPath string
	QemuNBDPath string
}

func (o Options) defaults() Options {
	if o.MkfsPath == "" {
		o.MkfsPath = "mkfs.erofs"
	}
	if o.FsckPath == "" {
		o.FsckPath = "fsck.erofs"
	}
	if o.QemuImgPath == "" {
		o.QemuImgPath = "qemu-img"
	}
	if o.QemuNBDPath == "" {
		o.QemuNBDPath = "qemu-nbd"
	}
	return o
}

// Artifact paths are relative to Store.Root, including dependencies. Digests
// bind device order to immutable bytes, rather than merely to local filenames.
type Artifact struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type Image struct {
	Artifact
	Size    int64      `json:"size"`
	Devices []Artifact `json:"devices"`
}

type Manifest struct {
	Format             string      `json:"format"`
	ID                 string      `json:"id"`
	ParentID           string      `json:"parent_id,omitempty"`
	Memory             Image       `json:"memory"`
	Disk               Image       `json:"disk,omitzero"`
	Upper              *Image      `json:"upper,omitempty"`
	UpperContentSHA256 string      `json:"upper_content_sha256,omitempty"`
	Lower              *Lower      `json:"lower,omitempty"`
	Boot               *BootLayout `json:"boot,omitempty"`
	MemoryCapture      string      `json:"memory_capture,omitempty"`
	VMState            Artifact    `json:"vmstate"`
	Metadata           *Artifact   `json:"metadata,omitempty"`
	Capture            *Artifact   `json:"capture,omitempty"`
}

type Store struct {
	Root    string
	Options Options
}

type Snapshot struct {
	Dir      string
	Manifest Manifest
	store    *Store
}

func (s *Snapshot) VMStatePath() string { return filepath.Join(s.store.Root, s.Manifest.VMState.File) }
func (s *Snapshot) MetadataPath() string {
	if s.Manifest.Metadata == nil {
		return ""
	}
	return filepath.Join(s.store.Root, s.Manifest.Metadata.File)
}

type Capture struct {
	Dir         string
	MemoryPath  string
	DiskPath    string
	VMStatePath string
}

func NewStore(root string, opts Options) (*Store, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(abs, ":,\n") {
		return nil, errors.New("EROFS store path contains a CLI delimiter")
	}
	if err := os.MkdirAll(abs, 0700); err != nil {
		return nil, err
	}
	return &Store{Root: abs, Options: opts.defaults()}, nil
}

// Begin allocates a fresh capture. Callers keep this object across retries and
// never recapture a Diff after Firecracker has consumed its dirty bitmap.
func (s *Store) Begin(id string) (*Capture, error) {
	if !validID.MatchString(id) {
		return nil, errors.New("invalid snapshot ID")
	}
	base := filepath.Join(s.Root, ".captures")
	if err := os.MkdirAll(base, 0700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(base, id+"-")
	if err != nil {
		return nil, err
	}
	return &Capture{Dir: dir, MemoryPath: filepath.Join(dir, "memory.capture"), DiskPath: filepath.Join(dir, "disk.qcow2"), VMStatePath: filepath.Join(dir, "vmstate")}, nil
}

type BuildRequest struct {
	ID           string
	ParentID     string
	MemoryPath   string
	DiskPath     string
	VMStatePath  string
	MetadataPath string
	MemorySize   int64
	DiskSize     int64
}

// Build publishes one cutoff atomically. Inputs must already be sealed: the FC
// process has exited and its qcow2 backend has closed successfully. On every
// failure all caller-owned inputs, especially the sparse RAM file, survive.
// Retrying the same sealed input cutoff returns its committed snapshot without
// rebuilding. Reusing an ID with different capture bytes or sparse allocation
// returns ErrSnapshotConflict.
func (s *Store) Build(ctx context.Context, r BuildRequest) (*Snapshot, error) {
	if !validID.MatchString(r.ID) || r.ID == r.ParentID {
		return nil, errors.New("invalid snapshot ID or parent")
	}
	if r.MemorySize <= 0 || r.DiskSize <= 0 || r.MemorySize%BlockSize != 0 || r.DiskSize%BlockSize != 0 {
		return nil, errors.New("memory and disk sizes must be positive multiples of 4096")
	}
	var parent *Snapshot
	var err error
	if r.ParentID != "" {
		parent, err = s.Load(r.ParentID)
		if err != nil {
			return nil, fmt.Errorf("load parent: %w", err)
		}
		if parent.Manifest.Memory.Size != r.MemorySize || parent.Manifest.Disk.Size != r.DiskSize {
			return nil, errors.New("snapshot layout changed")
		}
	} else {
		if err := regularSize(r.DiskPath, r.DiskSize); err != nil {
			return nil, err
		}
	}
	if err := regularSize(r.MemoryPath, r.MemorySize); err != nil {
		return nil, err
	}
	identity, err := captureRequest(ctx, r, parent)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filepath.Join(s.Root, r.ID)); err == nil {
		return s.committedCapture(r.ID, identity)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if parent != nil {
		if err := ProbeSparseFilesystem(filepath.Dir(r.MemoryPath)); err != nil {
			return nil, err
		}
		if err := validateDiskSeal(r.DiskPath, r.ParentID, r.DiskSize); err != nil {
			return nil, err
		}
		if err := validateQCOW2(ctx, s.Options.QemuImgPath, r.DiskPath, r.DiskSize, ""); err != nil {
			return nil, err
		}
	}
	pending, err := os.MkdirTemp(s.Root, ".pending-"+r.ID+"-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(pending)
	m := Manifest{Format: Format, ID: r.ID, ParentID: r.ParentID}
	for _, item := range []struct {
		name, target, input, backend string
		size                         int64
		image                        *Image
		previous                     *Image
	}{
		{"memory.erofs", "/memory/memfile", r.MemoryPath, "sparse", r.MemorySize, &m.Memory, imageOf(parent, true)},
		{"disk.erofs", "/disk/rootfs.ext4", r.DiskPath, "qcow2", r.DiskSize, &m.Disk, imageOf(parent, false)},
	} {
		out := filepath.Join(pending, item.name)
		args := []string{"-b4096", "-Eforce-chunk-indexes", "--chunksize=4096"}
		if item.previous == nil {
			tree := filepath.Join(pending, "source-"+item.name)
			dest := filepath.Join(tree, item.target)
			if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
				return nil, err
			}
			// Full exports do not encode inheritance; a streamed copy is safe here.
			if err := copyFile(item.input, dest); err != nil {
				return nil, err
			}
			args = append(args, out, tree)
			if err := command(ctx, s.Options.MkfsPath, args...); err != nil {
				return nil, err
			}
			if err := os.RemoveAll(tree); err != nil {
				return nil, err
			}
		} else {
			if strings.ContainsAny(item.input, ":\n") {
				return nil, errors.New("delta path contains a CLI delimiter")
			}
			args = append(args, "--file-delta="+item.backend+":"+item.target+":"+item.input, out, filepath.Join(s.Root, item.previous.File))
			if err := command(ctx, s.Options.MkfsPath, args...); err != nil {
				return nil, err
			}
			item.image.Devices = append([]Artifact{item.previous.Artifact}, item.previous.Devices...)
		}
		fsckArgs := make([]string, 0, len(item.image.Devices)+1)
		for _, dev := range item.image.Devices {
			fsckArgs = append(fsckArgs, "--device="+filepath.Join(s.Root, dev.File))
		}
		if err := command(ctx, s.Options.FsckPath, append(fsckArgs, out)...); err != nil {
			return nil, err
		}
		artifact, err := describe(out, filepath.Join(r.ID, item.name))
		if err != nil {
			return nil, err
		}
		item.image.Artifact, item.image.Size = artifact, item.size
	}
	for _, f := range []struct {
		source, name string
		out          **Artifact
	}{{r.VMStatePath, "vmstate", nil}, {r.MetadataPath, "metadata.json", &m.Metadata}} {
		if f.source == "" && f.out != nil {
			continue
		}
		path := filepath.Join(pending, f.name)
		if err := copyFile(f.source, path); err != nil {
			return nil, err
		}
		a, err := describe(path, filepath.Join(r.ID, f.name))
		if err != nil {
			return nil, err
		}
		if a.Bytes == 0 {
			return nil, fmt.Errorf("empty %s", f.name)
		}
		if f.out == nil {
			m.VMState = a
		} else {
			*f.out = &a
		}
	}
	// Input files are a sealed-capture contract. Detect accidental modification
	// while external tools ran before binding their output to this identity.
	after, err := captureRequest(ctx, r, parent)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(identity, after) {
		return nil, errors.New("sealed capture changed during EROFS build")
	}
	m.Capture, err = s.writeCapture(pending, r.ID, identity)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(pending, ManifestName), append(data, '\n'), 0400); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(pending)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		path := filepath.Join(pending, entry.Name())
		if err := os.Chmod(path, 0400); err != nil {
			return nil, err
		}
		if err := syncPath(path); err != nil {
			return nil, err
		}
	}
	if err := syncPath(pending); err != nil {
		return nil, err
	}
	// RENAME_NOREPLACE prevents concurrent retries from replacing a generation.
	if err := unix.Renameat2(unix.AT_FDCWD, pending, unix.AT_FDCWD, filepath.Join(s.Root, r.ID), unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return s.committedCapture(r.ID, identity)
		}
		return nil, err
	}
	snapshot := &Snapshot{Dir: filepath.Join(s.Root, r.ID), Manifest: m, store: s}
	// A returned snapshot with an error means rename committed but directory fsync
	// failed. The caller must retry from the committed snapshot, not recapture.
	return snapshot, syncPath(s.Root)
}

func imageOf(s *Snapshot, memory bool) *Image {
	if s == nil {
		return nil
	}
	if memory {
		return &s.Manifest.Memory
	}
	return &s.Manifest.Disk
}

func (s *Store) Load(id string) (*Snapshot, error) {
	return s.load(context.Background(), id, make(map[string]bool))
}

// VerifyCommitted validates the entire immutable manifest chain and confirms
// durability of the published directory entry. It never builds or recovers an
// image. A nonnil snapshot with an error means its contents were validated but
// directory durability (or the caller's remaining context) was not confirmed.
// Missing/corrupt snapshots always return nil with the validation error.
func (s *Store) VerifyCommitted(ctx context.Context, id string) (*Snapshot, error) {
	return s.verifyCommitted(ctx, id, syncPath)
}

func (s *Store) verifyCommitted(ctx context.Context, id string, syncDir func(string) error) (*Snapshot, error) {
	snapshot, err := s.load(ctx, id, make(map[string]bool))
	if err != nil {
		return nil, err
	}
	for _, dir := range []string{snapshot.Dir, s.Root} {
		if err := ctx.Err(); err != nil {
			return snapshot, err
		}
		if err := syncDir(dir); err != nil {
			return snapshot, fmt.Errorf("confirm committed snapshot directory %s: %w", dir, err)
		}
		if err := ctx.Err(); err != nil {
			return snapshot, err
		}
	}
	return snapshot, nil
}

func (s *Store) load(ctx context.Context, id string, seen map[string]bool) (*Snapshot, error) {
	ctx = withVerification(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validID.MatchString(id) || seen[id] || len(seen) > 255 {
		return nil, errors.New("invalid or cyclic snapshot chain")
	}
	seen[id] = true
	dir := filepath.Join(s.Root, id)
	data, err := trackedMetadata(ctx, filepath.Join(dir, ManifestName))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.Format == FormatV2 {
		return s.loadV2(ctx, dir, id, m, seen)
	}
	if m.Upper != nil || m.Lower != nil || m.Boot != nil || m.MemoryCapture != "" || m.UpperContentSHA256 != "" {
		return nil, errors.New("legacy snapshot contains v2 layout fields")
	}
	if m.Format != Format || m.ID != id || m.Memory.Size <= 0 || m.Memory.Size%BlockSize != 0 || m.Disk.Size <= 0 || m.Disk.Size%BlockSize != 0 {
		return nil, errors.New("invalid EROFS snapshot manifest")
	}
	if m.Memory.File != filepath.Join(id, "memory.erofs") || m.Disk.File != filepath.Join(id, "disk.erofs") || m.VMState.File != filepath.Join(id, "vmstate") || (m.Metadata != nil && m.Metadata.File != filepath.Join(id, "metadata.json")) || (m.Capture != nil && m.Capture.File != filepath.Join(id, captureName)) {
		return nil, errors.New("snapshot artifact names do not match their generation")
	}
	if m.ParentID == "" {
		if len(m.Memory.Devices) != 0 || len(m.Disk.Devices) != 0 {
			return nil, errors.New("baseline has unexpected external devices")
		}
	} else {
		parent, err := s.load(ctx, m.ParentID, seen)
		if err != nil {
			return nil, fmt.Errorf("load parent of %s: %w", id, err)
		}
		if m.Memory.Size != parent.Manifest.Memory.Size || m.Disk.Size != parent.Manifest.Disk.Size || !slices.Equal(m.Memory.Devices, append([]Artifact{parent.Manifest.Memory.Artifact}, parent.Manifest.Memory.Devices...)) || !slices.Equal(m.Disk.Devices, append([]Artifact{parent.Manifest.Disk.Artifact}, parent.Manifest.Disk.Devices...)) {
			return nil, errors.New("snapshot parent size or ordered device binding mismatch")
		}
	}
	artifacts := []Artifact{m.Memory.Artifact, m.Disk.Artifact, m.VMState}
	if m.Metadata != nil {
		artifacts = append(artifacts, *m.Metadata)
	}
	if m.Capture != nil {
		artifacts = append(artifacts, *m.Capture)
	}
	for _, a := range artifacts {
		if err := s.verifyArtifact(ctx, a); err != nil {
			return nil, err
		}
	}

	return &Snapshot{Dir: dir, Manifest: m, store: s}, nil
}

func describe(path, name string) (Artifact, error) {
	return describeContext(context.Background(), path, name)
}

func describeContext(ctx context.Context, path, name string) (Artifact, error) {
	if err := ctx.Err(); err != nil {
		return Artifact{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Artifact{}, err
	}
	if !info.Mode().IsRegular() {
		return Artifact{}, fmt.Errorf("not a regular file: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return Artifact{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx: ctx, reader: f})
	if err != nil {
		return Artifact{}, err
	}
	if err := ctx.Err(); err != nil {
		return Artifact{}, err
	}
	return Artifact{File: name, Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

func regularSize(path string, size int64) error {
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !i.Mode().IsRegular() || i.Size() != size {
		return fmt.Errorf("%s must be a regular file of size %d", path, size)
	}
	return nil
}

func copyFile(src, dst string) error {
	i, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !i.Mode().IsRegular() {
		return fmt.Errorf("not a regular capture: %s", src)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	return errors.Join(copyErr, out.Close())
}

func syncPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func command(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %w: %s", name, err, out)
	}
	return nil
}
