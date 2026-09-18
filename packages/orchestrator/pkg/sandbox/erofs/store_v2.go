//go:build linux

package erofs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// BuildV2Request describes a sealed, same-cutoff VM capture. UpperPath is always
// a complete raw image; ParentUpperPath is the verified parent's complete view.
// MemoryCapture is "full" or "diff", independently of whether Upper has a parent.
type BuildV2Request struct {
	ID, ParentID                           string
	MemoryPath, UpperPath, ParentUpperPath string
	VMStatePath, MetadataPath              string
	MemorySize, UpperSize                  int64
	MemoryCapture                          string
	Boot                                   BootLayout
	Lower                                  *Lower
}

func (s *Store) BuildV2(ctx context.Context, r BuildV2Request) (*Snapshot, error) {
	if !validID.MatchString(r.ID) || r.ID == r.ParentID || r.MemorySize <= 0 || r.MemorySize%BlockSize != 0 || r.UpperSize <= 0 || r.UpperSize%BlockSize != 0 {
		return nil, errors.New("invalid v2 capture ID or capacity")
	}
	if r.MemoryCapture != "full" && r.MemoryCapture != "diff" {
		return nil, errors.New("invalid memory capture kind")
	}
	if r.ParentID == "" && r.MemoryCapture != "full" {
		return nil, errors.New("initial memory capture must be full")
	}
	if err := s.validateBoot(ctx, r.Boot, r.Lower); err != nil {
		return nil, err
	}
	if err := regularSize(r.MemoryPath, r.MemorySize); err != nil {
		return nil, err
	}
	if err := regularSize(r.UpperPath, r.UpperSize); err != nil {
		return nil, err
	}
	var parent *Snapshot
	if r.ParentID != "" {
		var err error
		parent, err = s.LoadContext(ctx, r.ParentID)
		if err != nil {
			return nil, err
		}
		m := parent.Manifest
		if m.Format != FormatV2 || m.Memory.Size != r.MemorySize || m.Upper.Size != r.UpperSize ||
			descriptorDigest(m.Boot) != descriptorDigest(r.Boot) || descriptorDigest(m.Lower) != descriptorDigest(r.Lower) {
			return nil, errors.New("v2 parent layout, binaries, lower or capacity changed")
		}
		if err := regularSize(r.ParentUpperPath, r.UpperSize); err != nil {
			return nil, err
		}
	}
	identity, upperDigest, err := s.v2CaptureIdentity(ctx, r, parent)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filepath.Join(s.Root, r.ID)); err == nil {
		return s.committedCapture(r.ID, identity)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	pending, err := os.MkdirTemp(s.Root, ".pending-"+r.ID+"-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(pending)
	m := Manifest{Format: FormatV2, ID: r.ID, ParentID: r.ParentID, Boot: &r.Boot, Lower: r.Lower,
		MemoryCapture: r.MemoryCapture, UpperContentSHA256: upperDigest}
	var memoryParent, upperParent *Image
	if parent != nil {
		upperParent = parent.Manifest.Upper
		if r.MemoryCapture == "diff" {
			memoryParent = &parent.Manifest.Memory
		}
	}
	m.Memory, err = s.buildFileImage(ctx, pending, r.ID, "memory.erofs", "/memory/memfile", r.MemoryPath, r.MemorySize, memoryParent)
	if err != nil {
		return nil, err
	}
	upperInput := r.UpperPath
	if parent != nil {
		upperInput = filepath.Join(pending, "upper.delta")
		if _, err := CreateRawDelta(ctx, r.ParentUpperPath, r.UpperPath, upperInput, r.UpperSize); err != nil {
			return nil, err
		}
	}
	upper, err := s.buildFileImage(ctx, pending, r.ID, "upper.erofs", "/upper/upper.ext4", upperInput, r.UpperSize, upperParent)
	if err != nil {
		return nil, err
	}
	m.Upper = &upper
	if parent != nil {
		if err := os.Remove(upperInput); err != nil {
			return nil, err
		}
	}
	for _, item := range []struct {
		source, name string
		target       **Artifact
	}{
		{r.VMStatePath, "vmstate", nil}, {r.MetadataPath, "metadata.json", &m.Metadata},
	} {
		if item.source == "" && item.target != nil {
			continue
		}
		path := filepath.Join(pending, item.name)
		if err := copyFile(item.source, path); err != nil {
			return nil, err
		}
		a, err := describeContext(ctx, path, filepath.Join(r.ID, item.name))
		if err != nil {
			return nil, err
		}
		if a.Bytes == 0 {
			return nil, errors.New("empty captured state or metadata")
		}
		if item.target == nil {
			m.VMState = a
		} else {
			*item.target = &a
		}
	}
	after, _, err := s.v2CaptureIdentity(ctx, r, parent)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(identity, after) {
		return nil, errors.New("sealed v2 inputs changed during publication")
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
	if err := sealDirectory(pending); err != nil {
		return nil, err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, pending, unix.AT_FDCWD, filepath.Join(s.Root, r.ID), unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return s.committedCapture(r.ID, identity)
		}
		return nil, err
	}
	return &Snapshot{Dir: filepath.Join(s.Root, r.ID), Manifest: m, store: s}, syncPath(s.Root)
}

func (s *Store) v2CaptureIdentity(ctx context.Context, r BuildV2Request, parent *Snapshot) ([]byte, string, error) {
	memory, err := fingerprintMemory(ctx, r.MemoryPath, r.MemorySize, r.MemoryCapture == "diff")
	if err != nil {
		return nil, "", err
	}
	inputs := make(map[string]Artifact)
	for name, path := range map[string]string{"upper": r.UpperPath, "vmstate": r.VMStatePath, "metadata": r.MetadataPath} {
		if name == "metadata" && path == "" {
			continue
		}
		a, err := describeContext(ctx, path, "")
		if err != nil {
			return nil, "", err
		}
		if a.Bytes == 0 {
			return nil, "", errors.New("empty v2 input")
		}
		inputs[name] = a
	}
	var parentDigest string
	if parent != nil {
		a, err := describeContext(ctx, r.ParentUpperPath, "")
		if err != nil {
			return nil, "", err
		}
		if a.SHA256 != parent.Manifest.UpperContentSHA256 {
			return nil, "", errors.New("parent upper content differs from committed snapshot")
		}
		inputs["parent_upper"] = a
		parentDigest = fmt.Sprintf("%x", descriptorDigest(parent.Manifest))
	}
	data, err := json.Marshal(struct {
		Format, ID, ParentID, ParentDigest, MemoryCapture string
		MemorySize, UpperSize                             int64
		Memory                                            inputIdentity
		Inputs                                            map[string]Artifact
		Boot                                              BootLayout
		Lower                                             *Lower
	}{FormatV2, r.ID, r.ParentID, parentDigest, r.MemoryCapture, r.MemorySize, r.UpperSize, memory, inputs, r.Boot, r.Lower})
	return data, inputs["upper"].SHA256, err
}

func (s *Store) buildFileImage(ctx context.Context, dir, prefix, name, target, input string, size int64, parent *Image) (Image, error) {
	out := filepath.Join(dir, name)
	args := []string{"-b4096", "-Eforce-chunk-indexes", "--chunksize=4096"}
	image := Image{Size: size}
	if parent == nil {
		tree := filepath.Join(dir, "source-"+name)
		destination := filepath.Join(tree, strings.TrimPrefix(target, "/"))
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return image, err
		}
		if err := copyFile(input, destination); err != nil {
			return image, err
		}
		args = append(args, out, tree)
		if err := command(ctx, s.Options.MkfsPath, args...); err != nil {
			return image, err
		}
		if err := os.RemoveAll(tree); err != nil {
			return image, err
		}
	} else {
		if strings.ContainsAny(input, ":\n") {
			return image, errors.New("delta path contains a CLI delimiter")
		}
		if err := ValidateSparseDiff(input, size); err != nil {
			return image, err
		}
		args = append(args, "--file-delta=sparse:"+target+":"+input, out, filepath.Join(s.Root, parent.File))
		if err := command(ctx, s.Options.MkfsPath, args...); err != nil {
			return image, err
		}
		image.Devices = append([]Artifact{parent.Artifact}, parent.Devices...)
	}
	var fsck []string
	for _, device := range image.Devices {
		fsck = append(fsck, "--device="+filepath.Join(s.Root, device.File))
	}
	if err := command(ctx, s.Options.FsckPath, append(fsck, out)...); err != nil {
		return image, err
	}
	a, err := describeContext(ctx, out, filepath.Join(prefix, name))
	if err != nil {
		return image, err
	}
	image.Artifact = a
	return image, nil
}

func (s *Store) loadV2(ctx context.Context, dir, id string, m Manifest, seen map[string]bool) (*Snapshot, error) {
	if m.ID != id || m.Upper == nil || m.Boot == nil || m.Capture == nil ||
		descriptorDigest(m.Disk) != descriptorDigest(Image{}) ||
		m.Memory.Size <= 0 || m.Memory.Size%BlockSize != 0 || m.Upper.Size <= 0 || m.Upper.Size%BlockSize != 0 || !validDigest(m.UpperContentSHA256) ||
		(m.MemoryCapture != "full" && m.MemoryCapture != "diff") {
		return nil, errors.New("invalid v2 snapshot manifest")
	}
	if err := s.validateBoot(ctx, *m.Boot, m.Lower); err != nil {
		return nil, err
	}
	if m.Memory.File != filepath.Join(id, "memory.erofs") || m.Upper.File != filepath.Join(id, "upper.erofs") ||
		m.VMState.File != filepath.Join(id, "vmstate") || m.Capture.File != filepath.Join(id, captureName) ||
		(m.Metadata != nil && m.Metadata.File != filepath.Join(id, "metadata.json")) {
		return nil, errors.New("v2 artifacts do not match their generation")
	}
	if m.MemoryCapture == "full" && len(m.Memory.Devices) != 0 {
		return nil, errors.New("full memory has external devices")
	}
	if m.ParentID == "" {
		if m.MemoryCapture != "full" || len(m.Upper.Devices) != 0 {
			return nil, errors.New("invalid v2 baseline inheritance")
		}
	} else {
		parent, err := s.load(ctx, m.ParentID, seen)
		if err != nil {
			return nil, err
		}
		p := parent.Manifest
		if p.Format != FormatV2 || m.Memory.Size != p.Memory.Size || m.Upper.Size != p.Upper.Size ||
			descriptorDigest(m.Boot) != descriptorDigest(p.Boot) || descriptorDigest(m.Lower) != descriptorDigest(p.Lower) ||
			!slices.Equal(m.Upper.Devices, append([]Artifact{p.Upper.Artifact}, p.Upper.Devices...)) {
			return nil, errors.New("v2 parent layout or upper dependencies changed")
		}
		if m.MemoryCapture == "diff" && !slices.Equal(m.Memory.Devices, append([]Artifact{p.Memory.Artifact}, p.Memory.Devices...)) {
			return nil, errors.New("v2 memory dependencies differ from parent")
		}
	}
	artifacts := []Artifact{m.Memory.Artifact, m.Upper.Artifact, m.VMState, *m.Capture}
	if m.Metadata != nil {
		artifacts = append(artifacts, *m.Metadata)
	}
	for _, artifact := range artifacts {
		if err := s.verifyArtifact(ctx, artifact); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &Snapshot{Dir: dir, Manifest: m, store: s}, nil
}
