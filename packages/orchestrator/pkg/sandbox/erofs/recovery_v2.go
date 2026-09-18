//go:build linux

package erofs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type rawRecoveryRecord struct {
	Version      int             `json:"version"`
	Request      BuildV2Request  `json:"request"`
	Firecracker  ProcessIdentity `json:"firecracker"`
	RawPath      string          `json:"raw_path"`
	RawFile      FileIdentity    `json:"raw_file"`
	Target       string          `json:"target"`
	ParentDigest string          `json:"parent_digest"`
	Memory       inputIdentity   `json:"memory"`
	Upper        inputIdentity   `json:"upper"`
	VMState      inputIdentity   `json:"vmstate"`
	Metadata     *inputIdentity  `json:"metadata,omitempty"`
}

func (s *Store) validateV2CapturePaths(recordPath string, r BuildV2Request, target string) error {
	if r.MemorySize <= 0 || r.MemorySize%BlockSize != 0 || r.UpperSize <= 0 || r.UpperSize%BlockSize != 0 || r.ParentID == r.ID ||
		(r.ParentID != "" && !validID.MatchString(r.ParentID)) {
		return errors.New("invalid v2 recovery sizes or parent")
	}
	dir := filepath.Dir(recordPath)
	if !validID.MatchString(r.ID) || !filepath.IsAbs(dir) || filepath.Dir(dir) != filepath.Join(s.Root, ".captures") || !strings.HasPrefix(filepath.Base(dir), r.ID+"-") {
		return errors.New("v2 recovery record is outside its capture directory")
	}
	if target != filepath.Join(dir, "upper.sealed.raw") {
		return errors.New("invalid v2 sealed upper target")
	}
	for _, path := range []string{r.MemoryPath, r.VMStatePath, r.MetadataPath} {
		if path != "" && (filepath.Dir(path) != dir || filepath.Clean(path) != path) {
			return errors.New("v2 capture input is outside its directory")
		}
	}
	return nil
}

// RecordV2Recovery runs after RAM capture with the VM paused and upper quiesced.
// It binds the raw bytes as well as inode and original writer, so recovery can
// accept either an atomic move or a completed copy into the capture directory.
func (s *Store) RecordV2Recovery(ctx context.Context, path string, r BuildV2Request, rawPath, target string, writer ProcessIdentity) error {
	if err := s.validateV2CapturePaths(path, r, target); err != nil {
		return err
	}
	if !filepath.IsAbs(rawPath) || filepath.Clean(rawPath) != rawPath {
		return errors.New("raw recovery source must be canonical and absolute")
	}
	if writer.PID <= 0 || writer.StartTime == 0 || writer.BootID == "" {
		return errors.New("missing raw writer identity")
	}
	if r.MemoryCapture != "full" && r.MemoryCapture != "diff" {
		return errors.New("invalid memory capture kind")
	}
	if err := s.validateBoot(ctx, r.Boot, r.Lower); err != nil {
		return err
	}
	if err := regularSize(rawPath, r.UpperSize); err != nil {
		return err
	}
	file, err := identifyFile(rawPath)
	if err != nil {
		return err
	}
	record := rawRecoveryRecord{Version: 2, Request: r, Firecracker: writer, RawPath: rawPath, RawFile: file, Target: target}
	if r.ParentID != "" {
		parent, err := s.LoadContext(ctx, r.ParentID)
		if err != nil {
			return err
		}
		record.ParentDigest, err = manifestDigest(parent.Manifest)
		if err != nil {
			return err
		}
	}
	record.Memory, err = fingerprintMemory(ctx, r.MemoryPath, r.MemorySize, r.MemoryCapture == "diff")
	if err != nil {
		return err
	}
	record.Upper, err = fingerprintInput(ctx, rawPath)
	if err != nil {
		return err
	}
	record.VMState, err = fingerprintInput(ctx, r.VMStatePath)
	if err != nil {
		return err
	}
	if record.VMState.Bytes == 0 {
		return errors.New("empty captured vmstate")
	}
	if r.MetadataPath != "" {
		metadata, err := fingerprintInput(ctx, r.MetadataPath)
		if err != nil {
			return err
		}
		record.Metadata = &metadata
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if err := s.syncRecoveryParents(path); err != nil {
		return err
	}
	if err := atomicRecord(path, data, false); err != nil {
		return err
	}
	return s.syncRecoveryParents(path)
}

func (s *Store) recoverV2(ctx context.Context, path string, data []byte) (snapshot *Snapshot, result error) {
	var record rawRecoveryRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	r := record.Request
	if record.Version != 2 || !filepath.IsAbs(record.RawPath) || filepath.Clean(record.RawPath) != record.RawPath {
		return nil, errors.New("invalid v2 recovery source")
	}
	if err := s.validateV2CapturePaths(path, r, record.Target); err != nil {
		return nil, err
	}
	if r.MemoryCapture != "full" && r.MemoryCapture != "diff" {
		return nil, errors.New("invalid recovered memory kind")
	}
	if err := processTerminated(record.Firecracker); err != nil {
		return nil, err
	}
	if err := s.validateBoot(ctx, r.Boot, r.Lower); err != nil {
		return nil, err
	}
	memory, err := fingerprintMemory(ctx, r.MemoryPath, r.MemorySize, r.MemoryCapture == "diff")
	if err != nil {
		return nil, err
	}
	vmstate, err := fingerprintInput(ctx, r.VMStatePath)
	if err != nil {
		return nil, err
	}
	if memory != record.Memory || vmstate != record.VMState {
		return nil, errors.New("v2 RAM or vmstate changed since capture")
	}
	if record.Metadata != nil {
		metadata, err := fingerprintInput(ctx, r.MetadataPath)
		if err != nil {
			return nil, err
		}
		if metadata != *record.Metadata {
			return nil, errors.New("v2 metadata changed since capture")
		}
	} else if r.MetadataPath != "" {
		return nil, errors.New("missing v2 metadata binding")
	}
	if record.Upper.Bytes != r.UpperSize || !validDigest(record.Upper.SHA256) {
		return nil, errors.New("invalid raw upper recovery fingerprint")
	}
	if _, err := os.Lstat(record.Target); errors.Is(err, os.ErrNotExist) {
		file, err := identifyFile(record.RawPath)
		if err != nil {
			return nil, err
		}
		if file != record.RawFile {
			return nil, errors.New("raw source inode changed since capture")
		}
		upper, err := fingerprintInput(ctx, record.RawPath)
		if err != nil {
			return nil, err
		}
		if upper != record.Upper {
			return nil, errors.New("raw source bytes changed since capture")
		}
		dir, err := os.MkdirTemp(filepath.Dir(path), ".raw-recover-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		tmp := filepath.Join(dir, "upper.raw")
		stats, err := MaterializeRawFile(ctx, record.RawPath, tmp, r.UpperSize)
		if err != nil {
			return nil, err
		}
		if stats.SourceSHA256 != record.Upper.SHA256 {
			return nil, errors.New("raw source changed during recovery copy")
		}
		if err := os.Chmod(tmp, 0400); err != nil {
			return nil, err
		}
		if err := syncPath(tmp); err != nil {
			return nil, err
		}
		if err := unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, record.Target, unix.RENAME_NOREPLACE); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if err := regularSize(record.Target, r.UpperSize); err != nil {
		return nil, err
	}
	upper, err := fingerprintInput(ctx, record.Target)
	if err != nil {
		return nil, err
	}
	if upper != record.Upper {
		return nil, errors.New("sealed raw upper differs from recorded cutoff")
	}
	if err := s.syncRecoveryParents(path); err != nil {
		return nil, err
	}
	r.UpperPath = record.Target
	if r.ParentID != "" {
		parent, err := s.LoadContext(ctx, r.ParentID)
		if err != nil {
			return nil, err
		}
		digest, err := manifestDigest(parent.Manifest)
		if err != nil {
			return nil, err
		}
		if digest != record.ParentDigest {
			return nil, errors.New("v2 recovery parent changed")
		}
		mounted, err := parent.Mount(ctx, filepath.Join(s.Root, ".shared-mounts"))
		if err != nil {
			return nil, err
		}
		defer func() { result = errors.Join(result, mounted.Close()) }()
		r.ParentUpperPath = mounted.DiskPath
	}
	return s.BuildV2(ctx, r)
}

// PublishV2Request retries a sealed request after its original shared mounts
// have gone away, reacquiring the immutable parent upper view when necessary.
func (s *Store) PublishV2Request(ctx context.Context, r BuildV2Request) (snapshot *Snapshot, result error) {
	if r.ParentID != "" {
		parent, err := s.LoadContext(ctx, r.ParentID)
		if err != nil {
			return nil, err
		}
		if parent.Manifest.Format != FormatV2 {
			return nil, fmt.Errorf("v2 request has a legacy parent")
		}
		mounted, err := parent.Mount(ctx, filepath.Join(s.Root, ".shared-mounts"))
		if err != nil {
			return nil, err
		}
		defer func() { result = errors.Join(result, mounted.Close()) }()
		r.ParentUpperPath = mounted.DiskPath
	}
	return s.BuildV2(ctx, r)
}
