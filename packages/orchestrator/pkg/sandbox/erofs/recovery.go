//go:build linux

package erofs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// ProcessIdentity identifies a producer across PID reuse and host restarts.
// Recovery only observes this identity; it never signals a persisted PID.
type ProcessIdentity struct {
	PID       int    `json:"pid"`
	StartTime uint64 `json:"start_time"`
	BootID    string `json:"boot_id"`
}

type FileIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

// OverlayRecovery binds the retained qcow2 inode to its original backing view
// and producer. ParentID is the backing generation even when a cold boot will
// publish a new Full baseline with BuildRequest.ParentID empty.
type OverlayRecovery struct {
	Path        string          `json:"path"`
	BackingPath string          `json:"backing_path"`
	ParentID    string          `json:"parent_id"`
	Size        int64           `json:"size"`
	File        FileIdentity    `json:"file"`
	Producer    ProcessIdentity `json:"producer"`
}

type recoveryRecord struct {
	Version              int             `json:"version"`
	Request              BuildRequest    `json:"request"`
	Overlay              OverlayRecovery `json:"overlay"`
	Firecracker          ProcessIdentity `json:"firecracker"`
	ParentManifestSHA256 string          `json:"parent_manifest_sha256"`
	Memory               inputIdentity   `json:"memory"`
	VMState              inputIdentity   `json:"vmstate"`
	Metadata             *inputIdentity  `json:"metadata,omitempty"`
}

func IdentifyProcess(pid int) (ProcessIdentity, error) {
	if pid <= 0 {
		return ProcessIdentity{}, errors.New("invalid producer PID")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ProcessIdentity{}, err
	}
	start, _, err := processStat(pid)
	if err != nil {
		return ProcessIdentity{}, err
	}
	return ProcessIdentity{PID: pid, StartTime: start, BootID: strings.TrimSpace(string(boot))}, nil
}

func processStat(pid int) (uint64, string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, "", err
	}
	// comm is parenthesized and may itself contain spaces or parentheses.
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return 0, "", errors.New("malformed process stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 {
		return 0, "", errors.New("short process stat")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	return start, fields[0], err
}

// ProcessTerminated returns nil only when the recorded producer has exited or
// its PID belongs to a different process/boot. It never signals a process.
func ProcessTerminated(p ProcessIdentity) error { return processTerminated(p) }

func processTerminated(p ProcessIdentity) error {
	if p.PID <= 0 || p.StartTime == 0 || p.BootID == "" {
		return errors.New("incomplete producer identity")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(boot)) != p.BootID {
		return nil
	}
	start, state, err := processStat(p.PID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if start != p.StartTime || state == "Z" || state == "X" {
		return nil
	}
	return fmt.Errorf("original producer PID %d is still alive; close it before recovery", p.PID)
}

func identifyFile(path string) (FileIdentity, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return FileIdentity{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return FileIdentity{}, errors.New("overlay is not a regular file")
	}
	return FileIdentity{Device: uint64(st.Dev), Inode: st.Ino}, nil
}

func (o *Overlay) RecoveryInfo() (OverlayRecovery, error) {
	file, err := identifyFile(o.file)
	if err != nil {
		return OverlayRecovery{}, err
	}
	if file != o.fileIdentity {
		return OverlayRecovery{}, errors.New("runtime qcow2 inode changed")
	}
	return OverlayRecovery{Path: o.file, BackingPath: o.opts.BackingPath, ParentID: o.opts.ParentID, Size: o.opts.Size, File: file, Producer: o.producer}, nil
}

// RecordRecovery must be called after successful native RAM/vmstate capture,
// while the VM remains paused, and before stopping the original processes.
// The caller must not resume the captured VM after recording this cutoff.
func (s *Store) RecordRecovery(ctx context.Context, path string, r BuildRequest, overlay OverlayRecovery, fc ProcessIdentity) error {
	if !validID.MatchString(r.ID) || !validID.MatchString(overlay.ParentID) || r.ID == overlay.ParentID || (r.ParentID != "" && r.ParentID != overlay.ParentID) {
		return errors.New("invalid recovery snapshot or backing parent")
	}
	if r.MemorySize <= 0 || r.MemorySize%BlockSize != 0 || r.DiskSize != overlay.Size || overlay.Size <= 0 || overlay.Size%BlockSize != 0 {
		return errors.New("invalid recovery sizes")
	}
	if fc.PID <= 0 || fc.StartTime == 0 || fc.BootID == "" || overlay.Producer.PID <= 0 || overlay.Producer.StartTime == 0 || overlay.Producer.BootID == "" {
		return errors.New("recovery requires original producer identities")
	}
	if !filepath.IsAbs(overlay.Path) || !filepath.IsAbs(overlay.BackingPath) {
		return errors.New("recovery overlay paths must be absolute")
	}
	file, err := identifyFile(overlay.Path)
	if err != nil {
		return err
	}
	if file != overlay.File {
		return errors.New("recovery qcow2 inode mismatch")
	}
	parent, err := s.Load(overlay.ParentID)
	if err != nil {
		return err
	}
	if parent.Manifest.Disk.Size != overlay.Size {
		return errors.New("recovery backing capacity mismatch")
	}
	if r.ParentID != "" && parent.Manifest.Memory.Size != r.MemorySize {
		return errors.New("recovery parent RAM size mismatch")
	}
	for _, p := range []*string{&r.MemoryPath, &r.VMStatePath, &r.MetadataPath} {
		if *p == "" {
			continue
		}
		*p, err = filepath.Abs(*p)
		if err != nil {
			return err
		}
	}
	if err := regularSize(r.MemoryPath, r.MemorySize); err != nil {
		return err
	}
	// Before seal, the runtime qcow2 is the retained disk input. The Full
	// baseline recovery branch later converts this through the bound parent.
	r.DiskPath = overlay.Path
	record := recoveryRecord{Version: 1, Request: r, Overlay: overlay, Firecracker: fc}
	record.ParentManifestSHA256, err = manifestDigest(parent.Manifest)
	if err != nil {
		return err
	}
	record.Memory, err = fingerprintMemory(ctx, r.MemoryPath, r.MemorySize, r.ParentID != "")
	if err != nil {
		return err
	}
	record.VMState, err = fingerprintInput(ctx, r.VMStatePath)
	if err != nil {
		return err
	}
	if record.VMState.Bytes == 0 {
		return errors.New("empty recovery vmstate")
	}
	if r.MetadataPath != "" {
		metadata, err := fingerprintInput(ctx, r.MetadataPath)
		if err != nil {
			return err
		}
		if metadata.Bytes == 0 {
			return errors.New("empty recovery metadata")
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

func (s *Store) syncRecoveryParents(path string) error {
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(s.Root, dir)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("recovery record must be inside its snapshot store")
	}
	// Begin creates both .captures and the per-capture directory lazily. Their
	// names must be durable along with the record, before producers are stopped.
	for {
		if err := syncPath(dir); err != nil {
			return err
		}
		if dir == s.Root {
			return syncPath(filepath.Dir(s.Root))
		}
		dir = filepath.Dir(dir)
	}
}

func manifestDigest(m Manifest) (string, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

// Recover finishes sealing only after both original producers have terminated.
// Clean qcow2 validation and its backing binding are mandatory. RAM is never
// recaptured, copied or rebased here, so its original DATA/HOLE layout survives.
func (s *Store) Recover(ctx context.Context, path string) (snapshot *Snapshot, result error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var record recoveryRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	if record.Version != 1 {
		return nil, errors.New("unsupported capture recovery version")
	}
	r := record.Request
	if !validID.MatchString(r.ID) || !validID.MatchString(record.Overlay.ParentID) || (r.ParentID != "" && r.ParentID != record.Overlay.ParentID) || r.DiskPath != record.Overlay.Path || r.DiskSize != record.Overlay.Size || r.MemorySize <= 0 || r.MemorySize%BlockSize != 0 || r.DiskSize <= 0 || r.DiskSize%BlockSize != 0 {
		return nil, errors.New("recovery request binding mismatch")
	}
	if err := processTerminated(record.Firecracker); err != nil {
		return nil, fmt.Errorf("Firecracker: %w", err)
	}
	if err := processTerminated(record.Overlay.Producer); err != nil {
		return nil, fmt.Errorf("QEMU: %w", err)
	}
	file, err := identifyFile(record.Overlay.Path)
	if err != nil {
		return nil, err
	}
	if file != record.Overlay.File {
		return nil, errors.New("retained qcow2 inode does not match recovery record")
	}
	parent, err := s.Load(record.Overlay.ParentID)
	if err != nil {
		return nil, err
	}
	digest, err := manifestDigest(parent.Manifest)
	if err != nil {
		return nil, err
	}
	if digest != record.ParentManifestSHA256 {
		return nil, errors.New("recovery parent manifest changed")
	}
	memory, err := fingerprintMemory(ctx, r.MemoryPath, r.MemorySize, r.ParentID != "")
	if err != nil {
		return nil, err
	}
	vmstate, err := fingerprintInput(ctx, r.VMStatePath)
	if err != nil {
		return nil, err
	}
	if memory != record.Memory || vmstate != record.VMState {
		return nil, errors.New("retained RAM or vmstate changed since capture")
	}
	if record.Metadata != nil {
		metadata, err := fingerprintInput(ctx, r.MetadataPath)
		if err != nil {
			return nil, err
		}
		if metadata != *record.Metadata {
			return nil, errors.New("retained metadata changed since capture")
		}
	} else if r.MetadataPath != "" {
		return nil, errors.New("recovery metadata binding missing")
	}
	if err := validateQCOW2(ctx, s.Options.QemuImgPath, r.DiskPath, r.DiskSize, record.Overlay.BackingPath); err != nil {
		return nil, fmt.Errorf("qcow2 recovery requires a clean closed image: %w", err)
	}
	if err := writeDiskSeal(r.DiskPath, record.Overlay.ParentID, record.Overlay.BackingPath, r.DiskSize); err != nil {
		return nil, err
	}
	if r.ParentID == "" {
		// Cold boot from an EROFS template publishes a fresh Full baseline. The
		// old runtime mount may be gone, so bind a new mount of the recorded
		// immutable parent explicitly while converting the clean qcow2.
		mounted, err := parent.Mount(ctx, filepath.Join(s.Root, ".recovery-mounts"))
		if err != nil {
			return nil, err
		}
		defer func() { result = errors.Join(result, mounted.Close()) }()
		out, err := os.CreateTemp(filepath.Dir(path), "disk.recovered-*.raw")
		if err != nil {
			return nil, err
		}
		if err := out.Close(); err != nil {
			return nil, err
		}
		image, err := qcowImageFilename(r.DiskPath, mounted.DiskPath)
		if err != nil {
			return nil, err
		}
		if err := command(ctx, s.Options.QemuImgPath, "convert", "-O", "raw", image, out.Name()); err != nil {
			return nil, err
		}
		if err := regularSize(out.Name(), r.DiskSize); err != nil {
			return nil, err
		}
		if err := syncPath(out.Name()); err != nil {
			return nil, err
		}
		r.DiskPath = out.Name()
	}
	request, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	requestPath := path + ".build-request.json"
	if err := atomicRecord(requestPath, request, true); err != nil {
		return nil, err
	}
	snapshot, err = s.Build(ctx, r)
	if err != nil {
		return snapshot, fmt.Errorf("publish recovered capture; retry retained request %s: %w", requestPath, err)
	}
	return snapshot, nil
}

func atomicRecord(path string, data []byte, replace bool) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".record-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	flags := uint(0)
	if !replace {
		flags = unix.RENAME_NOREPLACE
	}
	if err := unix.Renameat2(unix.AT_FDCWD, f.Name(), unix.AT_FDCWD, path, flags); err != nil {
		if !replace && errors.Is(err, unix.EEXIST) {
			existing, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if !bytes.Equal(existing, data) {
				return errors.New("recovery record already binds a different cutoff")
			}
		} else {
			return err
		}
	}
	return syncPath(filepath.Dir(path))
}
