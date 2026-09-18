//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/fc"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/template"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/build/core/filesystem"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/build/core/pmem"
)

type MergedRootfs struct {
	Path   string
	Size   int64
	SHA256 string
	dir    string
}

func (m *MergedRootfs) Close() error { return os.RemoveAll(m.dir) }

// ExportPmemRootfs cold-boots a trusted initramfs helper with a private upper
// copy and a fresh output drive. It does not start tenant init or restore RAM.
// The Guest kernel resolves OverlayFS metadata; Host tools only read the final
// plain ext4 as a regular file after the helper has unmounted it and exited.
func (f *Factory) ExportPmemRootfs(ctx context.Context, t template.Template, boot erofs.BootLayout, teamID string) (_ *MergedRootfs, resultErr error) {
	source, ok := template.EROFS(t)
	if !ok || source.Manifest.Format != erofs.FormatV2 || source.Manifest.Boot == nil || source.Manifest.Boot.Layout != erofs.LayoutPmem || source.Manifest.Lower == nil || source.Manifest.Upper == nil {
		return nil, errors.New("merged export requires a committed pmem template")
	}
	if boot.Initramfs == nil {
		return nil, errors.New("merged export needs a pinned initramfs")
	}
	if err := pmem.CheckExportInitramfs(ctx, filepath.Join(f.config.EROFSSnapshotDir, boot.Initramfs.File)); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	base := filepath.Join(f.config.EROFSSnapshotDir, ".build-rootfs")
	if err := os.MkdirAll(base, 0700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(base, "merged-")
	if err != nil {
		return nil, err
	}
	output := &MergedRootfs{Path: filepath.Join(dir, "rootfs.raw"), dir: dir}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, output.Close())
		}
	}()
	ref, err := f.sharedMounts.Acquire(ctx, source, teamID)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, ref.Release()) }()
	lower, err := f.sharedMounts.AcquireLower(ctx, source.Manifest.Lower, teamID)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, lower.Release()) }()
	inodeCount := uint64(0)
	for _, path := range []string{ref.DiskPath(), lower.LowerPath()} {
		file, e := os.Open(path)
		if e != nil {
			return nil, e
		}
		var sb [1024]byte
		_, e = file.ReadAt(sb[:], 1024)
		closeErr := file.Close()
		if e = errors.Join(e, closeErr); e != nil {
			return nil, e
		}
		if binary.LittleEndian.Uint16(sb[0x38:]) != 0xef53 {
			return nil, errors.New("export source is not ext4")
		}
		inodeCount += uint64(binary.LittleEndian.Uint32(sb[:4]))
	}
	if inodeCount == 0 || inodeCount > math.MaxUint32 {
		return nil, errors.New("merged inode capacity exceeds ext4 limit")
	}
	a, b := source.Manifest.Lower.Image.Size, source.Manifest.Upper.Size
	if a <= 0 || b <= 0 || a > math.MaxInt64-b-(66<<20) {
		return nil, errors.New("merged capacity overflow")
	}
	output.Size = ((a + b + (64 << 20) + (2 << 20) - 1) / (2 << 20)) * (2 << 20)
	disk, err := os.OpenFile(output.Path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(disk.Truncate(output.Size), disk.Close()); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "mkfs.ext4", "-q", "-F", "-b", "4096", "-m", "0", "-N", strconv.FormatUint(inodeCount, 10), "-O", "^orphan_file,^inline_data", output.Path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("format merged output: %w: %s", err, out)
	}
	logPath := filepath.Join(dir, "export.log")
	log, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	defer log.Close()
	nonce := uuid.NewString()
	versions := fc.Config{NativeMemory: true, KernelVersion: boot.KernelVersion, FirecrackerVersion: boot.FirecrackerVersion}
	vm, err := f.CreateSandbox(ctx, NewConfig(Config{Vcpu: 1, RamMB: 512, FirecrackerConfig: versions, SkipEnvdWait: true}),
		RuntimeMetadata{TemplateID: "rootfs-export", SandboxID: "export-" + uuid.NewString(), ExecutionID: uuid.NewString(), BuildID: source.Manifest.ID, TeamID: teamID, SandboxType: SandboxTypeBuild},
		t, 10*time.Minute, "", fc.ProcessOptions{InitScriptPath: "/sbin/init", KernelLogs: true, Stdout: log, Stderr: log}, nil, nil, WithDeferredMarkRunning(),
		WithPmemBootstrap(PmemBootstrap{Boot: boot, Lower: source.Manifest.Lower, UpperPath: ref.DiskPath(), UpperContentSHA256: source.Manifest.UpperContentSHA256, UpperSize: b,
			Export: &fc.PmemExportSource{Path: output.Path, Size: output.Size, Nonce: nonce}}))
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, vm.Close(context.WithoutCancel(ctx))) }()
	// Some microVM kernels halt on poweroff without exiting the VMM. The
	// trusted helper emits its nonce only after unmounting output. Once observed,
	// stop and reap FC ourselves before any Host consumer opens that output.
	marker := []byte("E2B_ROOTFS_EXPORT_OK:" + nonce)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	readCompletion := func() (bool, []byte, error) {
		info, err := log.Stat()
		if err != nil {
			return false, nil, err
		}
		data := make([]byte, min(info.Size(), int64(64<<10)))
		if _, err := log.ReadAt(data, info.Size()-int64(len(data))); err != nil {
			return false, nil, err
		}
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			if bytes.Equal(bytes.TrimSuffix(line, []byte{'\r'}), marker) {
				return true, data, nil
			}
		}
		return false, data, nil
	}
	for {
		done, _, err := readCompletion()
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		case <-vm.process.Exit.Done():
			done, data, err := readCompletion()
			if err != nil {
				return nil, err
			}
			if !done {
				return nil, fmt.Errorf("rootfs helper exited before confirming export: %s", data[max(0, len(data)-(4<<10)):])
			}
		}
	}
	if err := vm.process.Stop(ctx); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-vm.process.Exit.Done():
	}
	if err := vm.process.Exit.Wait(); err != nil {
		return nil, fmt.Errorf("rootfs helper exited: %w", err)
	}
	if _, err := filesystem.CheckIntegrity(ctx, output.Path, false); err != nil {
		return nil, err
	}
	output.SHA256, err = runtimeBinaryDigest(ctx, output.Path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(output.Path, 0400); err != nil {
		return nil, err
	}
	return output, nil
}
