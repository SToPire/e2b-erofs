//go:build linux

package fc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/e2b-dev/infra/packages/shared/pkg/fc/client/operations"
	"github.com/e2b-dev/infra/packages/shared/pkg/fc/models"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage"
)

const (
	PmemRootfsLayout = "pmem-overlay-raw-v1"
	pmemDeviceDir    = "/run/e2b-devices"
	pmemLowerID      = "lower"
	pmemUpperID      = "upper"
)

// PmemRootfsSource is per-runtime input, not serialized template metadata.
// Both disk paths are complete raw views. Upper must be an independently owned
// writable inode; Lower and Initramfs stay immutable for the runtime lifetime.
type PmemRootfsSource struct {
	LowerPath     string
	LowerSize     int64
	UpperPath     string
	UpperSize     int64
	InitramfsPath string
	Export        *PmemExportSource
}

// PmemExportSource attaches an output disk only to a disposable cold helper.
// Helpers never publish RAM snapshots or serve envd/customer requests.
type PmemExportSource struct {
	Path  string
	Size  int64
	Nonce string
}

type runtimeFileBind struct {
	host, target string
	info         os.FileInfo
	readonly     bool
}

type preparedPmemRootfs struct {
	source PmemRootfsSource
	binds  []runtimeFileBind
}

func (sb *StartScriptBuilder) buildPmemScript(versions Config, files *storage.SandboxFiles, namespaceID string, sources RuntimeSources) (*StartScriptResult, error) {
	if runtime.GOARCH != "amd64" || !versions.NativeMemory || !sb.builderConfig.EROFSPmemVerified || sb.builderConfig.EROFSSnapshotDir == "" {
		return nil, errors.New("pmem rootfs requires amd64, native memory, a persistent EROFS store and EROFS_PMEM_VERIFIED")
	}
	source := *sources.Rootfs // Snapshot the caller's descriptor before starting a process.
	if source.LowerSize <= 0 || source.LowerSize%(2<<20) != 0 || source.UpperSize <= 0 || source.UpperSize%4096 != 0 {
		return nil, errors.New("pmem lower must be 2 MiB aligned and raw upper 4 KiB aligned")
	}
	prepared := &preparedPmemRootfs{source: source}
	inputs := []struct {
		host, name string
		size       int64
		readonly   bool
	}{
		{source.LowerPath, "lower.ext4", source.LowerSize, true},
		{source.UpperPath, "upper.ext4", source.UpperSize, false},
		{source.InitramfsPath, "initramfs", 0, true},
		{versions.HostKernelPath(sb.builderConfig), "vmlinux.bin", 0, true},
	}
	if source.Export != nil {
		export := *source.Export
		prepared.source.Export = &export
		if sources.MemoryPath != "" || export.Size <= 0 || export.Size%4096 != 0 || len(export.Nonce) != 36 || strings.Trim(export.Nonce, "0123456789abcdef-") != "" {
			return nil, errors.New("export requires a cold helper, aligned output and UUID nonce")
		}
		inputs = append(inputs, struct {
			host, name string
			size       int64
			readonly   bool
		}{export.Path, "export.ext4", export.Size, false})
	}
	if sources.MemoryPath != "" {
		inputs = append(inputs, struct {
			host, name string
			size       int64
			readonly   bool
		}{sources.MemoryPath, "memfile", 0, true})
	}
	for _, input := range inputs {
		if !filepath.IsAbs(input.host) || filepath.Clean(input.host) != input.host || strings.ContainsAny(input.host, "\x00\r\n") ||
			input.host == pmemDeviceDir || strings.HasPrefix(input.host, pmemDeviceDir+"/") {
			return nil, fmt.Errorf("invalid or namespace-covered pmem input: %q", input.host)
		}
		info, err := os.Lstat(input.host)
		if input.name == "vmlinux.bin" {
			info, err = os.Stat(input.host) // Kernel artifact caches may use symlinks.
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 || (input.size != 0 && info.Size() != input.size) {
			return nil, fmt.Errorf("invalid pmem input type or size: %s", input.host)
		}
		if input.name == "memfile" && info.Size()%nativePageSize != 0 {
			return nil, errors.New("pmem File restore memfile must be page aligned")
		}
		prepared.binds = append(prepared.binds, runtimeFileBind{
			host: input.host, target: filepath.Join(pmemDeviceDir, input.name), info: info, readonly: input.readonly,
		})
	}
	for i, left := range prepared.binds {
		for _, right := range prepared.binds[i+1:] {
			if os.SameFile(left.info, right.info) {
				return nil, errors.New("pmem inputs must not alias the same inode")
			}
		}
	}
	var script strings.Builder
	script.WriteString("set -e\nmount --make-rprivate /\n")
	fmt.Fprintf(&script, "test ! -L %s\nmkdir -p -- %s\nmount -t tmpfs -o mode=0700 tmpfs %s\n",
		shellPath(pmemDeviceDir), shellPath(pmemDeviceDir), shellPath(pmemDeviceDir))
	for _, bind := range prepared.binds {
		fmt.Fprintf(&script, "touch -- %s\nmount --bind -- %s %s\n", shellPath(bind.target), shellPath(bind.host), shellPath(bind.target))
		flags := "rw,nosuid,nodev,noexec"
		if bind.readonly {
			flags = "ro,nosuid,nodev,noexec"
		}
		fmt.Fprintf(&script, "mount -o remount,bind,%s -- %s\n", flags, shellPath(bind.target))
	}
	cleanup, err := sharedMountScript(filepath.Join(sb.builderConfig.EROFSSnapshotDir, ".shared-mounts"), "", "")
	if err != nil {
		return nil, err
	}
	script.WriteString(cleanup + "\n")
	fmt.Fprintf(&script, "exec ip netns exec %s %s --api-sock %s\n", shellPath(namespaceID),
		shellPath(versions.FirecrackerPath(sb.builderConfig)), shellPath(files.SandboxFirecrackerSocketPath()))
	result := &StartScriptResult{Value: script.String(), RootfsPath: filepath.Join(pmemDeviceDir, "upper.ext4"),
		KernelPath: filepath.Join(pmemDeviceDir, "vmlinux.bin"), InitramfsPath: filepath.Join(pmemDeviceDir, "initramfs"), pmem: prepared}
	if sources.MemoryPath != "" {
		result.MemoryPath = filepath.Join(pmemDeviceDir, "memfile")
	}
	return result, nil
}

func (p *Process) validatePmemBindings() error {
	if p.pmem == nil {
		return nil
	}
	pid, err := p.Pid()
	if err != nil {
		return err
	}
	for _, bind := range p.pmem.binds {
		bound, err := os.Stat(fmt.Sprintf("/proc/%d/root%s", pid, bind.target))
		if err != nil {
			return err
		}
		if !bound.Mode().IsRegular() || !os.SameFile(bind.info, bound) || bind.info.Size() != bound.Size() {
			return fmt.Errorf("pmem namespace bind does not reference the prepared inode: %s", bind.target)
		}
	}
	path, err := p.rootfsProvider.Path()
	if err != nil {
		return err
	}
	if path != p.pmem.source.UpperPath {
		return errors.New("pmem raw upper provider differs from the prepared source")
	}
	return nil
}

func (p *preparedPmemRootfs) kernelArgs(args KernelArgs, init string) (KernelArgs, error) {
	if init == "" {
		init = "/sbin/init"
	}
	if !filepath.IsAbs(init) || filepath.Clean(init) != init || strings.ContainsAny(init, " \t\r\n\x00") {
		return nil, errors.New("pmem Guest init must be an absolute path without whitespace")
	}
	delete(args, "root")
	delete(args, "rootflags")
	delete(args, "init")
	args["rdinit"] = "/init"
	args["e2b.rootfs_layout"] = PmemRootfsLayout
	args["e2b.lower_bytes"] = strconv.FormatInt(p.source.LowerSize, 10)
	args["e2b.upper_bytes"] = strconv.FormatInt(p.source.UpperSize, 10)
	args["e2b.init"] = init
	if p.source.Export != nil {
		args["rdinit"] = "/export-init"
		args["e2b.export_bytes"] = strconv.FormatInt(p.source.Export.Size, 10)
		args["e2b.export_nonce"] = p.source.Export.Nonce
	}
	return args, nil
}

func (c *apiClient) setExportDrive(ctx context.Context) error {
	id, root, engine, cache := "zz_export", false, "Sync", models.DriveCacheTypeWriteback
	_, err := c.client.Operations.PutGuestDriveByID(&operations.PutGuestDriveByIDParams{Context: ctx, DriveID: id,
		Body: &models.Drive{DriveID: &id, PathOnHost: filepath.Join(pmemDeviceDir, "export.ext4"), IsRootDevice: &root, IsReadOnly: false, IoEngine: &engine, CacheType: &cache}})
	return err
}

func (c *apiClient) setPmemRootfs(ctx context.Context, lowerPath, upperPath string, rateLimiter *models.RateLimiter) error {
	id := pmemLowerID
	_, err := c.client.Operations.PutGuestPmemByID(&operations.PutGuestPmemByIDParams{Context: ctx, ID: id,
		Body: &models.Pmem{ID: &id, PathOnHost: &lowerPath, ReadOnly: true, RootDevice: false}})
	if err != nil {
		return fmt.Errorf("configure read-only pmem lower: %w", err)
	}
	id = pmemUpperID
	root := false
	engine := "Sync"
	cache := models.DriveCacheTypeWriteback
	_, err = c.client.Operations.PutGuestDriveByID(&operations.PutGuestDriveByIDParams{Context: ctx, DriveID: id,
		Body: &models.Drive{DriveID: &id, PathOnHost: upperPath, IsRootDevice: &root, IsReadOnly: false,
			IoEngine: &engine, CacheType: &cache, RateLimiter: rateLimiter}})
	return err
}

func (p *Process) diskDriveID() string {
	if p.pmem != nil {
		return pmemUpperID
	}
	return rootfsDriveID
}
