//go:build linux

package pmem

import (
	"context"
	"errors"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/cfg"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/fc"
)

func BootArtifacts(ctx context.Context, store *erofs.Store, config cfg.BuilderConfig, versions fc.Config) (erofs.BootLayout, error) {
	boot := erofs.BootLayout{Layout: erofs.LayoutPmem, KernelVersion: versions.KernelVersion, FirecrackerVersion: versions.FirecrackerVersion}
	if config.EROFSPmemInitramfsPath == "" {
		return boot, errors.New("file-only template builds require EROFS_PMEM_INITRAMFS_PATH")
	}
	if err := CheckExportInitramfs(ctx, config.EROFSPmemInitramfsPath); err != nil {
		return boot, err
	}
	var err error
	boot.KernelSHA256, err = DigestBinary(ctx, versions.HostKernelPath(config))
	if err != nil {
		return boot, err
	}
	boot.FirecrackerSHA256, err = DigestBinary(ctx, versions.FirecrackerPath(config))
	if err != nil {
		return boot, err
	}
	boot.Initramfs, err = store.ImportInitramfs(ctx, config.EROFSPmemInitramfsPath)
	return boot, err
}
