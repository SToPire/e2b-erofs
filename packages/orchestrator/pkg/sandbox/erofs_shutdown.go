//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/fc"
)

// Provisioning shuts down a cold VM without publishing a snapshot. Native
// Firecracker's snapshot API still requires a memfile: use a disposable Full
// export to exercise the device drain/flush before closing the writable disk.
func (s *Sandbox) shutdownNative(ctx context.Context) error {
	err := func() error {
		s.nativeCaptureMu.Lock()
		defer s.nativeCaptureMu.Unlock()
		if err := os.MkdirAll(s.config.EROFSSnapshotDir, 0700); err != nil {
			return err
		}
		dir, err := os.MkdirTemp(s.config.EROFSSnapshotDir, ".shutdown-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		s.Checks.Stop()
		if err := s.process.Pause(ctx); err != nil {
			return fmt.Errorf("pause native provisioning VM: %w", err)
		}
		if err := s.process.CreateNativeSnapshot(ctx, filepath.Join(dir, "vmstate"), filepath.Join(dir, "memory"), fc.NativeSnapshotFull); err != nil {
			return fmt.Errorf("drain native provisioning VM: %w", err)
		}
		return s.process.Stop(ctx)
	}()
	if err != nil {
		return err
	}
	return s.Close(ctx)
}
