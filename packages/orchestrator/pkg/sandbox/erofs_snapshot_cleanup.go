//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// cleanupNativeInputs is called with nativeCaptureMu held and only after the
// runtime resource owner has closed FC, disk and mounts. Failed or uncertain
// captures retain their original inputs and recovery record. Committed EROFS
// generations are never removed here.
func (s *Sandbox) cleanupNativeInputs(ctx context.Context) error {
	state := s.nativeCapture
	if state != nil && (!state.published || state.inputsCleaned) {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if state != nil {
		if state.capture == nil || state.store == nil {
			return errors.New("published native capture ownership is missing")
		}
		dir := filepath.Clean(state.capture.Dir)
		base := filepath.Join(state.store.Root, ".captures")
		if !filepath.IsAbs(dir) || filepath.Dir(dir) != base || state.request.ID == "" || !strings.HasPrefix(filepath.Base(dir), state.request.ID+"-") {
			return fmt.Errorf("refuse to remove a directory outside this native capture: %s", dir)
		}
	}
	if s.Resources != nil {
		if provider, ok := s.rootfs.(*erofsRootfs); ok {
			if err := provider.discard(); err != nil {
				return fmt.Errorf("discard native disk inputs: %w", err)
			}
		}
	}
	if state != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := os.RemoveAll(state.capture.Dir); err != nil {
			return fmt.Errorf("discard published native capture inputs: %w", err)
		}
		state.inputsCleaned = true
	}
	return nil
}
