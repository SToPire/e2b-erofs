//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/envd"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/fc"
)

func (s *Sandbox) usesPmemRootfs() bool {
	return s.v2Runtime != nil && s.v2Runtime.boot.Layout == erofs.LayoutPmem
}

func (s *Sandbox) freezePmemForCapture(ctx context.Context) (bool, error) {
	if !s.usesPmemRootfs() || s.Config.SkipEnvdWait {
		return false, nil
	}
	result, observed, err := s.callEnvdFreeze(ctx, 5*time.Second, true, 512)
	if err != nil || !observed || result.Failed != 0 || result.NotFrozen != 0 || result.Unobservable != 0 || result.Truncated || result.Vanished != 0 || string(result.Mode) != "hierarchy" {
		cause := errors.Join(err, errors.New("pmem capture could not confirm workload freeze"))
		return false, errors.Join(cause, s.rollbackPmemFreeze(ctx))
	}
	if err := s.callEnvdFsfreeze(ctx, 20*time.Second); err != nil {
		return false, errors.Join(err, s.rollbackPmemFreeze(ctx))
	}
	return true, nil
}

func (s *Sandbox) rollbackPmemFreeze(ctx context.Context) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := s.callEnvdFsthaw(cleanup, 5*time.Second); err != nil {
		return errors.Join(fmt.Errorf("cannot thaw upper after failed capture: %w", err), s.process.Stop(cleanup))
	}
	return s.callEnvdUnfreeze(cleanup, 5*time.Second)
}

// CommitPmemResume is the last step after initialization/optional envd upgrade,
// before routing or customer operations are enabled for this execution.
func (s *Sandbox) CommitPmemResume(ctx context.Context) error {
	if !s.usesPmemRootfs() || s.Config.SkipEnvdWait {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, _, err := s.doRequestWithInfiniteRetries(ctx, http.MethodPost, s.envdServerURL()+"/init", envd.Commit)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.Header.Get("X-Envd-Rootfs-Layout") != fc.PmemRootfsLayout || response.Header.Get("X-Envd-Resume-Phase") != "commit" {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("envd pmem commit failed (%d): %s", response.StatusCode, body)
	}
	return nil
}
