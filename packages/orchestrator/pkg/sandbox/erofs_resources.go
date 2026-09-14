//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/fc"
)

// nativeResources owns resources which must close in dependency order. Unlike
// Cleanup's one-shot callbacks, failed steps retain ownership and can retry.
// All fields are populated before the VM starts or its exit waiter is installed.
type nativeResources struct {
	mu         sync.Mutex
	process    *fc.Process
	closeDisk  func(context.Context) error
	closeMount func() error
}

func (r *nativeResources) close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.process != nil {
		if _, err := r.process.Pid(); err == nil {
			if err := r.process.Stop(ctx); err != nil {
				return err
			}
			select {
			case <-r.process.Exit.Done():
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		r.process = nil
	}
	if r.closeDisk != nil {
		if err := r.closeDisk(ctx); err != nil {
			return fmt.Errorf("close native disk: %w", err)
		}
		r.closeDisk = nil
	}
	if r.closeMount != nil {
		if err := r.closeMount(); err != nil {
			return fmt.Errorf("close native mounts: %w", err)
		}
		r.closeMount = nil
	}
	return nil
}

// Keep the caller's lifecycle/work hold through transient cleanup failures.
// Cancellation returns with the remaining callbacks still owned by r, so a
// later Close continues at the failed step rather than double-closing resources.
func (r *nativeResources) closeUntilDone(ctx context.Context) error {
	for {
		err := r.close(ctx)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}
