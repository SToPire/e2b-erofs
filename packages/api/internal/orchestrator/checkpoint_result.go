package orchestrator

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/e2b-dev/infra/packages/db/pkg/types"
	"github.com/e2b-dev/infra/packages/shared/pkg/grpc/orchestrator"
)

// recordCheckpointFailure distinguishes loss of the runtime from loss of the
// snapshot. A node's build-bound commit receipt preserves the recovery point;
// callers must still clean up the failed runtime and return the restore error.
func (o *Orchestrator) recordCheckpointFailure(ctx context.Context, sandboxID string, buildID uuid.UUID, committedStatus types.BuildStatus, cause error) error {
	if !orchestrator.IsCheckpointCommittedError(cause, buildID.String()) {
		o.failSnapshotBuild(ctx, buildID, cause)
		return nil
	}

	err := o.finishSnapshotBuild(ctx, buildID, committedStatus)
	// Invalidate even if the database write fails: neither an older cached
	// snapshot nor the failed runtime describes this committed cutoff.
	o.snapshotCache.Invalidate(context.WithoutCancel(ctx), sandboxID)
	if err != nil {
		return fmt.Errorf("record committed checkpoint after runtime restore failure: %w", err)
	}
	return nil
}
