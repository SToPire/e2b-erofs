package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bsm/redislock"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/e2b-dev/infra/packages/api/internal/sandbox"
	"github.com/e2b-dev/infra/packages/db/pkg/types"
	"github.com/e2b-dev/infra/packages/shared/pkg/grpc/orchestrator"
	"github.com/e2b-dev/infra/packages/shared/pkg/logger"
)

const checkpointIntentsKey = "e2b:checkpoint-reconciliation:v1"

var errCheckpointPending = errors.New("checkpoint outcome is pending reconciliation")

type checkpointIntent struct {
	ClusterID   uuid.UUID         `json:"cluster_id"`
	NodeID      string            `json:"node_id"`
	TeamID      uuid.UUID         `json:"team_id"`
	SandboxID   string            `json:"sandbox_id"`
	ExecutionID string            `json:"execution_id"`
	BuildID     uuid.UUID         `json:"build_id"`
	Status      types.BuildStatus `json:"status"`
	// Monotonic receipt, recorded only after a successful RPC, a matching
	// commit ErrorInfo, or a durable COMMITTED status response.
	Committed bool `json:"committed,omitempty"`
	// Only the foreground caller may use the just-received runtime outcome.
	// Background retries must observe current runtime state again.
	RuntimeReceipt orchestrator.CheckpointRuntimeState `json:"-"`
}

func (i checkpointIntent) request() *orchestrator.SandboxCheckpointStatusRequest {
	return &orchestrator.SandboxCheckpointStatusRequest{SandboxId: i.SandboxID, BuildId: i.BuildID.String(), ExecutionId: i.ExecutionID, TeamId: i.TeamID.String()}
}

func (i checkpointIntent) valid() bool {
	return i.BuildID != uuid.Nil && i.TeamID != uuid.Nil && i.NodeID != "" && i.SandboxID != "" && i.ExecutionID != "" &&
		(i.Status == types.BuildStatusSuccess || i.Status == types.BuildStatusUploaded)
}

func (o *Orchestrator) queryCheckpoint(ctx context.Context, intent checkpointIntent) (*orchestrator.SandboxCheckpointStatusResponse, error) {
	node := o.GetNode(intent.ClusterID, intent.NodeID)
	if node == nil {
		return nil, ErrNodeNotFound
	}
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client, queryCtx := node.GetClient(queryCtx)
	result, err := client.Sandbox.CheckpointStatus(queryCtx, intent.request())
	if err != nil {
		return nil, err
	}
	if result == nil || result.GetBuildId() != intent.BuildID.String() || result.GetExecutionId() != intent.ExecutionID {
		return nil, errors.New("checkpoint status identity mismatch")
	}
	return result, nil
}

// The intent is stored before sending the destructive action. A restarted API
// can discover it without the original request, callback, or in-memory sandbox.
func (o *Orchestrator) prepareNativeCheckpoint(ctx context.Context, sbx sandbox.Sandbox, buildID uuid.UUID, finalStatus types.BuildStatus) (*checkpointIntent, error) {
	if o.checkpointRedis == nil {
		return nil, nil
	}
	i := checkpointIntent{ClusterID: sbx.ClusterID, NodeID: sbx.NodeID, TeamID: sbx.TeamID, SandboxID: sbx.SandboxID, ExecutionID: sbx.ExecutionID, BuildID: buildID, Status: finalStatus}
	state, err := o.queryCheckpoint(ctx, i)
	if status.Code(err) == codes.Unimplemented {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("probe checkpoint status: %w", err)
	}
	if !state.GetNative() {
		return nil, nil
	}
	if !i.valid() {
		return nil, errors.New("invalid checkpoint reconciliation identity")
	}
	data, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}
	added, err := o.checkpointRedis.HSetNX(ctx, checkpointIntentsKey, buildID.String(), data).Result()
	if err != nil {
		return nil, fmt.Errorf("persist checkpoint intent: %w", err)
	}
	if !added {
		return nil, errors.New("checkpoint build already has a pending operation")
	}
	if err := o.sandboxStore.PinCheckpoint(ctx, i.TeamID, i.SandboxID, i.ExecutionID, i.BuildID.String(), sbx.TransitionID); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return nil, errors.Join(err, o.checkpointRedis.HDel(cleanupCtx, checkpointIntentsKey, i.BuildID.String()).Err())
	}
	return &i, nil
}

type checkpointResolution struct{ done, committed, running, runtimeApplied bool }

func (o *Orchestrator) observeCheckpointResult(ctx context.Context, i *checkpointIntent, actionErr error) error {
	if actionErr != nil && !orchestrator.IsCheckpointCommittedError(actionErr, i.BuildID.String()) {
		return nil
	}
	i.RuntimeReceipt = orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING
	if actionErr != nil {
		i.RuntimeReceipt = orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_STOPPED
	}
	return o.rememberCheckpointCommit(ctx, i)
}

func (o *Orchestrator) rememberCheckpointCommit(ctx context.Context, i *checkpointIntent) error {
	i.Committed = true
	data, err := json.Marshal(i)
	if err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return o.checkpointRedis.HSet(writeCtx, checkpointIntentsKey, i.BuildID.String(), data).Err()
}

// Reconciliation runs under a per-build lease. Every attempt is bounded well
// below the lease, including the existing detached ten-second DB status write.
func (o *Orchestrator) reconcileCheckpoint(ctx context.Context, i checkpointIntent) (checkpointResolution, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	lock, err := redislock.New(o.checkpointRedis).Obtain(ctx, checkpointIntentsKey+":"+i.BuildID.String(), time.Minute, nil)
	if errors.Is(err, redislock.ErrNotObtained) {
		return checkpointResolution{}, nil
	}
	if err != nil {
		return checkpointResolution{}, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = lock.Release(cleanupCtx)
	}()
	data, err := o.checkpointRedis.HGet(ctx, checkpointIntentsKey, i.BuildID.String()).Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		return checkpointResolution{}, err
	}
	if err == nil {
		var stored checkpointIntent
		if err := json.Unmarshal(data, &stored); err != nil {
			return checkpointResolution{}, err
		}
		if !stored.valid() || stored.BuildID != i.BuildID || stored.TeamID != i.TeamID || stored.ExecutionID != i.ExecutionID || stored.SandboxID != i.SandboxID || stored.NodeID != i.NodeID || stored.ClusterID != i.ClusterID || stored.Status != i.Status {
			return checkpointResolution{}, errors.New("pending checkpoint identity changed")
		}
		i.Committed = i.Committed || stored.Committed
	}
	err = nil
	var state *orchestrator.SandboxCheckpointStatusResponse
	if i.RuntimeReceipt != orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_UNKNOWN {
		state = &orchestrator.SandboxCheckpointStatusResponse{Native: true, SnapshotState: orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, RuntimeState: i.RuntimeReceipt}
	} else {
		state, err = o.queryCheckpoint(ctx, i)
	}
	if err != nil {
		if i.Committed {
			dbErr := o.finishSnapshotBuild(ctx, i.BuildID, i.Status)
			if dbErr == nil {
				o.snapshotCache.Invalidate(context.WithoutCancel(ctx), i.SandboxID)
			}
			err = errors.Join(err, dbErr)
		}
		return checkpointResolution{}, err
	}
	if !state.GetNative() {
		if i.Committed {
			// A node rollback/disabled backend cannot revoke an already received
			// durable commit. Keep its DB write independent of current runtime
			// observability, just as for a failed status RPC above.
			dbErr := o.finishSnapshotBuild(ctx, i.BuildID, i.Status)
			if dbErr == nil {
				o.snapshotCache.Invalidate(context.WithoutCancel(ctx), i.SandboxID)
			}
			return checkpointResolution{}, errors.Join(errCheckpointPending, dbErr)
		}
		return checkpointResolution{}, errCheckpointPending
	}
	if !i.Committed && state.GetSnapshotState() == orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED {
		if err := o.rememberCheckpointCommit(ctx, &i); err != nil {
			return checkpointResolution{}, err
		}
	}
	committed := i.Committed
	failed := !committed && state.GetSnapshotState() == orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_NOT_COMMITTED
	if !committed && !failed {
		// CAPTURED may still be published by recovery, including after process
		// restart. Missing responses and durability uncertainty are not failure.
		return checkpointResolution{}, nil
	}
	targetStatus := i.Status
	if failed {
		targetStatus = types.BuildStatusFailed
	}
	dbErr := o.finishSnapshotBuild(ctx, i.BuildID, targetStatus)
	if dbErr == nil {
		o.snapshotCache.Invalidate(context.WithoutCancel(ctx), i.SandboxID)
	}

	resolved := checkpointResolution{committed: committed}
	var runtimeErr error
	switch state.GetRuntimeState() {
	case orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING:
		resolved.running = true
		runtimeErr = o.sandboxStore.RestoreCheckpointRunning(ctx, i.TeamID, i.SandboxID, i.ExecutionID, i.BuildID.String())
		if errors.Is(runtimeErr, sandbox.ErrNotFound) || errors.Is(runtimeErr, sandbox.ErrExecutionMismatch) || errors.Is(runtimeErr, sandbox.ErrCheckpointMismatch) {
			runtimeErr = nil
		}
		resolved.done = runtimeErr == nil
	case orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_STOPPED:
		runtimeErr = o.removeCheckpointRuntime(ctx, i)
		if errors.Is(runtimeErr, sandbox.ErrExecutionMismatch) || errors.Is(runtimeErr, sandbox.ErrNotFound) || errors.Is(runtimeErr, ErrSandboxNotFound) {
			runtimeErr = nil
		}
		resolved.done = runtimeErr == nil
	}
	resolved.runtimeApplied = resolved.done
	if dbErr != nil || runtimeErr != nil {
		resolved.done = false
		return resolved, errors.Join(dbErr, runtimeErr)
	}
	if resolved.done {
		if err := o.checkpointRedis.HDel(ctx, checkpointIntentsKey, i.BuildID.String()).Err(); err != nil {
			resolved.done = false
			return resolved, err
		}
	}
	return resolved, nil
}

func (o *Orchestrator) removeCheckpointRuntime(ctx context.Context, i checkpointIntent) error {
	current, err := o.sandboxStore.Get(ctx, i.TeamID, i.SandboxID)
	if errors.Is(err, sandbox.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.ExecutionID != i.ExecutionID || current.CheckpointBuildID != i.BuildID.String() {
		return nil
	}
	return o.RemoveSandbox(ctx, i.TeamID, i.SandboxID, sandbox.RemoveOpts{Action: sandbox.StateActionKill, ExpectExecutionID: i.ExecutionID, ExpectCheckpointBuildID: i.BuildID.String()})
}

func (o *Orchestrator) finishNativeCheckpoint(ctx context.Context, i checkpointIntent, actionErr error) error {
	waitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		result, err := o.reconcileCheckpoint(waitCtx, i)
		if result.runtimeApplied {
			i.RuntimeReceipt = orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_UNKNOWN
		}
		if err != nil {
			lastErr = err
		}
		if result.done {
			if result.committed && result.running {
				return nil
			}
			return errors.Join(actionErr, fmt.Errorf("checkpoint resolved: committed=%t, running=%t", result.committed, result.running))
		}
		select {
		case <-waitCtx.Done():
			return errors.Join(errCheckpointPending, actionErr, lastErr)
		case <-ticker.C:
		}
	}
}

func (o *Orchestrator) startCheckpointReconciler(ctx context.Context) {
	if o.checkpointRedis == nil {
		return
	}
	ctx, o.checkpointCancel = context.WithCancel(ctx)
	o.checkpointDone = make(chan struct{})
	go func() {
		defer close(o.checkpointDone)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			o.reconcilePendingCheckpoints(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (o *Orchestrator) stopCheckpointReconciler(ctx context.Context) error {
	if o.checkpointCancel == nil {
		return nil
	}
	o.checkpointCancel()
	select {
	case <-o.checkpointDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (o *Orchestrator) reconcilePendingCheckpoints(ctx context.Context) {
	var cursor uint64
	for {
		scanCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		entries, next, err := o.checkpointRedis.HScan(scanCtx, checkpointIntentsKey, cursor, "*", 32).Result()
		cancel()
		if err != nil {
			return
		}
		for idx := 0; idx+1 < len(entries); idx += 2 {
			if ctx.Err() != nil {
				return
			}
			var intent checkpointIntent
			if err := json.Unmarshal([]byte(entries[idx+1]), &intent); err != nil || !intent.valid() || entries[idx] != intent.BuildID.String() {
				logger.L().Error(ctx, "invalid pending checkpoint intent", zap.String("build_id", entries[idx]))
				continue
			}
			if _, err := o.reconcileCheckpoint(ctx, intent); err != nil && ctx.Err() == nil {
				logger.L().Warn(ctx, "checkpoint reconciliation remains pending", logger.WithBuildID(intent.BuildID.String()), zap.Error(err))
			}
		}
		cursor = next
		if cursor == 0 {
			return
		}
	}
}
