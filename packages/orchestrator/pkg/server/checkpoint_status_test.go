//go:build linux

package server

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/cfg"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/shared/pkg/grpc/orchestrator"
)

// The store checks cancellation when verification starts. Block that check to
// deterministically admit another checkpoint while the old query is validating,
// without adding a test hook to the production server or store.
type checkpointValidationBarrier struct {
	context.Context
	once             sync.Once
	entered, release chan struct{}
}

func (c *checkpointValidationBarrier) Err() error {
	c.once.Do(func() {
		close(c.entered)
		select {
		case <-c.release:
		case <-c.Context.Done():
		}
	})
	return c.Context.Err()
}

func TestCheckpointStatusObservesCheckpointStartedDuringVerification(t *testing.T) {
	t.Parallel()
	s := &Server{
		config:         cfg.Config{BuilderConfig: cfg.BuilderConfig{EROFSSnapshotDir: t.TempDir()}},
		sandboxFactory: &sandbox.Factory{Sandboxes: sandbox.NewSandboxesMap()},
	}
	producer, err := erofs.IdentifyProcess(os.Getpid())
	require.NoError(t, err)
	// This completed operation belongs to an earlier boot and has no remaining
	// runtime or published snapshot. A later operation shares its execution.
	producer.BootID = uuid.NewString()
	old := checkpointRecord{Version: 1, BuildID: uuid.NewString(), SandboxID: "sandbox",
		ExecutionID: uuid.NewString(), TeamID: uuid.NewString(), Original: producer, Finished: true}
	require.NoError(t, writeCheckpointRecord(s.checkpointRecordPath(old.BuildID), old, true))
	request := &orchestrator.SandboxCheckpointStatusRequest{BuildId: old.BuildID,
		SandboxId: old.SandboxID, ExecutionId: old.ExecutionID, TeamId: old.TeamID}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	barrier := &checkpointValidationBarrier{Context: ctx, entered: make(chan struct{}), release: make(chan struct{})}
	type result struct {
		response *orchestrator.SandboxCheckpointStatusResponse
		err      error
	}
	done := make(chan result, 1)
	go func() {
		response, err := s.CheckpointStatus(barrier, request)
		done <- result{response, err}
	}()
	select {
	case <-barrier.entered:
	case <-ctx.Done():
		t.Fatal("status query did not reach snapshot verification")
	}
	next := &nativeCheckpointOperation{record: checkpointRecord{
		Version: 1, BuildID: uuid.NewString(), SandboxID: old.SandboxID,
		ExecutionID: old.ExecutionID, TeamID: old.TeamID,
	}}
	s.nativeCheckpoints.Store(next.record.BuildID, next)
	close(barrier.release)
	select {
	case got := <-done:
		require.NoError(t, got.err)
		require.Equal(t, orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_NOT_COMMITTED, got.response.GetSnapshotState())
		require.Equal(t, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_TRANSITIONING, got.response.GetRuntimeState())
	case <-ctx.Done():
		t.Fatal("status query did not finish")
	}
}
