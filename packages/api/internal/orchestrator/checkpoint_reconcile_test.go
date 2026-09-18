package orchestrator

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/e2b-dev/infra/packages/api/internal/sandbox"
	"github.com/e2b-dev/infra/packages/db/pkg/types"
	"github.com/e2b-dev/infra/packages/shared/pkg/consts"
	"github.com/e2b-dev/infra/packages/shared/pkg/grpc/orchestrator"
	redisutils "github.com/e2b-dev/infra/packages/shared/pkg/redis"
)

type reconciliationNode struct {
	orchestrator.UnimplementedSandboxServiceServer
	mu         sync.Mutex
	snapshot   orchestrator.CheckpointSnapshotState
	runtime    orchestrator.CheckpointRuntimeState
	queryErr   error
	legacy     bool
	deletes    int
	checkpoint func(context.Context, *orchestrator.SandboxCheckpointRequest) error
}

func (s *reconciliationNode) CheckpointStatus(_ context.Context, r *orchestrator.SandboxCheckpointStatusRequest) (*orchestrator.SandboxCheckpointStatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	return &orchestrator.SandboxCheckpointStatusResponse{Native: !s.legacy, BuildId: r.GetBuildId(), ExecutionId: r.GetExecutionId(), SnapshotState: s.snapshot, RuntimeState: s.runtime}, nil
}
func (s *reconciliationNode) Checkpoint(ctx context.Context, r *orchestrator.SandboxCheckpointRequest) (*orchestrator.SandboxCheckpointResponse, error) {
	if s.checkpoint != nil {
		return &orchestrator.SandboxCheckpointResponse{}, s.checkpoint(ctx, r)
	}
	return nil, status.Error(codes.Unavailable, "response lost")
}
func (s *reconciliationNode) Delete(context.Context, *orchestrator.SandboxDeleteRequest) (*emptypb.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	return &emptypb.Empty{}, nil
}
func (s *reconciliationNode) set(snapshot orchestrator.CheckpointSnapshotState, runtime orchestrator.CheckpointRuntimeState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot, s.runtime = snapshot, runtime
}
func (s *reconciliationNode) deleteCount() int { s.mu.Lock(); defer s.mu.Unlock(); return s.deletes }

func reconciliationFixture(t *testing.T) (refusalFixture, *reconciliationNode) {
	t.Helper()
	f := newRefusalFixture(t, true, consts.LocalClusterID, nil)
	f.o.checkpointRedis = redisutils.SetupInstance(t)
	stub := &reconciliationNode{runtime: orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	orchestrator.RegisterSandboxServiceServer(server, stub)
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///checkpoint-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(); server.Stop(); _ = listener.Close() })
	f.o.GetNode(f.sbx.ClusterID, f.sbx.NodeID).SetSandboxClient(orchestrator.NewSandboxServiceClient(conn))
	return f, stub
}

func preparedReconciliation(t *testing.T, f refusalFixture) (checkpointIntent, func(context.Context, error)) {
	t.Helper()
	transition, _, finish, err := f.o.sandboxStore.StartRemoving(t.Context(), f.sbx.TeamID, f.sbx.SandboxID, sandbox.RemoveOpts{Action: sandbox.StateActionSnapshot})
	require.NoError(t, err)
	require.NoError(t, f.o.sqlcDB.TestsRawSQL(t.Context(), "UPDATE public.env_builds SET status='snapshotting' WHERE id=$1", f.sbx.BuildID))
	intent, err := f.o.prepareNativeCheckpoint(t.Context(), transition, f.sbx.BuildID, types.BuildStatusSuccess)
	require.NoError(t, err)
	require.NotNil(t, intent)
	return *intent, finish
}

func TestNativeCheckpointLostResponseKeepsHealthyRuntime(t *testing.T) {
	t.Parallel()
	f, node := reconciliationFixture(t)
	node.checkpoint = func(ctx context.Context, r *orchestrator.SandboxCheckpointRequest) error {
		exists, err := f.o.checkpointRedis.HExists(ctx, checkpointIntentsKey, r.GetBuildId()).Result()
		if err != nil || !exists {
			return status.Error(codes.Internal, "action ran without a persisted intent")
		}
		node.set(orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING)
		return status.Error(codes.Unavailable, "committed success response lost")
	}
	require.NoError(t, f.o.CheckpointSandbox(t.Context(), f.sbx.TeamID, f.sbx.SandboxID))
	stored, err := f.o.sandboxStore.Get(t.Context(), f.sbx.TeamID, f.sbx.SandboxID)
	require.NoError(t, err)
	assert.Equal(t, sandbox.StateRunning, stored.State)
	last, err := f.o.sqlcDB.GetLastSnapshot(t.Context(), f.sbx.SandboxID)
	require.NoError(t, err)
	assert.Equal(t, types.BuildStatusSuccess, last.EnvBuild.Status)
	assert.Zero(t, node.deleteCount())
	assert.EqualValues(t, 0, f.o.checkpointRedis.HLen(t.Context(), checkpointIntentsKey).Val())
}

func TestNativeCheckpointClientCancellationLeavesIntentForBackgroundReconciliation(t *testing.T) {
	t.Parallel()
	f, node := reconciliationFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	node.checkpoint = func(context.Context, *orchestrator.SandboxCheckpointRequest) error {
		node.set(orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING)
		cancel()
		return status.Error(codes.Canceled, "caller lost completed response")
	}
	require.ErrorIs(t, f.o.CheckpointSandbox(ctx, f.sbx.TeamID, f.sbx.SandboxID), errCheckpointPending)
	require.Positive(t, f.o.checkpointRedis.HLen(t.Context(), checkpointIntentsKey).Val())
	f.o.reconcilePendingCheckpoints(t.Context())
	stored, err := f.o.sandboxStore.Get(t.Context(), f.sbx.TeamID, f.sbx.SandboxID)
	require.NoError(t, err)
	assert.Equal(t, sandbox.StateRunning, stored.State)
	last, err := f.o.sqlcDB.GetLastSnapshot(t.Context(), f.sbx.SandboxID)
	require.NoError(t, err)
	assert.Equal(t, types.BuildStatusSuccess, last.EnvBuild.Status)
	assert.Zero(t, node.deleteCount())
}

func TestNativeCheckpointTransitionReleaseCannotHoldCaller(t *testing.T) {
	t.Parallel()
	f, node := reconciliationFixture(t)
	i, finish := preparedReconciliation(t, f)
	node.set(orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING)
	entered := make(chan context.Context, 1)
	unblock := make(chan struct{})
	released := make(chan struct{})
	defer func() {
		close(unblock)
		<-released
	}()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- f.o.finishNativeCheckpoint(ctx, i, nil, func(releaseCtx context.Context, err error) {
			entered <- releaseCtx
			<-unblock
			finish(releaseCtx, err)
			close(released)
		})
	}()
	var releaseCtx context.Context
	select {
	case releaseCtx = <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("transition release did not start")
	}
	_, bounded := releaseCtx.Deadline()
	require.True(t, bounded)
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, errCheckpointPending)
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("caller waited for blocked transition release")
	}
	require.NoError(t, releaseCtx.Err(), "release must survive caller cancellation")
	// Reconciliation cannot run ahead of transition release. The durable intent
	// and Snapshotting state remain for a later background attempt.
	require.True(t, f.o.checkpointRedis.HExists(t.Context(), checkpointIntentsKey, i.BuildID.String()).Val())
	stored, err := f.o.sandboxStore.Get(t.Context(), i.TeamID, i.SandboxID)
	require.NoError(t, err)
	require.Equal(t, sandbox.StateSnapshotting, stored.State)
}

type blockedCheckpointReceipt struct {
	once    sync.Once
	entered chan struct{}
	unblock chan struct{}
}

func (h *blockedCheckpointReceipt) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *blockedCheckpointReceipt) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *blockedCheckpointReceipt) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, command redis.Cmder) error {
		if command.Name() == "hset" && len(command.Args()) > 1 && command.Args()[1] == checkpointIntentsKey {
			// Simulate socket I/O that ignores the context until its own timeout.
			h.once.Do(func() { close(h.entered); <-h.unblock })
		}
		return next(ctx, command)
	}
}

func TestNativeCheckpointCallersReturnWhileReceiptIOIsBlocked(t *testing.T) {
	t.Parallel()
	for _, template := range []bool{false, true} {
		t.Run(map[bool]string{false: "sandbox", true: "template"}[template], func(t *testing.T) {
			t.Parallel()
			f, node := reconciliationFixture(t)
			node.checkpoint = func(context.Context, *orchestrator.SandboxCheckpointRequest) error {
				node.set(orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING)
				return nil
			}
			hook := &blockedCheckpointReceipt{entered: make(chan struct{}), unblock: make(chan struct{})}
			f.o.checkpointRedis.AddHook(hook)
			var unblockOnce sync.Once
			unblock := func() { unblockOnce.Do(func() { close(hook.unblock) }) }
			defer unblock()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				if template {
					_, err := f.o.CreateSnapshotTemplate(ctx, f.sbx.TeamID, f.sbx.SandboxID, SnapshotTemplateOpts{Tag: "default"})
					result <- err
				} else {
					result <- f.o.CheckpointSandbox(ctx, f.sbx.TeamID, f.sbx.SandboxID)
				}
			}()
			select {
			case <-hook.entered:
			case err := <-result:
				t.Fatalf("caller exited before receipt write: %v", err)
			case <-time.After(10 * time.Second):
				t.Fatal("receipt write did not start")
			}
			cancel()
			select {
			case err := <-result:
				require.ErrorIs(t, err, errCheckpointPending)
			case <-time.After(time.Second):
				t.Fatal("caller remained blocked by receipt I/O")
			}
			unblock()
			waitCtx, waitCancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer waitCancel()
			require.NoError(t, f.o.sandboxStore.WaitForStateChange(waitCtx, f.sbx.TeamID, f.sbx.SandboxID))
			f.o.reconcilePendingCheckpoints(t.Context())
			stored, err := f.o.sandboxStore.Get(t.Context(), f.sbx.TeamID, f.sbx.SandboxID)
			require.NoError(t, err)
			require.Equal(t, sandbox.StateRunning, stored.State)
		})
	}
}

func TestNativeCheckpointCommittedStoppedRetainsSnapshotAndRemovesRuntime(t *testing.T) {
	t.Parallel()
	f, node := reconciliationFixture(t)
	node.checkpoint = func(context.Context, *orchestrator.SandboxCheckpointRequest) error {
		node.set(orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_STOPPED)
		return status.Error(codes.Unavailable, "committed restore failure response lost")
	}
	require.Error(t, f.o.CheckpointSandbox(t.Context(), f.sbx.TeamID, f.sbx.SandboxID))
	last, err := f.o.sqlcDB.GetLastSnapshot(t.Context(), f.sbx.SandboxID)
	require.NoError(t, err)
	assert.Equal(t, types.BuildStatusSuccess, last.EnvBuild.Status)
	assert.Equal(t, 1, node.deleteCount())
	assert.EqualValues(t, 0, f.o.checkpointRedis.HLen(t.Context(), checkpointIntentsKey).Val())
}

func TestNativeCheckpointUnknownAndCapturedStayPending(t *testing.T) {
	t.Parallel()
	f, node := reconciliationFixture(t)
	i, finish := preparedReconciliation(t, f)
	finish(t.Context(), errCheckpointPending)
	for _, state := range []orchestrator.CheckpointSnapshotState{
		orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_UNKNOWN,
		orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_IN_PROGRESS,
		orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_DURABILITY_UNKNOWN,
		orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_CAPTURED,
	} {
		node.set(state, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_STOPPED)
		result, err := f.o.reconcileCheckpoint(t.Context(), i)
		require.NoError(t, err)
		assert.False(t, result.done)
		assert.True(t, f.o.checkpointRedis.HExists(t.Context(), checkpointIntentsKey, i.BuildID.String()).Val())
		stored, err := f.o.sandboxStore.Get(t.Context(), i.TeamID, i.SandboxID)
		require.NoError(t, err)
		assert.Equal(t, sandbox.StateSnapshotting, stored.State)
	}
	assert.Zero(t, node.deleteCount())
}

func TestNativeCheckpointReconcilerRestartAndTransitionPin(t *testing.T) {
	t.Parallel()
	f, node := reconciliationFixture(t)
	i, finish := preparedReconciliation(t, f)
	node.set(orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING)
	// Before the original callback releases its transition, no worker may
	// overwrite it, even when the node has already completed the checkpoint.
	_, err := f.o.reconcileCheckpoint(t.Context(), i)
	require.Error(t, err)
	finish(t.Context(), errCheckpointPending)
	// A fresh owner has no request-local state and discovers the persisted hash.
	restarted := &Orchestrator{checkpointRedis: f.o.checkpointRedis, sandboxStore: f.o.sandboxStore, sqlcDB: f.o.sqlcDB, snapshotCache: f.o.snapshotCache, nodes: f.o.nodes}
	restarted.startCheckpointReconciler(t.Context())
	t.Cleanup(func() { require.NoError(t, restarted.stopCheckpointReconciler(context.WithoutCancel(t.Context()))) })
	require.Eventually(t, func() bool { return f.o.checkpointRedis.HLen(t.Context(), checkpointIntentsKey).Val() == 0 }, 10*time.Second, 20*time.Millisecond)
	stored, err := f.o.sandboxStore.Get(t.Context(), i.TeamID, i.SandboxID)
	require.NoError(t, err)
	assert.Equal(t, sandbox.StateRunning, stored.State)
	assert.Zero(t, node.deleteCount())
}

func TestNativeCheckpointDatabaseFailureRetainsIntentWithoutKilling(t *testing.T) {
	t.Parallel()
	f, node := reconciliationFixture(t)
	i, finish := preparedReconciliation(t, f)
	finish(t.Context(), errCheckpointPending)
	node.set(orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING)
	_, tx, err := f.o.sqlcDB.WithTx(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) })
	_, err = tx.Exec(t.Context(), "SELECT id FROM public.env_builds WHERE id=$1 FOR UPDATE", i.BuildID)
	require.NoError(t, err)
	_, err = f.o.reconcileCheckpoint(t.Context(), i)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.True(t, f.o.checkpointRedis.HExists(t.Context(), checkpointIntentsKey, i.BuildID.String()).Val())
	stored, err := f.o.sandboxStore.Get(t.Context(), i.TeamID, i.SandboxID)
	require.NoError(t, err)
	assert.Equal(t, sandbox.StateRunning, stored.State)
	assert.Zero(t, node.deleteCount())
	require.NoError(t, tx.Rollback(t.Context()))
	result, err := f.o.reconcileCheckpoint(t.Context(), i)
	require.NoError(t, err)
	assert.True(t, result.done)
	assert.True(t, result.committed)
	assert.False(t, f.o.checkpointRedis.HExists(t.Context(), checkpointIntentsKey, i.BuildID.String()).Val())
}

func TestNativeCheckpointReconciliationProtectsNewerExecution(t *testing.T) {
	t.Parallel()
	f, node := reconciliationFixture(t)
	i, finish := preparedReconciliation(t, f)
	finish(t.Context(), errCheckpointPending)
	newer := f.sbx
	newer.ExecutionID = uuid.NewString()
	newer.State = sandbox.StateSnapshotting
	require.NoError(t, f.o.sandboxStore.Add(t.Context(), newer, nil))
	node.set(orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING)
	result, err := f.o.reconcileCheckpoint(t.Context(), i)
	require.NoError(t, err)
	assert.True(t, result.done)
	stored, err := f.o.sandboxStore.Get(t.Context(), i.TeamID, i.SandboxID)
	require.NoError(t, err)
	assert.Equal(t, newer.ExecutionID, stored.ExecutionID)
	assert.Equal(t, sandbox.StateSnapshotting, stored.State)
	assert.Zero(t, node.deleteCount())
}

func TestNativeCheckpointOldNodeDoesNotCreateIntent(t *testing.T) {
	t.Parallel()
	f, node := reconciliationFixture(t)
	node.queryErr = status.Error(codes.Unimplemented, "old node")
	i, err := f.o.prepareNativeCheckpoint(t.Context(), f.sbx, uuid.New(), types.BuildStatusSuccess)
	require.NoError(t, err)
	assert.Nil(t, i)
	assert.EqualValues(t, 0, f.o.checkpointRedis.HLen(t.Context(), checkpointIntentsKey).Val())
}

func TestNativeCheckpointOldIntentCannotChangeLaterCheckpointInSameExecution(t *testing.T) {
	t.Parallel()
	for _, currentState := range []sandbox.State{sandbox.StateRunning, sandbox.StateSnapshotting} {
		for _, receipt := range []orchestrator.CheckpointRuntimeState{orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_STOPPED} {
			t.Run(string(currentState)+"/"+receipt.String(), func(t *testing.T) {
				t.Parallel()
				f, node := reconciliationFixture(t)
				i, finish := preparedReconciliation(t, f)
				finish(t.Context(), errCheckpointPending)
				newer := f.sbx
				newer.CheckpointBuildID = uuid.NewString()
				newer.State = currentState
				require.NoError(t, f.o.sandboxStore.Add(t.Context(), newer, nil))
				i.RuntimeReceipt = receipt
				result, err := f.o.reconcileCheckpoint(t.Context(), i)
				require.NoError(t, err)
				assert.True(t, result.done)
				stored, err := f.o.sandboxStore.Get(t.Context(), i.TeamID, i.SandboxID)
				require.NoError(t, err)
				assert.Equal(t, newer.ExecutionID, stored.ExecutionID)
				assert.Equal(t, currentState, stored.State)
				assert.Equal(t, newer.CheckpointBuildID, stored.CheckpointBuildID)
				assert.Zero(t, node.deleteCount())
			})
		}
	}
}

func TestNativeCheckpointKnownReceiptDoesNotDependOnStatusAvailability(t *testing.T) {
	t.Parallel()
	for _, stopped := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "committed_restore_failure"}[stopped], func(t *testing.T) {
			t.Parallel()
			f, node := reconciliationFixture(t)
			node.checkpoint = func(_ context.Context, r *orchestrator.SandboxCheckpointRequest) error {
				node.mu.Lock()
				node.queryErr = status.Error(codes.Unavailable, "status service unavailable after action")
				node.mu.Unlock()
				if stopped {
					return orchestrator.CheckpointCommittedError(r.GetBuildId(), status.Error(codes.Internal, "restore failed"))
				}
				return nil
			}
			err := f.o.CheckpointSandbox(t.Context(), f.sbx.TeamID, f.sbx.SandboxID)
			if stopped {
				require.Error(t, err)
				assert.Equal(t, 1, node.deleteCount())
			} else {
				require.NoError(t, err)
				assert.Zero(t, node.deleteCount())
			}
			last, err := f.o.sqlcDB.GetLastSnapshot(t.Context(), f.sbx.SandboxID)
			require.NoError(t, err)
			assert.Equal(t, types.BuildStatusSuccess, last.EnvBuild.Status)
			assert.EqualValues(t, 0, f.o.checkpointRedis.HLen(t.Context(), checkpointIntentsKey).Val())
		})
	}
}

func TestNativeCheckpointDurableReceiptAllowsDatabaseRetryWhileNodeUnavailable(t *testing.T) {
	t.Parallel()
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "unavailable", true: "native_disabled"}[legacy], func(t *testing.T) {
			f, node := reconciliationFixture(t)
			i, finish := preparedReconciliation(t, f)
			finish(t.Context(), errCheckpointPending)
			require.NoError(t, f.o.observeCheckpointResult(t.Context(), &i, nil))
			// A restarted reconciler only recovers the durable commit bit, never an
			// obsolete assertion that the prior runtime is still running.
			i.RuntimeReceipt = orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_UNKNOWN
			if legacy {
				node.legacy = true
			} else {
				node.queryErr = status.Error(codes.Unavailable, "node temporarily unavailable")
			}
			_, err := f.o.reconcileCheckpoint(t.Context(), i)
			require.Error(t, err)
			var dbStatus string
			require.NoError(t, f.o.sqlcDB.TestsRawSQLQuery(t.Context(), "SELECT status FROM public.env_builds WHERE id=$1", func(rows pgx.Rows) error { rows.Next(); return rows.Scan(&dbStatus) }, i.BuildID))
			assert.Equal(t, string(types.BuildStatusSuccess), dbStatus)
			stored, err := f.o.sandboxStore.Get(t.Context(), i.TeamID, i.SandboxID)
			require.NoError(t, err)
			assert.Equal(t, sandbox.StateSnapshotting, stored.State)
			assert.True(t, f.o.checkpointRedis.HExists(t.Context(), checkpointIntentsKey, i.BuildID.String()).Val())
			assert.Zero(t, node.deleteCount())
		})
	}
}
