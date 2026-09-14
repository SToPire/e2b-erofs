package redis

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/e2b-dev/infra/packages/api/internal/sandbox/sandboxtypes"
)

func TestCheckpointOperationPinSurvivesCallbackAndProtectsNextCheckpoint(t *testing.T) {
	t.Parallel()
	s, _ := setupTestStorage(t)
	sbx := createTestSandbox("checkpoint-operation")
	require.NoError(t, s.Add(t.Context(), sbx))
	first, second := uuid.NewString(), uuid.NewString()
	transition, _, finish, err := s.StartRemoving(t.Context(), sbx.TeamID, sbx.SandboxID, sandboxtypes.RemoveOpts{Action: sandboxtypes.StateActionSnapshot})
	require.NoError(t, err)
	require.NoError(t, s.PinCheckpoint(t.Context(), sbx.TeamID, sbx.SandboxID, sbx.ExecutionID, first, transition.TransitionID))
	require.Error(t, s.RestoreCheckpointRunning(t.Context(), sbx.TeamID, sbx.SandboxID, sbx.ExecutionID, first), "original transition still owns the record")
	finish(t.Context(), errors.New("pending reconciliation"))
	require.NoError(t, s.RestoreCheckpointRunning(t.Context(), sbx.TeamID, sbx.SandboxID, sbx.ExecutionID, first))
	oldTransition := transition.TransitionID
	transition, _, finish, err = s.StartRemoving(t.Context(), sbx.TeamID, sbx.SandboxID, sandboxtypes.RemoveOpts{Action: sandboxtypes.StateActionSnapshot})
	require.NoError(t, err)
	require.Error(t, s.PinCheckpoint(t.Context(), sbx.TeamID, sbx.SandboxID, sbx.ExecutionID, first, oldTransition))
	require.NoError(t, s.PinCheckpoint(t.Context(), sbx.TeamID, sbx.SandboxID, sbx.ExecutionID, second, transition.TransitionID))
	finish(t.Context(), errors.New("new checkpoint pending"))
	require.ErrorIs(t, s.RestoreCheckpointRunning(t.Context(), sbx.TeamID, sbx.SandboxID, sbx.ExecutionID, first), sandboxtypes.ErrCheckpointMismatch)
	_, _, _, err = s.StartRemoving(t.Context(), sbx.TeamID, sbx.SandboxID, sandboxtypes.RemoveOpts{Action: sandboxtypes.StateActionKill, ExpectExecutionID: sbx.ExecutionID, ExpectCheckpointBuildID: first})
	require.ErrorIs(t, err, sandboxtypes.ErrCheckpointMismatch)
	stored, err := s.Get(t.Context(), sbx.TeamID, sbx.SandboxID)
	require.NoError(t, err)
	assert.Equal(t, second, stored.CheckpointBuildID)
	assert.Equal(t, sandboxtypes.StateSnapshotting, stored.State)
}

func TestCheckpointRemovalPinIsCheckedAtAtomicWrite(t *testing.T) {
	t.Parallel()
	s, client := setupTestStorage(t)
	old := createTestSandbox("checkpoint-atomic")
	old.CheckpointBuildID = uuid.NewString()
	newer := old
	newer.CheckpointBuildID = uuid.NewString()
	require.NoError(t, s.Add(t.Context(), newer))
	old.State = sandboxtypes.StateKilling
	stale, err := json.Marshal(old)
	require.NoError(t, err)
	transition := uuid.NewString()
	written, err := startTransitionScript.Run(t.Context(), client, []string{getSandboxKey(old.TeamID.String(), old.SandboxID), getTransitionKey(old.TeamID.String(), old.SandboxID), getTransitionResultKey(old.TeamID.String(), old.SandboxID, transition)}, stale, transition, 60, 60, old.ExecutionID, old.CheckpointBuildID).Int()
	require.NoError(t, err)
	assert.Equal(t, -1, written)
	stored, err := s.Get(t.Context(), old.TeamID, old.SandboxID)
	require.NoError(t, err)
	assert.Equal(t, newer.CheckpointBuildID, stored.CheckpointBuildID)
	assert.Equal(t, sandboxtypes.StateRunning, stored.State)
}

func TestDelayedCheckpointCallbackDoesNotReleaseNewerTransition(t *testing.T) {
	t.Parallel()
	s, client := setupTestStorage(t)
	sbx := createTestSandbox("delayed-native-checkpoint")
	require.NoError(t, s.Add(t.Context(), sbx))
	_, _, finishOld, err := s.StartRemoving(t.Context(), sbx.TeamID, sbx.SandboxID, sandboxtypes.RemoveOpts{Action: sandboxtypes.StateActionSnapshot})
	require.NoError(t, err)
	key := getTransitionKey(sbx.TeamID.String(), sbx.SandboxID)
	// Expiry permits a separately authorized kill to acquire a new transition
	// while the old, slow checkpoint is still completing on the node.
	require.NoError(t, client.Del(t.Context(), key).Err())
	newer, _, finishNew, err := s.StartRemoving(t.Context(), sbx.TeamID, sbx.SandboxID, sandboxtypes.RemoveOpts{Action: sandboxtypes.StateActionKill})
	require.NoError(t, err)
	finishOld(t.Context(), errors.New("native checkpoint pending reconciliation"))
	current, err := client.Get(t.Context(), key).Result()
	require.NoError(t, err)
	require.Equal(t, newer.TransitionID, current)
	stored, err := s.Get(t.Context(), sbx.TeamID, sbx.SandboxID)
	require.NoError(t, err)
	require.Equal(t, sandboxtypes.StateKilling, stored.State)
	finishNew(t.Context(), nil)
}
