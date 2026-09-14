package sandbox

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// RestoreCheckpointRunning completes only this execution's released checkpoint
// transition. It cannot overwrite a concurrent Add or a later lifecycle action.
func (s *Store) RestoreCheckpointRunning(ctx context.Context, teamID uuid.UUID, sandboxID, executionID, buildID string) error {
	backend, ok := s.storage.(interface {
		RestoreCheckpointRunning(context.Context, uuid.UUID, string, string, string) error
	})
	if !ok {
		return errors.New("sandbox storage does not support checkpoint reconciliation")
	}
	return backend.RestoreCheckpointRunning(ctx, teamID, sandboxID, executionID, buildID)
}

func (s *Store) PinCheckpoint(ctx context.Context, teamID uuid.UUID, sandboxID, executionID, buildID, transitionID string) error {
	backend, ok := s.storage.(interface {
		PinCheckpoint(context.Context, uuid.UUID, string, string, string, string) error
	})
	if !ok {
		return errors.New("sandbox storage does not support checkpoint operation binding")
	}
	return backend.PinCheckpoint(ctx, teamID, sandboxID, executionID, buildID, transitionID)
}
