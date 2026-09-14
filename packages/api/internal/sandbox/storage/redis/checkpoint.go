package redis

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/e2b-dev/infra/packages/api/internal/sandbox/sandboxtypes"
)

// A native capture may outlive transitionKeyTTL. Its callback must not delete
// the key of a newer lifecycle action after the old lease expired.
var deleteTransitionIfOwnedScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`)

var restoreCheckpointScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then return 0 end
local item = cjson.decode(data)
if item.executionID ~= ARGV[1] then return -1 end
if item.checkpointBuildID ~= ARGV[2] then return -3 end
if redis.call('EXISTS', KEYS[2]) ~= 0 then return -2 end
if item.state == 'running' then return 1 end
if item.state ~= 'snapshotting' then return -2 end
item.state = 'running'
redis.call('SET', KEYS[1], cjson.encode(item), 'KEEPTTL')
return 1
`)

// Add is lockless, so the execution comparison and write must happen together
// in Redis, not in the Go callback passed to Update.
func (s *Storage) RestoreCheckpointRunning(ctx context.Context, teamID uuid.UUID, sandboxID, executionID, buildID string) error {
	if executionID == "" {
		return sandboxtypes.ErrExecutionMismatch
	}
	result, err := restoreCheckpointScript.Run(ctx, s.redisClient, []string{
		getSandboxKey(teamID.String(), sandboxID), getTransitionKey(teamID.String(), sandboxID),
	}, executionID, buildID).Int()
	if err != nil {
		return err
	}
	switch result {
	case 1:
		return nil
	case 0:
		return sandboxtypes.ErrNotFound
	case -1:
		return sandboxtypes.ErrExecutionMismatch
	case -3:
		return sandboxtypes.ErrCheckpointMismatch
	default:
		return fmt.Errorf("sandbox transition still active during checkpoint reconciliation")
	}
}

var pinCheckpointScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then return 0 end
local item = cjson.decode(data)
if item.executionID ~= ARGV[1] then return -1 end
if item.state ~= 'snapshotting' or redis.call('GET', KEYS[2]) ~= ARGV[3] then return -2 end
item.checkpointBuildID = ARGV[2]
redis.call('SET', KEYS[1], cjson.encode(item), 'KEEPTTL')
return 1
`)

func (s *Storage) PinCheckpoint(ctx context.Context, teamID uuid.UUID, sandboxID, executionID, buildID, transitionID string) error {
	if transitionID == "" {
		return fmt.Errorf("missing checkpoint transition ownership")
	}
	result, err := pinCheckpointScript.Run(ctx, s.redisClient, []string{getSandboxKey(teamID.String(), sandboxID), getTransitionKey(teamID.String(), sandboxID)}, executionID, buildID, transitionID).Int()
	if err != nil {
		return err
	}
	switch result {
	case 1:
		return nil
	case 0:
		return sandboxtypes.ErrNotFound
	case -1:
		return sandboxtypes.ErrExecutionMismatch
	default:
		return fmt.Errorf("checkpoint no longer owns sandbox transition")
	}
}
