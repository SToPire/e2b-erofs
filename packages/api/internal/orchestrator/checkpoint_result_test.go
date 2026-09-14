package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	gogostatus "github.com/gogo/status"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/e2b-dev/infra/packages/db/pkg/testutils"
	"github.com/e2b-dev/infra/packages/db/pkg/types"
	"github.com/e2b-dev/infra/packages/db/queries"
	"github.com/e2b-dev/infra/packages/shared/pkg/grpc/orchestrator"
)

type checkpointCacheRecorder struct {
	ids           []string
	contextErrors []error
}

func (c *checkpointCacheRecorder) Invalidate(ctx context.Context, id string) {
	c.ids = append(c.ids, id)
	c.contextErrors = append(c.contextErrors, ctx.Err())
}

func checkpointErrorRoundTrip(t *testing.T, err error) error {
	t.Helper()
	data, marshalErr := proto.Marshal(status.Convert(err).Proto())
	require.NoError(t, marshalErr)
	var wire statuspb.Status
	require.NoError(t, proto.Unmarshal(data, &wire))
	return status.FromProto(&wire).Err()
}

func TestCheckpointFailurePreservesOnlyMatchingCommittedBuild(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name            string
		committedStatus types.BuildStatus
		marker          bool
		wrongID         bool
		cancelled       bool
	}{
		{name: "checkpoint success", committedStatus: types.BuildStatusSuccess, marker: true},
		{name: "snapshot template uploaded", committedStatus: types.BuildStatusUploaded, marker: true},
		{name: "known commit survives caller cancellation", committedStatus: types.BuildStatusSuccess, marker: true, cancelled: true},
		{name: "another build receipt cannot claim success", committedStatus: types.BuildStatusSuccess, marker: true, wrongID: true},
		{name: "ordinary failure still fails build", committedStatus: types.BuildStatusUploaded},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			db := testutils.SetupDatabase(t)
			teamID := testutils.CreateTestTeam(t, db)
			baseID := testutils.CreateTestTemplate(t, db, teamID)
			snapshot := testutils.UpsertTestSnapshotWithStatus(t, t.Context(), db, uuid.NewString(), "sandbox", teamID, baseID, types.BuildStatusSnapshotting)
			buildID := snapshot.BuildID
			_, createErr := db.SqlcClient.CreateSnapshotTemplateEnv(t.Context(), queries.CreateSnapshotTemplateEnvParams{
				SnapshotID: uuid.NewString(), TeamID: teamID, SandboxID: "sandbox", BuildID: &buildID, Tag: "default",
			})
			require.NoError(t, createErr)
			o := &Orchestrator{sqlcDB: db.SqlcClient}
			cache := &checkpointCacheRecorder{}
			o.snapshotCache = cache
			cause := status.Error(codes.Internal, "runtime restore failed")
			if test.marker {
				id := buildID.String()
				if test.wrongID {
					id = uuid.NewString()
				}
				cause = orchestrator.CheckpointCommittedError(id, errors.New("runtime restore failed"))
			}
			cause = checkpointErrorRoundTrip(t, cause)
			// The handlers use gogo/status to decide whether a failed runtime
			// must be removed. A commit receipt must remain an Internal error,
			// including when the request context has since been canceled.
			fatalStatus, ok := gogostatus.FromError(cause)
			require.True(t, ok)
			require.Equal(t, codes.Internal, fatalStatus.Code())
			ctx := t.Context()
			if test.cancelled {
				ctx = cancelledContext(t)
			}
			require.NoError(t, o.recordCheckpointFailure(ctx, "sandbox", buildID, test.committedStatus, cause))
			last, lastErr := db.SqlcClient.GetLastSnapshot(t.Context(), "sandbox")
			listed, listErr := db.SqlcClient.ListTeamSnapshotTemplates(t.Context(), queries.ListTeamSnapshotTemplatesParams{
				TeamID: teamID, CursorTime: time.Now().Add(time.Hour), CursorID: "", PageLimit: 10,
			})
			require.NoError(t, listErr)
			if test.marker && !test.wrongID {
				assert.Equal(t, string(test.committedStatus), testutils.GetBuildStatus(t, t.Context(), db, buildID))
				require.NoError(t, lastErr, "saved checkpoint must remain a normal resume source")
				assert.Equal(t, buildID, last.EnvBuild.ID)
				require.Len(t, listed, 1, "saved snapshot template must remain discoverable")
				assert.Equal(t, buildID, listed[0].BuildID)
				assert.Equal(t, []string{"sandbox"}, cache.ids)
				assert.Equal(t, []error{nil}, cache.contextErrors)
			} else {
				assert.Equal(t, string(types.BuildStatusFailed), testutils.GetBuildStatus(t, t.Context(), db, buildID))
				assert.ErrorIs(t, lastErr, pgx.ErrNoRows)
				assert.Empty(t, listed)
				assert.Empty(t, cache.ids)
			}
			assert.NotNil(t, buildFinishedAt(t, db, buildID))
		})
	}
}
