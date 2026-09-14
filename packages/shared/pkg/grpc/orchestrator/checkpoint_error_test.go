package orchestrator

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestCheckpointCommitSurvivesGRPCStatusWireEncoding(t *testing.T) {
	const build = "67b14018-7518-49cd-a9df-e0b8856e90fb"
	err := CheckpointCommittedError(build, errors.New("Firecracker failed to load"))
	wire, marshalErr := proto.Marshal(status.Convert(err).Proto())
	require.NoError(t, marshalErr)
	var received statuspb.Status
	require.NoError(t, proto.Unmarshal(wire, &received))
	receivedErr := fmt.Errorf("checkpoint RPC: %w", status.FromProto(&received).Err())
	require.True(t, IsCheckpointCommittedError(receivedErr, build))
	require.False(t, IsCheckpointCommittedError(receivedErr, "different-build"))
	require.Equal(t, codes.Internal, status.Code(receivedErr), "older clients retain the fatal runtime error classification")
}

func TestCheckpointCommitRequiresTypedMatchingDetails(t *testing.T) {
	for _, tc := range []struct {
		name               string
		code               codes.Code
		reason, domain, id string
	}{
		{"wrong code", codes.FailedPrecondition, checkpointCommittedReason, checkpointErrorDomain, "build"},
		{"wrong reason", codes.Internal, "different", checkpointErrorDomain, "build"},
		{"wrong domain", codes.Internal, checkpointCommittedReason, "different", "build"},
		{"wrong id", codes.Internal, checkpointCommittedReason, checkpointErrorDomain, "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := status.New(tc.code, "committed").WithDetails(&errdetails.ErrorInfo{Reason: tc.reason, Domain: tc.domain, Metadata: map[string]string{"build_id": tc.id}})
			require.NoError(t, err)
			require.False(t, IsCheckpointCommittedError(s.Err(), "build"))
		})
	}
	require.False(t, IsCheckpointCommittedError(status.Error(codes.Internal, "CHECKPOINT_COMMITTED build"), "build"))
	require.False(t, IsCheckpointCommittedError(errors.New("CHECKPOINT_COMMITTED build"), "build"))
	require.False(t, IsCheckpointCommittedError(nil, "build"))
	require.NoError(t, CheckpointCommittedError("build", nil))
}
