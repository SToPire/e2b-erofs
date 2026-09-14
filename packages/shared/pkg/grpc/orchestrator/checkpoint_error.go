package orchestrator

import (
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const checkpointCommittedReason = "CHECKPOINT_COMMITTED"
const checkpointErrorDomain = "orchestrator.e2b.dev"

// CheckpointCommittedError distinguishes a failed runtime restore from a failed
// snapshot publication. The control plane must retain this build as resumable
// even though it must remove the failed runtime's running-sandbox state.
// ErrorInfo is additive: older clients still observe an Internal failure.
func CheckpointCommittedError(buildID string, cause error) error {
	if cause == nil {
		return nil
	}
	s := status.New(codes.Internal, fmt.Sprintf("checkpoint %s committed, but runtime restore failed: %v", buildID, cause))
	withDetails, err := s.WithDetails(&errdetails.ErrorInfo{
		Reason:   checkpointCommittedReason,
		Domain:   checkpointErrorDomain,
		Metadata: map[string]string{"build_id": buildID},
	})
	if err != nil {
		return s.Err()
	}
	return withDetails.Err()
}

func IsCheckpointCommittedError(err error, buildID string) bool {
	if buildID == "" {
		return false
	}
	s, ok := status.FromError(err)
	if !ok || s.Code() != codes.Internal {
		return false
	}
	for _, detail := range s.Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok && info.Reason == checkpointCommittedReason && info.Domain == checkpointErrorDomain && info.Metadata["build_id"] == buildID {
			return true
		}
	}
	return false
}
