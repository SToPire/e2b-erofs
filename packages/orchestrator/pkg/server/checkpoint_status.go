//go:build linux

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/shared/pkg/grpc/orchestrator"
	"github.com/e2b-dev/infra/packages/shared/pkg/logger"
)

type checkpointRecord struct {
	Version                                 int
	BuildID, SandboxID, ExecutionID, TeamID string
	Server, Original                        erofs.ProcessIdentity
	Replacement                             *erofs.ProcessIdentity
	Finished, Captured, Committed           bool
	ReplacementUnknown                      bool
	RecoveryPath                            string
}

type nativeCheckpointOperation struct {
	mu                    sync.Mutex
	record                checkpointRecord
	path                  string
	original, replacement *sandbox.Sandbox
}

func (s *Server) checkpointRecordPath(buildID string) string {
	return filepath.Join(s.config.EROFSSnapshotDir, ".checkpoint-operations", buildID+".json")
}

func writeCheckpointRecord(path string, record checkpointRecord, create bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".receipt-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return err
	}
	flags := uint(0)
	if create {
		flags = unix.RENAME_NOREPLACE
	}
	if err := unix.Renameat2(unix.AT_FDCWD, f.Name(), unix.AT_FDCWD, path, flags); err != nil {
		return err
	}
	for _, p := range []string{dir, filepath.Dir(dir), filepath.Dir(filepath.Dir(dir))} {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		if err := errors.Join(f.Sync(), f.Close()); err != nil {
			return err
		}
	}
	return nil
}

// Register before admission or destructive steps. A duplicate action never
// captures a second cutoff; clients reconcile it through CheckpointStatus.
func (s *Server) beginNativeCheckpoint(ctx context.Context, sbx *sandbox.Sandbox, in *orchestrator.SandboxCheckpointRequest) (*nativeCheckpointOperation, error) {
	if !sbx.UsesEROFS() {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	if id, err := uuid.Parse(in.GetBuildId()); err != nil || id.String() != in.GetBuildId() {
		return nil, status.Error(codes.InvalidArgument, "checkpoint build ID must be a canonical UUID")
	}
	if s.config.EROFSSnapshotDir == "" {
		return nil, status.Error(codes.FailedPrecondition, "native checkpoint store is not configured")
	}
	producer, err := erofs.IdentifyProcess(os.Getpid())
	if err != nil {
		return nil, err
	}
	original, err := sbx.ProcessIdentity()
	if err != nil {
		return nil, err
	}
	op := &nativeCheckpointOperation{path: s.checkpointRecordPath(in.GetBuildId()), original: sbx,
		record: checkpointRecord{Version: 1, BuildID: in.GetBuildId(), SandboxID: sbx.Runtime.SandboxID,
			ExecutionID: sbx.Runtime.ExecutionID, TeamID: sbx.Runtime.TeamID, Server: producer, Original: original}}
	if err := writeCheckpointRecord(op.path, op.record, true); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, status.Error(codes.AlreadyExists, "checkpoint request already recorded; query its status")
		}
		return nil, fmt.Errorf("record native checkpoint: %w", err)
	}
	s.nativeCheckpointStateMu.Lock()
	s.nativeCheckpoints.Store(in.GetBuildId(), op)
	s.nativeCheckpointStateMu.Unlock()
	return op, nil
}

func (s *Server) updateNativeCheckpoint(buildID string, update func(*nativeCheckpointOperation)) {
	s.nativeCheckpointStateMu.Lock()
	defer s.nativeCheckpointStateMu.Unlock()
	value, ok := s.nativeCheckpoints.Load(buildID)
	if !ok {
		return
	}
	op := value.(*nativeCheckpointOperation)
	op.mu.Lock()
	defer op.mu.Unlock()
	update(op)
	if err := writeCheckpointRecord(op.path, op.record, false); err != nil {
		// In-memory facts remain valid. After restart an older receipt only
		// provides weaker UNKNOWN facts; it cannot fabricate a failed commit.
		logger.L().Error(context.Background(), "persist native checkpoint receipt", zap.Error(err), zap.String("build_id", buildID))
	}
}

func (s *Server) finishNativeCheckpoint(op *nativeCheckpointOperation) {
	if op == nil {
		return
	}
	s.updateNativeCheckpoint(op.record.BuildID, func(op *nativeCheckpointOperation) { op.record.Finished = true })
}

func (s *Server) noteNativeCommit(buildID string) {
	s.updateNativeCheckpoint(buildID, func(op *nativeCheckpointOperation) { op.record.Committed = true })
}

func (s *Server) noteNativeCapture(buildID string, err error) {
	var capture *sandbox.NativeCaptureFailure
	if !errors.As(err, &capture) {
		return
	}
	s.updateNativeCheckpoint(buildID, func(op *nativeCheckpointOperation) {
		op.record.Captured = true
		op.record.RecoveryPath = capture.RecoveryPath
	})
}

func (s *Server) noteNativeReplacement(buildID string, sbx *sandbox.Sandbox) {
	identity, err := sbx.ProcessIdentity()
	s.updateNativeCheckpoint(buildID, func(op *nativeCheckpointOperation) {
		op.replacement = sbx
		op.record.ReplacementUnknown = err != nil
		if err == nil {
			op.record.Replacement = &identity
		}
	})
}

func sameCheckpointExecution(r checkpointRecord, in *orchestrator.SandboxCheckpointStatusRequest) bool {
	return r.BuildID == in.GetBuildId() && r.SandboxID == in.GetSandboxId() && r.ExecutionID == in.GetExecutionId() && r.TeamID == in.GetTeamId()
}

func (s *Server) readNativeCheckpoint(buildID string) (checkpointRecord, *nativeCheckpointOperation, error) {
	if value, ok := s.nativeCheckpoints.Load(buildID); ok {
		op := value.(*nativeCheckpointOperation)
		op.mu.Lock()
		defer op.mu.Unlock()
		return op.record, op, nil
	}
	data, err := os.ReadFile(s.checkpointRecordPath(buildID))
	if err != nil {
		return checkpointRecord{}, nil, err
	}
	var record checkpointRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return record, nil, err
	}
	if record.Version != 1 || record.BuildID != buildID {
		return record, nil, errors.New("invalid native checkpoint receipt")
	}
	return record, nil, nil
}

func (s *Server) CheckpointStatus(ctx context.Context, in *orchestrator.SandboxCheckpointStatusRequest) (*orchestrator.SandboxCheckpointStatusResponse, error) {
	if id, err := uuid.Parse(in.GetBuildId()); err != nil || id.String() != in.GetBuildId() || in.GetSandboxId() == "" || in.GetTeamId() == "" || in.GetExecutionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "checkpoint status requires build, sandbox, team and execution identity")
	}
	response := &orchestrator.SandboxCheckpointStatusResponse{BuildId: in.GetBuildId(), ExecutionId: in.GetExecutionId()}
	live, found := s.sandboxFactory.Sandboxes.Get(in.GetSandboxId())
	liveMatches := found && live.Runtime.TeamID == in.GetTeamId() && live.Runtime.ExecutionID == in.GetExecutionId()
	if liveMatches {
		response.Native = live.UsesEROFS()
		if !live.ProcessExited() {
			response.RuntimeState = orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING
			response.LifecycleId = live.LifecycleID
			response.RuntimeBuildId = live.Template.Files().BuildID
		}
	}
	if s.config.EROFSSnapshotDir == "" {
		return response, nil
	}
	record, op, recordErr := s.readNativeCheckpoint(in.GetBuildId())
	if recordErr != nil {
		if errors.Is(recordErr, os.ErrNotExist) {
			// Absence proves neither failed publication nor process exit.
			// This also serves native preflight before the action starts.
			return response, nil
		}
		return nil, status.Errorf(codes.DataLoss, "read checkpoint receipt: %v", recordErr)
	}
	if !sameCheckpointExecution(record, in) {
		return nil, status.Error(codes.FailedPrecondition, "checkpoint identity does not match recorded operation")
	}
	response.Native = true
	active := !record.Finished && (op != nil || erofs.ProcessTerminated(record.Server) != nil)
	store, err := erofs.NewStore(s.config.EROFSSnapshotDir, erofs.Options{MkfsPath: s.config.EROFSMkfsPath})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "open checkpoint store: %v", err)
	}
	_, generationErr := os.Lstat(filepath.Join(store.Root, in.GetBuildId()))
	generationMissing := errors.Is(generationErr, os.ErrNotExist)
	if generationErr != nil && !generationMissing {
		return nil, status.Errorf(codes.Internal, "inspect checkpoint directory: %v", generationErr)
	}
	var snapshot *erofs.Snapshot
	var verifyErr error
	pendingVerification := false
	if generationMissing {
		snapshot, verifyErr = store.VerifyCommitted(ctx, in.GetBuildId())
	} else {
		snapshot, verifyErr, pendingVerification = s.verifyNativeCheckpointStatus(ctx, store, in.GetBuildId())
	}
	switch {
	case pendingVerification:
		response.SnapshotState = orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_IN_PROGRESS
	case verifyErr == nil:
		if err := s.persistObservedNativeCommit(in.GetBuildId()); err != nil {
			return nil, status.Errorf(codes.Internal, "persist checkpoint commit observation: %v", err)
		}
		response.SnapshotState = orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED
	case snapshot != nil:
		response.SnapshotState = orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_DURABILITY_UNKNOWN
	case generationMissing && errors.Is(verifyErr, os.ErrNotExist):
		if record.Committed {
			return nil, status.Error(codes.DataLoss, "previously committed checkpoint artifacts are missing")
		}
		switch {
		case record.Captured:
			response.SnapshotState = orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_CAPTURED
		case !record.Finished && active:
			response.SnapshotState = orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_IN_PROGRESS
		case record.Finished:
			response.SnapshotState = orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_NOT_COMMITTED
		}
	default:
		if errors.Is(verifyErr, erofs.ErrUnprotectedVerificationStore) {
			return nil, status.Error(codes.FailedPrecondition, verifyErr.Error())
		}
		if ctx.Err() != nil {
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		return nil, status.Errorf(codes.DataLoss, "validate checkpoint: %v", verifyErr)
	}
	s.nativeCheckpointStateMu.RLock()
	defer s.nativeCheckpointStateMu.RUnlock()
	// Receipt, active checkpoint operations and runtime are observed against
	// checkpoint admission/completion under one lock. Live registration precedes
	// completion, so a replacement cannot disappear between the two samples.
	record, op, recordErr = s.readNativeCheckpoint(in.GetBuildId())
	if recordErr != nil {
		return nil, status.Errorf(codes.Internal, "reread checkpoint receipt: %v", recordErr)
	}
	active = !record.Finished && (op != nil || erofs.ProcessTerminated(record.Server) != nil)
	// Re-sample after validation: a snapshot can commit while hashing its
	// parent chain. A live observation taken before that commit could refer
	// to the old VM and cannot be combined with the new committed snapshot.
	response.RuntimeState = orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_UNKNOWN
	response.LifecycleId, response.RuntimeBuildId = "", ""
	live, found = s.sandboxFactory.Sandboxes.Get(in.GetSandboxId())
	if found && live.Runtime.TeamID == in.GetTeamId() && live.Runtime.ExecutionID == in.GetExecutionId() && !live.ProcessExited() {
		response.RuntimeState = orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING
		response.LifecycleId = live.LifecycleID
		response.RuntimeBuildId = live.Template.Files().BuildID
		return response, nil
	}
	// A later checkpoint can start while VerifyCommitted hashes the old chain.
	// Observe active operations after validation and the empty live-map read:
	// that temporary gap must not be reported as a stopped execution.
	s.nativeCheckpoints.Range(func(_, value any) bool {
		other := value.(*nativeCheckpointOperation)
		other.mu.Lock()
		defer other.mu.Unlock()
		r := other.record
		if !r.Finished && r.SandboxID == in.GetSandboxId() && r.TeamID == in.GetTeamId() && r.ExecutionID == in.GetExecutionId() {
			active = true
		}
		return true
	})
	if active {
		response.RuntimeState = orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_TRANSITIONING
		return response, nil
	}
	if record.Finished {
		stopped := !record.ReplacementUnknown && erofs.ProcessTerminated(record.Original) == nil
		if record.Replacement != nil {
			stopped = stopped && erofs.ProcessTerminated(*record.Replacement) == nil
		}
		if op != nil {
			op.mu.Lock()
			stopped = op.original != nil && op.original.ProcessExited() && (op.replacement == nil || op.replacement.ProcessExited())
			op.mu.Unlock()
		}
		if stopped {
			response.RuntimeState = orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_STOPPED
		}
	}
	return response, nil
}

// Verification can discover an externally recovered commit after the action
// returned. Persist that fact without replacing newer runtime receipt fields.
func (s *Server) persistObservedNativeCommit(buildID string) error {
	s.nativeCheckpointStateMu.Lock()
	defer s.nativeCheckpointStateMu.Unlock()
	record, op, err := s.readNativeCheckpoint(buildID)
	if err != nil {
		return err
	}
	record.Committed = true
	if op != nil {
		op.mu.Lock()
		defer op.mu.Unlock()
		op.record.Committed = true
		record = op.record
	}
	return writeCheckpointRecord(s.checkpointRecordPath(buildID), record, false)
}
