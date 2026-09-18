//go:build linux

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/fc"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/template"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/metadata"
)

type nativeCapture struct {
	store            *erofs.Store
	capture          *erofs.Capture
	request          erofs.BuildRequest
	v2Request        *erofs.BuildV2Request
	sealed           bool
	memoryCaptured   bool
	memoryAttempts   int
	baselineCopied   bool
	diskSealed       bool
	recoveryRecorded bool
	firecracker      erofs.ProcessIdentity
	committed        *erofs.Snapshot
	published        bool
	inputsCleaned    bool
}

// NativeCaptureFailure preserves a successful RAM cutoff across RPC error
// conversion. The node's operation receipt can keep it pending for recovery
// instead of declaring that the checkpoint can never produce a snapshot.
type NativeCaptureFailure struct {
	Cause        error
	RecoveryPath string
}

func (e *NativeCaptureFailure) Error() string { return e.Cause.Error() }
func (e *NativeCaptureFailure) Unwrap() error { return e.Cause }

func (s *Sandbox) UsesEROFS() bool { return s.Config.FirecrackerConfig.NativeMemory }

func (s *Sandbox) pauseEROFS(ctx context.Context, meta metadata.Template) (_ *Snapshot, resultErr error) {
	if s.v2Runtime != nil && s.v2Runtime.exportHelper {
		return nil, errors.New("disposable rootfs export helpers cannot publish RAM snapshots")
	}
	s.nativeCaptureMu.Lock()
	defer s.nativeCaptureMu.Unlock()
	defer func() {
		if resultErr != nil && s.nativeCapture != nil && s.nativeCapture.memoryCaptured {
			name := "build-request.json"
			if s.nativeCapture.recoveryRecorded {
				name = "recovery.json"
			}
			resultErr = &NativeCaptureFailure{Cause: resultErr, RecoveryPath: filepath.Join(s.nativeCapture.capture.Dir, name)}
		}
	}()
	buildID, err := uuid.Parse(meta.Template.BuildID)
	if err != nil {
		return nil, err
	}
	if s.nativeCapture != nil {
		if s.nativeCapture.request.ID != buildID.String() {
			return nil, errors.New("native capture already consumed dirty state; retry the original capture")
		}
		return s.finishNativeCapture(ctx, buildID)
	}
	store, err := erofs.NewStore(s.config.EROFSSnapshotDir, erofs.Options{MkfsPath: s.config.EROFSMkfsPath})
	if err != nil {
		return nil, err
	}
	capture, err := store.Begin(buildID.String())
	if err != nil {
		return nil, err
	}
	if err := fc.ValidateSparseStaging(capture.Dir); err != nil {
		return nil, err
	}
	parentID := ""
	diskSize := s.nativeDiskSize
	if parent, ok := template.EROFS(s.Template); ok && !s.nativeBaseline {
		parentID = parent.Manifest.ID
		diskSize = parent.Manifest.WritableDisk().Size
	}
	if s.v2Runtime != nil && s.v2Runtime.upper.identity != nil {
		diskSize = s.v2Runtime.upper.identity.Size()
	}
	frozen, err := s.freezePmemForCapture(ctx)
	if err != nil {
		_ = os.RemoveAll(capture.Dir)
		return nil, err
	}
	rollback := true
	checksStopped := false
	defer func() {
		if rollback && frozen {
			rollbackErr := s.rollbackPmemFreeze(ctx)
			resultErr = errors.Join(resultErr, rollbackErr)
			if rollbackErr == nil && checksStopped {
				s.Checks = NewChecks(s)
				go s.Checks.Start(context.WithoutCancel(ctx))
			}
		}
		if rollback {
			resultErr = errors.Join(resultErr, os.RemoveAll(capture.Dir))
		}
	}()
	meta = meta.MarkFilesystemOnly(false).MarkFsQuiesced(frozen)
	meta.Prefetch = nil
	metadataPath := filepath.Join(capture.Dir, "metadata.json")
	if err := meta.ToFile(metadataPath); err != nil {
		return nil, err
	}
	state := &nativeCapture{store: store, capture: capture, request: erofs.BuildRequest{
		ID: buildID.String(), ParentID: parentID,
		MemoryPath: capture.MemoryPath, DiskPath: capture.DiskPath,
		VMStatePath: capture.VMStatePath, MetadataPath: metadataPath,
		MemorySize: s.Config.RamMB * 1024 * 1024, DiskSize: diskSize,
	}}
	if s.v2Runtime != nil {
		state.request.DiskPath = filepath.Join(capture.Dir, "upper.sealed.raw")
		state.v2Request = &erofs.BuildV2Request{ID: buildID.String(), ParentID: parentID,
			MemorySize: state.request.MemorySize, UpperSize: diskSize, Boot: s.v2Runtime.boot, Lower: s.v2Runtime.lower,
			ParentUpperPath: s.v2Runtime.parentUpper, MemoryCapture: "full"}
		state.syncV2Request()
	}
	pid, err := s.process.Pid()
	if err != nil {
		return nil, err
	}
	state.firecracker, err = erofs.IdentifyProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("identify native capture producer: %w", err)
	}
	s.Checks.Stop()
	checksStopped = true
	if err := s.process.Pause(ctx); err != nil {
		if frozen {
			if resumeErr := s.process.ResumeInPlace(context.WithoutCancel(ctx)); resumeErr != nil {
				rollback = false
				return nil, errors.Join(err, resumeErr, s.process.Stop(context.WithoutCancel(ctx)))
			}
		}
		return nil, err
	}
	// Once this request starts, the native dirty bitmap may be consumed even
	// if transport cancellation hides its response. Never issue another Diff.
	s.nativeCapture = state
	rollback = false
	return s.finishNativeCapture(ctx, buildID)
}

// Continue the same cutoff after a transient failure. A successful RAM export is
// never repeated; an uncertain one can only be replaced by Full while FC is
// still paused. Disk sealing and publication can retry after FC has exited.
func (s *Sandbox) finishNativeCapture(ctx context.Context, buildID uuid.UUID) (*Snapshot, error) {
	state := s.nativeCapture
	if state.sealed {
		return s.publishNativeCapture(ctx, buildID)
	}
	if state.v2Request != nil && state.recoveryRecorded && s.v2Runtime.upper.isClosed() {
		return s.publishNativeCapture(ctx, buildID)
	}
	capture := state.capture
	sealCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
	defer cancel()
	if !state.memoryCaptured {
		select {
		case <-s.process.Exit.Done():
			return nil, fmt.Errorf("Firecracker exited before a complete RAM capture; retained files at %s", capture.Dir)
		default:
		}
		var captureErr error
		for attempt := 0; attempt < 2; attempt++ {
			kind := fc.NativeSnapshotFull
			if state.memoryAttempts == 0 && state.request.ParentID != "" {
				kind = fc.NativeSnapshotDiff
			}
			if state.memoryAttempts != 0 {
				suffix := uuid.NewString()
				state.request.MemoryPath = filepath.Join(capture.Dir, "memory.full-"+suffix)
				state.request.VMStatePath = filepath.Join(capture.Dir, "vmstate.full-"+suffix)
			}
			state.memoryAttempts++
			if err := s.process.CreateNativeSnapshot(sealCtx, state.request.VMStatePath, state.request.MemoryPath, kind); err != nil {
				captureErr = errors.Join(captureErr, err)
				continue
			}
			state.memoryCaptured = true
			if state.v2Request != nil {
				state.v2Request.MemoryCapture = "full"
				if kind == fc.NativeSnapshotDiff {
					state.v2Request.MemoryCapture = "diff"
				}
				state.syncV2Request()
			}
			break
		}
		if !state.memoryCaptured {
			return nil, fmt.Errorf("native RAM capture failed; retained files at %s: %w", capture.Dir, captureErr)
		}
	}
	if !state.recoveryRecorded {
		if state.v2Request != nil {
			rawPath, err := s.rootfs.Path()
			if err != nil {
				return nil, err
			}
			if err := state.store.RecordV2Recovery(sealCtx, filepath.Join(capture.Dir, "recovery.json"), *state.v2Request, rawPath, state.request.DiskPath, state.firecracker); err != nil {
				return nil, err
			}
			s.v2Runtime.upper.retainForCapture()
			state.recoveryRecorded = true
		} else if provider, ok := s.rootfs.(*erofsRootfs); ok {
			overlay, err := provider.overlay.RecoveryInfo()
			if err != nil {
				return nil, err
			}
			path := filepath.Join(capture.Dir, "recovery.json")
			if err := state.store.RecordRecovery(sealCtx, path, state.request, overlay, state.firecracker); err != nil {
				return nil, fmt.Errorf("record native capture recovery: %w", err)
			}
			state.recoveryRecorded = true
		}
	}
	if err := s.sealNativeCapture(sealCtx); err != nil {
		return nil, err
	}
	return s.publishNativeCapture(ctx, buildID)
}

// Seal and persist captured inputs without publishing a generation. The first
// cold baseline can still be served by a legacy raw/NBD provider whose Close
// deletes its writable cache; retain that disk before allowing teardown.
func (s *Sandbox) sealNativeCapture(ctx context.Context) error {
	state := s.nativeCapture
	capture := state.capture
	// Close is serialized with this operation; exit waiters can stop the VM
	// but cannot close its raw NBD provider or backing mounts during capture.
	if err := s.process.Stop(ctx); err != nil {
		return err
	}
	select {
	case <-s.process.Exit.Done():
	case <-ctx.Done():
		return ctx.Err()
	}
	if !state.diskSealed {
		if state.v2Request != nil {
			provider := s.v2Runtime.upper
			if provider.privateDir != "" {
				path, err := provider.seal(ctx, state.request.DiskPath)
				if err != nil {
					return err
				}
				state.request.DiskPath = path
			} else if !state.baselineCopied {
				path, err := provider.Path()
				if err != nil {
					return err
				}
				if err := captureRawDisk(path, state.request.DiskPath, state.request.DiskSize); err != nil {
					return err
				}
				state.baselineCopied = true
			}
			state.syncV2Request()
		} else if state.request.ParentID != "" {
			provider, ok := s.rootfs.(*erofsRootfs)
			if !ok {
				return errors.New("incremental EROFS disk requires a qcow2 runtime")
			}
			path, err := provider.seal(ctx)
			if err != nil {
				return fmt.Errorf("seal native disk: %w", err)
			}
			state.request.DiskPath = path
		} else {
			if !state.baselineCopied {
				path, err := s.rootfs.Path()
				if err != nil {
					return err
				}
				output := filepath.Join(capture.Dir, "disk.full-"+uuid.NewString())
				if err := captureRawDisk(path, output, state.request.DiskSize); err != nil {
					return err
				}
				state.request.DiskPath = output
				state.baselineCopied = true
			}
			if provider, ok := s.rootfs.(*erofsRootfs); ok {
				if _, err := provider.seal(ctx); err != nil {
					return err
				}
			}
		}
		state.diskSealed = true
	}
	var requestData any = state.request
	if state.v2Request != nil {
		requestData = struct {
			Version int                   `json:"version"`
			Request *erofs.BuildV2Request `json:"request"`
		}{2, state.v2Request}
	}
	requestBytes, err := json.MarshalIndent(requestData, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNativeBuildRequest(filepath.Join(capture.Dir, "build-request.json"), requestBytes); err != nil {
		return err
	}
	for _, path := range []string{state.request.MetadataPath, filepath.Join(capture.Dir, "build-request.json"), capture.Dir, filepath.Dir(capture.Dir), state.store.Root} {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		if err := errors.Join(f.Sync(), f.Close()); err != nil {
			return err
		}
	}
	state.sealed = true
	return nil
}

func writeNativeBuildRequest(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".build-request-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return err
	}
	// The capture mutex serializes writers. Rename works both for the first
	// record and a retry; readers can only observe a complete descriptor.
	return os.Rename(f.Name(), path)
}

func (s *Sandbox) retainNativeCapture(ctx context.Context) error {
	state := s.nativeCapture
	if state == nil || !state.memoryCaptured || state.sealed || state.recoveryRecorded {
		return nil
	}
	for {
		if err := s.sealNativeCapture(ctx); err != nil {
			select {
			case <-ctx.Done():
				return errors.Join(err, ctx.Err())
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		return nil
	}
}

func (s *Sandbox) publishNativeCapture(ctx context.Context, id uuid.UUID) (*Snapshot, error) {
	state := s.nativeCapture
	if state.committed != nil {
		// Successful operation staging can be released at Close. A retry of
		// that same operation verifies its immutable committed output instead
		// of requiring those now-unneeded capture inputs to remain forever.
		snapshot, err := state.store.VerifyCommitted(ctx, id.String())
		if err != nil {
			return nil, fmt.Errorf("verify committed native capture: %w", err)
		}
		state.published = true
		return nativeSnapshot(snapshot, id), nil
	}
	var snapshot *erofs.Snapshot
	var err error
	if state.v2Request != nil {
		if state.recoveryRecorded {
			snapshot, err = state.store.Recover(ctx, filepath.Join(state.capture.Dir, "recovery.json"))
		} else {
			snapshot, err = state.store.PublishV2Request(ctx, *state.v2Request)
		}
	} else {
		snapshot, err = state.store.Build(ctx, state.request)
	}
	if snapshot != nil {
		state.committed = snapshot
	}
	if err != nil {
		return nil, fmt.Errorf("publish EROFS snapshot; retry retained request %s: %w", filepath.Join(state.capture.Dir, "build-request.json"), err)
	}
	state.published = true
	if state.v2Request != nil {
		state.sealed = true
		state.diskSealed = true
	}
	return nativeSnapshot(snapshot, id), nil
}

func (s *nativeCapture) syncV2Request() {
	if s.v2Request == nil {
		return
	}
	s.v2Request.MemoryPath = s.request.MemoryPath
	s.v2Request.VMStatePath = s.request.VMStatePath
	s.v2Request.MetadataPath = s.request.MetadataPath
	s.v2Request.UpperPath = s.request.DiskPath
}

func nativeSnapshot(snapshot *erofs.Snapshot, id uuid.UUID) *Snapshot {
	return &Snapshot{LocalEROFS: snapshot, BuildID: id}
}

func captureRawDisk(source, output string, size int64) error {
	if size <= 0 || size%erofs.BlockSize != 0 {
		return errors.New("invalid baseline disk size")
	}
	in, err := os.OpenFile(source, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := in.Sync(); err != nil {
		return err
	}
	out, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.CopyN(out, in, size)
	if err := errors.Join(copyErr, out.Sync(), out.Close()); err != nil {
		// The original provider is retained until a complete copy succeeds.
		// Discard only this incomplete output, so retry does not consume the
		// remaining staging space with a second partial full-disk copy.
		return errors.Join(err, os.Remove(output))
	}
	return nil
}
