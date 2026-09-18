package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/e2b-dev/infra/packages/envd/internal/logs"
)

// rootfsMountpoint is the guest root filesystem — the only persisted filesystem
// in a filesystem-only snapshot.
const rootfsMountpoint = "/"

// PostFsfreeze freezes the guest rootfs (FIFREEZE) so it is flushed to a
// consistent on-disk state before a filesystem-only pause. This closes the
// sync->pause race: without a memory snapshot, a write acknowledged after the
// pre-pause sync but before the VM pause would otherwise be lost on the reboot
// resume. Idempotent: freezing an already-frozen filesystem is a no-op. On a
// successful filesystem-only pause the VM is rebooted, so no thaw is needed; the
// orchestrator thaws (PostFsthaw) only on the pause-failure rollback path.
func (a *API) PostFsfreeze(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	logger := a.logger.With().Str(string(logs.OperationIDKey), logs.AssignOperationID()).Logger()
	if a.pmem != nil {
		if err := a.initLock.Acquire(r.Context(), 1); err != nil {
			jsonError(w, http.StatusServiceUnavailable, err)
			return
		}
		defer a.initLock.Release(1)
		if a.pmem.Snapshot().Phase != "committed" {
			jsonError(w, http.StatusConflict, errors.New("resume must commit before a new freeze"))
			return
		}
	}

	if err := a.fsFreezeLock.Acquire(r.Context(), 1); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}
	defer a.fsFreezeLock.Release(1)

	target := rootfsMountpoint
	if a.pmem != nil {
		target = a.pmem.Mountpoint()
		if err := a.pmem.SetFrozen(true); err != nil {
			jsonError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if err := a.fsFreezer.Freeze(target); err != nil {
		if a.pmem != nil {
			if thawErr := a.fsFreezer.Thaw(target); thawErr == nil {
				err = errors.Join(err, a.pmem.SetFrozen(false))
			} else {
				err = errors.Join(err, thawErr)
			}
		}
		logger.Error().Err(err).Msg("freeze rootfs")
		jsonError(w, http.StatusInternalServerError, err)

		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// PostFsthaw thaws the guest rootfs (FITHAW). Exists ONLY for the orchestrator's
// pause-failure rollback path, so a frozen filesystem cannot leave the live VM
// deadlocked. Idempotent: thawing a filesystem that is not frozen is a no-op.
func (a *API) PostFsthaw(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	ctx := r.Context()
	if a.pmem != nil {
		if err := a.initLock.Acquire(context.WithoutCancel(ctx), 1); err != nil {
			jsonError(w, http.StatusServiceUnavailable, err)
			return
		}
		defer a.initLock.Release(1)
		if err := a.thawPmemUpper(context.WithoutCancel(ctx)); err != nil {
			jsonError(w, http.StatusInternalServerError, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	logger := a.logger.With().Str(string(logs.OperationIDKey), logs.AssignOperationID()).Logger()

	// Acquire with WithoutCancel so a cancelled HTTP client can't abandon the
	// thaw and leave the live VM's filesystem frozen.
	if err := a.fsFreezeLock.Acquire(context.WithoutCancel(ctx), 1); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}
	defer a.fsFreezeLock.Release(1)

	if err := a.fsFreezer.Thaw(rootfsMountpoint); err != nil {
		logger.Error().Err(err).Msg("thaw rootfs")
		jsonError(w, http.StatusInternalServerError, err)

		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
