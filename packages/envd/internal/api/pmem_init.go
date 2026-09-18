package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/awnumar/memguard"
	"github.com/e2b-dev/infra/packages/envd/internal/host"
	"github.com/e2b-dev/infra/packages/envd/internal/services/cgroups"
	"github.com/e2b-dev/infra/packages/envd/internal/services/pmemstate"
	"github.com/e2b-dev/infra/packages/shared/pkg/keys"
)

type resumeMMDSClient interface {
	GetResumeMetadata(context.Context) (*host.MMDSOpts, error)
}

func (a *API) validatePmemControl(r *http.Request) error {
	client, ok := a.mmdsClient.(resumeMMDSClient)
	if !ok || a.isNotFC || !a.Authenticated() {
		return ErrAccessTokenMismatch
	}
	m, err := client.GetResumeMetadata(r.Context())
	if err != nil {
		return err
	}
	s := a.pmem.Snapshot()
	if m == nil || m.RootfsLayout != pmemstate.Layout || m.LifecycleID == "" || m.LifecycleID != s.LifecycleID || m.AccessTokenHash != keys.HashAccessToken(r.Header.Get(accessTokenHeader)) {
		return ErrAccessTokenMismatch
	}
	return nil
}

// Called with initLock held. Unlike legacy init, a cached old token can never
// authorize a new lifecycle: all phased requests use one current MMDS view.
func (a *API) validatePmemInit(ctx context.Context, request *PostInitJSONBody) (string, error) {
	if a.pmem == nil || request.ResumePhase == nil || request.LifecycleID == nil || *request.LifecycleID == "" || a.isNotFC {
		return "", errors.New("pmem resume requires a phase, lifecycle and verified rootfs")
	}
	client, ok := a.mmdsClient.(resumeMMDSClient)
	if !ok {
		return "", errors.New("MMDS resume identity is unavailable")
	}
	metadata, err := client.GetResumeMetadata(ctx)
	if err != nil {
		return "", err
	}
	if metadata == nil || metadata.RootfsLayout != pmemstate.Layout || metadata.LifecycleID != *request.LifecycleID || metadata.AccessTokenHash == "" {
		return "", ErrAccessTokenMismatch
	}
	hash := keys.HashAccessToken("")
	if request.AccessToken.IsSet() {
		data, err := request.AccessToken.Bytes()
		if err != nil {
			return "", err
		}
		hash = keys.HashAccessTokenBytes(data)
		memguard.WipeBytes(data)
	}
	if hash != metadata.AccessTokenHash {
		return "", ErrAccessTokenMismatch
	}
	return metadata.LifecycleID, nil
}

func (a *API) postPmemInit(w http.ResponseWriter, r *http.Request, request *PostInitJSONBody) {
	ctx := r.Context()
	lifecycle, err := a.validatePmemInit(ctx, request)
	if err != nil {
		jsonError(w, http.StatusForbidden, err)
		return
	}
	phase := string(*request.ResumePhase)
	w.Header().Set("X-Envd-Rootfs-Layout", pmemstate.Layout)
	w.Header().Set("X-Envd-Resume-Phase", phase)
	switch phase {
	case "prepare":
		already, err := a.pmem.BeginPrepare(lifecycle)
		if err != nil {
			jsonError(w, http.StatusConflict, err)
			return
		}
		a.initialized.Store(false)
		a.adoptInitToken(request.AccessToken)
		if !already {
			if err := a.thawPmemUpper(ctx); err != nil {
				jsonError(w, http.StatusInternalServerError, err)
				return
			}
		}
		if err := a.setData(ctx, *a.logger, *request, false); err != nil {
			jsonError(w, http.StatusInternalServerError, err)
			return
		}
		if !already {
			if err := a.pmem.Prepared(lifecycle); err != nil {
				jsonError(w, http.StatusInternalServerError, err)
				return
			}
		}
		a.initialized.Store(true)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			host.PollForMMDSOpts(ctx, a.mmdsChan, a.defaults.EnvVars)
		}()
	case "commit":
		if !a.Authenticated() || (a.handover != nil && a.handover.Failed) {
			jsonError(w, http.StatusConflict, errors.New("envd preparation or handover is incomplete"))
			return
		}
		if err := a.pmem.Commit(lifecycle, func() error {
			result, err := a.workloadFreezer.UnfreezeReporting(ctx, cgroups.DefaultThawMaxCgroups)
			if err != nil {
				return err
			}
			if result.Failed != 0 || result.Truncated {
				return errors.New("workload thaw was incomplete")
			}
			return nil
		}); err != nil {
			jsonError(w, http.StatusConflict, err)
			return
		}
	default:
		jsonError(w, http.StatusBadRequest, errors.New("unknown resume phase"))
		return
	}
	a.reportEffectiveDefaults(w, *a.logger)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) thawPmemUpper(ctx context.Context) error {
	if err := a.fsFreezeLock.Acquire(ctx, 1); err != nil {
		return err
	}
	defer a.fsFreezeLock.Release(1)
	if err := a.fsFreezer.Thaw(a.pmem.Mountpoint()); err != nil {
		return err
	}
	return a.pmem.SetFrozen(false)
}

// HoldPmemUpgrade keeps init/commit from racing execve and persists the hold on
// tmpfs. The new envd opens the same state before adopting/thawing workloads.
func (a *API) HoldPmemUpgrade(ctx context.Context) (func(), error) {
	if a.pmem == nil {
		return func() {}, nil
	}
	if err := a.initLock.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	rollback, err := a.pmem.HoldUpgrade()
	if err != nil {
		a.initLock.Release(1)
		return nil, err
	}
	return func() {
		if err := rollback(); err != nil {
			a.logger.Error().Err(err).Msg("restore rootfs resume state after failed upgrade")
		}
		a.initLock.Release(1)
	}, nil
}
