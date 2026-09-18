package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/e2b-dev/infra/packages/envd/internal/host"
	"github.com/e2b-dev/infra/packages/envd/internal/services/pmemstate"
	"github.com/e2b-dev/infra/packages/shared/pkg/keys"
	"github.com/stretchr/testify/require"
)

type phaseController struct {
	state pmemstate.State
	thaws int
}

func (p *phaseController) Snapshot() pmemstate.State { return p.state }
func (p *phaseController) Ready() bool               { return p.state.Phase == "committed" && !p.state.Frozen }
func (*phaseController) Mountpoint() string          { return "/pinned-upper" }
func (p *phaseController) BeginPrepare(id string) (bool, error) {
	if p.state.LifecycleID == id && p.Ready() {
		return true, nil
	}
	p.state.LifecycleID = id
	p.state.Phase = "preparing"
	return false, nil
}
func (p *phaseController) Prepared(id string) error {
	if p.state.LifecycleID != id || p.state.Frozen {
		return errors.New("bad state")
	}
	p.state.Phase = "prepared"
	return nil
}
func (p *phaseController) SetFrozen(value bool) error { p.state.Frozen = value; return nil }
func (p *phaseController) Commit(id string, thaw func() error) error {
	if p.state.LifecycleID != id || p.state.Frozen {
		return errors.New("bad state")
	}
	if p.Ready() {
		return nil
	}
	if p.state.Phase != "prepared" {
		return errors.New("not prepared")
	}
	if err := thaw(); err != nil {
		return err
	}
	p.thaws++
	p.state.Phase = "committed"
	return nil
}
func (p *phaseController) HoldUpgrade() (func() error, error) {
	old := p.state
	p.state.Phase = "prepared"
	return func() error { p.state = old; return nil }, nil
}

type phaseMMDS struct{ metadata host.MMDSOpts }

func (p *phaseMMDS) GetAccessTokenHash(context.Context) (string, error) {
	return p.metadata.AccessTokenHash, nil
}
func (p *phaseMMDS) GetResumeMetadata(context.Context) (*host.MMDSOpts, error) {
	m := p.metadata
	return &m, nil
}

type orderedFreezer struct{ thaw func(string) error }

func (orderedFreezer) Freeze(string) error      { return nil }
func (f orderedFreezer) Thaw(path string) error { return f.thaw(path) }

func phaseRequest(t *testing.T, a *API, life, phase, token string) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(map[string]any{"lifecycleID": life, "resumePhase": phase, "accessToken": token, "envVars": map[string]string{"test": "new"}})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/init", bytes.NewReader(data))
	w := httptest.NewRecorder()
	a.PostInit(w, r)
	return w
}

func TestPmemInitRejectsCachedTokenAndStaleLifecycle(t *testing.T) {
	a := newAPIWithFreezer(&fakeFreezer{})
	a.isNotFC = false
	a.accessToken.Set([]byte("old-token"))
	a.initialized.Store(true)
	c := &phaseController{state: pmemstate.State{LifecycleID: "old-life", Phase: "committed", Frozen: true}}
	a.pmem = c
	a.mmdsClient = &phaseMMDS{metadata: host.MMDSOpts{LifecycleID: "new-life", RootfsLayout: pmemstate.Layout, AccessTokenHash: keys.HashAccessToken("new-token")}}
	for _, pair := range [][2]string{{"new-life", "old-token"}, {"old-life", "new-token"}} {
		w := phaseRequest(t, a, pair[0], "prepare", pair[1])
		require.Equal(t, http.StatusForbidden, w.Code)
	}
	require.Equal(t, "old-life", c.state.LifecycleID)
	require.True(t, c.state.Frozen)
	w := phaseRequest(t, a, "new-life", "commit", "new-token")
	require.Equal(t, http.StatusConflict, w.Code)
}

func TestPmemPrepareThawsUpperAfterAuthAndCommitIsIdempotent(t *testing.T) {
	a := newAPIWithFreezer(&fakeFreezer{})
	a.isNotFC = false
	c := &phaseController{state: pmemstate.State{LifecycleID: "old", Phase: "committed", Frozen: true}}
	a.pmem = c
	a.mmdsClient = &phaseMMDS{metadata: host.MMDSOpts{LifecycleID: "new", RootfsLayout: pmemstate.Layout, AccessTokenHash: keys.HashAccessToken("token")}}
	upperThaws := 0
	a.fsFreezer = orderedFreezer{thaw: func(path string) error {
		require.Equal(t, "/pinned-upper", path)
		require.True(t, a.accessToken.Equals("token"))
		require.False(t, a.Authenticated())
		require.Equal(t, "preparing", c.state.Phase)
		upperThaws++
		return nil
	}}
	w := phaseRequest(t, a, "new", "prepare", "token")
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	require.True(t, a.Authenticated())
	require.False(t, a.Initialized())
	require.Equal(t, 1, upperThaws)
	w = phaseRequest(t, a, "new", "commit", "token")
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	require.True(t, a.Initialized())
	w = phaseRequest(t, a, "new", "prepare", "token")
	require.Equal(t, http.StatusNoContent, w.Code)
	w = phaseRequest(t, a, "new", "commit", "token")
	require.Equal(t, http.StatusNoContent, w.Code)
	require.Equal(t, 1, upperThaws)
	require.Equal(t, 1, c.thaws)
}

func TestPmemControlRejectsPreviousLifecycle(t *testing.T) {
	a := newAPIWithFreezer(&fakeFreezer{})
	a.isNotFC = false
	a.accessToken.Set([]byte("old-token"))
	a.initialized.Store(true)
	c := &phaseController{state: pmemstate.State{LifecycleID: "old-life", Phase: "committed", Frozen: true}}
	a.pmem = c
	m := &phaseMMDS{metadata: host.MMDSOpts{LifecycleID: "new-life", RootfsLayout: pmemstate.Layout, AccessTokenHash: keys.HashAccessToken("new-token")}}
	a.mmdsClient = m
	for _, path := range []string{"/fsthaw", "/unfreeze", "/upgrade", "/fsfreeze", "/freeze"} {
		called := false
		h := a.WithAuthorization(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusNoContent) }))
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set(accessTokenHeader, "old-token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		require.Equal(t, http.StatusForbidden, w.Code, path)
		require.False(t, called)
		require.True(t, c.state.Frozen)
		require.False(t, a.Initialized())
	}
	// Even a reused token must not authorize the old lifecycle's thaw.
	m.metadata.AccessTokenHash = keys.HashAccessToken("old-token")
	req := httptest.NewRequest(http.MethodPost, "/fsthaw", nil)
	req.Header.Set(accessTokenHeader, "old-token")
	w := httptest.NewRecorder()
	a.WithAuthorization(http.HandlerFunc(a.PostFsthaw)).ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.True(t, c.state.Frozen)
	// A rollback in the same lifecycle is still allowed and reopens readiness.
	m.metadata.LifecycleID = "old-life"
	thaws := 0
	a.fsFreezer = orderedFreezer{thaw: func(string) error { thaws++; return nil }}
	w = httptest.NewRecorder()
	a.WithAuthorization(http.HandlerFunc(a.PostFsthaw)).ServeHTTP(w, req)
	require.Equal(t, http.StatusNoContent, w.Code)
	require.Equal(t, 1, thaws)
	require.True(t, a.Initialized())
}
