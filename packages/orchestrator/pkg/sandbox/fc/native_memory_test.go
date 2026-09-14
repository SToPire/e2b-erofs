//go:build linux

package fc

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/e2b-dev/infra/packages/shared/pkg/fc/models"
)

func nativeAPIStub(t *testing.T, handler http.HandlerFunc) *apiClient {
	t.Helper()
	dir, err := os.MkdirTemp("", "fcn-") //nolint:usetesting // Keep the UNIX socket path below sun_path's limit.
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "api.sock")
	ln, err := new(net.ListenConfig).Listen(t.Context(), "unix", path)
	require.NoError(t, err)
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })

	return newApiClient(path)
}

func TestLoadFileSnapshotNativeDirtyTracking(t *testing.T) {
	t.Parallel()
	requests := make(chan map[string]any, 1)
	c := nativeAPIStub(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		requests <- body
		w.WriteHeader(http.StatusNoContent)
	})
	require.NoError(t, c.loadFileSnapshot(t.Context(), "/erofs/memory/memfile", "/snapshots/vmstate"))
	body := <-requests
	require.Equal(t, true, body["track_dirty_pages"])
	require.NotEqual(t, true, body["resume_vm"])
	require.Equal(t, map[string]any{
		"backend_type": "File", "backend_path": "/erofs/memory/memfile",
	}, body["mem_backend"])
}

func TestNativeSnapshotRetainsSparseZeroUpdates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	statePath, memoryPath := filepath.Join(dir, "state"), filepath.Join(dir, "memory")
	requests := make(chan models.SnapshotCreateParams, 1)
	c := nativeAPIStub(t, func(w http.ResponseWriter, r *http.Request) {
		var body models.SnapshotCreateParams
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)

			return
		}
		requests <- body
		f, err := os.OpenFile(body.MemFilePath, os.O_WRONLY, 0)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}
		defer f.Close()
		_ = f.Truncate(3 * nativePageSize)
		_, _ = f.WriteAt(make([]byte, nativePageSize), nativePageSize)
		_ = os.WriteFile(*body.SnapshotPath, []byte("vmstate"), 0o600)
		w.WriteHeader(http.StatusNoContent)
	})
	p := &Process{Versions: Config{NativeMemory: true}, client: c, nativeMemorySize: 3 * nativePageSize}
	require.NoError(t, p.CreateNativeSnapshot(t.Context(), statePath, memoryPath, NativeSnapshotDiff))
	body := <-requests
	require.Equal(t, "Diff", body.SnapshotType)
	require.Equal(t, memoryPath, body.MemFilePath)

	// A second export to the same path cannot destroy a captured generation.
	require.ErrorContains(t, p.CreateNativeSnapshot(t.Context(), statePath, memoryPath, NativeSnapshotDiff), "file exists")
	contents, err := os.ReadFile(memoryPath)
	require.NoError(t, err)
	require.Equal(t, make([]byte, 3*nativePageSize), contents)
	f, err := os.Open(memoryPath)
	require.NoError(t, err)
	defer f.Close()
	start, err := f.Seek(0, unix.SEEK_DATA)
	require.NoError(t, err)
	require.EqualValues(t, nativePageSize, start)
	end, err := f.Seek(start, unix.SEEK_HOLE)
	require.NoError(t, err)
	require.EqualValues(t, 2*nativePageSize, end)
}

func TestNativeSnapshotFailedRequestRetainsCapture(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	statePath, memoryPath := filepath.Join(dir, "state"), filepath.Join(dir, "memory")
	c := nativeAPIStub(t, func(w http.ResponseWriter, r *http.Request) {
		_ = os.WriteFile(statePath, []byte("partial state"), 0o600)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"fault_message":"memory export failed"}`))
	})
	p := &Process{Versions: Config{NativeMemory: true}, client: c}
	require.Error(t, p.CreateNativeSnapshot(t.Context(), statePath, memoryPath, NativeSnapshotDiff))
	require.FileExists(t, statePath)
	require.FileExists(t, memoryPath)
}

func TestNativeSnapshotDetectsIgnoredMemoryExport(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := nativeAPIStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	p := &Process{Versions: Config{NativeMemory: true}, client: c}
	require.ErrorContains(t, p.CreateNativeSnapshot(t.Context(), filepath.Join(dir, "state"), filepath.Join(dir, "memory"), NativeSnapshotFull), "invalid native memfile size")
}

func TestValidateNativeMemorySnapshotConfiguration(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name, hugepages string
		dirty, balloon  bool
		wantError       bool
	}{
		{"ordinary pages", "None", true, false, false},
		{"huge pages", "2M", true, false, true},
		{"no dirty tracking", "None", false, false, true},
		{"balloon", "None", true, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := nativeAPIStub(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/machine-config" {
					_ = json.NewEncoder(w).Encode(map[string]any{"huge_pages": tt.hugepages, "track_dirty_pages": tt.dirty})
				} else if tt.balloon {
					_, _ = w.Write([]byte(`{"amount_mib":0,"deflate_on_oom":false}`))
				} else {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"fault_message":"No balloon device"}`))
				}
			})
			err := c.validateNativeMemory(t.Context())
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateSparseStaging(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	require.NoError(t, ValidateSparseStaging(dir))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries)
	require.Error(t, ValidateSparseStaging(filepath.Join(dir, "missing")))
}
