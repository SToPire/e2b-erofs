//go:build linux

package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCheckpointVerificationSurvivesPollingDeadline(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	id := uuid.NewString()
	dir := filepath.Join(root, id)
	require.NoError(t, os.Mkdir(dir, 0700))
	artifact := func(name string, data []byte) erofs.Artifact {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, data, 0400))
		return erofs.Artifact{File: filepath.Join(id, name), Bytes: int64(len(data)), SHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
	}
	m := erofs.Manifest{Format: erofs.Format, ID: id, Memory: erofs.Image{Artifact: artifact("memory.erofs", make([]byte, 8<<20)), Size: 4096},
		Disk: erofs.Image{Artifact: artifact("disk.erofs", []byte("disk")), Size: 4096}, VMState: artifact("vmstate", []byte("vm"))}
	data, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, erofs.ManifestName), data, 0400))
	store, err := erofs.NewStore(root, erofs.Options{})
	require.NoError(t, err)
	server := &Server{done: make(chan struct{})}
	defer close(server.done)
	short, cancel := context.WithTimeout(t.Context(), time.Nanosecond)
	defer cancel()
	_, _, pending := server.verifyNativeCheckpointStatus(short, store, id)
	require.True(t, pending)
	require.Eventually(t, func() bool {
		snapshot, e, wait := server.verifyNativeCheckpointStatus(t.Context(), store, id)
		if wait {
			return false
		}
		require.NoError(t, e)
		return snapshot != nil
	}, 3*time.Second, 10*time.Millisecond)
	path := filepath.Join(dir, "disk.erofs")
	require.NoError(t, os.Chmod(path, 0600))
	require.NoError(t, os.WriteFile(path, []byte("bad!"), 0600))
	snapshot, e, wait := server.verifyNativeCheckpointStatus(t.Context(), store, id)
	require.Nil(t, snapshot)
	require.NoError(t, e)
	require.True(t, wait, "changed cached proof must not be returned valid")
	require.Eventually(t, func() bool {
		snapshot, e, wait := server.verifyNativeCheckpointStatus(t.Context(), store, id)
		if wait {
			return false
		}
		require.Nil(t, snapshot)
		return e != nil
	}, 3*time.Second, 10*time.Millisecond)
}

func TestCheckpointVerificationKeepsUnobservedResults(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := erofs.NewStore(root, erofs.Options{})
	require.NoError(t, err)
	server := &Server{done: make(chan struct{})}
	defer close(server.done)
	server.nativeVerifications.entries = make(map[string]*checkpointVerification)
	for i := 0; i < checkpointVerificationLimit; i++ {
		done := make(chan struct{})
		close(done)
		server.nativeVerifications.entries[fmt.Sprint(i)] = &checkpointVerification{done: done, started: time.Now(), finished: time.Now()}
	}
	_, _, pending := server.verifyNativeCheckpointStatus(t.Context(), store, "new")
	require.True(t, pending)
	require.Len(t, server.nativeVerifications.entries, checkpointVerificationLimit)
	require.NotContains(t, server.nativeVerifications.entries, filepath.Join(root, "new"))
	server.nativeVerifications.entries["0"].observed = true
	_, _, pending = server.verifyNativeCheckpointStatus(t.Context(), store, "new")
	require.True(t, pending)
	require.Contains(t, server.nativeVerifications.entries, filepath.Join(root, "new"))
	require.NotContains(t, server.nativeVerifications.entries, "0")
}
