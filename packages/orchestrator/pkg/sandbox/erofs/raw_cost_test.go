//go:build linux

package erofs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Run after workload measurement, in a private mount namespace, against an
// actual immutable checkpoint and its parent. Timings isolate the existing raw
// materialization/delta functions, including their syncs, from Store validation.
func TestRawUpperCost(t *testing.T) { //nolint:paralleltest // explicit host experiment
	if os.Getenv("E2B_RAW_COST") != "1" {
		t.Skip("set E2B_RAW_COST=1, E2B_RAW_COST_STORE/ID/OUT for a sealed v2 checkpoint")
	}
	require.Zero(t, os.Geteuid())
	_, err := os.Stat("/sys/module/nbd")
	require.ErrorIs(t, err, os.ErrNotExist)
	root, id, out := os.Getenv("E2B_RAW_COST_STORE"), os.Getenv("E2B_RAW_COST_ID"), os.Getenv("E2B_RAW_COST_OUT")
	require.NotEmpty(t, root)
	require.NotEmpty(t, id)
	require.NotEmpty(t, out)
	require.NoError(t, os.Mkdir(out, 0700), "output must not already exist")
	store, err := NewStore(root, Options{})
	require.NoError(t, err)
	started := time.Now()
	snapshot, err := store.LoadContext(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, FormatV2, snapshot.Manifest.Format)
	require.NotEmpty(t, snapshot.Manifest.ParentID)
	parent, err := store.LoadContext(t.Context(), snapshot.Manifest.ParentID)
	require.NoError(t, err)
	size := snapshot.Manifest.Upper.Size
	require.Equal(t, size, parent.Manifest.Upper.Size)
	mount := func(s *Snapshot) *Mounted {
		t.Helper()
		m, err := s.Mount(t.Context(), filepath.Join(out, "mounts"))
		if m != nil {
			t.Cleanup(func() { require.NoError(t, m.Close()) })
		}
		require.NoError(t, err)
		return m
	}
	previous, current := mount(parent), mount(snapshot)
	report := map[string]any{"id": id, "parent_id": parent.Manifest.ID, "upper_logical_bytes": size,
		"verification_mount_seconds": time.Since(started).Seconds(), "cache_policy": "no cache eviction; validation precedes timed operations"}
	for _, delta := range []bool{false, true} {
		name := "materialize"
		if delta {
			name = "delta"
		}
		path := filepath.Join(out, name+".raw")
		t.Cleanup(func() {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				require.NoError(t, err)
			}
		})
		started = time.Now()
		var stats RawCopyStats
		if delta {
			stats, err = CreateRawDelta(t.Context(), previous.DiskPath, current.DiskPath, path, size)
		} else {
			stats, err = MaterializeRawFile(t.Context(), current.DiskPath, path, size)
		}
		duration := time.Since(started).Seconds()
		require.NoError(t, err)
		require.Equal(t, snapshot.Manifest.UpperContentSHA256, stats.SourceSHA256)
		var st unix.Stat_t
		require.NoError(t, unix.Stat(path, &st))
		report[name] = map[string]any{"seconds": duration, "stats": stats, "allocated_bytes": st.Blocks * 512}
		require.NoError(t, os.Remove(path))
	}
	data, err := json.MarshalIndent(report, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(out, "report.json"), append(data, '\n'), 0600))
}
