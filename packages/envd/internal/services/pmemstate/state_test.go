//go:build linux

package pmemstate

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func testController(t *testing.T, dir, upper string) *Controller {
	t.Helper()
	d, err := os.Open(dir)
	require.NoError(t, err)
	u, err := os.Open(upper)
	require.NoError(t, err)
	c, err := openController(d, u)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	return c
}

func TestResumeJournalSurvivesReopenAndPreservesThawGate(t *testing.T) {
	dir, upper := t.TempDir(), t.TempDir()
	c := testController(t, dir, upper)
	already, err := c.BeginPrepare("life-one")
	require.NoError(t, err)
	require.False(t, already)
	require.False(t, c.CanThaw())
	require.NoError(t, c.SetFrozen(true))
	require.Error(t, c.Prepared("life-one"))
	require.NoError(t, c.SetFrozen(false))
	require.NoError(t, c.Prepared("life-one"))
	require.NoError(t, c.Close())
	c = testController(t, dir, upper)
	require.Equal(t, "prepared", c.Snapshot().Phase)
	require.False(t, c.CanThaw())
	thaws := 0
	require.Error(t, c.Commit("stale-life", func() error { thaws++; return nil }))
	require.Zero(t, thaws)
	require.NoError(t, c.Commit("life-one", func() error { require.True(t, c.CanThaw()); thaws++; return nil }))
	require.True(t, c.Ready())
	require.NoError(t, c.Commit("life-one", func() error { thaws++; return nil }))
	require.Equal(t, 1, thaws)
	already, err = c.BeginPrepare("life-one")
	require.NoError(t, err)
	require.True(t, already)
	require.NoError(t, c.SetFrozen(true))
	require.False(t, c.CanThaw())
	already, err = c.BeginPrepare("life-two")
	require.NoError(t, err)
	require.False(t, already)
	require.True(t, c.Snapshot().Frozen)
	require.False(t, c.Ready())
}

func TestFailedCommitAndUpgradeCannotReleaseWorkloads(t *testing.T) {
	dir, upper := t.TempDir(), t.TempDir()
	c := testController(t, dir, upper)
	_, err := c.BeginPrepare("life")
	require.NoError(t, err)
	require.NoError(t, c.Prepared("life"))
	require.Error(t, c.Commit("life", func() error { return errors.New("thaw failed") }))
	require.False(t, c.CanThaw())
	require.False(t, c.Ready())
	require.NoError(t, c.Commit("life", func() error { return nil }))
	rollback, err := c.HoldUpgrade()
	require.NoError(t, err)
	require.False(t, c.CanThaw())
	require.NoError(t, rollback())
	require.True(t, c.Ready())
	_, err = c.HoldUpgrade()
	require.NoError(t, err)
	require.NoError(t, c.Close())
	incoming := testController(t, dir, upper)
	require.False(t, incoming.CanThaw(), "execve must retain the prepared hold")
	require.Equal(t, "life", incoming.Snapshot().LifecycleID)
}
