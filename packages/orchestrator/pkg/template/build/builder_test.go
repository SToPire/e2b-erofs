//go:build linux

package build

import (
	"context"
	"math"
	"testing"

	"github.com/launchdarkly/go-server-sdk/v7/testhelpers/ldtestdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/build/config"
	"github.com/e2b-dev/infra/packages/shared/pkg/featureflags"
	templatemanager "github.com/e2b-dev/infra/packages/shared/pkg/grpc/template-manager"
)

func TestEROFSBuildConfigUsesOrdinaryMemoryAndFixedDiskReserve(t *testing.T) {
	t.Parallel()
	input := config.TemplateConfig{
		HugePages: true, FreePageReporting: true, FreePageHinting: true,
		DiskSizeMB: 1024, FreeDiskSizeMB: 2048,
	}
	actual := erofsBuildConfig(input)
	require.False(t, actual.HugePages)
	require.False(t, actual.FreePageReporting)
	require.False(t, actual.FreePageHinting)
	require.Equal(t, int64(2048), actual.DiskSizeMB)
	require.Equal(t, int64(2048), actual.FreeDiskSizeMB)
	require.True(t, input.HugePages)
}

func TestEROFSInitialDiskCapacityIncludesReservedBlocks(t *testing.T) {
	t.Parallel()
	input := config.TemplateConfig{DiskSizeMB: 512, FreeDiskSizeMB: 256}
	actual, err := erofsInitialDiskConfig(input, 256)
	require.NoError(t, err)
	require.Equal(t, int64(768), actual.DiskSizeMB)
	require.Equal(t, int64(256), actual.FreeDiskSizeMB)
	require.Equal(t, int64(512), input.DiskSizeMB, "the caller's working-space request is unchanged")
	for _, reserve := range []int64{0, -1} {
		actual, err = erofsInitialDiskConfig(input, reserve)
		require.NoError(t, err)
		require.Equal(t, input, actual)
	}
	input.FreeDiskSizeMB = 1024
	actual, err = erofsInitialDiskConfig(input, 256)
	require.NoError(t, err)
	require.Equal(t, int64(1280), actual.DiskSizeMB)
	input.FromTemplate = &templatemanager.FromTemplateConfig{BuildID: "existing"}
	actual, err = erofsInitialDiskConfig(input, 256)
	require.NoError(t, err)
	require.Equal(t, input, actual, "an existing EROFS template must never grow its captured disk")
}

func TestEROFSInitialDiskCapacityRejectsByteOverflow(t *testing.T) {
	t.Parallel()
	const maxMiB = math.MaxInt64 / (1024 * 1024)
	for _, input := range []config.TemplateConfig{
		{DiskSizeMB: maxMiB, FreeDiskSizeMB: 1},
		{DiskSizeMB: 1, FreeDiskSizeMB: maxMiB},
		{DiskSizeMB: math.MaxInt64},
		{DiskSizeMB: -1},
	} {
		_, err := erofsInitialDiskConfig(input, 256)
		require.Error(t, err)
	}
	_, err := erofsInitialDiskConfig(config.TemplateConfig{DiskSizeMB: 1}, math.MaxInt64)
	require.Error(t, err)
}

func newFlagClient(t *testing.T, source *ldtestdata.TestDataSource) *featureflags.Client {
	t.Helper()

	client, err := featureflags.NewClientWithDatasource(source)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(context.WithoutCancel(t.Context())))
	})

	return client
}

func TestResolveRootfsOptions(t *testing.T) {
	t.Parallel()

	cfg := config.TemplateConfig{TemplateID: "template-1", TeamID: "team-1"}
	flag := featureflags.BuildEnvdMemoryProtection

	t.Run("the flag's fallback leaves the protection off", func(t *testing.T) {
		t.Parallel()

		// A cluster with no flag data resolves to the fallback; that is the
		// state the whole fleet ships in, so it has to be off.
		assert.False(t, flag.Fallback())

		client := newFlagClient(t, ldtestdata.DataSource())
		assert.False(t, resolveRootfsOptions(t.Context(), client, cfg).EnvdMemoryProtection)
	})

	t.Run("the flag on turns the protection on", func(t *testing.T) {
		t.Parallel()

		source := ldtestdata.DataSource()
		source.Update(source.Flag(flag.Key()).BooleanFlag().VariationForAll(true))

		client := newFlagClient(t, source)
		assert.True(t, resolveRootfsOptions(t.Context(), client, cfg).EnvdMemoryProtection)
	})

	t.Run("the flag is evaluated on the build's team", func(t *testing.T) {
		t.Parallel()

		// The rollout is a percentage of teams, so a rule targeting this
		// build's team must reach the evaluation. Build also adds the team
		// context to ctx; this pins that the evaluation carries it on its own,
		// as the provision-version evaluation does, with a bare ctx.
		source := ldtestdata.DataSource()
		source.Update(source.Flag(flag.Key()).BooleanFlag().
			VariationForAll(false).
			VariationForKey(featureflags.TeamKind, cfg.TeamID, true))

		client := newFlagClient(t, source)
		assert.True(t, resolveRootfsOptions(t.Context(), client, cfg).EnvdMemoryProtection)

		other := cfg
		other.TeamID = "team-2"
		assert.False(t, resolveRootfsOptions(t.Context(), client, other).EnvdMemoryProtection)
	})
}
