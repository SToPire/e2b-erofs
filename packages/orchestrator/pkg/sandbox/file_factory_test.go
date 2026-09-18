//go:build linux

package sandbox

import (
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/cfg"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestFileFactoryHasNoLegacyRootfsCapability(t *testing.T) {
	t.Parallel()
	config := cfg.BuilderConfig{EROFSSnapshotDir: t.TempDir(), EROFSNativeMemoryVerified: true, EROFSPmemVerified: true}
	factory, err := NewFileFactory(t.Context(), config, nil, nil, nil, nil, nil, nil, NewSandboxesMap())
	require.NoError(t, err)
	require.True(t, factory.config.EROFSNativeOnly)
	require.Nil(t, factory.legacyRootfs)
	_, err = factory.legacyDevices()
	require.ErrorContains(t, err, "disabled")
	require.NoError(t, factory.CloseSharedMounts(t.Context()))
	config.EROFSPmemVerified = false
	_, err = NewFileFactory(t.Context(), config, nil, nil, nil, nil, nil, nil, NewSandboxesMap())
	require.Error(t, err)
}
