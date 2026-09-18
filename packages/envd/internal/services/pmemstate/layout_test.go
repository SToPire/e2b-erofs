//go:build linux

package pmemstate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestLegacyMetadataFileDoesNotSelectPmem(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".e2b"), []byte("BUILD_ID=example\n"), 0644))
	c, err := openLayout(filepath.Join(dir, ".e2b/rootfs"), true)
	require.NoError(t, err)
	require.Nil(t, c)
	// A malformed new dedicated mount directory still fails closed.
	c, err = openLayout(filepath.Join(dir, ".e2b/rootfs"), false)
	require.ErrorIs(t, err, unix.ENOTDIR)
	require.Nil(t, c)
}
