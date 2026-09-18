//go:build linux

package cfg

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEROFSPathsDisabledPreservesLegacyConfiguration(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	alias := filepath.Join(root, "sandbox-alias")
	require.NoError(t, os.Symlink(filepath.Join(root, "not-created"), alias))
	c := BuilderConfig{DefaultCacheDir: "relative-build-cache", SandboxDir: alias}
	require.NoError(t, makePathsAbsolute(&c))
	require.Empty(t, c.EROFSSnapshotDir)
	require.False(t, c.EROFSNativeMemoryVerified)
	expected, err := filepath.Abs("relative-build-cache")
	require.NoError(t, err)
	require.Equal(t, expected, c.DefaultCacheDir)
	// Disabling EROFS must not canonicalize or reject legacy namespace paths.
	require.Equal(t, alias, c.SandboxDir)
}

func TestEROFSPathsRequireExplicitNativeVerification(t *testing.T) {
	t.Parallel()
	c := BuilderConfig{EROFSSnapshotDir: filepath.Join(t.TempDir(), "snapshots")}
	require.ErrorContains(t, makePathsAbsolute(&c), "EROFS_NATIVE_MEMORY_VERIFIED")
}

func TestEROFSNativeOnlyRequiresVerifiedPmemStore(t *testing.T) {
	t.Parallel()
	for _, config := range []BuilderConfig{
		{EROFSNativeOnly: true},
		{EROFSNativeOnly: true, EROFSSnapshotDir: t.TempDir()},
		{EROFSNativeOnly: true, EROFSSnapshotDir: t.TempDir(), EROFSNativeMemoryVerified: true},
	} {
		require.ErrorContains(t, makePathsAbsolute(&config), "EROFS_NATIVE_ONLY")
	}
	config := BuilderConfig{EROFSNativeOnly: true, EROFSSnapshotDir: t.TempDir(), EROFSNativeMemoryVerified: true, EROFSPmemVerified: true}
	require.NoError(t, makePathsAbsolute(&config))
}

func TestEROFSPathsRejectDisposableAndNamespaceDirectories(t *testing.T) {
	t.Parallel()
	for name, set := range erofsExcludedDirectories() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			disposable := filepath.Join(root, "disposable")
			for _, suffix := range []string{"", "new/snapshots"} {
				c := BuilderConfig{
					EROFSSnapshotDir:          filepath.Join(disposable, suffix),
					EROFSNativeMemoryVerified: true,
				}
				set(&c, disposable)
				require.ErrorContains(t, makePathsAbsolute(&c), "must be outside", "suffix %q", suffix)
			}
		})
	}
}

func TestEROFSPathsRejectSymlinkAliasesWithMissingLeaf(t *testing.T) {
	t.Parallel()
	for name, set := range erofsExcludedDirectories() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			disposable := filepath.Join(root, "disposable")
			require.NoError(t, os.Mkdir(disposable, 0o700))
			alias := filepath.Join(root, "alias")
			require.NoError(t, os.Symlink(disposable, alias))
			c := BuilderConfig{
				EROFSSnapshotDir:          filepath.Join(alias, "not-created", "snapshots"),
				EROFSNativeMemoryVerified: true,
			}
			set(&c, disposable)
			require.ErrorContains(t, makePathsAbsolute(&c), "must be outside")

			// Aliasing the excluded directory rather than the store is equally
			// important: comparison must canonicalize both sides.
			c.EROFSSnapshotDir = filepath.Join(disposable, "snapshots")
			set(&c, alias)
			require.ErrorContains(t, makePathsAbsolute(&c), "must be outside")
		})
	}
}

func TestEROFSPathsRejectDanglingSymlinkIntoExcludedDirectory(t *testing.T) {
	t.Parallel()
	for name, set := range erofsExcludedDirectories() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			disposable := filepath.Join(root, "disposable")
			require.NoError(t, os.Mkdir(disposable, 0o700))
			alias := filepath.Join(root, "alias")
			// The link already exists but its destination is created only when
			// the snapshot store is initialized later during startup.
			require.NoError(t, os.Symlink(filepath.Join(disposable, "new"), alias))
			c := BuilderConfig{
				EROFSSnapshotDir:          filepath.Join(alias, "snapshots"),
				EROFSNativeMemoryVerified: true,
			}
			set(&c, disposable)
			require.ErrorContains(t, makePathsAbsolute(&c), "dangling symlink")
		})
	}
}

func TestEROFSPathsRejectDanglingSymlinkAsConfiguredDirectory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	alias := filepath.Join(root, "alias")
	require.NoError(t, os.Symlink("not-created", alias))
	c := BuilderConfig{EROFSSnapshotDir: alias, EROFSNativeMemoryVerified: true}
	require.ErrorContains(t, makePathsAbsolute(&c), "dangling symlink")

	// Both the store path and excluded-directory paths must be resolvable.
	c.EROFSSnapshotDir = filepath.Join(root, "snapshots")
	c.SandboxDir = alias
	require.ErrorContains(t, makePathsAbsolute(&c), "dangling symlink")
}

func TestEROFSPathsCanonicalizePersistentSiblingWithoutCreatingIt(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	persistent := filepath.Join(root, "persistent")
	require.NoError(t, os.Mkdir(persistent, 0o700))
	alias := filepath.Join(root, "alias")
	require.NoError(t, os.Symlink(persistent, alias))
	c := BuilderConfig{
		EROFSSnapshotDir:          filepath.Join(alias, "new", "snapshots"),
		EROFSNativeMemoryVerified: true,
	}
	for name, set := range erofsExcludedDirectories() {
		set(&c, filepath.Join(root, name))
	}
	require.NoError(t, makePathsAbsolute(&c))
	require.Equal(t, filepath.Join(persistent, "new", "snapshots"), c.EROFSSnapshotDir)
	_, err := os.Stat(c.EROFSSnapshotDir)
	require.ErrorIs(t, err, os.ErrNotExist)

	// A sibling with a common string prefix must not be classified as nested.
	c.EROFSSnapshotDir = c.SandboxDir + "-persistent"
	require.NoError(t, makePathsAbsolute(&c))
}

func erofsExcludedDirectories() map[string]func(*BuilderConfig, string) {
	return map[string]func(*BuilderConfig, string){
		"build-cache":       func(c *BuilderConfig, path string) { c.DefaultCacheDir = path },
		"sandbox-cache":     func(c *BuilderConfig, path string) { c.StorageConfig.SandboxCacheDir = path },
		"template-cache":    func(c *BuilderConfig, path string) { c.StorageConfig.TemplateCacheDir = path },
		"build-templates":   func(c *BuilderConfig, path string) { c.TemplatesDir = path },
		"sandbox-namespace": func(c *BuilderConfig, path string) { c.SandboxDir = path },
	}
}
