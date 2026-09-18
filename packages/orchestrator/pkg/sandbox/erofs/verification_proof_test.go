//go:build linux

package erofs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestV2DirectorySyncFailureRetainsCommittedSnapshot(t *testing.T) {
	store, request := v2Fixture(t)
	snapshot, err := store.BuildV2(t.Context(), request)
	require.NoError(t, err)
	before, err := os.ReadFile(filepath.Join(snapshot.Dir, ManifestName))
	require.NoError(t, err)
	observed, err := store.verifyCommitted(t.Context(), request.ID, func(string) error { return unix.EIO })
	require.True(t, errors.Is(err, unix.EIO))
	require.NotNil(t, observed, "a directory durability error does not discard verified content")
	require.Equal(t, FormatV2, observed.Manifest.Format)
	require.Equal(t, snapshot.Manifest, observed.Manifest)
	confirmed, err := store.VerifyCommitted(t.Context(), request.ID)
	require.NoError(t, err)
	require.Equal(t, snapshot.Manifest, confirmed.Manifest)
	after, err := os.ReadFile(filepath.Join(snapshot.Dir, ManifestName))
	require.NoError(t, err)
	require.Equal(t, before, after, "sync retry must not rewrite the committed generation")
}

func TestVerificationProofRejectsArtifactAndMetadataChanges(t *testing.T) {
	for _, which := range []string{"artifact", "manifest", "lower_manifest"} {
		t.Run(which, func(t *testing.T) {
			store, request := v2Fixture(t)
			lower := makeLowerFixture(t, store)
			initPath := filepath.Join(t.TempDir(), "initramfs")
			require.NoError(t, os.WriteFile(initPath, []byte("boot"), 0600))
			initrd, err := store.ImportInitramfs(t.Context(), initPath)
			require.NoError(t, err)
			request.Boot.Layout = LayoutPmem
			request.Boot.Initramfs = initrd
			request.Lower = lower
			snapshot, err := store.BuildV2(t.Context(), request)
			require.NoError(t, err)
			proof, err := store.VerifyWithProof(t.Context(), snapshot.Manifest.ID)
			require.NoError(t, err)
			got, err := proof.Recheck(t.Context())
			require.NoError(t, err)
			require.Equal(t, snapshot.Manifest.ID, got.Manifest.ID)
			path := filepath.Join(store.Root, snapshot.Manifest.Memory.File)
			if which == "manifest" {
				path = filepath.Join(snapshot.Dir, ManifestName)
			}
			if which == "lower_manifest" {
				path = filepath.Join(store.Root, "lowers", lower.ID, ManifestName)
			}
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NoError(t, os.Chmod(path, 0600))
			data[len(data)-1] ^= 1
			require.NoError(t, os.WriteFile(path, data, 0600))
			got, err = proof.Recheck(t.Context())
			require.Error(t, err)
			require.Nil(t, got)
		})
	}
}

func TestVerificationMemoRejectsMutationWithinTraversal(t *testing.T) {
	store, request := v2Fixture(t)
	snapshot, err := store.BuildV2(t.Context(), request)
	require.NoError(t, err)
	ctx := withVerification(t.Context())
	artifact := snapshot.Manifest.Memory.Artifact
	require.NoError(t, store.verifyArtifact(ctx, artifact))
	require.NoError(t, store.verifyArtifact(ctx, artifact))
	path := filepath.Join(store.Root, artifact.File)
	require.NoError(t, os.Chmod(path, 0600))
	require.ErrorContains(t, store.verifyArtifact(ctx, artifact), "changed during verification")
}
