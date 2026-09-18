//go:build linux

package sandbox

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAgentMappingPermissionsRemainDistinct(t *testing.T) {
	t.Parallel()
	pmem := "1000-3000 r--s 00000000 00:42 123 /run/e2b-devices/lower.ext4\nRss: 8 kB\nPss: 4 kB\nShared_Clean: 8 kB\nPrivate_Dirty: 0 kB\n"
	value, err := sharedBenchFileSmaps(pmem, "0:42:123", "r--s")
	require.NoError(t, err)
	require.Equal(t, uint64(4), value["Pss"])
	_, err = sharedBenchMemSmaps(pmem, "0:42:123")
	require.Error(t, err)
	ram := "4000-6000 rw-p 00000000 00:43 456 /run/e2b-devices/memfile\nRss: 8 kB\nPss: 6 kB\nPrivate_Dirty: 4 kB\n"
	value, err = sharedBenchMemSmaps(ram, "0:43:456")
	require.NoError(t, err)
	require.Equal(t, uint64(6), value["Pss"])
	_, err = sharedBenchFileSmaps(ram, "0:43:456", "r--s")
	require.Error(t, err)
}
