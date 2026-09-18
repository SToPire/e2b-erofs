//go:build linux

package erofs

import (
	"strings"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/require"
)

func TestOverlayBackendIdentifierEncoding(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
	}{
		{"absolute path", "/var/lib/e2b/runtime/sandbox-123/disk.qcow2"},
		{"spaces and unicode", "/var/lib/e2b/runtime/sandbox 空间/disk.qcow2"},
		{"long path", "/var/lib/e2b/" + strings.Repeat("generation/", 40) + "disk.qcow2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := netlink.NewAttributeEncoder()
			withBackendIdentifier(tc.path)(e)
			data, err := e.Encode()
			require.NoError(t, err)

			attrs, err := netlink.UnmarshalAttributes(data)
			require.NoError(t, err)
			require.Len(t, attrs, 1)
			// Check the literal Linux UAPI number independently of the local
			// constant, and require the exact path plus its NUL terminator.
			require.Equal(t, uint16(10), attrs[0].Type)
			require.Equal(t, []byte(tc.path+"\x00"), attrs[0].Data)
		})
	}
}
