//go:build linux

package pmem

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExportInitramfsRequiresDedicatedEntry(t *testing.T) {
	t.Parallel()
	makeImage := func(entries []string) string {
		var raw bytes.Buffer
		for i, name := range append(entries, "TRAILER!!!") {
			data := []byte("executable")
			if name == "e2b-rootfs.json" {
				data = []byte(`{"layout":"pmem-overlay-raw-v1","export_version":2,"root_metadata_version":2}`)
			}
			mode := uint32(0100755)
			if name == "TRAILER!!!" {
				data = nil
				mode = 0
			}
			raw.WriteString("070701")
			values := []uint32{uint32(i + 1), mode, 0, 0, 1, 0, uint32(len(data)), 0, 0, 0, 0, uint32(len(name) + 1), 0}
			for _, v := range values {
				fmt.Fprintf(&raw, "%08x", v)
			}
			raw.WriteString(name)
			raw.WriteByte(0)
			for raw.Len()%4 != 0 {
				raw.WriteByte(0)
			}
			raw.Write(data)
			for raw.Len()%4 != 0 {
				raw.WriteByte(0)
			}
		}
		var out bytes.Buffer
		gz := gzip.NewWriter(&out)
		_, err := gz.Write(raw.Bytes())
		require.NoError(t, err)
		require.NoError(t, gz.Close())
		path := filepath.Join(t.TempDir(), "initramfs")
		require.NoError(t, os.WriteFile(path, out.Bytes(), 0600))
		return path
	}
	require.ErrorContains(t, CheckExportInitramfs(t.Context(), makeImage([]string{"init", "bin/busybox"})), "dedicated")
	require.ErrorContains(t, CheckExportInitramfs(t.Context(), makeImage([]string{"init", "bin/rootfs-copy"})), "dedicated")
	require.NoError(t, CheckExportInitramfs(t.Context(), makeImage([]string{"init", "export-init", "bin/rootfs-copy", "e2b-rootfs.json"})))
}
