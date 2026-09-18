//go:build linux

package pmem

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// CheckExportInitramfs checks the bounded newc artifact format emitted by our
// initramfs builder. An old boot image must fail before the helper starts; its
// ordinary /init would otherwise ignore export arguments and start tenant init.
func CheckExportInitramfs(ctx context.Context, path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("initramfs must be regular")
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	r := io.LimitReader(gz, 64<<20)
	foundEntry, foundCopy, foundContract := false, false, false
	number := func(b []byte) (int64, error) { return strconv.ParseInt(string(b), 16, 64) }
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var h [110]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return fmt.Errorf("read initramfs newc header: %w", err)
		}
		if string(h[:6]) != "070701" {
			return errors.New("export initramfs requires newc format")
		}
		mode, e1 := number(h[14:22])
		size, e2 := number(h[54:62])
		namesize, e3 := number(h[94:102])
		if errors.Join(e1, e2, e3) != nil || size < 0 || size > (64<<20) || namesize < 1 || namesize > 4096 {
			return errors.New("invalid initramfs entry")
		}
		name := make([]byte, namesize)
		if _, err := io.ReadFull(r, name); err != nil {
			return err
		}
		if name[len(name)-1] != 0 {
			return errors.New("invalid newc name")
		}
		if _, err := io.CopyN(io.Discard, r, (4-(110+namesize)%4)%4); err != nil {
			return err
		}
		path := strings.TrimPrefix(string(name[:len(name)-1]), "./")
		if path == "TRAILER!!!" {
			break
		}
		remaining, padding := size, (4-size%4)%4
		if path == "e2b-rootfs.json" {
			if mode&unix.S_IFMT != unix.S_IFREG || size == 0 || size > 4096 {
				return errors.New("invalid rootfs boot contract")
			}
			data := make([]byte, size)
			if _, err := io.ReadFull(r, data); err != nil {
				return err
			}
			var contract struct {
				Layout       string `json:"layout"`
				Export       int    `json:"export_version"`
				RootMetadata int    `json:"root_metadata_version"`
			}
			if err := json.Unmarshal(data, &contract); err != nil {
				return err
			}
			foundContract = contract.Layout == "pmem-overlay-raw-v1" && contract.Export == 2 && contract.RootMetadata == 2
			remaining = 0
		}
		if path == "export-init" || path == "bin/rootfs-copy" {
			if mode&unix.S_IFMT != unix.S_IFREG || mode&0111 == 0 || size == 0 {
				return errors.New("invalid export executable entry")
			}
			if path == "export-init" {
				foundEntry = true
			} else {
				foundCopy = true
			}
		}
		if _, err := io.CopyN(io.Discard, r, remaining+padding); err != nil {
			return err
		}
	}
	if !foundEntry || !foundCopy {
		return errors.New("initramfs lacks the dedicated merged-root export entry; rebuild it")
	}
	if !foundContract {
		return errors.New("initramfs lacks the required root-metadata/export contract; rebuild it")
	}
	return nil
}
