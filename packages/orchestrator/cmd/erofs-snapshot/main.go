//go:build linux

// erofs-snapshot retries publication of an already sealed local capture.
// The same retained request also succeeds after publication has committed:
// Store.Build validates the capture identity and committed artifacts before
// retrying directory durability, without rebuilding either image.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
)

func run() error {
	root := flag.String("store", "", "persistent EROFS snapshot directory")
	request := flag.String("request", "", "retained build-request.json from a sealed capture")
	recovery := flag.String("recovery", "", "retained recovery record; both original producers must have exited")
	mkfs := flag.String("mkfs", "mkfs.erofs", "mkfs.erofs with sparse and qcow2 file-delta support")
	fsck := flag.String("fsck", "fsck.erofs", "fsck.erofs binary")
	flag.Parse()
	if *root == "" || (*request == "") == (*recovery == "") {
		return fmt.Errorf("--store and exactly one of --request or --recovery are required")
	}
	store, err := erofs.NewStore(*root, erofs.Options{MkfsPath: *mkfs, FsckPath: *fsck})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var snapshot *erofs.Snapshot
	if *recovery != "" {
		snapshot, err = store.Recover(ctx, *recovery)
	} else {
		data, readErr := os.ReadFile(*request)
		if readErr != nil {
			return readErr
		}
		var req erofs.BuildRequest
		var tagged struct {
			Version int                  `json:"version"`
			Request erofs.BuildV2Request `json:"request"`
		}
		if err := json.Unmarshal(data, &tagged); err != nil {
			return err
		}
		if tagged.Version == 2 {
			snapshot, err = store.PublishV2Request(ctx, tagged.Request)
		} else {
			if err := json.Unmarshal(data, &req); err != nil {
				return err
			}
			snapshot, err = store.Build(ctx, req)
		}
	}
	if err != nil {
		return err
	}
	fmt.Println(snapshot.Dir)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
