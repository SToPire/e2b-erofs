//go:build linux

package erofs

import (
	"os/exec"
	"sync"
	"testing"
)

func TestOverlayExitClassificationSurvivesCleanup(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		expected     bool
		wantError    bool
	}{
		{"unexpected normal exit", "exit 0", false, true},
		{"unexpected failed exit", "exit 7", false, true},
		{"failure during disconnect", "exit 7", true, true},
		{"intentional disconnect", "exit 0", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := &Overlay{cmd: exec.Command("sh", "-c", tc.script), exited: make(chan struct{})}
			o.expectExit.Store(tc.expected)
			if err := o.cmd.Start(); err != nil {
				t.Fatal(err)
			}
			go o.waitProcess()
			<-o.Done()
			// Match the watcher ordering: Done has already fired, but a parallel
			// closer advances shutdown state before the watcher gets to Err.
			var wg sync.WaitGroup
			wg.Go(func() {
				for range 1000 {
					o.expectExit.Store(true)
				}
			})
			wg.Go(func() {
				for range 1000 {
					if (o.Err() != nil) != tc.wantError {
						t.Error("cleanup changed recorded exit status")
						return
					}
				}
			})
			wg.Wait()
		})
	}
}
