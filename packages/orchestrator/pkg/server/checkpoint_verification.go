//go:build linux

package server

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
)

const checkpointVerificationLimit = 32
const checkpointVerificationTTL = 5 * time.Minute

type checkpointVerification struct {
	done     chan struct{}
	proof    *erofs.VerifiedSnapshot
	err      error
	started  time.Time
	finished time.Time
	observed bool
}

type checkpointVerifications struct {
	mu      sync.Mutex
	entries map[string]*checkpointVerification
}

// Status callers have short deadlines. One bounded checksum traversal survives
// those polls; subsequent polls recheck every verified file identity and stamp.
// A changed path invalidates the proof before it can report a committed image.
func (s *Server) verifyNativeCheckpointStatus(ctx context.Context, store *erofs.Store, id string) (*erofs.Snapshot, error, bool) {
	idKey := filepath.Join(store.Root, id)
	cache := &s.nativeVerifications
	cache.mu.Lock()
	if cache.entries == nil {
		cache.entries = make(map[string]*checkpointVerification)
	}
	now := time.Now()
	for key, item := range cache.entries {
		select {
		case <-item.done:
			if now.Sub(item.finished) > checkpointVerificationTTL {
				delete(cache.entries, key)
			}
		default:
		}
	}
	entry := cache.entries[idKey]
	if entry == nil {
		if len(cache.entries) >= checkpointVerificationLimit {
			// Evict the oldest completed proof, never spawn unlimited active work.
			oldest := ""
			for key, item := range cache.entries {
				select {
				case <-item.done:
					if item.observed && (oldest == "" || item.started.Before(cache.entries[oldest].started)) {
						oldest = key
					}
				default:
				}
			}
			if oldest == "" {
				cache.mu.Unlock()
				return nil, nil, true
			}
			delete(cache.entries, oldest)
		}
		entry = &checkpointVerification{done: make(chan struct{}), started: now}
		cache.entries[idKey] = entry
		go func() {
			defer func() { entry.finished = time.Now(); close(entry.done) }()
			verifyCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			go func() {
				select {
				case <-s.done:
					cancel()
				case <-verifyCtx.Done():
				}
			}()
			entry.proof, entry.err = store.VerifyWithProof(verifyCtx, id)
		}()
	}
	cache.mu.Unlock()
	select {
	case <-entry.done:
		if entry.proof == nil {
			if errors.Is(entry.err, context.DeadlineExceeded) || errors.Is(entry.err, context.Canceled) {
				cache.mu.Lock()
				if cache.entries[idKey] == entry {
					delete(cache.entries, idKey)
				}
				cache.mu.Unlock()
				return nil, nil, true
			}
			cache.mu.Lock()
			if cache.entries[idKey] == entry {
				delete(cache.entries, idKey)
			}
			cache.mu.Unlock()
			return nil, entry.err, false
		}
		snapshot, err := entry.proof.Recheck(ctx)
		if snapshot == nil && err != nil && ctx.Err() == nil {
			cache.mu.Lock()
			if cache.entries[idKey] == entry {
				delete(cache.entries, idKey)
			}
			cache.mu.Unlock()
			return nil, nil, true
		}
		if ctx.Err() == nil {
			cache.mu.Lock()
			entry.observed = true
			cache.mu.Unlock()
		}
		return snapshot, err, false
	default:
		return nil, nil, true
	}
}
