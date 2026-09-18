//go:build linux

package erofs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

// A single traversal validates each immutable artifact once, even when the
// same lower/boot image is referenced by every generation. This is not a
// cross-request trust cache: each new traversal starts with an empty memo.
type verificationContextKey struct{}
type verifiedArtifact struct {
	artifact Artifact
	stamp    fileStamp
}
type verificationMemo struct {
	mu       sync.Mutex
	files    map[string]verifiedArtifact
	metadata map[string]fileStamp
}
type fileStamp struct {
	Dev, Ino     uint64
	Size         int64
	Mode         uint32
	UID, GID     uint32
	Mtime, Ctime unix.Timespec
}

func stampOf(st unix.Stat_t) fileStamp {
	return fileStamp{st.Dev, st.Ino, st.Size, st.Mode, st.Uid, st.Gid, st.Mtim, st.Ctim}
}
func withVerification(ctx context.Context) context.Context {
	if ctx.Value(verificationContextKey{}) != nil {
		return ctx
	}
	return context.WithValue(ctx, verificationContextKey{}, &verificationMemo{files: make(map[string]verifiedArtifact), metadata: make(map[string]fileStamp)})
}

func (s *Store) verifyArtifactBytes(ctx context.Context, a Artifact) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path := filepath.Join(s.Root, a.File)
	fd, err := openVerificationInput(path)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &before); err != nil {
		return err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size != a.Bytes {
		return fmt.Errorf("artifact type/size differs: %s", a.File)
	}
	stamp := stampOf(before)
	memo, _ := ctx.Value(verificationContextKey{}).(*verificationMemo)
	if memo != nil {
		memo.mu.Lock()
		cached, ok := memo.files[path]
		memo.mu.Unlock()
		if ok {
			if cached.artifact != a || cached.stamp != stamp {
				return fmt.Errorf("artifact changed during verification: %s", a.File)
			}
			if stamp.Mode&0222 == 0 && protectedVerificationStore(filepath.Dir(path)) == nil {
				return nil
			}
		}
	}
	h := sha256.New()
	size, err := io.Copy(h, contextReader{ctx: ctx, reader: file})
	if err != nil {
		return err
	}
	var after, named unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil {
		return err
	}
	if err := unix.Lstat(path, &named); err != nil {
		return err
	}
	if stampOf(after) != stamp || stampOf(named) != stamp {
		return fmt.Errorf("artifact changed while hashing: %s", a.File)
	}
	if size != a.Bytes || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return fmt.Errorf("artifact validation failed: %s", a.File)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if memo != nil {
		memo.mu.Lock()
		memo.files[path] = verifiedArtifact{a, stamp}
		memo.mu.Unlock()
	}
	return nil
}

// Keep this helper's identity check available to later verification stages;
// it rejects path replacement as well as modifications to the opened inode.
func verifiedPathStamp(path string) (fileStamp, error) {
	if err := protectedVerificationStore(filepath.Dir(path)); err != nil {
		return fileStamp{}, err
	}
	fd, err := openVerificationInput(path)
	if err != nil {
		return fileStamp{}, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fileStamp{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fileStamp{}, errors.New("verified artifact is no longer regular")
	}
	return stampOf(st), nil
}

func trackedMetadata(ctx context.Context, path string) ([]byte, error) {
	fd, err := openVerificationInput(path)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after, named unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("metadata is not regular")
	}
	data, err := io.ReadAll(contextReader{ctx: ctx, reader: f})
	if err != nil {
		return nil, err
	}
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, err
	}
	if err := unix.Lstat(path, &named); err != nil {
		return nil, err
	}
	stamp := stampOf(before)
	if stampOf(after) != stamp || stampOf(named) != stamp {
		return nil, errors.New("metadata changed while reading")
	}
	if memo, _ := ctx.Value(verificationContextKey{}).(*verificationMemo); memo != nil {
		memo.mu.Lock()
		if old, ok := memo.metadata[path]; ok && old != stamp {
			memo.mu.Unlock()
			return nil, errors.New("metadata changed during verification")
		}
		memo.metadata[path] = stamp
		memo.mu.Unlock()
	}
	return data, nil
}

// VerifiedSnapshot holds a complete checksum validation made in this process.
// Recheck is a short path for status polls: it verifies that every artifact and
// manifest still has the same inode, size, mode and nanosecond mtime/ctime, then
// reconfirms directory durability. Restores still do their normal full checks.
type VerifiedSnapshot struct {
	snapshot *Snapshot
	paths    map[string]fileStamp
}

func (s *Store) VerifyWithProof(ctx context.Context, id string) (*VerifiedSnapshot, error) {
	if err := protectedVerificationStore(s.Root); err != nil {
		return nil, err
	}
	ctx = withVerification(ctx)
	snapshot, err := s.VerifyCommitted(ctx, id)
	if snapshot == nil {
		return nil, err
	}
	memo := ctx.Value(verificationContextKey{}).(*verificationMemo)
	proof := &VerifiedSnapshot{snapshot: snapshot, paths: make(map[string]fileStamp)}
	memo.mu.Lock()
	for path, value := range memo.files {
		proof.paths[path] = value.stamp
	}
	for path, value := range memo.metadata {
		proof.paths[path] = value
	}
	memo.mu.Unlock()
	if e := proof.unchanged(context.WithoutCancel(ctx)); e != nil {
		return nil, e
	}
	return proof, err
}
func (p *VerifiedSnapshot) unchanged(ctx context.Context) error {
	if err := protectedVerificationStore(p.snapshot.store.Root); err != nil {
		return err
	}
	for path, expected := range p.paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		actual, err := verifiedPathStamp(path)
		if err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("verified snapshot input changed: %s", path)
		}
		if actual.Mode&0222 != 0 || (actual.UID != 0 && actual.UID != uint32(os.Geteuid())) {
			return ErrUnprotectedVerificationStore
		}
	}
	return nil
}
func (p *VerifiedSnapshot) Recheck(ctx context.Context) (*Snapshot, error) {
	if err := p.unchanged(ctx); err != nil {
		return nil, err
	}
	for _, dir := range []string{p.snapshot.Dir, p.snapshot.store.Root} {
		if err := ctx.Err(); err != nil {
			return p.snapshot, err
		}
		if err := syncPath(dir); err != nil {
			return p.snapshot, err
		}
	}
	if err := p.unchanged(ctx); err != nil {
		return nil, err
	}
	return p.snapshot, nil
}

var ErrUnprotectedVerificationStore = errors.New("cached checkpoint verification requires an exclusively managed, protected store")

func protectedVerificationStore(root string) error {
	for path := filepath.Clean(root); ; path = filepath.Dir(path) {
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
			return ErrUnprotectedVerificationStore
		}
		if st.Mode&0022 != 0 && !(path != root && st.Mode&unix.S_ISVTX != 0 && st.Uid == 0) {
			return ErrUnprotectedVerificationStore
		}
		if path == filepath.Dir(path) {
			break
		}
	}
	return nil
}

func openVerificationInput(path string) (int, error) {
	return unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK, Resolve: unix.RESOLVE_NO_SYMLINKS})
}
