//go:build linux

package erofs

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Merovius/nbd/nbdnl"
)

type OverlayOptions struct {
	Directory   string
	BackingPath string
	Size        int64
	// DevicePath must be reserved from the orchestrator's shared NBD pool. This
	// package never scans for unused NBD devices or releases the pool reservation.
	DevicePath string
	ParentID   string
	Tools      Options
}

type Overlay struct {
	mu           sync.Mutex
	opts         OverlayOptions
	file         string
	exited       chan struct{}
	expectExit   atomic.Bool
	disconnected bool
	sealed       bool
	cmd          *exec.Cmd
	waitErr      error
	exitErr      error
	socket       *os.File
	captureErr   error
	deviceIndex  uint32
	socketDir    string
	producer     ProcessIdentity
	fileIdentity FileIdentity
}

type diskSeal struct {
	ParentID    string   `json:"parent_id"`
	BackingPath string   `json:"backing_path"`
	Size        int64    `json:"size"`
	Artifact    Artifact `json:"artifact"`
}

var nbdPathPattern = regexp.MustCompile(`^/dev/nbd[0-9]+$`)

func (o *Overlay) dial(ctx context.Context, path string) (*net.UnixConn, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
		if err == nil {
			return conn.(*net.UnixConn), nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-o.exited:
			return nil, errors.Join(errors.New("qemu-nbd exited during startup"), o.waitErr)
		case <-ticker.C:
		}
	}
}

// Before any device is attached, no guest I/O exists and it is safe to kill a
// failed startup. This path is never used to seal a captured runtime overlay.
func (o *Overlay) abortStartup() error {
	if o.socket != nil {
		o.socket.Close()
		o.socket = nil
	}
	err := o.cmd.Process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		err = nil
	}
	<-o.exited
	return errors.Join(err, os.RemoveAll(o.socketDir))
}

// Negotiate the fixed-newstyle empty export with simple replies, as required by
// Linux NBD. See https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md.
func negotiateNBD(conn io.ReadWriter) (uint64, uint16, error) {
	var hello [18]byte
	if _, err := io.ReadFull(conn, hello[:]); err != nil {
		return 0, 0, err
	}
	be := binary.BigEndian
	if be.Uint64(hello[:8]) != 0x4e42444d41474943 || be.Uint64(hello[8:16]) != 0x49484156454f5054 || be.Uint16(hello[16:])&3 != 3 {
		return 0, 0, errors.New("qemu-nbd does not support fixed-newstyle/no-zeroes negotiation")
	}
	var request [20]byte
	be.PutUint32(request[:4], 3)
	be.PutUint64(request[4:12], 0x49484156454f5054)
	be.PutUint32(request[12:16], 1) // NBD_OPT_EXPORT_NAME, empty name
	if _, err := conn.Write(request[:]); err != nil {
		return 0, 0, err
	}
	var export [10]byte
	if _, err := io.ReadFull(conn, export[:]); err != nil {
		return 0, 0, err
	}
	return be.Uint64(export[:8]), be.Uint16(export[8:]), nil
}

func NewOverlay(ctx context.Context, o OverlayOptions) (*Overlay, error) {
	o.Tools = o.Tools.defaults()
	if !nbdPathPattern.MatchString(o.DevicePath) || !validID.MatchString(o.ParentID) {
		return nil, errors.New("invalid reserved NBD device or parent ID")
	}
	if o.Size <= 0 || o.Size%BlockSize != 0 {
		return nil, errors.New("invalid overlay size")
	}
	if !filepath.IsAbs(o.BackingPath) {
		return nil, errors.New("qcow2 backing path must be absolute")
	}
	if err := regularSize(o.BackingPath, o.Size); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(o.Directory, 0700); err != nil {
		return nil, err
	}
	dir, err := filepath.Abs(o.Directory)
	if err != nil {
		return nil, err
	}
	o.Directory = dir
	path := filepath.Join(dir, "disk.qcow2")
	// qemu-img create otherwise overwrites an existing captured generation.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := command(ctx, o.Tools.QemuImgPath, "create", "-f", "qcow2", "-F", "raw", "-b", o.BackingPath, "-o", "compat=1.1,cluster_size=4096,lazy_refcounts=off,preallocation=off,extended_l2=off", path, strconv.FormatInt(o.Size, 10)); err != nil {
		return nil, err
	}
	if err := validateQCOW2(ctx, o.Tools.QemuImgPath, path, o.Size, o.BackingPath); err != nil {
		return nil, err
	}
	log, err := os.OpenFile(filepath.Join(dir, "qemu-nbd.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	// Keep QEMU as a direct child so its normal exit status is observed. Only
	// handshake runs in userspace; the negotiated socket passes to kernel NBD.
	// Snapshot IDs and store prefixes routinely exceed sockaddr_un's 108-byte
	// limit. A private short runtime directory also prevents socket replacement.
	socketDir, err := os.MkdirTemp("/run", "e2b-nbd-")
	if err != nil {
		log.Close()
		return nil, err
	}
	socketPath := filepath.Join(socketDir, "nbd.sock")
	cmd := exec.Command(o.Tools.QemuNBDPath, "--socket="+socketPath, "--format=qcow2", "--cache=writeback", "--discard=ignore", "--detect-zeroes=off", path)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		log.Close()
		os.RemoveAll(socketDir)
		return nil, err
	}
	log.Close()
	overlay := &Overlay{opts: o, file: path, exited: make(chan struct{}), cmd: cmd, socketDir: socketDir}
	go overlay.waitProcess()
	overlay.producer, err = IdentifyProcess(cmd.Process.Pid)
	if err != nil {
		return nil, errors.Join(err, overlay.abortStartup())
	}
	overlay.fileIdentity, err = identifyFile(path)
	if err != nil {
		return nil, errors.Join(err, overlay.abortStartup())
	}
	startupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := overlay.dial(startupCtx, socketPath)
	if err != nil {
		return nil, errors.Join(err, overlay.abortStartup())
	}
	defer conn.Close()
	if deadline, ok := startupCtx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	size, flags, err := negotiateNBD(conn)
	if err != nil {
		return nil, errors.Join(err, overlay.abortStartup())
	}
	if size != uint64(o.Size) || flags&2 != 0 || flags&4 == 0 {
		return nil, errors.Join(errors.New("NBD export has incorrect size, is read-only, or lacks FLUSH"), overlay.abortStartup())
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, errors.Join(err, overlay.abortStartup())
	}
	socket, err := conn.File()
	if err != nil {
		return nil, errors.Join(err, overlay.abortStartup())
	}
	overlay.socket = socket
	slot, _ := strconv.ParseUint(strings.TrimPrefix(o.DevicePath, "/dev/nbd"), 10, 32)
	overlay.deviceIndex = uint32(slot)
	idx, err := nbdnl.Connect(uint32(slot), []*os.File{socket}, size, 0, nbdnl.ServerFlags(flags), nbdnl.WithBlockSize(512), nbdnl.WithTimeout(90*time.Second))
	if err != nil {
		return nil, errors.Join(err, overlay.abortStartup())
	}
	overlay.deviceIndex = idx
	if idx != uint32(slot) {
		return overlay, errors.New("NBD allocator returned a different device")
	}

	return overlay, nil
}

func (o *Overlay) Path() string          { return o.opts.DevicePath }
func (o *Overlay) Done() <-chan struct{} { return o.exited }

func (o *Overlay) waitProcess() {
	o.waitErr = o.cmd.Wait()
	// Latch classification before notifying watchers. Cleanup may start after
	// Done closes but before they read Err; it must not erase an already
	// unexpected exit, including a QEMU exit with status zero.
	if o.waitErr != nil || !o.expectExit.Load() {
		o.exitErr = errors.Join(errors.New("qemu-nbd exited unexpectedly"), o.waitErr)
	}
	close(o.exited)
}

func (o *Overlay) Err() error {
	select {
	case <-o.exited:
		return o.exitErr
	default:
	}
	return nil
}

// Flush is called only after vCPUs and Firecracker's device queues are quiescent.
func (o *Overlay) Flush() error {
	f, err := os.OpenFile(o.opts.DevicePath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

// Seal must follow Firecracker exit. It drains host writes, disconnects the
// kernel NBD client, waits for QEMU's normal close, then validates and fsyncs the
// captured qcow2. It never kills QEMU and calls a dirty file successfully sealed.
func (o *Overlay) Seal(ctx context.Context) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.sealed {
		return o.file, nil
	}
	if err := o.stop(ctx, true); err != nil {
		return "", err
	}
	if err := validateQCOW2(ctx, o.opts.Tools.QemuImgPath, o.file, o.opts.Size, o.opts.BackingPath); err != nil {
		return "", err
	}
	if err := writeDiskSeal(o.file, o.opts.ParentID, o.opts.BackingPath, o.opts.Size); err != nil {
		return "", err
	}
	o.sealed = true
	return o.file, nil
}

func writeDiskSeal(path, parentID, backing string, size int64) error {
	if err := os.Chmod(path, 0400); err != nil {
		return err
	}
	if err := syncPath(path); err != nil {
		return err
	}
	artifact, err := describe(path, filepath.Base(path))
	if err != nil {
		return err
	}
	seal := diskSeal{ParentID: parentID, BackingPath: backing, Size: size, Artifact: artifact}
	data, err := json.Marshal(seal)
	if err != nil {
		return err
	}
	return atomicRecord(path+".sealed.json", data, true)
}

func (o *Overlay) Close(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.stop(ctx, false)
}

func (o *Overlay) stop(ctx context.Context, sealing bool) error {
	if !o.disconnected {
		exited := false
		select {
		case <-o.exited:
			exited = true
			o.captureErr = errors.Join(o.captureErr, errors.New("qemu-nbd exited before a clean disconnect"), o.waitErr)
		default:
		}
		if !exited {
			if err := o.Flush(); err != nil {
				o.captureErr = errors.Join(o.captureErr, fmt.Errorf("flush qcow2 NBD: %w", err))
				if sealing {
					return o.captureErr
				}
			}
		}
		status, err := nbdnl.Status(o.deviceIndex)
		if err != nil {
			return err
		}
		if status.Connected {
			o.expectExit.Store(true)
			if err := nbdnl.Disconnect(o.deviceIndex); err != nil {
				return err
			}
		}
		o.disconnected = true
	}
	select {
	case <-o.exited:
		if o.socket != nil {
			o.socket.Close()
			o.socket = nil
		}
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			status, err := nbdnl.Status(o.deviceIndex)
			if err != nil {
				return err
			}
			if !status.Connected {
				if err := os.RemoveAll(o.socketDir); err != nil {
					return err
				}
				if sealing {
					return errors.Join(o.captureErr, o.waitErr)
				}
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}

func validateQCOW2(ctx context.Context, qemuImg, path string, size int64, backing string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	header := make([]byte, 104)
	_, readErr := f.ReadAt(header, 0)
	f.Close()
	if readErr != nil {
		return readErr
	}
	be := binary.BigEndian
	if be.Uint32(header[:4]) != 0x514649fb || be.Uint32(header[4:8]) != 3 || be.Uint32(header[20:24]) != 12 || be.Uint64(header[24:32]) != uint64(size) || be.Uint32(header[32:36]) != 0 || be.Uint32(header[60:64]) != 0 || be.Uint64(header[72:80]) != 0 || be.Uint64(header[80:88]) != 0 || be.Uint64(header[88:96]) != 0 || be.Uint32(header[96:100]) != 4 {
		return errors.New("qcow2 must be clean v3, standard 4 KiB clusters, without extra features")
	}
	if backing != "" {
		out, err := exec.CommandContext(ctx, qemuImg, "info", "--output=json", path).Output()
		if err != nil {
			return err
		}
		var info struct {
			Backing string `json:"backing-filename"`
			Format  string `json:"backing-filename-format"`
		}
		if err := json.Unmarshal(out, &info); err != nil {
			return err
		}
		if info.Backing != backing || info.Format != "raw" {
			return errors.New("qcow2 backing file binding mismatch")
		}
	}
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	// Integrity checking needs only the top-level container. Its original
	// runtime EROFS backing mount can be gone during post-exit recovery.
	image, err := qcowImageFilename(path, "")
	if err != nil {
		return err
	}
	return command(checkCtx, qemuImg, "check", "-q", image)
}

func qcowImageFilename(path, backing string) (string, error) {
	options := map[string]any{"driver": "qcow2", "file": map[string]string{"driver": "file", "filename": path}, "backing": nil}
	if backing != "" {
		options["backing"] = map[string]any{"driver": "raw", "file": map[string]string{"driver": "file", "filename": backing}}
	}
	data, err := json.Marshal(options)
	return "json:" + string(data), err
}

func validateDiskSeal(path, parent string, size int64) error {
	data, err := os.ReadFile(path + ".sealed.json")
	if err != nil {
		return fmt.Errorf("read qcow2 seal: %w", err)
	}
	var seal diskSeal
	if err := json.Unmarshal(data, &seal); err != nil {
		return err
	}
	actual, err := describe(path, filepath.Base(path))
	if err != nil {
		return err
	}
	if seal.ParentID != parent || seal.Size != size || seal.Artifact != actual {
		return errors.New("sealed qcow2 parent or content binding mismatch")
	}
	return nil
}
