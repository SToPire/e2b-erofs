//go:build linux

package uffd

import (
	"context"
	"errors"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/block"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/fc"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/uffd/userfaultfd"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage/header"
	"github.com/e2b-dev/infra/packages/shared/pkg/utils"
)

var ErrFileMemoryUnsupported = errors.New("operation requires a UFFD memory backend; File RAM uses native snapshots")

// FileMemory supplies lifecycle signals for RAM mapped privately by Firecracker.
// It never infers page contents from residency or reads a private mapping's base
// file to export modified RAM. Capture goes through CreateNativeSnapshot.
type FileMemory struct {
	exit *utils.ErrorOnce
}

var _ MemoryBackend = (*FileMemory)(nil)

func NewFileMemory() *FileMemory { return &FileMemory{exit: utils.NewErrorOnce()} }

func (*FileMemory) DiffMetadata(context.Context, *fc.Process, bool) (*header.DiffMetadata, error) {
	return nil, ErrFileMemoryUnsupported
}

func (*FileMemory) PrefetchData(context.Context) (block.PrefetchData, error) {
	return block.PrefetchData{}, ErrFileMemoryUnsupported
}

func (*FileMemory) Prefault(context.Context, int64, []byte) (bool, error) {
	return false, ErrFileMemoryUnsupported
}

func (*FileMemory) Start(context.Context) error { return nil }

func (m *FileMemory) Stop() error {
	m.exit.SetSuccess()
	return nil
}

func (*FileMemory) Ready() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func (m *FileMemory) Exit() *utils.ErrorOnce               { return m.exit }
func (*FileMemory) Memfd(context.Context) *block.Memfd     { return nil }
func (*FileMemory) PeekMemfd(context.Context) *block.Memfd { return nil }
func (*FileMemory) ServeStats() userfaultfd.ServeSnapshot  { return userfaultfd.ServeSnapshot{} }
