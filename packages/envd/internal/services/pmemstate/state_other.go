//go:build !linux

package pmemstate

import "errors"

const Layout = "pmem-overlay-raw-v1"

type State struct {
	LifecycleID, Phase string
	Frozen             bool
}
type Controller struct{}

func Open() (*Controller, error)       { return nil, nil }
func (*Controller) Mountpoint() string { return "" }
func (*Controller) Snapshot() State    { return State{} }
func (*Controller) CanThaw() bool      { return false }
func (*Controller) Ready() bool        { return false }
func (*Controller) Close() error       { return nil }
func (*Controller) BeginPrepare(string) (bool, error) {
	return false, errors.New("pmem requires Linux")
}
func (*Controller) Prepared(string) error              { return errors.New("pmem requires Linux") }
func (*Controller) SetFrozen(bool) error               { return errors.New("pmem requires Linux") }
func (*Controller) Commit(string, func() error) error  { return errors.New("pmem requires Linux") }
func (*Controller) HoldUpgrade() (func() error, error) { return nil, errors.New("pmem requires Linux") }
