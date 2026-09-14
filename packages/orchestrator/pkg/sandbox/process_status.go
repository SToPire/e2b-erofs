//go:build linux

package sandbox

import "github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"

func (s *Sandbox) ProcessExited() bool {
	if s.process == nil {
		return false
	}
	select {
	case <-s.process.Exit.Done():
		return true
	default:
		return false
	}
}

func (s *Sandbox) ProcessIdentity() (erofs.ProcessIdentity, error) {
	pid, err := s.process.Pid()
	if err != nil {
		return erofs.ProcessIdentity{}, err
	}
	return erofs.IdentifyProcess(pid)
}
