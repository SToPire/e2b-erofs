//go:build linux

package base

import (
	"context"
	"strings"
	"testing"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/build/phases"
)

// Provisioning must not decide the chrony time source: it runs on a build node,
// and the sandbox can cold-boot on a node with a different PHC situation. The
// baked config only includes what e2b-chrony-source writes at boot.
func TestProvisionScriptDefersChronySourceToBoot(t *testing.T) {
	t.Parallel()
	// E2B_CHRONY_PHC was the provision-time verdict the Alpine seccomp workaround
	// used to read. It no longer exists, and under `set -u` a leftover reference
	// is a hard provisioning failure on every distro, not just Alpine.
	for _, bad := range []string{"[ -e /dev/ptp0 ]", "refclock PHC", "E2B_CHRONY_PHC"} {
		if strings.Contains(provisionScriptFile, bad) {
			t.Errorf("provision.sh must not decide the time source (%q) — that happens at boot", bad)
		}
	}
	for _, want := range []string{
		`echo "include /run/chrony-e2b/source.conf"`,
		`echo "makestep 1.0 3"`,
	} {
		if !strings.Contains(provisionScriptFile, want) {
			t.Errorf("provision.sh missing chrony config line %q", want)
		}
	}
}

func TestProvisionAptMirror(t *testing.T) {
	t.Setenv("E2B_APT_MIRROR", "")
	t.Setenv("E2B_APT_SECURITY_MIRROR", "")
	params := ProvisionScriptParams{BusyBox: "/busybox", DistroSelector: "# distro selector"}
	baseline, err := getProvisionScript(context.Background(), params)
	if err != nil || strings.Contains(baseline, "E2B_APT_ARCHIVE=") {
		t.Fatalf("default: %v", err)
	}
	t.Setenv("E2B_APT_MIRROR", "https://mirrors.aliyun.com/debian")
	if _, err := getProvisionScript(context.Background(), params); err == nil {
		t.Fatal("incomplete mirror must reject script generation")
	}
	t.Setenv("E2B_APT_SECURITY_MIRROR", "https://deb.debian.org/debian-security")
	script, err := getProvisionScript(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}
	selector := strings.Index(script, "# distro selector")
	rewrite := strings.Index(script, "E2B_APT_ARCHIVE='https://mirrors.aliyun.com/debian'")
	install := strings.Index(script, "e2b_pkg_install $MISSING")
	if selector < 0 || rewrite < selector || install < rewrite {
		t.Fatal("mirror must run after distro detection and before installation")
	}
}

func TestAptMirrorRejectedBeforeBaseHashDependencies(t *testing.T) {
	t.Setenv("E2B_APT_MIRROR", "https://mirrors.aliyun.com/debian")
	t.Setenv("E2B_APT_SECURITY_MIRROR", "")
	// No cache, feature-flag client, or VM factory: invalid configuration must
	// fail before consulting any of these or allowing a cached layer to win.
	bb := &BaseBuilder{}
	if _, err := bb.Hash(context.Background(), phases.LayerResult{}); err == nil || !strings.Contains(err.Error(), "E2B_APT_SECURITY_MIRROR") {
		t.Fatalf("expected early configuration failure, got %v", err)
	}
}
