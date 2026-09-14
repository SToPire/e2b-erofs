// Package aptmirror configures Debian archive transport without changing trust or suites.
package aptmirror

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

//go:embed rewrite.sh
var rewriteScript string

// Config requires explicit, independent archive and security endpoints.
type Config struct{ Archive, Security string }

func FromEnv() (Config, error) {
	return Parse(os.Getenv("E2B_APT_MIRROR"), os.Getenv("E2B_APT_SECURITY_MIRROR"))
}

// URI characters are deliberately restricted: values enter both shell and awk.
var safeURI = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~-]+)*/?$`)

func Parse(archive, security string) (Config, error) {
	if archive == "" && security == "" {
		return Config{}, nil
	}
	for _, entry := range []struct{ name, value string }{{"E2B_APT_MIRROR", archive}, {"E2B_APT_SECURITY_MIRROR", security}} {
		u, err := url.Parse(entry.value)
		if err != nil || !safeURI.MatchString(entry.value) || u.Hostname() == "" {
			return Config{}, fmt.Errorf("%s must be an explicit HTTPS archive URI without credentials, query, fragment, escapes or shell characters; both apt mirror variables are required", entry.name)
		}
		for _, part := range strings.Split(u.Path, "/") {
			if part == "." || part == ".." {
				return Config{}, fmt.Errorf("%s must not contain dot path segments", entry.name)
			}
		}
	}
	archive, security = strings.TrimRight(archive, "/"), strings.TrimRight(security, "/")
	if archive == security {
		return Config{}, fmt.Errorf("archive and security apt mirror URIs must be distinct; security layout is never inferred")
	}
	return Config{Archive: archive, Security: security}, nil
}

// Script runs in the guest, before any package installation, using injected BusyBox.
func (c Config) Script() string {
	if c.Archive == "" {
		return ""
	}
	return fmt.Sprintf("E2B_APT_ARCHIVE='%s'\nE2B_APT_SECURITY='%s'\n", c.Archive, c.Security) + rewriteScript
}

// CacheKey covers both URIs and rewrite logic even with a pinned provision version.
func (c Config) CacheKey() string {
	if c.Archive == "" {
		return ""
	}
	return fmt.Sprintf("apt-mirror:%x", sha256.Sum256([]byte(c.Script())))
}
