package aptmirror

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const archive = "https://mirrors.aliyun.com/debian"
const security = "https://deb.debian.org/debian-security"

func TestConfig(t *testing.T) {
	c, err := Parse("", "")
	if err != nil || c.Script() != "" || c.CacheKey() != "" {
		t.Fatalf("default must be a no-op: %+v %v", c, err)
	}
	c, err = Parse(archive+"/", security+"/")
	if err != nil || c.Archive != archive || c.Security != security {
		t.Fatalf("mirror: %+v %v", c, err)
	}
	normalized, _ := Parse(archive, security)
	if c.CacheKey() != normalized.CacheKey() {
		t.Fatal("trailing slash changed cache key")
	}
	for _, pair := range [][2]string{{"https://mirror.example/debian", security}, {archive, "https://mirror.example/security"}} {
		other, err := Parse(pair[0], pair[1])
		if err != nil || other.CacheKey() == c.CacheKey() {
			t.Fatal("cache key must cover each URI")
		}
	}
	for _, pair := range [][2]string{
		{archive, ""}, {"", security}, {archive, archive}, {archive + "/", archive},
		{"http://mirror.example/debian", security}, {"file:///debian", security},
		{"https://user:password@mirror.example/debian", security},
		{archive + "?x=y", security}, {archive + "#fragment", security}, {archive + "\nTrusted: yes", security},
		{archive + "'", security}, {archive + "$(id)", security}, {archive + "`id`", security},
		{archive + ";id", security}, {archive + "%0a", security}, {archive + "/../security", security},
		{archive + "\\x", security}, {archive, "http://mirror.example/security"},
	} {
		if _, err := Parse(pair[0], pair[1]); err == nil {
			t.Errorf("accepted unsafe/ambiguous config %q", pair)
		}
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("E2B_APT_MIRROR", archive)
	t.Setenv("E2B_APT_SECURITY_MIRROR", security)
	c, err := FromEnv()
	if err != nil || c.Archive != archive || c.Security != security {
		t.Fatalf("%+v %v", c, err)
	}
	t.Setenv("E2B_APT_SECURITY_MIRROR", "")
	if _, err := FromEnv(); err == nil {
		t.Fatal("must reject incomplete environment")
	}
}

// Execute the production shell and awk with real utilities against temporary
// sources. env dispatches host utilities where the guest uses BusyBox applets;
// no apt invocation, guest, network, or package-manager mock is needed.
func TestRewrite(t *testing.T) {
	fixtures := map[string]string{
		"sources.list": "# deb http://deb.debian.org/debian bookworm main\n" +
			"deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian/ bookworm main # keep\n" +
			"deb-src https://security.debian.org/debian-security bookworm-security main\n" +
			"deb http://security.debian.org/debian bullseye/updates main\n" +
			"deb https://deb.debian.org/debian-other bookworm main\n" +
			"deb https://deb.debian.org.evil/debian bookworm main\n" +
			"deb http://archive.ubuntu.com/ubuntu noble main\n",
		"sources.list.d/debian.sources": "Types: deb deb-src\nURIs: http://deb.debian.org/debian\n https://deb.debian.org/debian/ https://vendor.example/repo\nSuites: bookworm bookworm-updates\nComponents: main non-free-firmware\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\n" +
			"Types: deb\nURIs: http://deb.debian.org/debian-security\nSuites: bookworm-security\nComponents: main\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n http://deb.debian.org/debian\n -----END PGP PUBLIC KEY BLOCK-----\n\n" +
			"Types: deb\nEnabled: no\nuris: https://deb.debian.org/debian\n# leave comment\nSuites: sid\n",
		"sources.list.d/vendor.list": "deb [signed-by=/keys/vendor.gpg] https://vendor.example/repo bookworm main\n",
	}
	for _, distro := range []string{"debian", "ubuntu", "kali"} {
		t.Run(distro, func(t *testing.T) {
			dir := t.TempDir()
			for name, contents := range fixtures {
				path := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
					t.Fatal(err)
				}
			}
			c, _ := Parse(archive, security)
			script := strings.ReplaceAll(c.Script(), "/etc/apt/", dir+"/")
			run := func() {
				t.Helper()
				cmd := exec.Command("sh", "-eu", "-c", script)
				cmd.Env = append(os.Environ(), "BUSYBOX=/usr/bin/env", "E2B_DISTRO_ID="+distro)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%v: %s", err, out)
				}
			}
			run()
			for name, before := range fixtures {
				want := before
				if distro == "debian" {
					if name == "sources.list" {
						want = strings.Replace(want, "http://deb.debian.org/debian/ bookworm", archive+" bookworm", 1)
						want = strings.Replace(want, "https://security.debian.org/debian-security", security, 1)
						want = strings.Replace(want, "http://security.debian.org/debian bullseye", security+" bullseye", 1)
					} else if strings.HasSuffix(name, ".sources") {
						want = strings.Replace(want, "URIs: http://deb.debian.org/debian\n", "URIs: "+archive+"\n", 1)
						want = strings.Replace(want, " https://deb.debian.org/debian/ https://vendor", " "+archive+" https://vendor", 1)
						want = strings.Replace(want, "URIs: http://deb.debian.org/debian-security", "URIs: "+security, 1)
						want = strings.Replace(want, "uris: https://deb.debian.org/debian", "uris: "+archive, 1)
					}
				}
				got, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != want {
					t.Fatalf("%s\ngot:\n%s\nwant:\n%s", name, got, want)
				}
			}
			snapshots := map[string]string{}
			for name := range fixtures {
				b, _ := os.ReadFile(filepath.Join(dir, name))
				snapshots[name] = string(b)
			}
			run()
			for name, want := range snapshots {
				got, _ := os.ReadFile(filepath.Join(dir, name))
				if string(got) != want {
					t.Fatalf("not idempotent: %s", name)
				}
			}
		})
	}
}
