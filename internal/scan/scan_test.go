package scan

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/larptard/bastion/internal/advisory"
)

// fakeELF builds a file that looks like a PHP build to the static probe:
// an ELF header followed by the SAPI version literal and optional extras.
func fakeELF(version string, extra ...string) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	b.Write(bytes.Repeat([]byte{0}, 4096))
	b.WriteString("X-Powered-By: PHP/" + version + "\x00")
	for _, e := range extra {
		b.WriteString(e + "\x00")
	}
	b.Write(bytes.Repeat([]byte{0}, 4096))
	return b.Bytes()
}

func write(t *testing.T, root, p string, b []byte) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func TestScanSysroot(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", []byte("ID=ubuntu\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04.5 LTS\"\n"))
	// Distribution package with a vendor backport.
	write(t, root, "usr/bin/php8.1", fakeELF("8.1.2-1ubuntu2.28"))
	if err := os.Symlink("/etc/alternatives/php", filepath.Join(root, "usr/bin/php")); err != nil {
		t.Fatal(err)
	}
	write(t, root, "etc/alternatives/.keep", nil)
	os.Symlink("/usr/bin/php8.1", filepath.Join(root, "etc/alternatives/php"))
	write(t, root, "var/lib/dpkg/status", []byte("Package: php8.1-cli\nStatus: install ok installed\nSource: php8.1\nVersion: 8.1.2-1ubuntu2.28\n\nPackage: php8.1-fpm\nStatus: install ok installed\nSource: php8.1\nVersion: 8.1.2-1ubuntu2.27\n"))
	write(t, root, "var/lib/dpkg/info/php8.1-cli.list", []byte("/usr/bin/php8.1\n"))
	write(t, root, "var/lib/dpkg/info/php8.1-fpm.list", []byte("/usr/sbin/php-fpm8.1\n"))
	write(t, root, "usr/sbin/php-fpm8.1", fakeELF("8.1.2-1ubuntu2.27"))
	write(t, root, "usr/share/doc/php8.1-cli/changelog.Debian.gz", gz("php8.1 (8.1.2-1ubuntu2.28) jammy-security\n  * CVE-2026-109618\n"))
	// BaoTa source builds.
	write(t, root, "www/server/php/74/bin/php", fakeELF("7.4.33"))
	write(t, root, "www/server/php/83/sbin/php-fpm", fakeELF("8.3.36", "Hard memory limit of"))
	// cPanel EA4.
	write(t, root, "opt/cpanel/ea-php82/root/usr/sbin/php-fpm", fakeELF("8.2.34"))
	// Not PHP: a shell script named like a helper, and a non-binary.
	write(t, root, "usr/bin/phpize", []byte("#!/bin/sh\n"))
	write(t, root, "usr/local/bin/php", []byte("#!/bin/sh\nexec docker run php \"$@\"\n"))

	db, _ := advisory.Builtin()
	res, err := Run(context.Background(), Options{DB: db, SysRoot: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		status advisory.Status
		env    string
	}{
		"/usr/bin/php8.1":                            {advisory.Fixed, "System package (apt)"},
		"/usr/sbin/php-fpm8.1":                       {advisory.Vulnerable, "System package (apt)"},
		"/www/server/php/74/bin/php":                 {advisory.LikelyVulnerable, "BaoTa / aaPanel"},
		"/www/server/php/83/sbin/php-fpm":            {advisory.Fixed, "BaoTa / aaPanel"},
		"/opt/cpanel/ea-php82/root/usr/sbin/php-fpm": {advisory.Vulnerable, "cPanel EasyApache 4"},
	}
	got := map[string]*Instance{}
	for _, i := range res.Instances {
		got[i.Path] = i
	}
	if len(got) != len(want) {
		for p := range got {
			t.Log("found", p)
		}
		t.Fatalf("found %d instances, want %d", len(got), len(want))
	}
	for p, w := range want {
		i := got[p]
		if i == nil {
			t.Errorf("%s not found", p)
			continue
		}
		if i.Worst() != w.status || i.Environment != w.env {
			t.Errorf("%s: %s / %s, want %s / %s (%s)", p, i.Worst(), i.Environment, w.status, w.env, i.Assessments[0].Reason)
		}
	}
	if a := got["/usr/bin/php8.1"].Aliases; len(a) != 1 || a[0] != "/usr/bin/php" {
		t.Errorf("aliases %v", a)
	}
	if got["/usr/sbin/php-fpm8.1"].SAPI != "fpm" {
		t.Error("sapi")
	}
	// Results are sorted worst first.
	if res.Instances[0].Worst() != advisory.Vulnerable {
		t.Error("not sorted")
	}
}
