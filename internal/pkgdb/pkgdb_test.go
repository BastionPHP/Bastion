package pkgdb

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/larptard/bastion/internal/sysroot"
)

func write(t *testing.T, root, p, content string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func gz(s string) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.String()
}

func TestDpkgLookup(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "var/lib/dpkg/status", "Package: php8.3-cli\nStatus: install ok installed\nSource: php8.3 (8.3.6-0ubuntu0.24.04.13)\nVersion: 8.3.6-0ubuntu0.24.04.13\n\nPackage: php8.3-fpm\nStatus: deinstall ok config-files\nVersion: 8.3.6-0ubuntu0.24.04.10\n")
	write(t, dir, "var/lib/dpkg/info/php8.3-cli.list", "/usr\n/usr/bin\n/usr/bin/php8.3\n")
	write(t, dir, "usr/share/doc/php8.3-cli/changelog.Debian.gz", gz("php8.3 (8.3.6-0ubuntu0.24.04.13) noble-security\n  * SECURITY UPDATE\n    - CVE-2026-109618\n"))
	db := &DB{Root: sysroot.Root{Dir: dir}}
	if db.Manager() != "dpkg" {
		t.Fatal(db.Manager())
	}
	info := db.Lookup(context.Background(), "/usr/bin/php8.3", []string{"CVE-2026-109618", "CVE-2026-109619"})
	if info.Package == nil || info.Package.Source != "php8.3" || info.Package.Version != "8.3.6-0ubuntu0.24.04.13" {
		t.Fatalf("%+v", info.Package)
	}
	if !info.ChangelogChecked || len(info.ChangelogHits) != 1 {
		t.Fatalf("changelog: %+v", info)
	}
	// usrmerge: /bin/php8.3 is the same file.
	if db.Lookup(context.Background(), "/bin/php8.3", nil).Package == nil {
		t.Fatal("usrmerge alternative not matched")
	}
	if db.Lookup(context.Background(), "/usr/local/bin/php", nil).Package != nil {
		t.Fatal("unowned file matched")
	}
}

func TestApkLookup(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "lib/apk/db/installed", "C:Q1abc\nP:php83\nV:8.3.36-r0\no:php83\nF:usr/bin\nR:php83\n\nP:musl\nV:1.2.5-r0\nF:lib\nR:ld-musl-x86_64.so.1\n")
	db := &DB{Root: sysroot.Root{Dir: dir}}
	info := db.Lookup(context.Background(), "/usr/bin/php83", nil)
	if info.Package == nil || info.Package.Version != "8.3.36-r0" || info.Package.Manager != "apk" {
		t.Fatalf("%+v", info.Package)
	}
}

func TestRPMLookup(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "var/lib/rpm/rpmdb.sqlite", "")
	fake := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if args[2] == "-qf" {
			return []byte("php-cli\t0:8.0.30-4.el9_6\tphp-8.0.30-4.el9_6.src.rpm\n"), nil
		}
		return []byte("* Mon Oct 20 2026 Remi - 8.0.30-4\n- fix CVE-2026-109618 CVE-2026-109619\n"), nil
	}
	db := &DB{Root: sysroot.Root{Dir: dir}, RPM: fake, RPMRootFlag: true}
	info := db.Lookup(context.Background(), "/usr/bin/php", []string{"CVE-2026-109618", "CVE-2026-109619"})
	if info.Package == nil || info.Package.Source != "php" || info.Package.Version != "8.0.30-4.el9_6" || len(info.ChangelogHits) != 2 {
		t.Fatalf("%+v %+v", info.Package, info)
	}
}
