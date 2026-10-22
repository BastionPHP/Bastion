package sysroot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveStaysInsideRoot(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "usr/bin"), 0o755))
	must(os.MkdirAll(filepath.Join(dir, "etc/alternatives"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "usr/bin/php8.3"), []byte("x"), 0o755))
	// Absolute links must be resolved against the tree, not the host.
	must(os.Symlink("/etc/alternatives/php", filepath.Join(dir, "usr/bin/php")))
	must(os.Symlink("/usr/bin/php8.3", filepath.Join(dir, "etc/alternatives/php")))
	r := Root{Dir: dir}
	got, err := r.Resolve("/usr/bin/php")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/usr/bin/php8.3" {
		t.Fatalf("got %s", got)
	}
	if m := r.Glob("/usr/bin/php*"); len(m) != 2 || m[0] != "/usr/bin/php" {
		t.Fatalf("glob: %v", m)
	}
}

func TestParseOSRelease(t *testing.T) {
	o := ParseOSRelease("PRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n")
	if o.ID != "ubuntu" || o.VersionID != "24.04" || o.Codename != "noble" || o.IDLike[0] != "debian" {
		t.Fatalf("%+v", o)
	}
}
