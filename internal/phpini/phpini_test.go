package phpini

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BastionPHP/Bastion/internal/sysroot"
)

func put(t *testing.T, root, p, s string) {
	t.Helper()
	full := filepath.Join(root, p)
	os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDebianFPMLayout(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, "etc/php/8.2/fpm/php.ini", "[PHP]\nmemory_limit = 256M ; comment\n;session.upload_progress.enabled = On\npost_max_size = \"64M\"\n")
	put(t, dir, "etc/php/8.2/fpm/conf.d/99-hardening.ini", "session.upload_progress.enabled = Off\n")
	put(t, dir, "etc/php/8.2/fpm/pool.d/www.conf", "[www]\nuser = www-data\nphp_admin_value[memory_limit] = -1\nphp_value[memory_limit] = 512M\n[shop]\nphp_value[session.upload_progress.enabled] = 1\n")
	put(t, dir, "etc/php/8.2/cli/php.ini", "memory_limit = -1\n")
	r := sysroot.Root{Dir: dir}
	l := Locate(r, "/usr/sbin/php-fpm8.2", "8.2", "fpm")
	if len(l.INI) != 2 || len(l.Pools) != 1 {
		t.Fatalf("%+v", l)
	}
	keys := []string{"memory_limit", "session.upload_progress.enabled", "post_max_size"}
	eff := Effective(r, l.INI, keys, map[string]string{"memory_limit": "128M", "session.upload_progress.enabled": "1", "post_max_size": "8M"})
	if eff["memory_limit"].Value != "256M" || eff["post_max_size"].Value != "64M" || Bool(eff["session.upload_progress.enabled"].Value) {
		t.Fatalf("%+v", eff)
	}
	if eff["memory_limit"].Source != "/etc/php/8.2/fpm/php.ini:2" {
		t.Fatalf("source %s", eff["memory_limit"].Source)
	}
	pools := Pools(r, l.Pools, keys)
	if len(pools) != 2 || pools[0].Values["memory_limit"].Value != "-1" || !pools[0].Values["memory_limit"].Admin {
		t.Fatalf("admin value must win: %+v", pools)
	}
	if !Bool(pools[1].Values["session.upload_progress.enabled"].Value) {
		t.Fatalf("%+v", pools[1])
	}
}

func TestOtherLayouts(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, "www/server/php/74/etc/php.ini", "memory_limit=-1\n")
	put(t, dir, "usr/local/etc/php/conf.d/zz.ini", "post_max_size=8M\n")
	put(t, dir, "etc/php83/php.ini", "x=1\n")
	r := sysroot.Root{Dir: dir}
	if l := Locate(r, "/www/server/php/74/bin/php", "7.4", "cli"); len(l.INI) != 1 {
		t.Errorf("baota %+v", l)
	}
	if l := Locate(r, "/usr/local/sbin/php-fpm", "8.3", "fpm"); len(l.INI) != 1 {
		t.Errorf("docker %+v", l)
	}
	if l := Locate(r, "/usr/bin/php83", "8.3", "cli"); len(l.INI) != 1 || l.INI[0] != "/etc/php83/php.ini" {
		t.Errorf("alpine %+v", l)
	}
}

func TestBytes(t *testing.T) {
	for in, want := range map[string]int64{"8M": 8 << 20, "1G": 1 << 30, "512K": 512 << 10, "-1": -1, "1048576": 1048576} {
		if got, ok := Bytes(in); !ok || got != want {
			t.Errorf("%s: %d", in, got)
		}
	}
}
