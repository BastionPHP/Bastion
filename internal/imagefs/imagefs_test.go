package imagefs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type entry struct {
	name, body, link string
	typ              byte
}

func layer(t *testing.T, gz bool, es ...entry) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range es {
		h := &tar.Header{Name: e.name, Mode: 0o755, Typeflag: e.typ, Linkname: e.link}
		if e.typ == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(e.body))
	}
	tw.Close()
	if !gz {
		return b.Bytes()
	}
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	w.Write(b.Bytes())
	w.Close()
	return z.Bytes()
}

func archive(t *testing.T, layers ...[]byte) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	add := func(name string, data []byte) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg})
		tw.Write(data)
	}
	var names []string
	for i, l := range layers {
		n := "blobs/sha256/layer" + string(rune('a'+i))
		names = append(names, n)
		add(n, l)
	}
	cfg, _ := json.Marshal(map[string]any{"config": map[string]any{"Env": []string{"PHP_VERSION=8.3.35", "PATH=/usr/bin"}}})
	add("blobs/sha256/config", cfg)
	m, _ := json.Marshal([]map[string]any{{"Config": "blobs/sha256/config", "Layers": names}})
	add("manifest.json", m) // deliberately last, as docker save may do
	tw.Close()
	return b.Bytes()
}

func TestExtract(t *testing.T) {
	outside := t.TempDir()
	l1 := layer(t, false,
		entry{name: "etc/os-release", body: "ID=debian\nVERSION_ID=13\n"},
		entry{name: "usr/local/bin/php", body: "\x7fELF old"},
		entry{name: "usr/local/bin/old-tool", body: "x"},
		entry{name: "usr/share/big/file.txt", body: "not wanted"},
		entry{name: "opt/evil", typ: tar.TypeSymlink, link: outside},
		entry{name: "usr/bin/php", typ: tar.TypeSymlink, link: "/usr/local/bin/php"},
		entry{name: "../../escape/php", body: "nope"},
	)
	l2 := layer(t, true,
		entry{name: "usr/local/bin/php", body: "\x7fELF new"},
		entry{name: "usr/local/bin/.wh.old-tool"},
		entry{name: "opt/evil/php", body: "must not land outside"},
		entry{name: "var/lib/dpkg/.wh..wh..opq"},
	)
	dst := t.TempDir()
	env, err := Extract(bytes.NewReader(archive(t, l1, l2)), dst)
	if err != nil {
		t.Fatal(err)
	}
	if env["PHP_VERSION"] != "8.3.35" {
		t.Errorf("env %v", env)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "usr/local/bin/php")); string(b) != "\x7fELF new" {
		t.Errorf("upper layer did not win: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dst, "usr/share/big/file.txt")); err == nil {
		t.Error("unwanted file extracted")
	}
	if l, _ := os.Readlink(filepath.Join(dst, "usr/bin/php")); l != "/usr/local/bin/php" {
		t.Errorf("symlink %q", l)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("write escaped through a symlink: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(dst, "..", "escape")); err == nil {
		t.Fatal("path traversal")
	}
}

func TestWanted(t *testing.T) {
	for p, want := range map[string]bool{
		"usr/sbin/php-fpm8.2": true, "usr/lib/apache2/modules/libphp8.2.so": true, "var/lib/dpkg/status": true,
		"var/lib/dpkg/info/php8.2-cli.list": true, "var/lib/dpkg/info/libc6.list": false,
		"usr/share/doc/php8.2-cli/changelog.Debian.gz": true, "usr/bin/phpize": false, "etc/passwd": false,
	} {
		if Wanted(p) != want {
			t.Errorf("%s: %v", p, !want)
		}
	}
}
