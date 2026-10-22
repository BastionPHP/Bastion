package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStaticProbe(t *testing.T) {
	bin := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 3<<20)...)
	bin = append(bin, []byte("X-Powered-By: PHP/8.1.34\x00junk\x00Oct 21 2026\x0009:12:44\x00Hard memory limit of\x00")...)
	p := filepath.Join(t.TempDir(), "php")
	if err := os.WriteFile(p, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := StaticProbe(p, []string{"Hard memory limit of", "absent"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsBinary || r.Version != "8.1.34" || r.BuildDate != "2026-10-21" || len(r.Found) != 1 {
		t.Fatalf("%+v", r)
	}
	script := filepath.Join(t.TempDir(), "php-wrapper")
	os.WriteFile(script, []byte("#!/bin/sh\necho X-Powered-By: PHP/9.9.9\n"), 0o755)
	if r, _ := StaticProbe(script, nil); r.IsBinary || r.Version != "" {
		t.Fatalf("script treated as binary: %+v", r)
	}
	if BuildDate("Oct", " 7", "2026") != "2026-10-07" {
		t.Fatal("single-digit day")
	}
}
