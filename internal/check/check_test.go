package check

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/BastionPHP/Bastion/internal/advisory"
)

func TestPasteVectors(t *testing.T) {
	b, err := os.ReadFile("../../testdata/paste.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf struct {
		Cases []struct {
			Name   string            `json:"name"`
			Text   string            `json:"text"`
			Expect map[string]string `json:"expect"`
			Status advisory.Status   `json:"status"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &vf); err != nil {
		t.Fatal(err)
	}
	db, _ := advisory.Builtin()
	a := db.Find("PHP2SHELL-2026")
	for _, c := range vf.Cases {
		p := Parse(c.Text)
		p.Infer(a)
		got := map[string]string{"version": p.Version, "sapi": p.SAPI}
		if p.Package != nil {
			got["package"], got["package_version"] = p.Package.Name, p.Package.Version
		}
		if p.OS.ID != "" {
			got["os"] = p.OS.ID + " " + p.OS.VersionID
		}
		for k, want := range c.Expect {
			if got[k] != want {
				t.Errorf("%s: %s = %q, want %q", c.Name, k, got[k], want)
			}
		}
		if st := a.Evaluate(p.Subject()).Status; st != c.Status {
			t.Errorf("%s: status %s, want %s (%+v)", c.Name, st, c.Status, p)
		}
	}
}

func TestDebSource(t *testing.T) {
	for in, want := range map[string]string{"php8.3-cli": "php8.3", "libapache2-mod-php8.1": "php8.1", "php5-fpm": "php5", "php-common": "php-common", "php8.3": "php8.3"} {
		if got := DebSource(in); got != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
}
