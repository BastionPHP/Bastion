package advisory

import (
	"encoding/json"
	"os"
	"testing"
)

type vectorFile struct {
	Advisory string `json:"advisory"`
	Cases    []struct {
		Name    string `json:"name"`
		Subject struct {
			Version          string   `json:"version"`
			OS               OS       `json:"os"`
			Package          *Package `json:"package"`
			ChangelogChecked bool     `json:"changelog_checked"`
			ChangelogHits    []string `json:"changelog_hits"`
			Fingerprints     []string `json:"fingerprints"`
			Environment      string   `json:"environment"`
			BuildDate        string   `json:"build_date"`
		} `json:"subject"`
		Status Status `json:"status"`
	} `json:"cases"`
}

func TestBuiltinLoads(t *testing.T) {
	db, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if db.Find("CVE-2026-109619") == nil || db.Find("php2shell") == nil {
		t.Fatal("PHP2Shell advisory not found by alias")
	}
}

func TestSharedVectors(t *testing.T) {
	b, err := os.ReadFile("../../testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(b, &vf); err != nil {
		t.Fatal(err)
	}
	db, _ := Builtin()
	a := db.Find(vf.Advisory)
	for _, c := range vf.Cases {
		s := Subject{
			Version: c.Subject.Version, OS: c.Subject.OS, Package: c.Subject.Package,
			ChangelogChecked: c.Subject.ChangelogChecked, ChangelogHits: c.Subject.ChangelogHits,
			Fingerprints: c.Subject.Fingerprints, Environment: c.Subject.Environment, BuildDate: c.Subject.BuildDate,
		}
		got := a.Evaluate(s)
		if got.Status != c.Status {
			t.Errorf("%s: got %s (%s), want %s", c.Name, got.Status, got.Reason, c.Status)
		}
		if len(got.Evidence) == 0 {
			t.Errorf("%s: no evidence recorded", c.Name)
		}
	}
}

func TestValidateRejectsBadData(t *testing.T) {
	if _, err := Parse([]byte(`{"schema":"bastion.advisory/v1","id":"X","product":"php","branches":[],"older_branches":"affected","newer_branches":"fixed"}`)); err == nil {
		t.Error("expected error for missing branches")
	}
	if _, err := Parse([]byte(`{"schema":"bastion.advisory/v1","id":"X","product":"php","bogus":1}`)); err == nil {
		t.Error("expected error for unknown field")
	}
}
