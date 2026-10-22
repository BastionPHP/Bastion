package report

import (
	"strings"
	"testing"
	"time"

	"github.com/larptard/bastion/internal/advisory"
	"github.com/larptard/bastion/internal/scan"
	"github.com/larptard/bastion/internal/trace"
)

func TestRenderIsSelfContained(t *testing.T) {
	db, _ := advisory.Builtin()
	a := db.Advisories[0]
	inst := &scan.Instance{Target: "web-01", TargetKind: "host", Path: "/usr/bin/php8.3", SAPI: "cli", Version: "8.3.6", VersionSource: "binary", Environment: "System package (apt)",
		Package: &advisory.Package{Manager: "dpkg", Name: "php8.3-cli", Version: "8.3.6-0ubuntu0.24.04.12", Source: "php8.3"}}
	inst.Assessments = []advisory.Assessment{a.Evaluate(advisory.Subject{Version: "8.3.6", Package: inst.Package, OS: advisory.OS{ID: "ubuntu", VersionID: "24.04"}})}
	sr := &scan.Result{Schema: scan.Schema, Host: scan.Host{Hostname: "web-01<script>"}, Advisories: db.Advisories, Instances: []*scan.Instance{inst}, Targets: []*scan.Target{{Kind: "host", Name: "web-01"}}}
	tm := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	tr := &trace.Result{Schema: trace.Schema, Verdict: trace.VerdictCompromised, Findings: []trace.Finding{{Rule: "php.eval-decoded", Severity: trace.High, Title: trace.Text{"en": "x", "zh": "y"}, Path: "/var/www/a.php", Snippet: "</script><img src=x onerror=alert(1)>", Time: &tm}},
		Timeline: []trace.Event{{Time: tm, Kind: "file", Severity: trace.High, Summary: "flagged", Path: "/var/www/a.php"}}}
	html, err := Render(Input{Scan: sr, Trace: tr, Lang: "auto", Version: "test", Now: tm})
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	for _, bad := range []string{"<script src", "<link ", "src=\"http", "href=\"http://", "@import", "url(http", "<img src=x"} {
		if strings.Contains(s, bad) {
			t.Errorf("report contains %q", bad)
		}
	}
	for _, want := range []string{"web-01&lt;script&gt;", "PHP2Shell", "8.3.6-0ubuntu0.24.04.13", "sudo apt update", "php.eval-decoded", "存在漏洞", "--red"} {
		if !strings.Contains(s, want) {
			t.Errorf("report misses %q", want)
		}
	}
	if strings.Count(s, "</script>") != 2 {
		t.Errorf("embedded data escaped badly: %d </script>", strings.Count(s, "</script>"))
	}
}
