package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/larptard/bastion/internal/advisory"
	"github.com/larptard/bastion/internal/scan"
	"github.com/larptard/bastion/internal/trace"
)

func TestFromScanAndTrace(t *testing.T) {
	db, _ := advisory.Builtin()
	a := db.Advisories[0]
	vuln := &scan.Instance{Target: "web-01", TargetKind: "host", Path: "/usr/bin/php8.3", Version: "8.3.35", Assessments: []advisory.Assessment{a.Evaluate(advisory.Subject{Version: "8.3.35"})}}
	fixed := &scan.Instance{Target: "web-01", TargetKind: "host", Path: "/usr/bin/php8.4", Version: "8.4.27", Assessments: []advisory.Assessment{a.Evaluate(advisory.Subject{Version: "8.4.27"})}}
	log := FromScan(&scan.Result{Tool: "test", Advisories: db.Advisories, Instances: []*scan.Instance{vuln, fixed}})
	b, _ := json.Marshal(log)
	s := string(b)
	if log.Version != "2.1.0" || len(log.Runs[0].Results) != 1 || log.Runs[0].Results[0].Level != "error" || !strings.Contains(s, `"security-severity":"9.2"`) || !strings.Contains(s, "file:///usr/bin/php8.3") {
		t.Fatalf("%s", s)
	}
	tr := FromTrace(&trace.Result{Tool: "test", Findings: []trace.Finding{{Rule: "php.eval-decoded", Severity: trace.High, Title: trace.Text{"en": "eval"}, Path: "/var/www/a.php", Line: 3, Snippet: "eval("}}})
	if r := tr.Runs[0].Results[0]; r.Level != "error" || r.Locations[0].PhysicalLocation.Region.StartLine != 3 {
		t.Fatalf("%+v", r)
	}
}
