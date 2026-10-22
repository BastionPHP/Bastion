// Package report renders a single-file HTML report that works offline: all
// CSS, JS, icons and data are inlined, nothing is fetched.
package report

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/larptard/bastion/design"
	"github.com/larptard/bastion/internal/advisory"
	"github.com/larptard/bastion/internal/remedy"
	"github.com/larptard/bastion/internal/scan"
	"github.com/larptard/bastion/internal/trace"
)

//go:embed report.html.tmpl report.css report.js
var assets embed.FS

type Input struct {
	Scan    *scan.Result
	Trace   *trace.Result
	Version string
	// Now overrides the generation time (tests).
	Now time.Time
}

type statusInfo struct{ En string }

var statusText = map[advisory.Status]statusInfo{
	advisory.Vulnerable:       {"Vulnerable"},
	advisory.LikelyVulnerable: {"Likely vulnerable"},
	advisory.Unknown:          {"Unknown"},
	advisory.Fixed:            {"Fixed"},
}

var sevText = map[string]statusInfo{
	trace.High: {"High"}, trace.Medium: {"Medium"}, trace.Low: {"Low"}, trace.Info: {"Info"},
}

type assessmentView struct {
	Advisory   string
	Status     string
	StatusEn   string
	Reason     string
	Confidence string
	Evidence   []advisory.Evidence
	Steps      []string
}

type instanceView struct {
	*scan.Instance
	KindIcon string
	Status   string
	StatusEn string
	Where    string
	Views    []assessmentView
}

type dayView struct {
	Day    string
	Events []trace.Event
}

type findingView struct {
	trace.Finding
	SevEn string
	Loc   string
}

type view struct {
	Version, Generated string
	CSS                template.CSS
	JS                 template.JS
	Logo               template.HTML
	Scan               *scan.Result
	Trace              *trace.Result
	Instances          []instanceView
	Worst              string
	WorstEn            string
	Counts             map[string]int
	TraceCounts        map[string]int
	Findings           []findingView
	Days               []dayView
	VerdictEn          string
	VerdictIcon        string
	TargetKinds        map[string]int
	VerdictTextEn      string
	DataJSON           template.JS
}

var funcs = template.FuncMap{
	"join":  strings.Join,
	"lower": strings.ToLower,
	"fmtTime": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format("2006-01-02 15:04")
	},
	"clock": func(t time.Time) string { return t.UTC().Format("15:04:05") },
	"pct": func(n, total int) int {
		if total == 0 {
			return 0
		}
		return n * 100 / total
	},
	"add":  func(a, b int) int { return a + b },
	"icon": design.Icon,
	"statusTag": func(status, text string) template.HTML {
		return template.HTML(`<span class="tag" data-status="`+template.HTMLEscapeString(status)+`">`) + design.Icon(statusIcon[status]) + template.HTML(template.HTMLEscapeString(text)+`</span>`)
	},
	"evIcon": func(v string) string {
		return map[string]string{"fixed": "check", "vulnerable": "x"}[v] + map[bool]string{true: "circle-dot"}[v != "fixed" && v != "vulnerable"]
	},
	"sevIcon": func(s string) string { return sevIcon[s] },
	"catIcon": func(c string) string {
		if i, ok := map[string]string{"file": "file-code", "config": "settings-2", "persistence": "key-round", "log": "scroll-text"}[c]; ok {
			return i
		}
		return "circle-dot"
	},
	"sapi": func(s string) string {
		if s == "apache2handler" {
			return "mod_php"
		}
		return s
	},
}

var statusIcon = map[string]string{"fixed": "shield-check", "vulnerable": "shield-x", "likely-vulnerable": "shield-alert", "unknown": "shield-question"}

var sevIcon = map[string]string{trace.High: "triangle-alert", trace.Medium: "circle-dot", trace.Low: "circle-dashed", trace.Info: "info"}

var kindIcon = map[string]string{"host": "server", "container": "container", "image": "layers", "namespace": "boxes", "sysroot": "hard-drive"}

// Render builds the report.
func Render(in Input) ([]byte, error) {
	tmplSrc, err := assets.ReadFile("report.html.tmpl")
	if err != nil {
		return nil, err
	}
	css, _ := assets.ReadFile("report.css")
	js, _ := assets.ReadFile("report.js")
	t, err := template.New("report").Funcs(funcs).Parse(string(tmplSrc))
	if err != nil {
		return nil, err
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	v := view{Version: in.Version, Generated: now.UTC().Format("2006-01-02 15:04 UTC"), CSS: template.CSS(design.CSS + "\n" + string(css)), JS: template.JS(js), Logo: template.HTML(design.Logo), Scan: in.Scan, Trace: in.Trace}

	v.Counts = map[string]int{}
	v.TargetKinds = map[string]int{}
	if in.Scan != nil {
		for _, t := range in.Scan.Targets {
			k := t.Kind
			if k != "host" && k != "sysroot" {
				k += "s"
				v.TargetKinds[k]++
			}
		}
	}
	worst := advisory.Fixed
	if in.Scan != nil {
		for _, inst := range in.Scan.Instances {
			iv := instanceView{Instance: inst, Status: string(inst.Worst()), KindIcon: kindIcon[inst.TargetKind]}
			if iv.KindIcon == "" {
				iv.KindIcon = "server"
			}
			iv.StatusEn = statusText[inst.Worst()].En
			iv.Where = inst.Target
			if inst.TargetKind != "host" {
				iv.Where = inst.TargetKind + ":" + inst.Target
			}
			for _, a := range inst.Assessments {
				adv := findAdv(in.Scan.Advisories, a.Advisory)
				name := a.Advisory
				if adv != nil {
					name = adv.Name
				}
				av := assessmentView{Advisory: name, Status: string(a.Status), StatusEn: statusText[a.Status].En, Reason: a.Reason, Confidence: a.Confidence, Evidence: a.Evidence}
				av.Steps = remedy.Steps(remedy.Input{Environment: inst.Environment, SAPI: inst.SAPI, Version: inst.Version, Package: inst.Package, Stale: inst.Stale, TargetKind: inst.TargetKind, Image: inst.Image, Assessment: a, Advisory: adv})
				iv.Views = append(iv.Views, av)
			}
			v.Instances = append(v.Instances, iv)
			v.Counts[string(inst.Worst())]++
			if inst.Worst().Severity() > worst.Severity() {
				worst = inst.Worst()
			}
		}
	}
	v.Worst, v.WorstEn = string(worst), statusText[worst].En

	if in.Trace != nil {
		v.TraceCounts = in.Trace.Counts()
		for _, f := range in.Trace.Findings {
			fv := findingView{Finding: f, SevEn: sevText[f.Severity].En, Loc: f.Path}
			if f.Line > 0 {
				fv.Loc += ":" + itoa(f.Line)
			}
			v.Findings = append(v.Findings, fv)
		}
		// Newest day first, events within a day in order.
		byDay := map[string][]trace.Event{}
		for _, e := range in.Trace.Timeline {
			d := e.Time.UTC().Format("2006-01-02")
			byDay[d] = append(byDay[d], e)
		}
		for d, evs := range byDay {
			v.Days = append(v.Days, dayView{Day: d, Events: evs})
		}
		sort.Slice(v.Days, func(i, j int) bool { return v.Days[i].Day > v.Days[j].Day })
		switch in.Trace.Verdict {
		case trace.VerdictCompromised:
			v.VerdictEn = "Compromise indicators found"
			v.VerdictIcon = "triangle-alert"
			v.VerdictTextEn = "Strong indicators of compromise. Treat the server as breached: preserve evidence (copy files and logs before changing anything), rotate credentials, and rebuild from a known-good source."
		case trace.VerdictSuspicious:
			v.VerdictEn = "Suspicious — review needed"
			v.VerdictIcon = "circle-dot"
			v.VerdictTextEn = "Weak or ambiguous indicators. Review each finding; most can be confirmed or ruled out by comparing with the original application files."
		default:
			v.VerdictEn = "No indicators found"
			v.VerdictIcon = "circle-check"
			v.VerdictTextEn = "Nothing matched Bastion's indicators. This is not proof the system is clean: attackers with root can hide from any on-host check."
		}
	}

	data := map[string]any{"scan": in.Scan, "trace": in.Trace, "generated": now.UTC()}
	b, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	// Keep the embedded JSON inert inside <script>.
	js2 := strings.NewReplacer("<", `<`, ">", `>`, "&", `&`, " ", ` `, " ", ` `).Replace(string(b))
	v.DataJSON = template.JS(js2)

	var buf bytes.Buffer
	if err := t.Execute(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func findAdv(advs []*advisory.Advisory, id string) *advisory.Advisory {
	for _, a := range advs {
		if a.ID == id {
			return a
		}
	}
	return nil
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
