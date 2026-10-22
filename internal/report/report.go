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
	Lang    string
	Version string
	// Now overrides the generation time (tests).
	Now time.Time
}

type statusInfo struct{ En, Zh string }

var statusText = map[advisory.Status]statusInfo{
	advisory.Vulnerable:       {"Vulnerable", "存在漏洞"},
	advisory.LikelyVulnerable: {"Likely vulnerable", "很可能存在漏洞"},
	advisory.Unknown:          {"Unknown", "无法判断"},
	advisory.Fixed:            {"Fixed", "已修复"},
}

var sevText = map[string]statusInfo{
	trace.High: {"High", "高"}, trace.Medium: {"Medium", "中"}, trace.Low: {"Low", "低"}, trace.Info: {"Info", "信息"},
}

type assessmentView struct {
	Advisory   string
	Status     string
	StatusEn   string
	StatusZh   string
	Reason     string
	Confidence string
	Evidence   []advisory.Evidence
	Steps      []string
}

type instanceView struct {
	*scan.Instance
	Status   string
	StatusEn string
	StatusZh string
	Where    string
	Views    []assessmentView
}

type dayView struct {
	Day    string
	Events []trace.Event
}

type findingView struct {
	trace.Finding
	SevEn, SevZh string
	Loc          string
}

type view struct {
	Lang, Version, Generated     string
	CSS                          template.CSS
	JS                           template.JS
	Logo                         template.HTML
	Scan                         *scan.Result
	Trace                        *trace.Result
	Instances                    []instanceView
	Worst                        string
	WorstEn, WorstZh             string
	Counts                       map[string]int
	TraceCounts                  map[string]int
	Findings                     []findingView
	Days                         []dayView
	VerdictEn, VerdictZh         string
	VerdictTextEn, VerdictTextZh string
	DataJSON                     template.JS
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
	"tx":    func(t trace.Text, lang string) string { return t[lang] },
	"pct": func(n, total int) int {
		if total == 0 {
			return 0
		}
		return n * 100 / total
	},
	"add": func(a, b int) int { return a + b },
}

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
	lang := in.Lang
	if lang != "en" && lang != "zh" {
		lang = "auto"
	}
	v := view{Lang: lang, Version: in.Version, Generated: now.UTC().Format("2006-01-02 15:04 UTC"), CSS: template.CSS(design.CSS + "\n" + string(css)), JS: template.JS(js), Logo: template.HTML(design.Logo), Scan: in.Scan, Trace: in.Trace}

	v.Counts = map[string]int{}
	worst := advisory.Fixed
	if in.Scan != nil {
		for _, inst := range in.Scan.Instances {
			iv := instanceView{Instance: inst, Status: string(inst.Worst())}
			iv.StatusEn, iv.StatusZh = statusText[inst.Worst()].En, statusText[inst.Worst()].Zh
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
				av := assessmentView{Advisory: name, Status: string(a.Status), StatusEn: statusText[a.Status].En, StatusZh: statusText[a.Status].Zh, Reason: a.Reason, Confidence: a.Confidence, Evidence: a.Evidence}
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
	v.Worst, v.WorstEn, v.WorstZh = string(worst), statusText[worst].En, statusText[worst].Zh

	if in.Trace != nil {
		v.TraceCounts = in.Trace.Counts()
		for _, f := range in.Trace.Findings {
			fv := findingView{Finding: f, SevEn: sevText[f.Severity].En, SevZh: sevText[f.Severity].Zh, Loc: f.Path}
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
			v.VerdictEn, v.VerdictZh = "Compromise indicators found", "发现入侵迹象"
			v.VerdictTextEn = "Strong indicators of compromise. Treat the server as breached: preserve evidence (copy files and logs before changing anything), rotate credentials, and rebuild from a known-good source."
			v.VerdictTextZh = "存在明显的入侵迹象。请按已被入侵处理：先保全证据（在改动任何东西之前复制文件和日志），轮换所有凭据，并从可信来源重建。"
		case trace.VerdictSuspicious:
			v.VerdictEn, v.VerdictZh = "Suspicious — review needed", "可疑，需要人工复核"
			v.VerdictTextEn = "Weak or ambiguous indicators. Review each finding; most can be confirmed or ruled out by comparing with the original application files."
			v.VerdictTextZh = "存在较弱或不确定的迹象。请逐条复核，多数可以通过与应用原始文件对比来确认或排除。"
		default:
			v.VerdictEn, v.VerdictZh = "No indicators found", "未发现入侵迹象"
			v.VerdictTextEn = "Nothing matched Bastion's indicators. This is not proof the system is clean: attackers with root can hide from any on-host check."
			v.VerdictTextZh = "没有命中 Bastion 的任何检测项。但这并不能证明系统是干净的：拿到 root 的攻击者可以躲过任何本机检查。"
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
