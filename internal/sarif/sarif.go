// Package sarif converts scan and trace results to SARIF 2.1.0, the format
// GitHub code scanning and most security dashboards import.
package sarif

import (
	"fmt"
	"strings"

	"github.com/larptard/bastion/internal/advisory"
	"github.com/larptard/bastion/internal/scan"
	"github.com/larptard/bastion/internal/trace"
)

const schema = "https://json.schemastore.org/sarif-2.1.0.json"

type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription Message        `json:"shortDescription"`
	FullDescription  *Message       `json:"fullDescription,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type Message struct {
	Text string `json:"text"`
}

type Result struct {
	RuleID     string         `json:"ruleId"`
	Level      string         `json:"level"`
	Message    Message        `json:"message"`
	Locations  []Location     `json:"locations"`
	Properties map[string]any `json:"properties,omitempty"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine int      `json:"startLine"`
	Snippet   *Message `json:"snippet,omitempty"`
}

const infoURI = "https://www.bastionphp.com/"

func fileURI(p string) string {
	return "file://" + strings.ReplaceAll(p, " ", "%20")
}

// FromScan converts a scan. Fixed builds are omitted: SARIF lists problems.
func FromScan(r *scan.Result) Log {
	run := Run{Tool: Tool{Driver: Driver{Name: "Bastion", Version: r.Tool, InformationURI: infoURI}}, Results: []Result{}}
	for _, a := range r.Advisories {
		ids := []string{}
		var help string
		for _, v := range a.Vulnerabilities {
			ids = append(ids, v.CVE)
			if help == "" {
				help = v.URL
			}
		}
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, Rule{
			ID: a.ID, Name: a.Name,
			ShortDescription: Message{Text: a.Name + " (" + strings.Join(ids, ", ") + ")"},
			FullDescription:  &Message{Text: a.Summary.Get("en")},
			HelpURI:          help,
			Properties:       map[string]any{"security-severity": fmt.Sprintf("%.1f", a.CVSS.Score), "tags": append([]string{"security", "php"}, ids...)},
		})
	}
	for _, i := range r.Instances {
		for _, as := range i.Assessments {
			level := map[advisory.Status]string{advisory.Vulnerable: "error", advisory.LikelyVulnerable: "warning", advisory.Unknown: "note"}[as.Status]
			if level == "" {
				continue
			}
			where := i.Target
			if i.TargetKind != "host" {
				where = i.TargetKind + " " + i.Target
			}
			msg := fmt.Sprintf("PHP %s at %s (%s, %s): %s — %s", orQ(i.Version), i.Path, where, i.Environment, as.Status, as.Reason)
			props := map[string]any{"status": as.Status, "confidence": as.Confidence, "target": i.Target, "target_kind": i.TargetKind, "sapi": i.SAPI}
			if as.FixedIn != "" {
				props["fixed_in"] = as.FixedIn
			}
			run.Results = append(run.Results, Result{RuleID: as.Advisory, Level: level, Message: Message{Text: msg},
				Locations: []Location{{PhysicalLocation: PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: fileURI(i.Path)}}}}, Properties: props})
		}
	}
	return Log{Schema: schema, Version: "2.1.0", Runs: []Run{run}}
}

var sevScore = map[string]string{trace.High: "8.0", trace.Medium: "5.5", trace.Low: "3.0", trace.Info: "0.0"}
var sevLevel = map[string]string{trace.High: "error", trace.Medium: "warning", trace.Low: "note", trace.Info: "note"}

// FromTrace converts trace findings.
func FromTrace(r *trace.Result) Log {
	run := Run{Tool: Tool{Driver: Driver{Name: "Bastion", Version: r.Tool, InformationURI: infoURI}}, Results: []Result{}}
	seen := map[string]bool{}
	for _, f := range r.Findings {
		if !seen[f.Rule] {
			seen[f.Rule] = true
			rule := Rule{ID: f.Rule, ShortDescription: Message{Text: f.Title.Get("en")}, Properties: map[string]any{"security-severity": sevScore[f.Severity], "tags": []string{"security", f.Category}}}
			if why := f.Why.Get("en"); why != "" {
				rule.FullDescription = &Message{Text: why}
			}
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
		}
		loc := PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: fileURI(f.Path)}}
		if f.Line > 0 {
			loc.Region = &Region{StartLine: f.Line}
			if f.Snippet != "" {
				loc.Region.Snippet = &Message{Text: f.Snippet}
			}
		}
		props := map[string]any{"severity": f.Severity, "category": f.Category}
		if f.Count > 0 {
			props["count"] = f.Count
		}
		if len(f.Details) > 0 {
			props["details"] = f.Details
		}
		run.Results = append(run.Results, Result{RuleID: f.Rule, Level: sevLevel[f.Severity], Message: Message{Text: f.Title.Get("en") + ": " + f.Path}, Locations: []Location{{PhysicalLocation: loc}}, Properties: props})
	}
	return Log{Schema: schema, Version: "2.1.0", Runs: []Run{run}}
}

func orQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}
