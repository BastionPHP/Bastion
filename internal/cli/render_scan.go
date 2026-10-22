package cli

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/BastionPHP/Bastion/internal/advisory"
	"github.com/BastionPHP/Bastion/internal/remedy"
	"github.com/BastionPHP/Bastion/internal/scan"
	"github.com/BastionPHP/Bastion/internal/ui"
)

func statusLabel(s ui.Style, st advisory.Status) string {
	switch st {
	case advisory.Vulnerable:
		return s.Red("● VULNERABLE")
	case advisory.LikelyVulnerable:
		return s.Amber("◐ LIKELY VULNERABLE")
	case advisory.Unknown:
		return s.Gray("○ UNKNOWN")
	}
	return s.Green("● FIXED")
}

func statusBadge(s ui.Style, st advisory.Status) string {
	switch st {
	case advisory.Vulnerable:
		return s.BadgeRed("VULNERABLE")
	case advisory.LikelyVulnerable:
		return s.BadgeAmber("LIKELY VULNERABLE")
	case advisory.Unknown:
		return s.BadgeGray("UNKNOWN")
	}
	return s.BadgeGreen("FIXED")
}

func verdictMark(s ui.Style, v string) string {
	switch v {
	case "fixed":
		return s.Green("✓")
	case "vulnerable":
		return s.Red("✗")
	}
	return s.Gray("·")
}

func header(w io.Writer, s ui.Style, title, version string, kv ...string) {
	fmt.Fprintf(w, "\n  %s %s  %s\n", s.Accent("▲"), s.Bold(s.White("BASTION")), s.Faint(version+" · "+title))
	var parts []string
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			continue
		}
		parts = append(parts, s.Faint(kv[i])+" "+kv[i+1])
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, "  %s\n", strings.Join(parts, s.Faint("  ·  ")))
	}
	fmt.Fprintln(w)
}

func section(w io.Writer, s ui.Style, title string, width int) {
	line := strings.Repeat("─", max(0, min(width, 110)-ui.Width(title)-5))
	fmt.Fprintf(w, "  %s %s\n\n", s.Bold(s.White(title)), s.Faint(line))
}

// RenderScan writes the human-readable scan report.
func RenderScan(w io.Writer, s ui.Style, width int, r *scan.Result, verbose bool) {
	osName := r.Host.OS.Pretty
	header(w, s, "PHP exposure scan", r.Tool, "host", r.Host.Hostname, "os", osName, "kernel", r.Host.Kernel, "at", r.StartedAt.Format("2006-01-02 15:04 UTC"))

	for _, a := range r.Advisories {
		ids := make([]string, 0, len(a.Vulnerabilities))
		for _, v := range a.Vulnerabilities {
			ids = append(ids, v.CVE)
		}
		fmt.Fprintf(w, "  %s  %s  %s  %s\n", s.Badge(strings.ToUpper(a.Severity)), s.Bold(a.Name), s.Gray(strings.Join(ids, " · ")), s.Faint(fmt.Sprintf("CVSS %s %.1f · published %s", a.CVSS.Version, a.CVSS.Score, a.Published)))
	}
	fmt.Fprintln(w)

	section(w, s, "PHP INSTANCES", width)
	if len(r.Instances) == 0 {
		fmt.Fprintf(w, "  %s\n\n", s.Gray("No PHP builds found. Use --glob to point Bastion at custom locations."))
	} else {
		t := &ui.Table{Indent: 2, Cols: []ui.Column{{Title: "status"}, {Title: "target", Flex: true, Min: 10}, {Title: "path", Flex: true, Min: 16}, {Title: "sapi"}, {Title: "version"}, {Title: "source", Flex: true, Min: 12}}}
		for _, i := range r.Instances {
			target := "host"
			if i.TargetKind != "host" {
				target = i.Target
			}
			ver := i.Version
			if ver == "" {
				ver = "?"
			}
			p := i.Path
			if i.Stale {
				p += " (replaced)"
			}
			t.Add(statusShort(s, i.Worst()), target, p, sapiShort(i.SAPI), s.White(ver), i.Environment)
		}
		fmt.Fprint(w, t.Render(s, width))
		fmt.Fprintln(w)
	}

	var attention []*scan.Instance
	for _, i := range r.Instances {
		if i.Worst() != advisory.Fixed || verbose || i.Stale {
			attention = append(attention, i)
		}
	}
	if len(attention) > 0 {
		section(w, s, "DETAILS", width)
		for _, i := range attention {
			renderInstance(w, s, width, r, i)
		}
	}

	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "  %s %s\n", s.Amber("!"), s.Gray(warn))
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintln(w)
	}

	c := r.Counts()
	fmt.Fprintf(w, "  %s  %s  %s  %s  %s\n",
		s.Bold("SUMMARY"),
		s.Red(strconv.Itoa(c[advisory.Vulnerable])+" vulnerable"),
		s.Amber(strconv.Itoa(c[advisory.LikelyVulnerable])+" likely vulnerable"),
		s.Gray(strconv.Itoa(c[advisory.Unknown])+" unknown"),
		s.Green(strconv.Itoa(c[advisory.Fixed])+" fixed"))
	fmt.Fprintf(w, "  %s\n\n", s.Faint(fmt.Sprintf("%d instances across %d targets in %s · next: bastion trace · bastion report", len(r.Instances), len(r.Targets), time.Duration(r.DurationMS)*time.Millisecond)))
}

func renderInstance(w io.Writer, s ui.Style, width int, r *scan.Result, i *scan.Instance) {
	where := i.Target
	if i.TargetKind != "host" {
		where = i.TargetKind + ":" + i.Target
	}
	fmt.Fprintf(w, "  %s  %s %s\n", statusBadge(s, i.Worst()), s.Bold(i.Path), s.Faint("@ "+where))
	meta := []string{"sapi " + i.SAPI, "version " + orQ(i.Version) + " (" + i.VersionSource + ")"}
	if i.Package != nil {
		meta = append(meta, "package "+i.Package.Name+" "+i.Package.Version)
	}
	if len(i.PIDs) > 0 {
		meta = append(meta, "running "+pidList(i.PIDs))
	}
	fmt.Fprintf(w, "     %s\n", s.Gray(strings.Join(meta, " · ")))
	if len(i.Aliases) > 0 {
		fmt.Fprintf(w, "     %s\n", s.Faint("also reachable as "+strings.Join(i.Aliases, ", ")))
	}
	for _, n := range i.Notes {
		fmt.Fprintf(w, "     %s %s\n", s.Amber("!"), n)
	}
	for _, a := range i.Assessments {
		adv := findAdv(r, a.Advisory)
		name := a.Advisory
		if adv != nil {
			name = adv.Name
		}
		fmt.Fprintf(w, "     %s %s %s\n", s.Faint("┌"), s.White(name), s.Gray("— "+a.Reason+" · confidence "+a.Confidence))
		for _, e := range a.Evidence {
			lines := ui.Wrap(e.Detail, max(30, width-24))
			for li, l := range lines {
				if li == 0 {
					fmt.Fprintf(w, "     %s %s %s %s\n", s.Faint("│"), verdictMark(s, e.Verdict), s.Faint(ui.Pad(e.Kind, 11)), l)
				} else {
					fmt.Fprintf(w, "     %s   %s %s\n", s.Faint("│"), ui.Pad("", 11), l)
				}
			}
		}
		steps := remedy.Steps(remedy.Input{Environment: i.Environment, SAPI: i.SAPI, Version: i.Version, Package: i.Package, Stale: i.Stale, TargetKind: i.TargetKind, Image: i.Image, Assessment: a, Advisory: adv})
		for si, st := range steps {
			lines := ui.Wrap(st, max(30, width-24))
			label := ""
			if si == 0 {
				label = "fix"
			}
			for li, l := range lines {
				if li == 0 {
					fmt.Fprintf(w, "     %s %s %s %s\n", s.Faint("│"), s.Accent("→"), s.Faint(ui.Pad(label, 11)), s.Accent(l))
				} else {
					fmt.Fprintf(w, "     %s   %s %s\n", s.Faint("│"), ui.Pad("", 11), s.Accent(l))
				}
			}
		}
		fmt.Fprintf(w, "     %s\n", s.Faint("└"))
	}
	if len(i.Mitigations) > 0 {
		fmt.Fprintf(w, "     %s %s %s\n", s.Faint("┌"), s.White("interim mitigations"), s.Gray("— reduce exposure until the update; not a fix"))
		for _, m := range i.Mitigations {
			mark := s.Red("✗")
			if m.OK {
				mark = s.Green("✓")
			}
			src := m.Source
			if src == "default" {
				src = "PHP default"
			}
			line := fmt.Sprintf("%s = %s", m.Setting, orQ(m.Value))
			fmt.Fprintf(w, "     %s %s %s %s %s\n", s.Faint("│"), mark, s.Faint(ui.Pad(m.Scope, 11)), ui.Pad(line, 44), s.Faint("want "+m.Want+" · "+src))
		}
		fmt.Fprintf(w, "     %s\n", s.Faint("└"))
	}
	fmt.Fprintln(w)
}

func findAdv(r *scan.Result, id string) *advisory.Advisory {
	for _, a := range r.Advisories {
		if a.ID == id {
			return a
		}
	}
	return nil
}

func orQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func pidList(p []int) string {
	parts := []string{}
	for i, x := range p {
		if i == 4 {
			parts = append(parts, fmt.Sprintf("+%d", len(p)-4))
			break
		}
		parts = append(parts, strconv.Itoa(x))
	}
	return "pid " + strings.Join(parts, ",")
}

func sapiShort(s string) string {
	if s == "apache2handler" {
		return "mod_php"
	}
	return s
}

// statusShort is the compact label used in the instance table.
func statusShort(s ui.Style, st advisory.Status) string {
	if st == advisory.LikelyVulnerable {
		return s.Amber("◐ LIKELY")
	}
	return statusLabel(s, st)
}
