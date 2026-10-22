package cli

import (
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/larptard/bastion/internal/trace"
	"github.com/larptard/bastion/internal/ui"
)

func sevLabel(s ui.Style, sev string) string {
	switch sev {
	case trace.High:
		return s.Red("▲ HIGH  ")
	case trace.Medium:
		return s.Amber("◆ MEDIUM")
	case trace.Low:
		return s.Blue("● LOW   ")
	}
	return s.Gray("· INFO  ")
}

func sevDot(s ui.Style, sev string) string {
	switch sev {
	case trace.High:
		return s.Red("●")
	case trace.Medium:
		return s.Amber("●")
	case trace.Low:
		return s.Blue("●")
	}
	return s.Faint("○")
}

func verdictBadge(s ui.Style, v string) string {
	switch v {
	case trace.VerdictCompromised:
		return s.BadgeRed("COMPROMISE INDICATORS FOUND")
	case trace.VerdictSuspicious:
		return s.BadgeAmber("SUSPICIOUS — REVIEW NEEDED")
	}
	return s.BadgeGreen("NO INDICATORS FOUND")
}

func verdictText(v string) string {
	switch v {
	case trace.VerdictCompromised:
		return "Strong indicators of compromise. Treat the server as breached: preserve evidence (copy files and logs before changing anything), rotate credentials, and rebuild from a known-good source."
	case trace.VerdictSuspicious:
		return "Weak or ambiguous indicators. Review each finding; most can be confirmed or ruled out by comparing with the original application files."
	}
	return "Nothing matched Bastion's indicators. This is not proof the system is clean: attackers with root can hide from any on-host check."
}

// RenderTrace writes the human-readable trace report.
func RenderTrace(w io.Writer, s ui.Style, width int, r *trace.Result, verbose bool) {
	header(w, s, "intrusion trace", r.Tool, "host", r.Hostname, "os", r.OS, "window", "since "+r.Since.Format("2006-01-02"), "at", r.StartedAt.Format("2006-01-02 15:04 UTC"))

	fmt.Fprintf(w, "  %s\n", verdictBadge(s, r.Verdict))
	for _, l := range ui.Wrap(verdictText(r.Verdict), min(width, 110)-4) {
		fmt.Fprintf(w, "  %s\n", s.Gray(l))
	}
	fmt.Fprintln(w)

	section(w, s, "SCOPE", width)
	t := &ui.Table{Indent: 2, Cols: []ui.Column{{Title: "web root", Flex: true, Min: 20}, {Title: "files"}, {Title: "found via", Flex: true, Min: 12}}}
	for _, wr := range r.Webroots {
		t.Add(wr.Path, strconv.Itoa(wr.Files), wr.Source)
	}
	if len(r.Webroots) > 0 {
		fmt.Fprint(w, t.Render(s, width))
	}
	fmt.Fprintf(w, "  %s\n\n", s.Faint(fmt.Sprintf("%d files (%d PHP, %d changed in window) · %s read · %d log files, %d lines",
		r.Stats.FilesScanned, r.Stats.PHPFiles, r.Stats.RecentPHP, humanBytes(r.Stats.BytesScanned), r.Stats.LogFiles, r.Stats.LogLines)))

	shown := 0
	section(w, s, "FINDINGS", width)
	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "  %s\n\n", s.Gray("none"))
	}
	for _, f := range r.Findings {
		if f.Severity == trace.Info && !verbose {
			continue
		}
		shown++
		loc := f.Path
		if f.Line > 0 {
			loc += ":" + strconv.Itoa(f.Line)
		}
		fmt.Fprintf(w, "  %s  %s %s\n", sevLabel(s, f.Severity), s.Bold(f.Title.Get("en")), s.Faint("["+f.Rule+"]"))
		fmt.Fprintf(w, "            %s", s.Accent(ui.Truncate(loc, max(30, width-14))))
		if f.Count > 0 {
			fmt.Fprintf(w, " %s", s.Faint("×"+strconv.Itoa(f.Count)))
		}
		if f.Time != nil {
			fmt.Fprintf(w, " %s", s.Faint(f.Time.Format("2006-01-02 15:04")))
		}
		fmt.Fprintln(w)
		if f.Snippet != "" {
			fmt.Fprintf(w, "            %s %s\n", s.Faint("│"), s.White(ui.Truncate(f.Snippet, max(30, width-16))))
		}
		if why := f.Why.Get("en"); why != "" {
			for _, l := range ui.Wrap(why, max(30, width-16)) {
				fmt.Fprintf(w, "            %s %s\n", s.Faint("│"), s.Gray(l))
			}
		}
		limit := 3
		if verbose {
			limit = 20
		}
		for i, d := range f.Details {
			if i == limit {
				fmt.Fprintf(w, "            %s %s\n", s.Faint("│"), s.Faint(fmt.Sprintf("… %d more (use -v or --json)", len(f.Details)-limit)))
				break
			}
			fmt.Fprintf(w, "            %s %s\n", s.Faint("│"), s.Faint(ui.Truncate(d, max(30, width-16))))
		}
		fmt.Fprintln(w)
	}
	if shown == 0 && len(r.Findings) > 0 {
		fmt.Fprintf(w, "  %s\n\n", s.Gray("only informational findings (use -v to list them)"))
	}

	renderTimeline(w, s, width, r.Timeline, verbose)

	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "  %s %s\n", s.Amber("!"), s.Gray(warn))
	}
	c := r.Counts()
	fmt.Fprintf(w, "\n  %s  %s  %s  %s  %s\n", s.Bold("SUMMARY"),
		s.Red(strconv.Itoa(c[trace.High])+" high"), s.Amber(strconv.Itoa(c[trace.Medium])+" medium"),
		s.Blue(strconv.Itoa(c[trace.Low])+" low"), s.Gray(strconv.Itoa(c[trace.Info])+" info"))
	fmt.Fprintf(w, "  %s\n\n", s.Faint("completed in "+(time.Duration(r.DurationMS)*time.Millisecond).String()+" · read-only: nothing was modified"))
}

func renderTimeline(w io.Writer, s ui.Style, width int, events []trace.Event, verbose bool) {
	var ev []trace.Event
	for _, e := range events {
		if verbose || e.Severity != trace.Info {
			ev = append(ev, e)
		}
	}
	if len(ev) == 0 {
		return
	}
	section(w, s, "TIMELINE", width)
	const maxEvents = 40
	if len(ev) > maxEvents && !verbose {
		fmt.Fprintf(w, "  %s\n", s.Faint(fmt.Sprintf("showing the latest %d of %d events", maxEvents, len(ev))))
		ev = ev[len(ev)-maxEvents:]
	}
	lastDay := ""
	for i, e := range ev {
		day := e.Time.Format("2006-01-02")
		if day != lastDay {
			fmt.Fprintf(w, "  %s\n", s.White(day))
			lastDay = day
		}
		branch := "├─"
		if i == len(ev)-1 || ev[i+1].Time.Format("2006-01-02") != day {
			branch = "└─"
		}
		summary := e.Summary
		if e.Path != "" {
			summary += "  " + e.Path
		}
		fmt.Fprintf(w, "  %s %s %s %s %s\n", s.Faint(branch), s.Gray(e.Time.Format("15:04:05")), sevDot(s, e.Severity), s.Faint(ui.Pad(e.Kind, 11)), ui.Truncate(summary, max(30, width-36)))
	}
	fmt.Fprintln(w)
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return strconv.FormatInt(n, 10) + " B"
}
