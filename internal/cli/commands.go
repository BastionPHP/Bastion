package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BastionPHP/Bastion/internal/advisory"
	"github.com/BastionPHP/Bastion/internal/check"
	"github.com/BastionPHP/Bastion/internal/report"
	"github.com/BastionPHP/Bastion/internal/sarif"
	"github.com/BastionPHP/Bastion/internal/scan"
	"github.com/BastionPHP/Bastion/internal/trace"
	"github.com/BastionPHP/Bastion/internal/ui"
)

type traceFlags struct {
	sysroot   string
	since     time.Duration
	noAuto    bool
	noLogs    bool
	noPersist bool
	logs      multiFlag
	maxSize   int64
}

func (f *traceFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.sysroot, "sysroot", "", "inspect a mounted filesystem (image, backup) instead of the live host")
	fs.DurationVar(&f.since, "since", 30*24*time.Hour, "time window for log analysis and the change timeline (e.g. 72h, 720h)")
	fs.BoolVar(&f.noAuto, "no-auto", false, "only scan directories given as arguments (no web root discovery)")
	fs.BoolVar(&f.noLogs, "no-logs", false, "skip web server / PHP log analysis")
	fs.BoolVar(&f.noPersist, "no-persistence", false, "skip cron, systemd, SSH key and account checks")
	fs.Var(&f.logs, "log", "extra log file or glob to analyse (repeatable)")
	fs.Int64Var(&f.maxSize, "max-file-size", 4<<20, "read at most this many bytes per file")
}

func (e *env) runTrace(ctx context.Context, c *common, f *traceFlags, dirs []string) (*trace.Result, error) {
	opt := trace.Options{SysRoot: f.sysroot, Webroots: dirs, NoAutoRoots: f.noAuto, Logs: f.logs, NoLogs: f.noLogs, NoPersist: f.noPersist, Since: f.since, MaxFileSize: f.maxSize, Progress: e.progress(c)}
	res, err := trace.Run(ctx, opt, Version)
	e.clearProgress(c)
	return res, err
}

func traceExit(r *trace.Result) int {
	switch r.Verdict {
	case trace.VerdictCompromised:
		return ExitAffected
	case trace.VerdictSuspicious:
		return ExitUnknown
	}
	return ExitOK
}

func (e *env) cmdTrace(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet("trace", "trace [flags] [web-root …]")
	var c common
	var f traceFlags
	c.register(fs)
	f.register(fs)
	if err := parse(fs, args); err != nil {
		return 0, err
	}
	if f.noAuto && fs.NArg() == 0 {
		return 0, usageErr{fmt.Errorf("--no-auto needs at least one directory")}
	}
	res, err := e.runTrace(ctx, &c, &f, fs.Args())
	if err != nil {
		return 0, err
	}
	switch {
	case c.format == "sarif":
		return traceExit(res), writeJSON(e.stdout, sarif.FromTrace(res))
	case c.machine():
		return traceExit(res), writeJSON(e.stdout, res)
	}
	RenderTrace(e.stdout, e.style(&c), ui.TerminalWidth(e.outFile), res, c.verbose)
	return traceExit(res), nil
}

func (e *env) cmdReport(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet("report", "report [flags] [web-root …]")
	var c common
	var sf scanFlags
	var tf traceFlags
	c.register(fs)
	sf.register(fs)
	var out, fromScan, fromTrace string
	var noTrace bool
	fs.StringVar(&out, "o", "", "output file (default bastion-report-<host>-<date>.html)")
	fs.StringVar(&fromScan, "scan", "", "build the report from a saved bastion scan --json file instead of scanning")
	fs.StringVar(&fromTrace, "trace", "", "build the report from a saved bastion trace --json file instead of tracing")
	fs.BoolVar(&noTrace, "no-trace", false, "only include the vulnerability scan")
	fs.DurationVar(&tf.since, "since", 30*24*time.Hour, "trace time window")
	fs.BoolVar(&tf.noLogs, "no-logs", false, "skip log analysis")
	if err := parse(fs, args); err != nil {
		return 0, err
	}
	tf.sysroot, tf.maxSize = sf.sysroot, 4<<20
	c.quiet = c.quiet || c.machine()

	var sr *scan.Result
	var tr *trace.Result
	var err error
	if fromScan != "" {
		if sr, err = readJSON[scan.Result](fromScan); err != nil {
			return 0, err
		}
	} else if sr, err = e.runScan(ctx, &c, &sf); err != nil {
		return 0, err
	}
	switch {
	case fromTrace != "":
		if tr, err = readJSON[trace.Result](fromTrace); err != nil {
			return 0, err
		}
	case !noTrace && fromScan == "":
		if tr, err = e.runTrace(ctx, &c, &tf, fs.Args()); err != nil {
			return 0, err
		}
	}
	if out == "" {
		host := sanitize(sr.Host.Hostname)
		out = fmt.Sprintf("bastion-report-%s-%s.html", host, sr.StartedAt.Format("20060102-1504"))
	}
	html, err := report.Render(report.Input{Scan: sr, Trace: tr, Version: Version})
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(out, html, 0o600); err != nil {
		return 0, err
	}
	s := e.style(&c)
	abs, _ := filepath.Abs(out)
	fmt.Fprintf(e.stdout, "\n  %s report written  %s\n  %s\n\n", s.Green("✓"), s.Bold(abs), s.Faint(fmt.Sprintf("%s · single file, works offline · contains host details: share with care", humanBytes(int64(len(html))))))
	code := scanExit(sr)
	if tr != nil && traceExit(tr) < code || tr != nil && code == ExitOK {
		code = max(code, traceExit(tr))
	}
	return code, nil
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "host"
	}
	return b.String()
}

func (e *env) cmdCheck(args []string) (int, error) {
	fs := newFlagSet("check", `check [flags] ["php -v output" | -]`)
	var c common
	c.register(fs)
	var osFlag string
	fs.StringVar(&osFlag, "os", "", "distribution as id:version (e.g. ubuntu:24.04) when the pasted text does not say")
	if err := parse(fs, args); err != nil {
		return 0, err
	}
	var input string
	if fs.NArg() == 0 || fs.Arg(0) == "-" {
		b, err := io.ReadAll(bufio.NewReader(os.Stdin))
		if err != nil {
			return 0, err
		}
		input = string(b)
	} else {
		input = strings.Join(fs.Args(), " ")
	}
	db, err := c.loadDB()
	if err != nil {
		return 0, err
	}
	parsed := check.Parse(input)
	if osFlag != "" {
		id, ver, _ := strings.Cut(osFlag, ":")
		parsed.OS = advisory.OS{ID: strings.ToLower(id), VersionID: ver}
	}
	if parsed.Version == "" && parsed.Package == nil {
		return 0, usageErr{fmt.Errorf("no PHP version found in the input; paste the output of `php -v` (and optionally `dpkg -l | grep php` or `rpm -q php-cli`)")}
	}
	var results []advisory.Assessment
	worst := advisory.Fixed
	for _, a := range db.Advisories {
		if a.Product != "php" {
			continue
		}
		parsed.Infer(a)
		as := a.Evaluate(parsed.Subject())
		results = append(results, as)
		if as.Status.Severity() > worst.Severity() {
			worst = as.Status
		}
	}
	code := map[advisory.Status]int{advisory.Fixed: ExitOK, advisory.Vulnerable: ExitAffected, advisory.LikelyVulnerable: ExitAffected, advisory.Unknown: ExitUnknown}[worst]
	if c.machine() {
		return code, writeJSON(e.stdout, map[string]any{"input": parsed, "assessments": results})
	}
	s := e.style(&c)
	fmt.Fprintln(e.stdout)
	fmt.Fprintf(e.stdout, "  %s %s\n", s.Faint("parsed"), parsed.Describe())
	for _, as := range results {
		fmt.Fprintf(e.stdout, "\n  %s  %s %s\n", statusBadge(s, as.Status), s.Bold(db.Find(as.Advisory).Name), s.Gray("— "+as.Reason))
		for _, ev := range as.Evidence {
			fmt.Fprintf(e.stdout, "     %s %s %s\n", verdictMark(s, ev.Verdict), s.Faint(ui.Pad(ev.Kind, 11)), ev.Detail)
		}
	}
	fmt.Fprintln(e.stdout)
	return code, nil
}

func (e *env) cmdAdvisories(args []string) (int, error) {
	fs := newFlagSet("advisories", "advisories [--json]")
	var c common
	c.register(fs)
	if err := parse(fs, args); err != nil {
		return 0, err
	}
	db, err := c.loadDB()
	if err != nil {
		return 0, err
	}
	if c.machine() {
		return 0, writeJSON(e.stdout, db.Advisories)
	}
	s := e.style(&c)
	width := ui.TerminalWidth(e.outFile)
	for _, a := range db.Advisories {
		fmt.Fprintf(e.stdout, "\n  %s  %s  %s\n", s.Badge(strings.ToUpper(a.Severity)), s.Bold(a.Name), s.Faint(a.ID+" · published "+a.Published+fmt.Sprintf(" · CVSS %s %.1f", a.CVSS.Version, a.CVSS.Score)))
		for _, v := range a.Vulnerabilities {
			fmt.Fprintf(e.stdout, "     %s %s  %s\n", s.White(v.CVE), s.Faint(v.GHSA), v.Title.Get("en"))
		}
		fmt.Fprintln(e.stdout)
		t := &ui.Table{Indent: 5, Cols: []ui.Column{{Title: "branch"}, {Title: "fixed in"}, {Title: "status"}, {Title: "note", Flex: true, Min: 20}}}
		for _, b := range a.Branches {
			fixed := b.Fixed
			if fixed == "" {
				fixed = s.Red("no release")
			} else {
				fixed = s.Green(fixed)
			}
			note := b.Note.Get("en")
			if b.SourceBackport != "" {
				note = "source backport: " + b.SourceBackport
			}
			t.Add(b.Branch, fixed, b.Status, note)
		}
		fmt.Fprint(e.stdout, t.Render(s, width))
		fmt.Fprintln(e.stdout)
		vt := &ui.Table{Indent: 5, Cols: []ui.Column{{Title: "distro"}, {Title: "release"}, {Title: "package"}, {Title: "fixed version"}, {Title: "advisory"}}}
		for _, f := range a.VendorFixes {
			vt.Add(f.Distro, f.Release, f.Package, s.Green(f.Fixed), f.Advisory+" "+s.Faint(f.Channel))
		}
		fmt.Fprint(e.stdout, vt.Render(s, width))
		fmt.Fprintf(e.stdout, "\n     %s\n", s.Faint(fmt.Sprintf("%d vendor fixes · %d changelog markers · %d binary fingerprints", len(a.VendorFixes), len(a.ChangelogMarkers), len(a.Fingerprints))))
	}
	fmt.Fprintln(e.stdout)
	return 0, nil
}

func readJSON[T any](path string) (*T, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v T
	if err := jsonUnmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &v, nil
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
