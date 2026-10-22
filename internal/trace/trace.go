// Package trace looks for evidence that a PHP site has already been
// compromised: backdoored files, persistence mechanisms and log traces.
// It reads files only; nothing is quarantined, deleted or modified.
package trace

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/larptard/bastion/internal/sysroot"
)

const Schema = "bastion.trace/v1"

// Severity levels, strongest first.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
	Info   = "info"
)

func sevRank(s string) int {
	switch s {
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	}
	return 0
}

// Verdicts.
const (
	VerdictCompromised = "compromised"
	VerdictSuspicious  = "suspicious"
	VerdictClean       = "no-indicators"
)

type Options struct {
	SysRoot string
	// Webroots are extra directories to scan; auto-discovery adds more
	// unless NoAutoRoots is set.
	Webroots    []string
	NoAutoRoots bool
	Logs        []string
	NoLogs      bool
	NoPersist   bool
	// Since bounds the "recently changed" timeline and log parsing.
	Since       time.Duration
	MaxFileSize int64
	MaxFiles    int
	Workers     int
	Progress    func(string)
	Now         time.Time
}

type Text map[string]string

// Finding is one indicator.
type Finding struct {
	ID       string     `json:"id"`
	Rule     string     `json:"rule"`
	Category string     `json:"category"` // file, persistence, config, log
	Severity string     `json:"severity"`
	Title    Text       `json:"title"`
	Why      Text       `json:"why,omitempty"`
	Path     string     `json:"path,omitempty"`
	Line     int        `json:"line,omitempty"`
	Snippet  string     `json:"snippet,omitempty"`
	Time     *time.Time `json:"time,omitempty"`
	Count    int        `json:"count,omitempty"`
	Details  []string   `json:"details,omitempty"`
	// Rules lists every rule that matched the same file.
	Rules []string `json:"rules,omitempty"`
}

// Event is one entry on the timeline.
type Event struct {
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Summary  string    `json:"summary"`
	Path     string    `json:"path,omitempty"`
}

type Webroot struct {
	Path   string `json:"path"`
	Source string `json:"source"`
	Files  int    `json:"files"`
}

type Stats struct {
	FilesScanned int   `json:"files_scanned"`
	PHPFiles     int   `json:"php_files"`
	BytesScanned int64 `json:"bytes_scanned"`
	LogFiles     int   `json:"log_files"`
	LogLines     int64 `json:"log_lines"`
	RecentPHP    int   `json:"recent_php_changes"`
}

type Result struct {
	Schema     string    `json:"schema"`
	Tool       string    `json:"tool"`
	Hostname   string    `json:"hostname"`
	OS         string    `json:"os"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	Since      time.Time `json:"since"`
	Verdict    string    `json:"verdict"`
	Webroots   []Webroot `json:"webroots"`
	Findings   []Finding `json:"findings"`
	Timeline   []Event   `json:"timeline"`
	Stats      Stats     `json:"stats"`
	Warnings   []string  `json:"warnings,omitempty"`
}

// Counts tallies findings by severity.
func (r *Result) Counts() map[string]int {
	m := map[string]int{}
	for _, f := range r.Findings {
		m[f.Severity]++
	}
	return m
}

type tracer struct {
	opt   Options
	root  sysroot.Root
	res   *Result
	rules []*Rule
	// flagged maps in-tree file paths to findings, for log correlation.
	flagged map[string]int
	// docRoots are all document roots, including nested ones.
	docRoots []string
	webUIDs  map[int]string
}

func (o Options) progress(f string, a ...any) {
	if o.Progress != nil {
		o.Progress(fmt.Sprintf(f, a...))
	}
}

// Run performs the trace.
func Run(ctx context.Context, opt Options, tool string) (*Result, error) {
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	if opt.Since == 0 {
		opt.Since = 30 * 24 * time.Hour
	}
	if opt.MaxFileSize == 0 {
		opt.MaxFileSize = 4 << 20
	}
	if opt.MaxFiles == 0 {
		opt.MaxFiles = 2_000_000
	}
	if opt.Workers == 0 {
		opt.Workers = 8
	}
	rules, err := LoadRules()
	if err != nil {
		return nil, err
	}
	t := &tracer{opt: opt, rules: rules, flagged: map[string]int{}}
	t.root = sysroot.Host
	if opt.SysRoot != "" {
		t.root = sysroot.Root{Dir: opt.SysRoot}
	}
	start := time.Now()
	t.res = &Result{Schema: Schema, Tool: tool, StartedAt: start.UTC(), Since: opt.Now.Add(-opt.Since).UTC()}
	t.res.Hostname, _ = os.Hostname()
	if opt.SysRoot != "" {
		t.res.Hostname = opt.SysRoot
	}
	t.res.OS = t.root.OSRelease().Pretty
	if os.Geteuid() != 0 && opt.SysRoot == "" {
		t.res.Warnings = append(t.res.Warnings, "not running as root: unreadable files, crontabs and logs are skipped silently; run with sudo for full coverage")
	}
	t.webUIDs = webUsers(t.root)

	t.scanWebroots(ctx)
	if !opt.NoPersist {
		opt.progress("checking persistence")
		t.checkPersistence()
		t.checkPHPConfig()
	}
	if !opt.NoLogs {
		t.scanLogs(ctx)
	}
	t.finish()
	t.res.DurationMS = time.Since(start).Milliseconds()
	return t.res, nil
}

// add records a finding and returns its index.
func (t *tracer) add(f Finding) int {
	t.res.Findings = append(t.res.Findings, f)
	return len(t.res.Findings) - 1
}

func (t *tracer) event(tm time.Time, kind, sev, summary, path string) {
	if tm.IsZero() {
		return
	}
	t.res.Timeline = append(t.res.Timeline, Event{Time: tm.UTC(), Kind: kind, Severity: sev, Summary: summary, Path: path})
}

func (t *tracer) finish() {
	sort.SliceStable(t.res.Findings, func(i, j int) bool {
		a, b := t.res.Findings[i], t.res.Findings[j]
		if sevRank(a.Severity) != sevRank(b.Severity) {
			return sevRank(a.Severity) > sevRank(b.Severity)
		}
		return a.Path < b.Path
	})
	for i := range t.res.Findings {
		t.res.Findings[i].ID = fmt.Sprintf("F%03d", i+1)
	}
	sort.SliceStable(t.res.Timeline, func(i, j int) bool { return t.res.Timeline[i].Time.Before(t.res.Timeline[j].Time) })
	// Keep the timeline readable: all high/medium events, and at most 200
	// low/info ones (the most recent).
	var keep, minor []Event
	for _, e := range t.res.Timeline {
		if sevRank(e.Severity) >= 2 {
			keep = append(keep, e)
		} else {
			minor = append(minor, e)
		}
	}
	if len(minor) > 200 {
		minor = minor[len(minor)-200:]
	}
	t.res.Timeline = append(keep, minor...)
	sort.SliceStable(t.res.Timeline, func(i, j int) bool { return t.res.Timeline[i].Time.Before(t.res.Timeline[j].Time) })

	t.res.Verdict = VerdictClean
	for _, f := range t.res.Findings {
		switch f.Severity {
		case High:
			t.res.Verdict = VerdictCompromised
		case Medium:
			if t.res.Verdict == VerdictClean {
				t.res.Verdict = VerdictSuspicious
			}
		}
	}
}

// webUsers returns uid → name for accounts that typically run PHP.
func webUsers(r sysroot.Root) map[int]string {
	names := map[string]bool{"www-data": true, "www": true, "nginx": true, "apache": true, "httpd": true, "nobody": true, "lsadm": true, "http": true, "daemon": false}
	out := map[int]string{}
	for _, u := range readPasswd(r) {
		if names[u.Name] {
			out[u.UID] = u.Name
		}
	}
	return out
}

type passwdEntry struct {
	Name  string
	UID   int
	Home  string
	Shell string
}

func readPasswd(r sysroot.Root) []passwdEntry {
	b, err := r.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	var out []passwdEntry
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid := 0
		fmt.Sscanf(f[2], "%d", &uid)
		out = append(out, passwdEntry{Name: f[0], UID: uid, Home: f[5], Shell: f[6]})
	}
	return out
}

// Get returns the text in lang, falling back to English.
func (t Text) Get(lang string) string {
	if s := t[lang]; s != "" {
		return s
	}
	return t["en"]
}
