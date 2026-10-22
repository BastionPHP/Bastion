// Package scan finds every PHP build on the machine and assesses it against
// the advisory database.
package scan

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/larptard/bastion/internal/advisory"
	"github.com/larptard/bastion/internal/discover"
	"github.com/larptard/bastion/internal/pkgdb"
	"github.com/larptard/bastion/internal/sysroot"
)

const Schema = "bastion.scan/v1"

type Options struct {
	DB *advisory.DB
	// SysRoot scans a mounted filesystem instead of the running host; it
	// disables process and container discovery.
	SysRoot string
	// Containers enables container discovery.
	Containers bool
	// Exec allows running `php -v` (on the host or via `docker exec`) when
	// a binary cannot be identified statically.
	Exec bool
	// ExtraGlobs are additional in-tree globs to inspect.
	ExtraGlobs []string
	Progress   func(string)
}

// Target is one filesystem tree that was scanned.
type Target struct {
	Kind    string              `json:"kind"` // host, container, namespace, sysroot
	Name    string              `json:"name"`
	ID      string              `json:"id,omitempty"`
	Image   string              `json:"image,omitempty"`
	Runtime string              `json:"runtime,omitempty"`
	OS      sysroot.OSRelease   `json:"os"`
	Access  string              `json:"access"` // filesystem, exec, none
	Note    string              `json:"note,omitempty"`
	root    sysroot.Root        `json:"-"`
	cont    *discover.Container `json:"-"`
	procs   []discover.Process  `json:"-"`
	env     map[string]string   `json:"-"`
	db      *pkgdb.DB           `json:"-"`
}

// Instance is one PHP build.
type Instance struct {
	ID            string                `json:"id"`
	Target        string                `json:"target"`
	TargetKind    string                `json:"target_kind"`
	Image         string                `json:"image,omitempty"`
	Path          string                `json:"path"`
	Aliases       []string              `json:"aliases,omitempty"`
	SAPI          string                `json:"sapi"`
	Environment   string                `json:"environment"`
	Version       string                `json:"version"`
	VersionSource string                `json:"version_source"` // binary, exec, package, image-env
	Package       *advisory.Package     `json:"package,omitempty"`
	Changelog     string                `json:"changelog,omitempty"`
	Fingerprints  []string              `json:"fingerprints,omitempty"`
	PIDs          []int                 `json:"pids,omitempty"`
	Stale         bool                  `json:"stale,omitempty"`
	Notes         []string              `json:"notes,omitempty"`
	OS            sysroot.OSRelease     `json:"os"`
	Assessments   []advisory.Assessment `json:"assessments"`
}

// Worst returns the worst status across advisories.
func (i Instance) Worst() advisory.Status {
	w := advisory.Fixed
	for _, a := range i.Assessments {
		if a.Status.Severity() > w.Severity() {
			w = a.Status
		}
	}
	return w
}

type Host struct {
	Hostname string            `json:"hostname"`
	OS       sysroot.OSRelease `json:"os"`
	Kernel   string            `json:"kernel"`
	Root     bool              `json:"root"`
}

type Result struct {
	Schema     string               `json:"schema"`
	Tool       string               `json:"tool"`
	Host       Host                 `json:"host"`
	StartedAt  time.Time            `json:"started_at"`
	DurationMS int64                `json:"duration_ms"`
	Advisories []*advisory.Advisory `json:"advisories"`
	Targets    []*Target            `json:"targets"`
	Instances  []*Instance          `json:"instances"`
	Warnings   []string             `json:"warnings,omitempty"`
}

// Counts tallies instances by worst status.
func (r *Result) Counts() map[advisory.Status]int {
	m := map[advisory.Status]int{}
	for _, i := range r.Instances {
		m[i.Worst()]++
	}
	return m
}

func (o Options) progress(f string, a ...any) {
	if o.Progress != nil {
		o.Progress(fmt.Sprintf(f, a...))
	}
}

// Run performs the scan.
func Run(ctx context.Context, opt Options, toolVersion string) (*Result, error) {
	start := time.Now()
	res := &Result{Schema: Schema, Tool: toolVersion, StartedAt: start.UTC()}
	for _, a := range opt.DB.Advisories {
		if a.Product == "php" {
			res.Advisories = append(res.Advisories, a)
		}
	}
	res.Host = hostInfo(opt.SysRoot)
	if !res.Host.Root && opt.SysRoot == "" {
		res.Warnings = append(res.Warnings, "not running as root: other users' processes and container filesystems may be invisible; results can be incomplete")
	}

	targets := buildTargets(ctx, opt, res)
	for _, t := range targets {
		opt.progress("scanning %s %s", t.Kind, t.Name)
		res.Targets = append(res.Targets, t)
		res.Instances = append(res.Instances, scanTarget(ctx, opt, t, res)...)
	}
	sort.SliceStable(res.Instances, func(i, j int) bool {
		a, b := res.Instances[i], res.Instances[j]
		if a.Worst().Severity() != b.Worst().Severity() {
			return a.Worst().Severity() > b.Worst().Severity()
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.Path < b.Path
	})
	res.DurationMS = time.Since(start).Milliseconds()
	return res, nil
}

func hostInfo(sysroot_ string) Host {
	h := Host{Root: os.Geteuid() == 0}
	h.Hostname, _ = os.Hostname()
	r := sysroot.Host
	if sysroot_ != "" {
		r = sysroot.Root{Dir: sysroot_}
		h.Hostname = sysroot_
	}
	h.OS = r.OSRelease()
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil && sysroot_ == "" {
		h.Kernel = strings.TrimSpace(string(b))
	}
	return h
}

func newDB(root sysroot.Root, c *discover.Container, exec bool) *pkgdb.DB {
	db := &pkgdb.DB{Root: root}
	switch {
	case pkgdb.HostHasRPM():
		db.RPM, db.RPMRootFlag = pkgdb.HostRunner, true
	case c != nil && exec:
		db.RPM = c.Exec
	}
	return db
}

func buildTargets(ctx context.Context, opt Options, res *Result) []*Target {
	if opt.SysRoot != "" {
		r := sysroot.Root{Dir: opt.SysRoot}
		return []*Target{{Kind: "sysroot", Name: opt.SysRoot, OS: r.OSRelease(), Access: "filesystem", root: r, db: newDB(r, nil, false)}}
	}
	host := &Target{Kind: "host", Name: res.Host.Hostname, OS: res.Host.OS, Access: "filesystem", root: sysroot.Host}
	host.db = newDB(sysroot.Host, nil, opt.Exec)
	targets := []*Target{host}

	procs, denied := discover.Processes("/proc")
	if denied > 0 && !res.Host.Root {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d processes could not be inspected (permission denied)", denied))
	}
	hostKey := discover.HostRootKey()
	byKey := map[string]*Target{hostKey: host}

	if opt.Containers {
		cs, warns := discover.Containers(ctx)
		for _, w := range warns {
			res.Warnings = append(res.Warnings, "containers: "+w)
		}
		for i := range cs {
			c := cs[i]
			t := &Target{Kind: "container", Name: c.Name, ID: shortID(c.ID), Image: c.Image, Runtime: c.Runtime, cont: &c, env: c.Env}
			r := sysroot.Root{Dir: "/proc/" + strconv.Itoa(c.PID) + "/root"}
			if _, err := os.Stat(r.Real("/")); err == nil && c.PID > 0 {
				t.root, t.Access = r, "filesystem"
				t.OS = r.OSRelease()
				if k := discover.RootKeyOf(c.PID); k != "" {
					byKey[k] = t
				}
			} else if opt.Exec {
				t.Access = "exec"
				t.Note = "container filesystem not readable; used " + c.Runtime + " exec"
			} else {
				t.Access = "none"
				t.Note = "container filesystem not readable and exec is disabled"
			}
			t.db = newDB(t.root, t.cont, opt.Exec)
			targets = append(targets, t)
		}
	}

	for _, p := range procs {
		t, ok := byKey[p.RootKey]
		if !ok && p.RootKey != "" {
			// A mount namespace we do not know (Kubernetes pod, LXC, chroot).
			r := sysroot.Root{Dir: "/proc/" + strconv.Itoa(p.PID) + "/root"}
			name := discover.ContainerHint(p.Cgroup)
			if name == "" {
				name = "pid " + strconv.Itoa(p.PID)
			} else {
				name = shortID(name)
			}
			t = &Target{Kind: "namespace", Name: name, OS: r.OSRelease(), Access: "filesystem", root: r, Note: "processes in a separate root filesystem (" + p.Cgroup + ")"}
			t.db = newDB(r, nil, false)
			byKey[p.RootKey] = t
			targets = append(targets, t)
		}
		if t != nil {
			t.procs = append(t.procs, p)
		}
	}
	return targets
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func scanTarget(ctx context.Context, opt Options, t *Target, res *Result) []*Instance {
	needles, markers := advisoryNeedles(res.Advisories)
	if t.Access == "exec" {
		return execOnly(ctx, t, res)
	}
	if t.Access != "filesystem" {
		return nil
	}

	cands := discover.FromPatterns(t.root, opt.ExtraGlobs)
	if t.Kind == "host" {
		cands = append(cands, discover.FromPATH(os.Getenv("PATH"))...)
	}
	pidsByPath := map[string][]int{}
	for _, p := range t.procs {
		if p.Libs == nil {
			c := discover.Candidate{Path: p.Exe, PID: p.PID, Deleted: p.Deleted}
			if p.Deleted {
				c.Real = "/proc/" + strconv.Itoa(p.PID) + "/exe"
			}
			cands = append(cands, c)
		}
		for _, l := range p.Libs {
			cands = append(cands, discover.Candidate{Path: l, PID: p.PID, Deleted: p.LibDeleted[l]})
		}
	}
	discover.SortCandidates(cands)

	byPath := map[string]*Instance{}
	var order []string
	for _, c := range cands {
		resolved := c.Path
		if !c.Deleted {
			r, err := t.root.Resolve(c.Path)
			if err != nil {
				continue
			}
			resolved = r
		}
		k := resolved
		if c.Deleted {
			k = resolved + " (deleted)"
		}
		if c.PID > 0 {
			pidsByPath[k] = append(pidsByPath[k], c.PID)
		}
		if inst, ok := byPath[k]; ok {
			if c.Path != resolved && !containsStr(inst.Aliases, c.Path) {
				inst.Aliases = append(inst.Aliases, c.Path)
			}
			if inst.Environment == "" && c.Env != "" {
				inst.Environment = c.Env
			}
			continue
		}
		real := t.root.Real(resolved)
		if c.Real != "" {
			real = c.Real
		}
		if c.Deleted && c.Real == "" {
			// A replaced shared library; we cannot read the old image.
			inst := &Instance{Path: resolved, SAPI: discover.SAPIFor(path.Base(resolved)), Stale: true}
			inst.Notes = append(inst.Notes, "loaded module was replaced on disk; the running process still uses the old code — restart the web server")
			byPath[k] = inst
			order = append(order, k)
			continue
		}
		st, err := discover.StaticProbe(real, needles)
		if err != nil || !st.IsBinary {
			continue
		}
		inst := &Instance{Path: resolved, SAPI: discover.SAPIFor(path.Base(resolved)), Version: st.Version, VersionSource: "binary", Fingerprints: st.Found, Stale: c.Deleted}
		if c.Env != "" {
			inst.Environment = c.Env
		}
		if c.Path != resolved {
			inst.Aliases = append(inst.Aliases, c.Path)
		}
		if inst.Version == "" && opt.Exec && t.Kind == "host" && !c.Deleted {
			if info, err := discover.ExecProbe(ctx, real); err == nil {
				inst.Version, inst.VersionSource = info.Version, "exec"
			}
		}
		if inst.Version == "" && inst.SAPI == "cli" && !strings.HasPrefix(path.Base(resolved), "php") {
			continue
		}
		byPath[k] = inst
		order = append(order, k)
	}

	var out []*Instance
	for _, k := range order {
		inst := byPath[k]
		inst.Target, inst.TargetKind, inst.OS, inst.Image = t.Name, t.Kind, t.OS, t.Image
		inst.PIDs = dedupInts(pidsByPath[k])
		staleDistro := false
		subj := advisory.Subject{Version: inst.Version, OS: advisory.OS{ID: t.OS.ID, VersionID: t.OS.VersionID, Pretty: t.OS.Pretty}, Fingerprints: inst.Fingerprints}
		if !inst.Stale {
			info := t.db.Lookup(ctx, inst.Path, markers)
			inst.Package = info.Package
			inst.Changelog = info.ChangelogPath
			subj.Package, subj.ChangelogChecked, subj.ChangelogHits = info.Package, info.ChangelogChecked, info.ChangelogHits
			if inst.Version == "" && info.Package != nil {
				inst.VersionSource = "package"
			}
		} else {
			if len(inst.Notes) == 0 {
				inst.Notes = append(inst.Notes, "binary was replaced on disk; this process still runs the old build — restart it")
			}
			// The package database describes the replacement, not the running
			// image, so a distro build's old version string proves nothing.
			staleDistro = t.db.Lookup(ctx, inst.Path, nil).Package != nil
		}
		pkgVer, mgr := "", ""
		if inst.Package != nil {
			pkgVer, mgr = inst.Package.Version, inst.Package.Manager
		}
		_, imageEnv := t.env["PHP_VERSION"]
		inst.Environment = discover.Classify(inst.Path, inst.Environment, inst.Package != nil, pkgVer, mgr, imageEnv)
		for _, a := range res.Advisories {
			as := a.Evaluate(subj)
			if inst.Stale && as.Status != advisory.Fixed && (staleDistro || as.Status != advisory.Vulnerable) {
				as.Status, as.Confidence = advisory.LikelyVulnerable, "medium"
				as.Reason = "process still runs a replaced build that cannot be verified; restart it"
			}
			inst.Assessments = append(inst.Assessments, as)
		}
		inst.ID = instanceID(t, inst.Path, inst.Stale)
		out = append(out, inst)
	}
	return out
}

// execOnly handles containers whose filesystem is not readable from the host.
func execOnly(ctx context.Context, t *Target, res *Result) []*Instance {
	if t.cont == nil {
		return nil
	}
	if b, err := t.cont.Exec(ctx, "cat", "/etc/os-release"); err == nil {
		t.OS = sysroot.ParseOSRelease(string(b))
	}
	out, err := t.cont.Exec(ctx, "php", "-v")
	info, ok := discover.ParseVersionOutput(string(out))
	if err != nil && !ok {
		return nil
	}
	inst := &Instance{Target: t.Name, TargetKind: t.Kind, Image: t.Image, Path: "php (container PATH)", SAPI: "cli", Version: info.Version, VersionSource: "exec", OS: t.OS}
	_, imageEnv := t.env["PHP_VERSION"]
	inst.Environment = discover.Classify("/usr/local/bin/php", "", false, "", "", imageEnv)
	inst.Notes = append(inst.Notes, "package and changelog checks skipped: container filesystem was not readable")
	for _, a := range res.Advisories {
		inst.Assessments = append(inst.Assessments, a.Evaluate(advisory.Subject{Version: inst.Version, OS: advisory.OS{ID: t.OS.ID, VersionID: t.OS.VersionID}}))
	}
	inst.ID = instanceID(t, inst.Path, false)
	return []*Instance{inst}
}

func advisoryNeedles(advs []*advisory.Advisory) (needles, markers []string) {
	seen := map[string]bool{}
	for _, a := range advs {
		for _, f := range a.Fingerprints {
			if f.Kind == "binary-string" && !seen[f.Value] {
				seen[f.Value] = true
				needles = append(needles, f.Value)
			}
		}
		markers = append(markers, a.ChangelogMarkers...)
	}
	return
}

func instanceID(t *Target, p string, stale bool) string {
	h := sha1.Sum([]byte(t.Kind + "\x00" + t.Name + "\x00" + p + "\x00" + strconv.FormatBool(stale)))
	return hex.EncodeToString(h[:])[:10]
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func dedupInts(xs []int) []int {
	sort.Ints(xs)
	out := xs[:0]
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}
