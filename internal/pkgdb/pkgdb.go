// Package pkgdb answers "which distribution package owns this file, at what
// version, and does its changelog mention a fix" for dpkg, apk and rpm trees.
// dpkg and apk databases are parsed directly so container trees can be
// inspected without executing anything inside them.
package pkgdb

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/larptard/bastion/internal/advisory"
	"github.com/larptard/bastion/internal/sysroot"
)

// Runner executes a command and returns stdout. It lets rpm queries run on
// the host (rpm --root) or inside a container.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// HostRunner runs commands on the host with a timeout and an empty locale.
func HostRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	return cmd.Output()
}

// DB inspects one root.
type DB struct {
	Root sysroot.Root
	// RPM runs rpm queries; nil disables rpm support.
	RPM Runner
	// RPMRootFlag is true when RPM runs on the host and needs --root.
	RPMRootFlag bool

	once     sync.Once
	manager  string
	dpkgOwn  map[string]string
	apkOwn   map[string]*advisory.Package
	dpkgStat map[string]dpkgEntry
}

// Info is what the database knows about one file.
type Info struct {
	Package          *advisory.Package
	ChangelogChecked bool
	ChangelogHits    []string
	ChangelogPath    string
}

func (d *DB) detect() {
	switch {
	case exists(d.Root, "/var/lib/dpkg/status"):
		d.manager = "dpkg"
	case exists(d.Root, "/lib/apk/db/installed"):
		d.manager = "apk"
	case exists(d.Root, "/var/lib/rpm") || exists(d.Root, "/usr/lib/sysimage/rpm"):
		d.manager = "rpm"
	}
}

// Manager returns the detected package manager or "".
func (d *DB) Manager() string {
	d.once.Do(d.detect)
	return d.manager
}

func exists(r sysroot.Root, p string) bool {
	_, err := os.Stat(r.Real(p))
	return err == nil
}

// Lookup returns package information for the in-tree path p (already
// symlink-resolved). markers are the strings searched for in changelogs.
func (d *DB) Lookup(ctx context.Context, p string, markers []string) Info {
	switch d.Manager() {
	case "dpkg":
		return d.dpkgLookup(p, markers)
	case "apk":
		return d.apkLookup(p)
	case "rpm":
		return d.rpmLookup(ctx, p, markers)
	}
	return Info{}
}

// alternatives returns p plus its usrmerge twin (/bin/x <-> /usr/bin/x).
func alternatives(p string) []string {
	out := []string{p}
	if strings.HasPrefix(p, "/usr/") {
		out = append(out, strings.TrimPrefix(p, "/usr"))
	} else {
		out = append(out, "/usr"+p)
	}
	return out
}

// ---- dpkg ----------------------------------------------------------------

type dpkgEntry struct {
	Version, Source, Status string
}

func (d *DB) dpkgIndex() {
	if d.dpkgOwn != nil {
		return
	}
	d.dpkgOwn = map[string]string{}
	d.dpkgStat = map[string]dpkgEntry{}
	for _, list := range d.Root.Glob("/var/lib/dpkg/info/*.list") {
		name := strings.TrimSuffix(path.Base(list), ".list")
		if !strings.Contains(name, "php") {
			continue
		}
		name, _, _ = strings.Cut(name, ":")
		b, err := d.Root.ReadFile(list)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if line != "" {
				d.dpkgOwn[line] = name
			}
		}
	}
	b, err := d.Root.ReadFile("/var/lib/dpkg/status")
	if err != nil {
		return
	}
	for _, block := range strings.Split(string(b), "\n\n") {
		var name string
		var e dpkgEntry
		for _, line := range strings.Split(block, "\n") {
			k, v, ok := strings.Cut(line, ": ")
			if !ok {
				continue
			}
			switch k {
			case "Package":
				name = v
			case "Version":
				e.Version = v
			case "Source":
				e.Source, _, _ = strings.Cut(v, " ")
			case "Status":
				e.Status = v
			}
		}
		if name != "" && strings.Contains(name, "php") && strings.HasSuffix(e.Status, " installed") {
			if e.Source == "" {
				e.Source = name
			}
			d.dpkgStat[name] = e
		}
	}
}

func (d *DB) dpkgLookup(p string, markers []string) Info {
	d.dpkgIndex()
	var name string
	for _, q := range alternatives(p) {
		if n, ok := d.dpkgOwn[q]; ok {
			name = n
			break
		}
	}
	e, ok := d.dpkgStat[name]
	if name == "" || !ok {
		return Info{}
	}
	info := Info{Package: &advisory.Package{Manager: "dpkg", Name: name, Version: e.Version, Source: e.Source}}
	for _, doc := range []string{name, e.Source, e.Source + "-common"} {
		cl := "/usr/share/doc/" + doc + "/changelog.Debian.gz"
		hits, err := d.scanChangelog(cl, markers)
		if err == nil {
			info.ChangelogChecked, info.ChangelogHits, info.ChangelogPath = true, hits, cl
			break
		}
	}
	return info
}

func (d *DB) scanChangelog(p string, markers []string) ([]string, error) {
	rp, err := d.Root.Resolve(p)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(d.Root.Real(rp))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(p, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	}
	b, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil {
		return nil, err
	}
	return matchMarkers(b, markers), nil
}

func matchMarkers(b []byte, markers []string) []string {
	var hits []string
	for _, m := range markers {
		if bytes.Contains(b, []byte(m)) {
			hits = append(hits, m)
		}
	}
	return hits
}

// ---- apk -----------------------------------------------------------------

func (d *DB) apkIndex() {
	if d.apkOwn != nil {
		return
	}
	d.apkOwn = map[string]*advisory.Package{}
	b, err := d.Root.ReadFile("/lib/apk/db/installed")
	if err != nil {
		return
	}
	var cur *advisory.Package
	dir := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			cur, dir = nil, ""
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		v := line[2:]
		switch line[0] {
		case 'P':
			cur = &advisory.Package{Manager: "apk", Name: v}
		case 'V':
			if cur != nil {
				cur.Version = v
			}
		case 'o':
			if cur != nil {
				cur.Source = v
			}
		case 'F':
			dir = "/" + v
		case 'R':
			if cur != nil {
				if cur.Source == "" {
					cur.Source = cur.Name
				}
				d.apkOwn[path.Join(dir, v)] = cur
			}
		}
	}
}

func (d *DB) apkLookup(p string) Info {
	d.apkIndex()
	for _, q := range alternatives(p) {
		if pkg, ok := d.apkOwn[q]; ok {
			// Alpine does not install changelogs; secfixes live in aports.
			return Info{Package: pkg}
		}
	}
	return Info{}
}

// ---- rpm -----------------------------------------------------------------

func (d *DB) rpmArgs(args ...string) []string {
	if d.RPMRootFlag && d.Root.Dir != "/" && d.Root.Dir != "" {
		return append([]string{"--root", d.Root.Dir}, args...)
	}
	return args
}

func (d *DB) rpmLookup(ctx context.Context, p string, markers []string) Info {
	if d.RPM == nil {
		return Info{}
	}
	out, err := d.RPM(ctx, "rpm", d.rpmArgs("-qf", "--qf", `%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n`, p)...)
	if err != nil {
		return Info{}
	}
	line := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	f := strings.Split(line, "\t")
	if len(f) != 3 || strings.Contains(line, "not owned") {
		return Info{}
	}
	ver := strings.TrimPrefix(f[1], "0:")
	pkg := &advisory.Package{Manager: "rpm", Name: f[0], Version: ver, Source: srpmName(f[2])}
	info := Info{Package: pkg}
	if cl, err := d.RPM(ctx, "rpm", d.rpmArgs("-q", "--changelog", f[0])...); err == nil {
		info.ChangelogChecked = len(bytes.TrimSpace(cl)) > 0
		info.ChangelogHits = matchMarkers(cl, markers)
		info.ChangelogPath = "rpm -q --changelog " + f[0]
	}
	return info
}

// srpmName turns "php-8.0.30-4.el9_6.src.rpm" into "php".
func srpmName(s string) string {
	s = strings.TrimSuffix(s, ".src.rpm")
	for i := 0; i < 2; i++ {
		if j := strings.LastIndexByte(s, '-'); j > 0 {
			s = s[:j]
		}
	}
	return s
}

// HostHasRPM reports whether an rpm binary exists on the host.
func HostHasRPM() bool {
	_, err := exec.LookPath("rpm")
	return err == nil
}
