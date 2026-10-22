// Package check parses text a user pasted — `php -v`, `dpkg -l`, `rpm -q`,
// `apk info`, /etc/os-release — into an advisory subject. The website's
// in-browser checker implements the same rules (site/assets/engine.js) and
// both are tested against testdata/paste.json.
package check

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/larptard/bastion/internal/advisory"
	"github.com/larptard/bastion/internal/version"
)

type Parsed struct {
	Version  string            `json:"version,omitempty"`
	SAPI     string            `json:"sapi,omitempty"`
	Built    string            `json:"built,omitempty"`
	Package  *advisory.Package `json:"package,omitempty"`
	OS       advisory.OS       `json:"os"`
	Inferred []string          `json:"inferred,omitempty"`
}

var (
	rePHPv   = regexp.MustCompile(`(?m)PHP ([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+~-]*) \(([a-z0-9-]+)\)(?: \(built: ([^)]*)\))?`)
	reDpkgL  = regexp.MustCompile(`(?m)^[a-z][a-z]\s+((?:lib)?[a-z0-9.+-]*php[a-z0-9.+-]*)(?::[a-z0-9]+)?\s+([0-9][^\s]*)\s`)
	reDpkgW  = regexp.MustCompile(`(?m)^((?:lib)?[a-z0-9.+-]*php[a-z0-9.+-]*)(?::[a-z0-9]+)?\t([0-9][^\s]*)\s*$`)
	reRPM    = regexp.MustCompile(`(?m)^((?:[a-z0-9_]+-)*php[a-z0-9_]*(?:-[a-z][a-z0-9_]*)*)-([0-9][^-\s]*)-([^-\s]+)\.(x86_64|aarch64|noarch|i686|ppc64le|s390x)$`)
	reAPK    = regexp.MustCompile(`(?m)^(php[0-9]*[a-z0-9-]*?)-([0-9][^-\s]*-r[0-9]+)\b`)
	reOSID   = regexp.MustCompile(`(?m)^ID="?([a-z0-9._-]+)"?\s*$`)
	reOSVer  = regexp.MustCompile(`(?m)^VERSION_ID="?([0-9.]+)"?\s*$`)
	reLSBRel = regexp.MustCompile(`(?m)^Release:\s+([0-9.]+)\s*$`)
	reLSBID  = regexp.MustCompile(`(?m)^Distributor ID:\s+(\S+)\s*$`)
	reUbuRel = regexp.MustCompile(`ubuntu[0-9.]*?\b(1[4-9]|2[0-9])\.(04|10)\b`)
	reDebRel = regexp.MustCompile(`~deb([0-9]{2})u`)
)

// cliPreferred orders binary package names when several are pasted.
func preferred(name string) int {
	switch {
	case strings.HasSuffix(name, "-cli"):
		return 3
	case strings.HasSuffix(name, "-fpm"), strings.Contains(name, "mod-php"):
		return 2
	case strings.HasSuffix(name, "-common"):
		return 1
	}
	return 0
}

// DebSource derives the source package from a Debian/Ubuntu binary
// package name: php8.3-cli → php8.3, libapache2-mod-php8.3 → php8.3.
func DebSource(name string) string {
	if m := regexp.MustCompile(`^libapache2-mod-(php[0-9.]*)$`).FindStringSubmatch(name); m != nil {
		return m[1]
	}
	if m := regexp.MustCompile(`^(php[0-9]+(?:\.[0-9]+)?)(?:-|$)`).FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return name
}

// Parse extracts what it can from free-form text.
func Parse(text string) Parsed {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	var p Parsed
	if m := rePHPv.FindStringSubmatch(text); m != nil {
		p.Version, p.SAPI, p.Built = m[1], m[2], m[3]
	}
	best := -1
	consider := func(pkg *advisory.Package) {
		if pkg.Manager == "dpkg" && !strings.HasPrefix(DebSource(pkg.Name), "php") {
			return
		}
		if r := preferred(pkg.Name); r > best {
			best, p.Package = r, pkg
		}
	}
	for _, m := range reDpkgL.FindAllStringSubmatch(text, -1) {
		consider(&advisory.Package{Manager: "dpkg", Name: m[1], Version: m[2], Source: DebSource(m[1])})
	}
	for _, m := range reDpkgW.FindAllStringSubmatch(text, -1) {
		consider(&advisory.Package{Manager: "dpkg", Name: m[1], Version: m[2], Source: DebSource(m[1])})
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if m := reRPM.FindStringSubmatch(line); m != nil {
			src := "php"
			if i := strings.Index(m[1], "-php"); i > 0 {
				src = m[1][:i]
			}
			consider(&advisory.Package{Manager: "rpm", Name: m[1], Version: m[2] + "-" + m[3], Source: src})
		} else if m := reAPK.FindStringSubmatch(line); m != nil && !strings.Contains(line, ".x86_64") {
			consider(&advisory.Package{Manager: "apk", Name: m[1], Version: m[2], Source: m[1]})
		}
	}
	if m := reOSID.FindStringSubmatch(text); m != nil {
		p.OS.ID = m[1]
		if v := reOSVer.FindStringSubmatch(text); v != nil {
			p.OS.VersionID = v[1]
		}
	} else if m := reLSBID.FindStringSubmatch(text); m != nil {
		p.OS.ID = strings.ToLower(m[1])
		if v := reLSBRel.FindStringSubmatch(text); v != nil {
			p.OS.VersionID = v[1]
		}
	}
	if p.OS.ID == "" {
		probe := p.Version
		if p.Package != nil {
			probe += " " + p.Package.Version
		}
		if m := reUbuRel.FindStringSubmatch(probe); m != nil {
			p.OS = advisory.OS{ID: "ubuntu", VersionID: m[1] + "." + m[2]}
			p.Inferred = append(p.Inferred, "os from package version")
		} else if m := reDebRel.FindStringSubmatch(probe); m != nil {
			p.OS = advisory.OS{ID: "debian", VersionID: strings.TrimLeft(m[1], "0")}
			p.Inferred = append(p.Inferred, "os from package version")
		}
	}
	return p
}

// Infer fills gaps using an advisory's vendor data. Ubuntu builds before
// 24.04 put the full package version into PHP_VERSION (PHP 8.1.2-1ubuntu2.28),
// which identifies both the package and — via the vendor table — the release.
func (p *Parsed) Infer(a *advisory.Advisory) {
	if p.Package != nil || p.Version == "" {
		return
	}
	v, err := version.ParsePHP(p.Version)
	if err != nil || !strings.Contains(v.Extra, "ubuntu") {
		return
	}
	src := "php" + v.Branch()
	if v.Major == 5 {
		src = "php5"
	}
	if p.OS.ID == "" {
		for _, f := range a.VendorFixes {
			if f.Distro == "ubuntu" && f.Package == src && advisory.UpstreamOf(f.Fixed) == v.Upstream() {
				p.OS = advisory.OS{ID: "ubuntu", VersionID: f.Release}
				p.Inferred = append(p.Inferred, "Ubuntu release from the package version")
				break
			}
		}
	}
	if p.OS.ID == "ubuntu" {
		p.Package = &advisory.Package{Manager: "dpkg", Name: src, Version: p.Version, Source: src}
		p.Inferred = append(p.Inferred, "package version from php -v")
	}
}

// Subject converts the parse into an engine subject.
func (p Parsed) Subject() advisory.Subject {
	return advisory.Subject{Version: p.Version, Package: p.Package, OS: p.OS}
}

// Describe is a one-line summary for the terminal.
func (p Parsed) Describe() string {
	parts := []string{}
	if p.Version != "" {
		parts = append(parts, "PHP "+p.Version)
	}
	if p.SAPI != "" {
		parts = append(parts, p.SAPI)
	}
	if p.Package != nil {
		parts = append(parts, fmt.Sprintf("package %s %s (%s)", p.Package.Name, p.Package.Version, p.Package.Manager))
	}
	if p.OS.ID != "" {
		parts = append(parts, "os "+p.OS.ID+" "+p.OS.VersionID)
	}
	if len(p.Inferred) > 0 {
		parts = append(parts, "inferred: "+strings.Join(p.Inferred, ", "))
	}
	return strings.Join(parts, " · ")
}
