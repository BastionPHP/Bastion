package advisory

import (
	"fmt"
	"strings"

	"github.com/BastionPHP/Bastion/internal/version"
)

// Status is the verdict for one PHP build against one advisory.
type Status string

const (
	Fixed            Status = "fixed"
	Vulnerable       Status = "vulnerable"
	LikelyVulnerable Status = "likely-vulnerable"
	Unknown          Status = "unknown"
)

// Severity orders statuses from worst to best for sorting and exit codes.
func (s Status) Severity() int {
	switch s {
	case Vulnerable:
		return 3
	case LikelyVulnerable:
		return 2
	case Unknown:
		return 1
	}
	return 0
}

// Package describes the distribution package that owns a PHP binary.
type Package struct {
	Manager string `json:"manager"` // dpkg, rpm, apk
	Name    string `json:"name"`
	Version string `json:"version"`
	// Source is the source package (dpkg Source:, rpm SOURCERPM name, apk origin).
	Source string `json:"source,omitempty"`
}

// OS is the subset of os-release the engine needs.
type OS struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
	Pretty    string `json:"pretty_name,omitempty"`
}

// Subject is everything Bastion learned about one PHP build.
type Subject struct {
	Version string
	Package *Package
	OS      OS
	// ChangelogChecked reports whether a package changelog was found and read;
	// ChangelogHits lists the advisory markers it mentioned.
	ChangelogChecked bool
	ChangelogHits    []string
	// Fingerprints lists the advisory fingerprint values found in the binary.
	Fingerprints []string
	// Environment is the installer that provided the build ("Plesk", …).
	Environment string
	// BuildDate is the compile date embedded in the binary (YYYY-MM-DD).
	BuildDate string
}

// Evidence is one observation that fed the verdict.
type Evidence struct {
	Kind    string `json:"kind"`    // version, vendor, changelog, fingerprint, note
	Verdict string `json:"verdict"` // fixed, vulnerable, neutral
	Detail  string `json:"detail"`
}

// Assessment is the engine's answer.
type Assessment struct {
	Advisory   string     `json:"advisory"`
	Status     Status     `json:"status"`
	Confidence string     `json:"confidence"` // high, medium, low
	Reason     string     `json:"reason"`
	FixedIn    string     `json:"fixed_in,omitempty"`
	VendorFix  *VendorFix `json:"vendor_fix,omitempty"`
	Evidence   []Evidence `json:"evidence"`
}

func (a *Advisory) branch(name string) *Branch {
	for i := range a.Branches {
		if a.Branches[i].Branch == name {
			return &a.Branches[i]
		}
	}
	return nil
}

// branchPosition reports whether name is older (-1) or newer (1) than every
// listed branch, or 0 if it falls inside the listed range.
func (a *Advisory) branchPosition(name string) int {
	older, newer := true, true
	for _, b := range a.Branches {
		c := version.CompareBranch(name, b.Branch)
		if c >= 0 {
			older = false
		}
		if c <= 0 {
			newer = false
		}
	}
	switch {
	case older:
		return -1
	case newer:
		return 1
	}
	return 0
}

// VendorFixFor returns the vendor fix entry that applies to pkg on os.
func (a *Advisory) VendorFixFor(os OS, pkg *Package) *VendorFix {
	if pkg == nil {
		return nil
	}
	branch := ""
	if v, err := version.ParsePHP(UpstreamOf(pkg.Version)); err == nil {
		branch = v.Branch()
	}
	for i := range a.VendorFixes {
		f := &a.VendorFixes[i]
		if f.Distro != os.ID || !releaseMatches(f.Release, os.VersionID) || f.Format != pkg.Manager {
			continue
		}
		if f.Branch != "" && f.Branch != branch {
			continue
		}
		if f.Package == pkg.Source || f.Package == pkg.Name {
			return f
		}
	}
	return nil
}

// releaseMatches compares a vendor release with VERSION_ID. A release
// without a dot ("9") covers all minor releases ("9.8").
func releaseMatches(release, versionID string) bool {
	return release == versionID || (!strings.Contains(release, ".") && strings.HasPrefix(versionID, release+"."))
}

func (a *Advisory) policyFor(os OS) *VendorPolicy {
	for i := range a.VendorPolicies {
		if a.VendorPolicies[i].Distro == os.ID {
			return &a.VendorPolicies[i]
		}
	}
	return nil
}

func compareVendor(format, a, b string) int {
	switch format {
	case "rpm", "apk":
		return version.CompareRPM(a, b)
	}
	return version.CompareDpkg(a, b)
}

// Evaluate decides whether the subject is affected. The rules, in order:
//
//  1. An upstream version at or above the branch's fixed release is fixed.
//  2. A distribution package listed in vendor_fixes is fixed or vulnerable
//     depending on its package version, regardless of the upstream number.
//  3. A package changelog that names the CVE/GHSA ids means a backport.
//  4. A binary containing code that only the fix introduces is fixed.
//  5. Otherwise packaged builds are "likely vulnerable" if their changelog was
//     readable and silent, or "unknown" if Bastion could not read it; builds
//     outside a package manager are judged on the upstream version alone.
func (a *Advisory) Evaluate(s Subject) Assessment {
	out := Assessment{Advisory: a.ID}
	add := func(kind, verdict, format string, args ...any) {
		out.Evidence = append(out.Evidence, Evidence{Kind: kind, Verdict: verdict, Detail: fmt.Sprintf(format, args...)})
	}
	done := func(st Status, conf, format string, args ...any) Assessment {
		out.Status, out.Confidence, out.Reason = st, conf, fmt.Sprintf(format, args...)
		return out
	}

	v, err := version.ParsePHP(s.Version)
	if err != nil {
		if s.Package == nil {
			add("version", "neutral", "could not determine the PHP version")
			return done(Unknown, "low", "PHP version could not be determined")
		}
		if pv, perr := version.ParsePHP(UpstreamOf(s.Package.Version)); perr == nil {
			v, err = pv, nil
			add("version", "neutral", "version taken from package %s %s", s.Package.Name, s.Package.Version)
		}
	}

	// upstream is what the upstream version alone says: "fixed",
	// "vulnerable" (a fixed release exists and this is older), "no-release"
	// (branch never got a fixed release) or "" when unknown.
	upstream := ""
	var br *Branch
	if err == nil {
		br = a.branch(v.Branch())
		switch {
		case br != nil && br.Fixed != "":
			out.FixedIn = br.Fixed
			if v.Compare(version.MustPHP(br.Fixed)) >= 0 {
				add("version", "fixed", "PHP %s is at or above the fixed release %s", v.Upstream(), br.Fixed)
				return done(Fixed, "high", "running %s, fixed in %s", v.Upstream(), br.Fixed)
			}
			upstream = "vulnerable"
			if s.Package != nil {
				add("version", "neutral", "PHP %s is below the fixed release %s, but distribution packages often carry backports", v.Upstream(), br.Fixed)
			} else {
				add("version", "vulnerable", "PHP %s is below the fixed release %s", v.Upstream(), br.Fixed)
			}
		case br != nil:
			upstream = "no-release"
			add("version", "vulnerable", "PHP %s has no fixed upstream release (branch status: %s)", v.Branch(), br.Status)
		default:
			switch pos := a.branchPosition(v.Branch()); {
			case pos > 0 && a.NewerBranches == "fixed":
				add("version", "fixed", "PHP %s is newer than every branch covered by this advisory", v.Branch())
				return done(Fixed, "medium", "branch %s postdates the fix", v.Branch())
			case pos < 0 && a.OlderBranches == "affected":
				upstream = "no-release"
				add("version", "vulnerable", "PHP %s is an end-of-life branch with no upstream fix", v.Branch())
			default:
				add("version", "neutral", "branch %s is not covered by this advisory's data", v.Branch())
			}
		}
	}

	if f := a.VendorFixFor(s.OS, s.Package); f != nil {
		out.VendorFix = f
		out.FixedIn = f.Fixed
		if compareVendor(f.Format, s.Package.Version, f.Fixed) >= 0 {
			add("vendor", "fixed", "%s %s ≥ %s (%s, %s %s)", s.Package.Name, s.Package.Version, f.Fixed, f.Advisory, f.Distro, f.Release)
			return done(Fixed, "high", "vendor backport %s in %s", f.Fixed, f.Advisory)
		}
		add("vendor", "vulnerable", "%s %s < %s (%s, %s %s)", s.Package.Name, s.Package.Version, f.Fixed, f.Advisory, f.Distro, f.Release)
		return done(Vulnerable, "high", "package %s is older than the vendor fix %s", s.Package.Version, f.Fixed)
	}

	if err == nil && s.BuildDate != "" {
		for _, r := range a.BuildDateFixes {
			if r.Environment != s.Environment || !contains(r.Branches, v.Branch()) {
				continue
			}
			if s.BuildDate >= r.FixedOn {
				add("build-date", "fixed", "%s builds of PHP %s dated %s or later carry the fix; this one was built %s (%s)", r.Environment, v.Branch(), r.FixedOn, s.BuildDate, r.Source)
				return done(Fixed, "high", "%s rebuild dated %s", r.Environment, s.BuildDate)
			}
			add("build-date", "vulnerable", "%s builds of PHP %s before %s are vulnerable; this one was built %s (%s)", r.Environment, v.Branch(), r.FixedOn, s.BuildDate, r.Source)
			return done(Vulnerable, "high", "%s build from %s predates the fixed rebuild", r.Environment, s.BuildDate)
		}
	}

	if len(s.ChangelogHits) > 0 {
		add("changelog", "fixed", "package changelog mentions %s", strings.Join(s.ChangelogHits, ", "))
		return done(Fixed, "high", "vendor changelog records the fix")
	}

	for _, fp := range a.Fingerprints {
		if !contains(s.Fingerprints, fp.Value) {
			continue
		}
		if fp.MinBranch != "" && err == nil && version.CompareBranch(v.Branch(), fp.MinBranch) < 0 {
			continue
		}
		add("fingerprint", fp.Indicates, "binary contains %q, which only patched builds include", fp.Value)
		if fp.Indicates == "fixed" {
			return done(Fixed, "medium", "binary contains code introduced by the fix")
		}
	}

	if s.Package != nil {
		if upstream == "" {
			return done(Unknown, "low", "packaged build with an unrecognised version")
		}
		if p := a.policyFor(s.OS); p != nil {
			add("vendor", "vulnerable", "%s (checked %s) records no backport below the upstream fix", p.Source, p.Checked)
			return done(LikelyVulnerable, "medium", "%s ships upstream releases; no backport recorded", s.OS.ID)
		}
		if s.ChangelogChecked {
			add("changelog", "vulnerable", "%s changelog does not mention %s", s.Package.Name, strings.Join(a.ChangelogMarkers[:min(2, len(a.ChangelogMarkers))], " / "))
			return done(LikelyVulnerable, "medium", "distribution package without a recorded backport")
		}
		add("note", "neutral", "distributions backport fixes without changing the upstream version; no changelog was readable and %s %s is not in Bastion's vendor data", s.OS.ID, s.OS.VersionID)
		return done(Unknown, "low", "packaged build; backport status cannot be verified")
	}

	switch upstream {
	case "vulnerable":
		return done(Vulnerable, "high", "PHP %s is below %s", v.Upstream(), out.FixedIn)
	case "no-release":
		if br != nil && br.SourceBackport != "" {
			add("note", "neutral", "upstream published a source-only backport branch (%s); builds from it keep the version string, so Bastion cannot tell them apart", br.SourceBackport)
			return done(LikelyVulnerable, "medium", "end-of-life branch; only a source backport exists")
		}
		return done(Vulnerable, "high", "end-of-life branch %s with no upstream fix", v.Branch())
	}
	return done(Unknown, "low", "not enough information")
}

// UpstreamOf strips epoch and revision from a package version.
func UpstreamOf(pkgVersion string) string {
	s := pkgVersion
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, "-+~"); i >= 0 {
		s = s[:i]
	}
	return s
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
