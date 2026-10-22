// Package version parses and compares the version strings Bastion meets in
// the wild: upstream PHP versions, Debian/Ubuntu package versions and RPM
// version-release pairs.
package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// PHP is a parsed upstream PHP version such as 8.3.6, 8.6.0RC4 or the
// 8.1.2-1ubuntu2.28 form that some distributions bake into PHP_VERSION.
type PHP struct {
	Major, Minor, Patch int
	// Pre is the pre-release tag ("dev", "alpha", "beta", "RC") and its
	// number. An empty Pre means a final release.
	Pre    string
	PreNum int
	// Extra is everything after the upstream part, e.g. "-1ubuntu2.28".
	// It never takes part in comparisons.
	Extra string
	Raw   string
}

var phpRe = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?(?:[-.]?(dev|alpha|beta|a|b|RC|rc|pl|p)(\d*))?(.*)$`)

// ParsePHP parses an upstream PHP version string.
func ParsePHP(s string) (PHP, error) {
	raw := strings.TrimSpace(s)
	m := phpRe.FindStringSubmatch(raw)
	if m == nil {
		return PHP{}, fmt.Errorf("not a PHP version: %q", s)
	}
	v := PHP{Raw: raw}
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	if m[3] != "" {
		v.Patch, _ = strconv.Atoi(m[3])
	}
	v.Pre = normalizePre(m[4])
	if m[5] != "" {
		v.PreNum, _ = strconv.Atoi(m[5])
	}
	v.Extra = m[6]
	return v, nil
}

// MustPHP is ParsePHP for literals known to be valid.
func MustPHP(s string) PHP {
	v, err := ParsePHP(s)
	if err != nil {
		panic(err)
	}
	return v
}

func normalizePre(p string) string {
	switch p {
	case "a":
		return "alpha"
	case "b":
		return "beta"
	case "rc":
		return "RC"
	case "p":
		return "pl"
	}
	return p
}

// preRank orders pre-release tags the way PHP's own version_compare does.
func preRank(p string) int {
	switch p {
	case "dev":
		return 0
	case "alpha":
		return 1
	case "beta":
		return 2
	case "RC":
		return 3
	case "":
		return 4
	case "pl":
		return 5
	}
	return 4
}

// Branch returns the release branch, e.g. "8.3".
func (v PHP) Branch() string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }

// Upstream returns the version without distribution suffixes.
func (v PHP) Upstream() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += v.Pre
		if v.PreNum > 0 {
			s += strconv.Itoa(v.PreNum)
		}
	}
	return s
}

func (v PHP) String() string { return v.Raw }

// Compare returns -1, 0 or 1. Extra suffixes are ignored.
func (v PHP) Compare(o PHP) int {
	for _, d := range [][2]int{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}, {preRank(v.Pre), preRank(o.Pre)}, {v.PreNum, o.PreNum}} {
		if d[0] < d[1] {
			return -1
		}
		if d[0] > d[1] {
			return 1
		}
	}
	return 0
}

// CompareBranch compares "X.Y" branch strings.
func CompareBranch(a, b string) int {
	pa, errA := ParsePHP(a)
	pb, errB := ParsePHP(b)
	if errA != nil || errB != nil {
		return strings.Compare(a, b)
	}
	if pa.Major != pb.Major {
		return sign(pa.Major - pb.Major)
	}
	return sign(pa.Minor - pb.Minor)
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
