package version

import (
	"strconv"
	"strings"
)

// CompareRPM compares [epoch:]version-release strings the way rpm does
// (rpmvercmp applied to epoch, version and release in turn).
func CompareRPM(a, b string) int {
	ea, va, ra := splitRPM(a)
	eb, vb, rb := splitRPM(b)
	if ea != eb {
		return sign(ea - eb)
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	if ra == "" || rb == "" {
		return 0
	}
	return rpmvercmp(ra, rb)
}

func splitRPM(v string) (epoch int, ver, rel string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, _ = strconv.Atoi(v[:i])
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func isAlnum(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		// Tilde sorts before everything, even the end of the string.
		if (i < len(a) && a[i] == '~') || (j < len(b) && b[j] == '~') {
			if i >= len(a) || a[i] != '~' {
				return 1
			}
			if j >= len(b) || b[j] != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		// Caret sorts after the end of the string but before anything else.
		if (i < len(a) && a[i] == '^') || (j < len(b) && b[j] == '^') {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if a[i] != '^' {
				return 1
			}
			if b[j] != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		numeric := isDigit(a[i])
		if numeric {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlnum(a[i]) && !isDigit(a[i]) {
				i++
			}
			for j < len(b) && isAlnum(b[j]) && !isDigit(b[j]) {
				j++
			}
		}
		x, y := a[si:i], b[sj:j]
		if y == "" {
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			x = strings.TrimLeft(x, "0")
			y = strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				return sign(len(x) - len(y))
			}
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	}
	return 1
}
