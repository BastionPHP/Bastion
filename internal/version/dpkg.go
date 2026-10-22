package version

import (
	"strconv"
	"strings"
	"unicode"
)

// CompareDpkg compares two Debian package versions ([epoch:]upstream[-revision])
// using the algorithm from dpkg's verrevcmp. It returns -1, 0 or 1.
func CompareDpkg(a, b string) int {
	ea, ua, ra := splitDpkg(a)
	eb, ub, rb := splitDpkg(b)
	if ea != eb {
		return sign(ea - eb)
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

func splitDpkg(v string) (epoch int, upstream, revision string) {
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

func order(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case unicode.IsLetter(rune(c)):
		return int(c)
	case c == '~':
		return -1
	case c == 0:
		return 0
	}
	return int(c) + 256
}

func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ac, bc int
			if i < len(a) {
				ac = order(a[i])
			}
			if j < len(b) {
				bc = order(b[j])
			}
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
