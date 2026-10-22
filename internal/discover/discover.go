// Package discover finds PHP builds on a machine: on disk in the places
// distributions, hosting panels and installers put them, in running
// processes (including ones whose binary was replaced on disk), and inside
// containers.
package discover

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/larptard/bastion/internal/sysroot"
)

// Patterns lists where PHP lives, as globs inside a root. Each entry names
// the environment that installs PHP there.
var Patterns = []struct {
	Glob, Env string
}{
	{"/usr/bin/php*", ""},
	{"/usr/sbin/php-fpm*", ""},
	{"/usr/lib/cgi-bin/php*", ""},
	{"/usr/local/bin/php*", ""},
	{"/usr/local/sbin/php-fpm*", ""},
	{"/usr/local/bin/frankenphp", "FrankenPHP"},
	{"/usr/bin/frankenphp", "FrankenPHP"},
	{"/usr/lib/apache2/modules/libphp*.so", ""},
	{"/usr/lib64/httpd/modules/libphp*.so", ""},
	{"/usr/lib/httpd/modules/libphp*.so", ""},
	{"/usr/lib/apache2/libphp*.so", ""},
	{"/usr/libexec/apache2/libphp*.so", ""},
	{"/www/server/php/*/bin/php", "BaoTa / aaPanel"},
	{"/www/server/php/*/sbin/php-fpm", "BaoTa / aaPanel"},
	{"/www/server/apache/modules/libphp*.so", "BaoTa / aaPanel"},
	{"/opt/cpanel/ea-php*/root/usr/bin/php", "cPanel EasyApache 4"},
	{"/opt/cpanel/ea-php*/root/usr/bin/php-cgi", "cPanel EasyApache 4"},
	{"/opt/cpanel/ea-php*/root/usr/sbin/php-fpm", "cPanel EasyApache 4"},
	{"/opt/alt/php*/usr/bin/php", "CloudLinux alt-php"},
	{"/opt/alt/php*/usr/bin/lsphp", "CloudLinux alt-php"},
	{"/opt/alt/php*/usr/sbin/php-fpm", "CloudLinux alt-php"},
	{"/opt/plesk/php/*/bin/php", "Plesk"},
	{"/opt/plesk/php/*/bin/php-cgi", "Plesk"},
	{"/opt/plesk/php/*/sbin/php-fpm", "Plesk"},
	{"/opt/remi/php*/root/usr/bin/php", "Remi SCL"},
	{"/opt/remi/php*/root/usr/sbin/php-fpm", "Remi SCL"},
	{"/usr/local/lsws/lsphp*/bin/php", "LiteSpeed"},
	{"/usr/local/lsws/lsphp*/bin/lsphp", "LiteSpeed"},
	{"/usr/local/php*/bin/php", "Source build (/usr/local/php*)"},
	{"/usr/local/php*/sbin/php-fpm", "Source build (/usr/local/php*)"},
	{"/usr/local/php/*/bin/php", "Source build (/usr/local/php*)"},
	{"/opt/php*/bin/php", "Source build (/opt/php*)"},
	{"/opt/php*/sbin/php-fpm", "Source build (/opt/php*)"},
	{"/opt/lampp/bin/php", "XAMPP"},
	{"/opt/lampp/modules/libphp*.so", "XAMPP"},
	{"/opt/bitnami/php/bin/php", "Bitnami"},
	{"/opt/bitnami/php/sbin/php-fpm", "Bitnami"},
	{"/opt/homebrew/opt/php*/bin/php", "Homebrew"},
	{"/opt/homebrew/opt/php*/sbin/php-fpm", "Homebrew"},
	{"/usr/local/opt/php*/bin/php", "Homebrew"},
	{"/home/linuxbrew/.linuxbrew/opt/php*/bin/php", "Homebrew"},
}

var nameRe = regexp.MustCompile(`^(php|php-fpm|php-cgi|lsphp|frankenphp)(-?[0-9][0-9.]*)?$|^libphp[0-9.]*\.so$|^php-fpm[0-9.]*$`)

// LooksLikePHP reports whether a file name could be a PHP build.
func LooksLikePHP(name string) bool { return nameRe.MatchString(name) }

// SAPIFor guesses the server API from a file name.
func SAPIFor(name string) string {
	switch {
	case strings.HasPrefix(name, "php-fpm"):
		return "fpm"
	case strings.HasPrefix(name, "php-cgi"):
		return "cgi"
	case strings.HasPrefix(name, "libphp"), strings.HasPrefix(name, "mod_php"):
		return "apache2handler"
	case strings.HasPrefix(name, "lsphp"):
		return "litespeed"
	case strings.HasPrefix(name, "frankenphp"):
		return "frankenphp"
	}
	return "cli"
}

// Candidate is a path that may hold a PHP build.
type Candidate struct {
	Path string // in-tree path as found
	Env  string // environment hint from the pattern, if any
	PID  int    // set for running processes
	// Deleted marks a running process whose binary was removed or replaced
	// on disk; Real then points at /proc/<pid>/exe.
	Deleted bool
	Real    string
}

// FromPatterns expands Patterns (and extra globs) inside root.
func FromPatterns(root sysroot.Root, extra []string) []Candidate {
	var out []Candidate
	for _, p := range Patterns {
		for _, m := range root.Glob(p.Glob) {
			if LooksLikePHP(path.Base(m)) {
				out = append(out, Candidate{Path: m, Env: p.Env})
			}
		}
	}
	for _, g := range extra {
		for _, m := range root.Glob(g) {
			out = append(out, Candidate{Path: m})
		}
	}
	return out
}

// FromPATH looks for PHP binaries in the directories of $PATH (host only).
func FromPATH(pathEnv string) []Candidate {
	var out []Candidate
	seen := map[string]bool{}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if LooksLikePHP(e.Name()) {
				out = append(out, Candidate{Path: filepath.Join(dir, e.Name())})
			}
		}
	}
	return out
}

// Classify names the environment a binary belongs to.
func Classify(p, hint string, packaged bool, pkgVersion, manager string, containerImageEnv bool) string {
	if hint != "" {
		return hint
	}
	for _, rule := range []struct{ prefix, env string }{
		{"/www/server/", "BaoTa / aaPanel"},
		{"/opt/cpanel/", "cPanel EasyApache 4"},
		{"/opt/alt/", "CloudLinux alt-php"},
		{"/opt/plesk/", "Plesk"},
		{"/opt/remi/", "Remi SCL"},
		{"/usr/local/lsws/", "LiteSpeed"},
		{"/opt/homebrew/", "Homebrew"},
		{"/opt/lampp/", "XAMPP"},
		{"/opt/bitnami/", "Bitnami"},
	} {
		if strings.HasPrefix(p, rule.prefix) {
			return rule.env
		}
	}
	if packaged {
		switch {
		case strings.Contains(pkgVersion, "deb.sury.org"):
			return "Sury PPA/DPA (apt)"
		case strings.Contains(pkgVersion, ".remi"):
			return "Remi repository (dnf)"
		}
		switch manager {
		case "dpkg":
			return "System package (apt)"
		case "rpm":
			return "System package (dnf/yum)"
		case "apk":
			return "System package (apk)"
		}
	}
	if containerImageEnv {
		return "Docker official image"
	}
	if strings.HasPrefix(p, "/usr/local/") || strings.HasPrefix(p, "/opt/") {
		return "Source build"
	}
	return "Unmanaged binary"
}

// SortCandidates orders candidates deterministically.
func SortCandidates(c []Candidate) {
	sort.SliceStable(c, func(i, j int) bool { return c[i].Path < c[j].Path })
}
