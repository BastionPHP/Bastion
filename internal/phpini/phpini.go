// Package phpini reads PHP configuration statically: php.ini, scan-dir
// .ini files and PHP-FPM pool overrides, for the layout each distribution
// and hosting panel uses. It answers "what is the effective value of this
// directive" without running PHP.
package phpini

import (
	"bufio"
	"bytes"
	"sort"
	"strconv"
	"strings"

	"github.com/larptard/bastion/internal/sysroot"
)

// Value is a directive's value and where it came from.
type Value struct {
	Value  string `json:"value"`
	Source string `json:"source"` // file:line, or "default"
	Admin  bool   `json:"admin,omitempty"`
}

// Layout lists the config files that apply to one PHP build.
type Layout struct {
	INI   []string // php.ini then scan-dir files, in load order
	Pools []string // PHP-FPM pool files (fpm builds only)
}

// Locate guesses the config layout for a binary from its path, branch and SAPI.
func Locate(r sysroot.Root, bin, branch, sapi string) Layout {
	var l Layout
	add := func(ini string, scan ...string) {
		if _, err := r.Stat(ini); err == nil {
			l.INI = append(l.INI, ini)
		}
		for _, g := range scan {
			m := r.Glob(g)
			sort.Strings(m)
			l.INI = append(l.INI, m...)
		}
	}
	pools := func(globs ...string) {
		if sapi != "fpm" {
			return
		}
		for _, g := range globs {
			m := r.Glob(g)
			sort.Strings(m)
			l.Pools = append(l.Pools, m...)
		}
	}
	nodot := strings.ReplaceAll(branch, ".", "")
	debSAPI := map[string]string{"cli": "cli", "fpm": "fpm", "apache2handler": "apache2", "cgi": "cgi", "litespeed": "litespeed"}[sapi]
	switch {
	case strings.HasPrefix(bin, "/www/server/php/"):
		base := strings.Join(strings.Split(bin, "/")[:5], "/") // /www/server/php/83
		add(base+"/etc/php.ini", base+"/etc/php.d/*.ini")
		pools(base + "/etc/php-fpm.conf")
	case strings.HasPrefix(bin, "/opt/cpanel/ea-php"):
		base := strings.Join(strings.Split(bin, "/")[:5], "/") // /opt/cpanel/ea-php83/root
		add(base+"/etc/php.ini", base+"/etc/php.d/*.ini")
		pools(base+"/etc/php-fpm.d/*.conf", "/opt/cpanel/ea-php"+nodot+"/root/etc/php-fpm.d/*.conf")
	case strings.HasPrefix(bin, "/opt/plesk/php/"):
		base := strings.Join(strings.Split(bin, "/")[:5], "/")
		add(base+"/etc/php.ini", base+"/etc/php.d/*.ini")
		pools(base + "/etc/php-fpm.d/*.conf")
	case strings.HasPrefix(bin, "/opt/alt/php"):
		base := strings.Join(strings.Split(bin, "/")[:4], "/")
		add(base+"/etc/php.ini", base+"/etc/php.d/*.ini", base+"/etc/php.d.all/*.ini")
	case strings.HasPrefix(bin, "/opt/remi/php"):
		add("/etc/opt/remi/php"+nodot+"/php.ini", "/etc/opt/remi/php"+nodot+"/php.d/*.ini")
		pools("/etc/opt/remi/php" + nodot + "/php-fpm.d/*.conf")
	case strings.HasPrefix(bin, "/usr/local/lsws/"):
		base := strings.Join(strings.Split(bin, "/")[:5], "/")
		add(base+"/etc/php.ini", base+"/etc/php/"+branch+"/mods-available/*.ini")
	case strings.HasPrefix(bin, "/usr/local/"):
		// Docker official images and most source builds.
		add("/usr/local/etc/php/php.ini", "/usr/local/etc/php/conf.d/*.ini")
		add("/usr/local/lib/php.ini")
		pools("/usr/local/etc/php-fpm.d/*.conf", "/usr/local/etc/php-fpm.conf")
	default:
		if debSAPI != "" {
			if _, err := r.Stat("/etc/php/" + branch); err == nil {
				add("/etc/php/"+branch+"/"+debSAPI+"/php.ini", "/etc/php/"+branch+"/"+debSAPI+"/conf.d/*.ini")
				pools("/etc/php/" + branch + "/fpm/pool.d/*.conf")
				break
			}
		}
		if _, err := r.Stat("/etc/php" + nodot); err == nil { // Alpine
			add("/etc/php"+nodot+"/php.ini", "/etc/php"+nodot+"/conf.d/*.ini")
			pools("/etc/php" + nodot + "/php-fpm.d/*.conf")
			break
		}
		add("/etc/php.ini", "/etc/php.d/*.ini") // RHEL family
		pools("/etc/php-fpm.d/*.conf")
	}
	return l
}

// Effective returns the value of each directive after php.ini and the scan
// directory. defaults supplies PHP's built-in values.
func Effective(r sysroot.Root, files []string, keys []string, defaults map[string]string) map[string]Value {
	out := map[string]Value{}
	for _, k := range keys {
		out[k] = Value{Value: defaults[k], Source: "default"}
	}
	for _, f := range files {
		b, err := r.ReadFile(f)
		if err != nil {
			continue
		}
		for k, v := range parseINI(f, b, keys) {
			out[k] = v
		}
	}
	return out
}

// Pool is one PHP-FPM pool's overrides.
type Pool struct {
	Name   string           `json:"name"`
	File   string           `json:"file"`
	Values map[string]Value `json:"values"`
}

// Pools parses php_value / php_admin_value overrides per pool.
func Pools(r sysroot.Root, files []string, keys []string) []Pool {
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	var pools []Pool
	for _, f := range files {
		b, err := r.ReadFile(f)
		if err != nil {
			continue
		}
		var cur *Pool
		sc := bufio.NewScanner(bytes.NewReader(b))
		n := 0
		for sc.Scan() {
			n++
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == ';' || line[0] == '#' {
				continue
			}
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				name := strings.Trim(line, "[]")
				if name == "global" {
					cur = nil
					continue
				}
				pools = append(pools, Pool{Name: name, File: f, Values: map[string]Value{}})
				cur = &pools[len(pools)-1]
				continue
			}
			if cur == nil {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			admin := strings.HasPrefix(k, "php_admin_value[") || strings.HasPrefix(k, "php_admin_flag[")
			if !admin && !strings.HasPrefix(k, "php_value[") && !strings.HasPrefix(k, "php_flag[") {
				continue
			}
			name := k[strings.IndexByte(k, '[')+1 : len(k)-1]
			if !want[name] {
				continue
			}
			// An admin value cannot be overridden by a later php_value.
			if prev, ok := cur.Values[name]; ok && prev.Admin && !admin {
				continue
			}
			cur.Values[name] = Value{Value: unquote(strings.TrimSpace(v)), Source: f + ":" + strconv.Itoa(n), Admin: admin}
		}
	}
	return pools
}

func parseINI(file string, b []byte, keys []string) map[string]Value {
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	out := map[string]Value{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == ';' || line[0] == '#' || line[0] == '[' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if !want[k] {
			continue
		}
		v = strings.TrimSpace(v)
		if i := strings.Index(v, ";"); i >= 0 && !strings.HasPrefix(v, `"`) {
			v = strings.TrimSpace(v[:i])
		}
		out[k] = Value{Value: unquote(v), Source: file + ":" + strconv.Itoa(n)}
	}
	return out
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		return v[1 : len(v)-1]
	}
	return v
}

// Bool interprets a PHP ini boolean.
func Bool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "on", "true", "yes":
		return true
	}
	return false
}

// Bytes interprets a PHP shorthand size ("32M"); -1 means unlimited.
func Bytes(v string) (int64, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	mult := int64(1)
	switch strings.ToUpper(v[len(v)-1:]) {
	case "K":
		mult = 1 << 10
	case "M":
		mult = 1 << 20
	case "G":
		mult = 1 << 30
	}
	if mult > 1 {
		v = v[:len(v)-1]
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, false
	}
	return n * mult, true
}
