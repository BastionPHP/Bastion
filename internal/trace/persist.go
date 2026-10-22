package trace

import (
	"bytes"
	"os"
	"path"
	"regexp"
	"strings"
)

// Command-line patterns that are rarely legitimate in a crontab, unit file
// or shell profile.
var persistPatterns = []struct {
	re    *regexp.Regexp
	sev   string
	label string
}{
	{regexp.MustCompile(`(?i)\b(curl|wget|fetch|lwp-download)\b[^|#\n]*\|\s*(ba|z|da|k)?sh\b`), High, "downloads and pipes into a shell"},
	{regexp.MustCompile(`(?i)base64\s+(-d|--decode)[^\n]*\|\s*(ba|z|da)?sh`), High, "decodes base64 into a shell"},
	{regexp.MustCompile(`/dev/(tcp|udp)/`), High, "bash /dev/tcp network redirection (reverse shell)"},
	{regexp.MustCompile(`(?i)\bnc(at)?\b[^\n]*\s-(e|c)\s`), High, "netcat with command execution"},
	{regexp.MustCompile(`(?i)\b(xmrig|kinsing|kdevtmpfsi|minerd|cpuminer|stratum\+tcp|cryptonight|nanominer)\b`), High, "cryptocurrency miner"},
	{regexp.MustCompile(`(?i)\b(python[23]?|perl|ruby)\s+-(c|e)\s+['"][^'"]*(socket|exec|system)`), High, "inline interpreter one-liner with sockets/exec"},
	{regexp.MustCompile(`(?i)\bphp\s+-r\s`), Medium, "inline PHP one-liner"},
	{regexp.MustCompile(`(?:^|[\s;'"=])(/tmp|/var/tmp|/dev/shm)/[^\s;'"]+`), Medium, "runs something from a world-writable temp directory"},
	{regexp.MustCompile(`(?i)\bchattr\s+\+[ia]\b`), Medium, "makes files immutable (anti-removal)"},
}

func matchPersist(line string) (string, string) {
	best, label := "", ""
	for _, p := range persistPatterns {
		if p.re.MatchString(line) && sevRank(p.sev) > sevRank(best) {
			best, label = p.sev, p.label
		}
	}
	return best, label
}

func (t *tracer) scanLines(p, category, rule string, title Text, webUser bool) {
	fi, err := os.Stat(t.root.Real(p))
	if err != nil || fi.IsDir() || fi.Size() > 4<<20 {
		return
	}
	b, err := t.root.ReadFile(p)
	if err != nil {
		return
	}
	mt := fi.ModTime().UTC()
	for i, line := range strings.Split(string(b), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		sev, label := matchPersist(trim)
		if sev == "" && webUser && !isCronEnvLine(trim) {
			sev, label = Medium, "scheduled job owned by a web server account"
		}
		if sev == "" {
			continue
		}
		f := Finding{Category: category, Rule: rule, Severity: sev, Title: title, Path: p, Line: i + 1, Snippet: clip(trim, 200), Time: &mt}
		f.Why = Text{"en": "Line " + label + "."}
		t.add(f)
		t.event(mt, category, sev, title["en"]+" ("+label+")", p)
	}
}

func isCronEnvLine(s string) bool { return reEnvLine.MatchString(s) }

var reEnvLine = regexp.MustCompile(`^[A-Z_]+=`)

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func (t *tracer) checkPersistence() {
	cronTitle := Text{"en": "Suspicious scheduled task"}
	for _, g := range []string{"/etc/crontab", "/etc/cron.d/*", "/etc/anacrontab", "/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*"} {
		for _, p := range t.root.Glob(g) {
			t.scanLines(p, "persistence", "persist.cron", cronTitle, false)
		}
	}
	for _, g := range []string{"/var/spool/cron/crontabs/*", "/var/spool/cron/*"} {
		for _, p := range t.root.Glob(g) {
			owner := path.Base(p)
			isWeb := false
			for _, n := range t.webUIDs {
				if n == owner {
					isWeb = true
				}
			}
			t.scanLines(p, "persistence", "persist.cron", cronTitle, isWeb)
		}
	}

	unitTitle := Text{"en": "Suspicious systemd unit"}
	for _, g := range []string{"/etc/systemd/system/*.service", "/etc/systemd/system/*/*.service", "/etc/systemd/system/*.timer", "/run/systemd/system/*.service", "/root/.config/systemd/user/*.service", "/home/*/.config/systemd/user/*.service"} {
		for _, p := range t.root.Glob(g) {
			if fi, err := os.Lstat(t.root.Real(p)); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				continue // enabled-unit symlinks point at vendor units
			}
			t.scanLines(p, "persistence", "persist.systemd", unitTitle, false)
			if fi, err := os.Stat(t.root.Real(p)); err == nil && fi.ModTime().After(t.opt.Now.Add(-t.opt.Since)) {
				t.event(fi.ModTime(), "persistence", Info, "systemd unit created or changed", p)
			}
		}
	}

	profTitle := Text{"en": "Suspicious shell start-up script"}
	for _, g := range []string{"/etc/rc.local", "/etc/profile", "/etc/profile.d/*.sh", "/etc/bash.bashrc", "/root/.bashrc", "/root/.profile", "/root/.bash_profile"} {
		for _, p := range t.root.Glob(g) {
			t.scanLines(p, "persistence", "persist.profile", profTitle, false)
		}
	}

	// /etc/ld.so.preload injects a library into every process.
	if b, err := t.root.ReadFile("/etc/ld.so.preload"); err == nil && len(bytes.TrimSpace(b)) > 0 {
		fi, _ := os.Stat(t.root.Real("/etc/ld.so.preload"))
		f := Finding{Category: "persistence", Rule: "persist.ld-preload", Severity: High, Path: "/etc/ld.so.preload", Line: 1, Snippet: clip(strings.TrimSpace(string(b)), 200)}
		f.Title = Text{"en": "Global library preload configured"}
		f.Why = Text{"en": "Libraries in /etc/ld.so.preload are loaded into every process; rootkits use it to hide. It is empty on almost every server."}
		if fi != nil {
			mt := fi.ModTime().UTC()
			f.Time = &mt
			t.event(mt, "persistence", High, "/etc/ld.so.preload written", f.Path)
		}
		t.add(f)
	}

	// Accounts.
	for _, u := range readPasswd(t.root) {
		if u.UID == 0 && u.Name != "root" {
			f := Finding{Category: "persistence", Rule: "persist.uid0", Severity: High, Path: "/etc/passwd", Snippet: u.Name + " uid=0 shell=" + u.Shell}
			f.Title = Text{"en": "Extra account with UID 0"}
			f.Why = Text{"en": "Any UID 0 account is root. Attackers add one to keep access."}
			t.add(f)
		}
		if _, web := t.webUIDs[u.UID]; web {
			if strings.HasSuffix(u.Shell, "/sh") || strings.HasSuffix(u.Shell, "bash") || strings.HasSuffix(u.Shell, "zsh") {
				f := Finding{Category: "persistence", Rule: "persist.web-shell-login", Severity: Low, Path: "/etc/passwd", Snippet: u.Name + " shell=" + u.Shell}
				f.Title = Text{"en": "Web server account has a login shell"}
				f.Why = Text{"en": "Distributions ship web accounts with nologin; a real shell makes SSH persistence easier."}
				t.add(f)
			}
			for _, k := range []string{u.Home + "/.ssh/authorized_keys", u.Home + "/.ssh/authorized_keys2"} {
				if fi, err := os.Stat(t.root.Real(k)); err == nil && fi.Size() > 0 {
					mt := fi.ModTime().UTC()
					f := Finding{Category: "persistence", Rule: "persist.web-ssh-key", Severity: Medium, Path: k, Time: &mt}
					f.Title = Text{"en": "SSH key installed for the web server account"}
					f.Why = Text{"en": "Attackers who gain code execution as " + u.Name + " often add a key to come back over SSH."}
					t.add(f)
					t.event(mt, "persistence", Medium, "authorized_keys of "+u.Name+" changed", k)
				}
			}
		}
	}
	for _, k := range []string{"/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2"} {
		if fi, err := os.Stat(t.root.Real(k)); err == nil && fi.ModTime().After(t.opt.Now.Add(-t.opt.Since)) {
			t.event(fi.ModTime(), "persistence", Low, "root authorized_keys changed", k)
		}
	}

	// Executables dropped in temp directories.
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		t.scanTempDir(dir, 0)
	}
}

func (t *tracer) scanTempDir(dir string, depth int) {
	if depth > 2 {
		return
	}
	entries, err := os.ReadDir(t.root.Real(dir))
	if err != nil {
		return
	}
	for _, e := range entries {
		p := path.Join(dir, e.Name())
		if e.IsDir() {
			if strings.HasPrefix(e.Name(), "systemd-private-") || e.Name() == ".X11-unix" || strings.HasPrefix(e.Name(), "claude") {
				continue
			}
			t.scanTempDir(p, depth+1)
			continue
		}
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Size() < 4 {
			continue
		}
		fh, err := os.Open(t.root.Real(p))
		if err != nil {
			continue
		}
		head := make([]byte, 4)
		_, _ = fh.Read(head)
		fh.Close()
		if !bytes.Equal(head, []byte{0x7f, 'E', 'L', 'F'}) {
			continue
		}
		sev := Medium
		mt := info.ModTime().UTC()
		f := Finding{Category: "persistence", Rule: "persist.tmp-elf", Severity: sev, Path: p, Time: &mt}
		if uid, ok := ownerUID(info); ok {
			if name, web := t.webUIDs[uid]; web {
				f.Severity = High
				f.Details = append(f.Details, "owned by web server account "+name)
			}
		}
		if strings.HasPrefix(e.Name(), ".") || strings.Contains(dir, "/.") {
			f.Details = append(f.Details, "hidden name")
		}
		f.Title = Text{"en": "Executable binary in a temp directory"}
		f.Why = Text{"en": "Droppers, miners and proxies are commonly staged in /tmp, /var/tmp or /dev/shm."}
		t.add(f)
		t.event(mt, "persistence", f.Severity, "executable dropped in temp directory", p)
	}
}

// checkPHPConfig flags global PHP configuration that loads extra code.
func (t *tracer) checkPHPConfig() {
	globs := []string{"/etc/php/*/*/php.ini", "/etc/php/*/*/conf.d/*.ini", "/etc/php/*/fpm/pool.d/*.conf", "/etc/php.ini", "/etc/php.d/*.ini", "/etc/php-fpm.d/*.conf",
		"/usr/local/etc/php/php.ini", "/usr/local/etc/php/conf.d/*.ini", "/usr/local/etc/php-fpm.d/*.conf", "/www/server/php/*/etc/php.ini", "/www/server/php/*/etc/php-fpm.conf",
		"/opt/cpanel/ea-php*/root/etc/php.ini", "/opt/cpanel/ea-php*/root/etc/php.d/*.ini", "/opt/alt/php*/etc/php.ini", "/opt/plesk/php/*/etc/php.ini", "/usr/local/lsws/lsphp*/etc/php/*/litespeed/php.ini"}
	reExt := regexp.MustCompile(`(?mi)^\s*(zend_)?extension\s*=\s*["']?((/tmp|/var/tmp|/dev/shm)/[^"'\s]+)`)
	for _, g := range globs {
		for _, p := range t.root.Glob(g) {
			b, err := t.root.ReadFile(p)
			if err != nil {
				continue
			}
			fi, _ := os.Stat(t.root.Real(p))
			var mt *timeT
			if fi != nil {
				m := fi.ModTime().UTC()
				mt = &m
			}
			for _, m := range reAutoPrepend.FindAllSubmatchIndex(b, -1) {
				target := string(b[m[4]:m[5]])
				if target == "" || strings.EqualFold(target, "none") || strings.HasPrefix(target, ";") {
					continue
				}
				f := Finding{Category: "config", Rule: "config.auto-prepend", Severity: High, Path: p, Line: lineOf(b, m[0]), Snippet: snippet(b, m[0], m[1]), Time: mt}
				f.Title = Text{"en": "Global PHP config prepends a file to every request"}
				f.Why = Text{"en": "auto_prepend_file/auto_append_file = " + target + " runs on every request served by this PHP."}
				for _, a := range allowedPrepend {
					if strings.Contains(target, a) {
						f.Severity = Info
					}
				}
				t.add(f)
			}
			for _, m := range reExt.FindAllSubmatchIndex(b, -1) {
				f := Finding{Category: "config", Rule: "config.extension-from-tmp", Severity: High, Path: p, Line: lineOf(b, m[0]), Snippet: snippet(b, m[0], m[1]), Time: mt}
				f.Title = Text{"en": "PHP loads an extension from a temp directory"}
				f.Why = Text{"en": "Malicious PHP extensions (e.g. hooking request handling) are often staged in /tmp."}
				t.add(f)
			}
		}
	}
}
