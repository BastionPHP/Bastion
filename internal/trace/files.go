package trace

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// phpExt are extensions a default PHP handler executes.
var phpExt = map[string]bool{".php": true, ".phtml": true, ".php3": true, ".php4": true, ".php5": true, ".php7": true, ".php8": true, ".pht": true, ".phar": true, ".inc": true, ".phps": false}

var imageExt = map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".ico": true, ".bmp": true, ".webp": true, ".svg": false}

var uploadDir = regexp.MustCompile(`(?i)/(wp-content/uploads|uploads?|upload_files|attachments?|files/images|images|cache|tmp|temp|media)/`)

var shellName = regexp.MustCompile(`(?i)^(shell|cmd|c99|r57|wso|b374k|alfa|alfashell|indoxploit|webshell|bypass|adminer\d*|phpspy|x-?shell)\.(php\d?|phtml)$`)

var skipDirs = map[string]bool{".git": true, ".svn": true, ".hg": true, "node_modules": true}

var (
	reNginxRoot   = regexp.MustCompile(`(?m)^\s*root\s+["']?([^;"'\s]+)["']?\s*;`)
	reApacheRoot  = regexp.MustCompile(`(?mi)^\s*DocumentRoot\s+["']?([^"'\s]+)["']?`)
	reNginxAccess = regexp.MustCompile(`(?m)^\s*(access_log|error_log)\s+([^;\s]+)`)
	reApacheLog   = regexp.MustCompile(`(?mi)^\s*(CustomLog|ErrorLog|TransferLog)\s+["']?([^"'\s]+)`)
)

// discoverWebroots finds document roots from web server configuration and
// the default locations of common hosting panels.
func (t *tracer) discoverWebroots() []Webroot {
	seen := map[string]bool{}
	var roots []Webroot
	addRoot := func(p, src string) {
		p = path.Clean(p)
		if p == "/" || p == "." || seen[p] || strings.ContainsAny(p, "$") {
			return
		}
		fi, err := os.Stat(t.root.Real(p))
		if err != nil || !fi.IsDir() {
			return
		}
		// Skip roots nested in one we already have.
		for _, r := range roots {
			if strings.HasPrefix(p, r.Path+"/") {
				return
			}
		}
		seen[p] = true
		roots = append(roots, Webroot{Path: p, Source: src})
	}
	for _, w := range t.opt.Webroots {
		if abs, err := filepath.Abs(w); err == nil && t.opt.SysRoot == "" {
			w = abs
		}
		addRoot(w, "argument")
	}
	if !t.opt.NoAutoRoots {
		confGlobs := []string{
			"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*", "/etc/nginx/vhosts/*",
			"/www/server/panel/vhost/nginx/*.conf", "/www/server/nginx/conf/nginx.conf", "/usr/local/nginx/conf/vhost/*.conf", "/usr/local/nginx/conf/nginx.conf",
			"/etc/apache2/sites-enabled/*", "/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf",
			"/www/server/panel/vhost/apache/*.conf", "/usr/local/apache/conf/httpd.conf", "/etc/apache2/conf.d/userdata/*/*/*.conf",
			"/usr/local/lsws/conf/vhosts/*/vhconf.conf", "/etc/caddy/Caddyfile",
		}
		for _, g := range confGlobs {
			for _, f := range t.root.Glob(g) {
				b, err := t.root.ReadFile(f)
				if err != nil {
					continue
				}
				for _, m := range reNginxRoot.FindAllSubmatch(b, -1) {
					addRoot(string(m[1]), "nginx: "+f)
				}
				for _, m := range reApacheRoot.FindAllSubmatch(b, -1) {
					addRoot(string(m[1]), "apache: "+f)
				}
				for _, m := range reNginxAccess.FindAllSubmatch(b, -1) {
					t.opt.Logs = append(t.opt.Logs, string(m[2]))
				}
				for _, m := range reApacheLog.FindAllSubmatch(b, -1) {
					t.opt.Logs = append(t.opt.Logs, string(m[2]))
				}
			}
		}
		defaults := []struct{ glob, src string }{
			{"/www/wwwroot/*", "BaoTa / aaPanel"},
			{"/home/*/public_html", "cPanel / DirectAdmin"},
			{"/home/*/domains/*/public_html", "DirectAdmin"},
			{"/var/www/vhosts/*/httpdocs", "Plesk"},
			{"/home/*/htdocs", "CloudPanel"},
			{"/var/www/html", "default"},
			{"/var/www", "default"},
			{"/srv/www", "default"},
			{"/srv/http", "default"},
			{"/usr/share/nginx/html", "default"},
			{"/opt/lampp/htdocs", "XAMPP"},
		}
		for _, d := range defaults {
			for _, m := range t.root.Glob(d.glob) {
				addRoot(m, d.src)
			}
		}
	}
	sort.SliceStable(roots, func(i, j int) bool { return roots[i].Path < roots[j].Path })
	// Drop roots nested inside another one discovered later.
	var out []Webroot
	for _, r := range roots {
		nested := false
		for _, o := range roots {
			if o.Path != r.Path && strings.HasPrefix(r.Path, o.Path+"/") {
				nested = true
			}
		}
		if !nested {
			out = append(out, r)
		}
	}
	return out
}

type fileJob struct {
	inner string
	root  int
	info  fs.FileInfo
}

func (t *tracer) scanWebroots(ctx context.Context) {
	roots := t.discoverWebroots()
	t.res.Webroots = roots
	if len(roots) == 0 {
		t.res.Warnings = append(t.res.Warnings, "no web roots found; pass directories as arguments: bastion trace /path/to/site")
		return
	}
	jobs := make(chan fileJob, 256)
	var mu sync.Mutex
	var wg sync.WaitGroup
	since := t.opt.Now.Add(-t.opt.Since)
	for w := 0; w < t.opt.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				fs := t.scanFile(j, since)
				mu.Lock()
				t.res.Stats.FilesScanned++
				t.res.Stats.BytesScanned += min(j.info.Size(), t.opt.MaxFileSize)
				t.res.Webroots[j.root].Files++
				if isPHPPath(j.inner) {
					t.res.Stats.PHPFiles++
					if j.info.ModTime().After(since) {
						t.res.Stats.RecentPHP++
						t.event(j.info.ModTime(), "file", Info, "PHP file modified", j.inner)
					}
				}
				for _, f := range fs {
					t.flagged[f.Path] = t.add(f)
					sev := f.Severity
					t.event(j.info.ModTime(), "file", sev, "flagged file last modified: "+f.Title["en"], f.Path)
					if ct := ctime(j.info); !ct.IsZero() && ct.Sub(j.info.ModTime()) > 24*time.Hour {
						t.event(ct, "file", sev, "flagged file metadata changed (ctime) long after its mtime — timestamps may be forged", f.Path)
					}
				}
				mu.Unlock()
			}
		}()
	}
	count := 0
	for i, r := range roots {
		t.opt.progress("scanning %s", r.Path)
		filepath.WalkDir(t.root.Real(r.Path), func(p string, d fs.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return nil
			}
			if d.IsDir() {
				if skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			name := strings.ToLower(d.Name())
			ext := path.Ext(name)
			if !(phpExt[ext] || imageExt[ext] || name == ".user.ini" || name == ".htaccess" || name == "php.ini" || isDoubleExt(name)) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			count++
			if count > t.opt.MaxFiles {
				return filepath.SkipAll
			}
			jobs <- fileJob{inner: t.root.Inner(p), root: i, info: info}
			return nil
		})
	}
	close(jobs)
	wg.Wait()
	if count > t.opt.MaxFiles {
		t.res.Warnings = append(t.res.Warnings, "file limit reached; scan was truncated")
	}
}

func isPHPPath(p string) bool { return phpExt[strings.ToLower(path.Ext(p))] }

// isDoubleExt catches names like shell.php.jpg that some misconfigured
// servers execute as PHP.
func isDoubleExt(name string) bool { return reDoubleExt.MatchString(name) }

var reDoubleExt = regexp.MustCompile(`\.ph(p\d?|tml|ar)\.[a-z0-9]{1,5}$`)

var (
	reAutoPrepend = regexp.MustCompile(`(?mi)^\s*(php_value\s+|php_admin_value\s+)?(auto_prepend_file|auto_append_file)\s*=?\s*["']?([^"'\s;]+)`)
	reHtHandler   = regexp.MustCompile(`(?mi)^\s*(AddType|AddHandler|SetHandler|ForceType)\s+[^\n]*(x-httpd-php|php\d?-script|application/x-httpd-php|proxy:unix:[^\n]*php)[^\n]*`)
	reHtExtList   = regexp.MustCompile(`(?i)\.(jpe?g|png|gif|ico|txt|html?|css|js|bmp|webp)\b`)
)

// allowedPrepend lists auto_prepend_file targets that belong to well-known
// security plugins.
var allowedPrepend = []string{"wordfence-waf.php", "ninjafirewall", "nfwlog", "/usr/share/php/"}

func (t *tracer) scanFile(j fileJob, since time.Time) []Finding {
	f, err := os.Open(t.root.Real(j.inner))
	if err != nil {
		return nil
	}
	defer f.Close()
	content, err := io.ReadAll(io.LimitReader(f, t.opt.MaxFileSize))
	if err != nil {
		return nil
	}
	name := strings.ToLower(path.Base(j.inner))
	ext := path.Ext(name)
	mt := j.info.ModTime().UTC()
	var out []Finding
	base := Finding{Category: "file", Path: j.inner, Time: &mt}

	switch {
	case name == ".user.ini" || name == ".htaccess" || name == "php.ini":
		for _, m := range reAutoPrepend.FindAllSubmatchIndex(content, -1) {
			target := string(content[m[6]:m[7]])
			if strings.EqualFold(target, "none") || target == "" {
				continue
			}
			f := base
			f.Rule, f.Category, f.Line, f.Snippet = "config.auto-prepend", "config", lineOf(content, m[0]), snippet(content, m[0], m[1])
			f.Severity = High
			f.Title = Text{"en": "PHP auto_prepend/append_file set in " + name, "zh": name + " 中设置了 auto_prepend/append_file"}
			f.Why = Text{"en": "Every request on this directory first runs " + target + ". A favourite way to keep a backdoor loaded.", "zh": "该目录下的每个请求都会先执行 " + target + "，这是常见的后门驻留方式。"}
			for _, a := range allowedPrepend {
				if strings.Contains(target, a) {
					f.Severity = Info
					f.Why = Text{"en": "Points at a known security plugin (" + target + ").", "zh": "指向已知的安全插件（" + target + "）。"}
				}
			}
			out = append(out, f)
		}
		if name == ".htaccess" {
			for _, m := range reHtHandler.FindAllIndex(content, -1) {
				line := content[m[0]:m[1]]
				if !reHtExtList.Match(line) {
					continue
				}
				f := base
				f.Rule, f.Category, f.Line, f.Snippet, f.Severity = "config.htaccess-php-handler", "config", lineOf(content, m[0]), snippet(content, m[0], m[1]), High
				f.Title = Text{"en": ".htaccess makes non-PHP files execute as PHP", "zh": ".htaccess 让非 PHP 文件按 PHP 执行"}
				f.Why = Text{"en": "Lets an uploaded image or text file run as code.", "zh": "这样上传的图片或文本文件就能被当作代码执行。"}
				out = append(out, f)
			}
		}
		return out
	}

	hasPHPTag := bytes.Contains(content, []byte("<?php")) || bytes.Contains(content, []byte("<?="))
	matches := []Match{}
	if phpExt[ext] || hasPHPTag {
		matches = MatchContent(t.rules, content)
	}

	if imageExt[ext] && hasPHPTag {
		f := base
		f.Rule, f.Severity = "file.php-in-image", Medium
		if len(matches) > 0 {
			f.Severity = High
		}
		f.Title = Text{"en": "PHP code hidden in an image file", "zh": "图片文件中藏有 PHP 代码"}
		f.Why = Text{"en": "Polyglot images are used with include() or a handler override to run code.", "zh": "这种“图片马”配合 include() 或处理器覆盖即可执行代码。"}
		i := bytes.Index(content, []byte("<?"))
		f.Line, f.Snippet = lineOf(content, i), snippet(content, i, i+60)
		f.Rules = ruleIDs(matches)
		out = append(out, f)
		return out
	}

	if len(matches) > 0 {
		sort.SliceStable(matches, func(a, b int) bool { return sevRank(matches[a].Rule.Severity) > sevRank(matches[b].Rule.Severity) })
		top := matches[0]
		f := base
		f.Rule, f.Severity, f.Title, f.Why, f.Line, f.Snippet = top.Rule.ID, top.Rule.Severity, top.Rule.Title, top.Rule.Why, top.Line, top.Snippet
		f.Rules = ruleIDs(matches)
		// Several medium signals in one file add up to a strong one.
		mediums := 0
		for _, m := range matches {
			if m.Rule.Severity == Medium {
				mediums++
			}
		}
		if f.Severity == Medium && mediums >= 3 {
			f.Severity = High
			f.Details = append(f.Details, "several independent obfuscation signals in one file")
		}
		// A lone low signal is not worth reporting.
		if f.Severity == Low && len(matches) == 1 {
			f.Severity = ""
		}
		for _, m := range matches[1:] {
			f.Details = append(f.Details, m.Rule.ID+" (line "+itoa(m.Line)+")")
		}
		if f.Severity != "" {
			if uploadDir.MatchString(j.inner) {
				f.Details = append(f.Details, "located in an upload/cache directory")
			}
			if strings.Contains(j.inner, "/vendor/") {
				f.Details = append(f.Details, "inside a vendor/ directory — confirm against the upstream package")
			}
			out = append(out, f)
			return out
		}
	}

	if phpExt[ext] {
		switch {
		case strings.Contains(strings.ToLower(j.inner), "/wp-content/uploads/") && ext != ".inc":
			f := base
			f.Rule, f.Severity = "file.php-in-uploads", Medium
			f.Title = Text{"en": "PHP file inside wp-content/uploads", "zh": "wp-content/uploads 目录中出现 PHP 文件"}
			f.Why = Text{"en": "WordPress never stores PHP in uploads; this is how uploaded webshells usually land.", "zh": "WordPress 不会在 uploads 中存放 PHP，上传型 Webshell 通常落在这里。"}
			out = append(out, f)
		case shellName.MatchString(name):
			f := base
			f.Rule, f.Severity = "file.webshell-name", Medium
			f.Title = Text{"en": "File name used by common webshells", "zh": "文件名与常见 Webshell 相同"}
			f.Why = Text{"en": "Names like " + name + " are the defaults of public shell kits.", "zh": name + " 这类名字是公开 Webshell 的默认文件名。"}
			out = append(out, f)
		case strings.HasPrefix(name, ".") && len(name) > 5:
			f := base
			f.Rule, f.Severity = "file.hidden-php", Low
			f.Title = Text{"en": "Hidden PHP file", "zh": "隐藏的 PHP 文件"}
			f.Why = Text{"en": "Dot-files are hidden from ls and many file managers.", "zh": "以点开头的文件在 ls 和多数文件管理器中默认不可见。"}
			out = append(out, f)
		}
	} else if isDoubleExt(name) && hasPHPTag {
		f := base
		f.Rule, f.Severity = "file.double-extension", Medium
		f.Title = Text{"en": "PHP code in a double-extension file", "zh": "双扩展名文件中含有 PHP 代码"}
		f.Why = Text{"en": "Names like x.php.jpg bypass upload filters and run as PHP on some servers.", "zh": "x.php.jpg 这类名字可以绕过上传过滤，在部分服务器上会被当作 PHP 执行。"}
		out = append(out, f)
	}
	return out
}

func ruleIDs(ms []Match) []string {
	var ids []string
	for _, m := range ms {
		ids = append(ids, m.Rule.ID)
	}
	return ids
}

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
