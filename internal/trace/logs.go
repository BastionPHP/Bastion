package trace

import (
	"bufio"
	"compress/gzip"
	"context"
	"io"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

var accessGlobs = []string{
	"/var/log/nginx/*access*.log*", "/var/log/nginx/*/*access*.log*", "/var/log/apache2/*access*.log*", "/var/log/apache2/other_vhosts_access.log*",
	"/var/log/httpd/*access_log*", "/var/log/httpd/*access.log*", "/www/wwwlogs/*.log", "/usr/local/apache/domlogs/*", "/usr/local/apache/logs/access_log*",
	"/var/www/vhosts/*/logs/access_log*", "/var/www/vhosts/system/*/logs/access_log*", "/usr/local/lsws/logs/access.log*", "/var/log/caddy/*.log",
}

var errorGlobs = []string{
	"/var/log/php*-fpm.log*", "/var/log/php-fpm/*.log*", "/var/log/php-fpm.log*", "/usr/local/var/log/php-fpm.log*", "/www/server/php/*/var/log/php-fpm.log*",
	"/var/log/apache2/*error*.log*", "/var/log/httpd/*error_log*", "/var/log/nginx/*error*.log*", "/www/wwwlogs/*error*.log", "/usr/local/apache/logs/error_log*",
	"/usr/local/lsws/logs/error.log*", "/usr/local/lsws/logs/stderr.log*", "/var/log/kern.log*", "/var/log/messages*", "/var/log/syslog*",
	"/opt/cpanel/ea-php*/root/usr/var/log/php-fpm/error.log*",
}

// combined/common log format, with tolerant tail.
var reAccess = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]{3,10}) (\S+)[^"]*" (\d{3}) `)

type logSignal struct {
	rule  string
	sev   string
	re    *regexp.Regexp
	title Text
	why   Text
}

var errorSignals = []logSignal{
	{"log.worker-crash", Medium, regexp.MustCompile(`(?i)(exited on signal (11|6|7)\b|exit signal Segmentation fault|php[-\w.]*\[\d+\]: segfault at|lsphp[^\n]*segfault|zend_mm_heap corrupted|child \d+ exited on signal 11)`),
		Text{"en": "PHP worker crashes (segfault / heap corruption)", "zh": "PHP 工作进程崩溃（段错误或堆损坏）"},
		Text{"en": "PHP2Shell is a memory-corruption bug; exploitation attempts often crash workers before they succeed. Crashes also happen for benign reasons — check timing against suspicious requests.", "zh": "PHP2Shell 属于内存破坏漏洞，利用尝试在成功前常会让进程崩溃。崩溃也可能有无害的原因，请结合可疑请求的时间判断。"}},
	{"log.early-oom", Medium, regexp.MustCompile(`Allowed memory size of \d+ bytes exhausted[^\n]*in Unknown on line 0`),
		Text{"en": "Out-of-memory during request start-up", "zh": "请求启动阶段发生内存耗尽"},
		Text{"en": "'in Unknown on line 0' means memory ran out before any script ran — while PHP was parsing the request. That is the trigger condition of CVE-2026-109618.", "zh": "“in Unknown on line 0”说明内存在任何脚本运行之前、PHP 解析请求时就已耗尽，这正是 CVE-2026-109618 的触发条件。"}},
	{"log.hard-oom", Low, regexp.MustCompile(`Hard memory limit of \d+ bytes exhausted`),
		Text{"en": "Patched hard memory limit reached", "zh": "触发了补丁引入的硬内存上限"},
		Text{"en": "Only patched builds log this. Repeated hits suggest someone is pushing requests into OOM.", "zh": "只有已修复的构建才会记录这条日志；频繁出现说明有人在刻意让请求耗尽内存。"}},
	{"log.multipart-limits", Low, regexp.MustCompile(`(?i)(Maximum number of allowable file uploads has been exceeded|Input variables exceeded|Multipart body parts limit exceeded|POST Content-Length of \d+ bytes exceeds the limit)`),
		Text{"en": "Request parsing limits hit", "zh": "触发请求解析上限"},
		Text{"en": "Oversized or over-partitioned multipart bodies are how attackers drive PHP into OOM during parsing.", "zh": "超大或分段过多的 multipart 请求体是让 PHP 在解析时耗尽内存的常见手段。"}},
}

var accessSignals = []logSignal{
	{"log.php-cgi-arg-injection", Medium, regexp.MustCompile(`(?i)(%AD[dn]\+|-d\+allow_url_include|allow_url_include%3d1|auto_prepend_file%3dphp://input)`),
		Text{"en": "PHP-CGI argument injection attempts", "zh": "PHP-CGI 参数注入尝试"},
		Text{"en": "Probes for php-cgi argument injection (e.g. CVE-2024-4577).", "zh": "针对 php-cgi 参数注入（如 CVE-2024-4577）的探测。"}},
	{"log.code-in-request", Medium, regexp.MustCompile(`(?i)(<\?php|%3C%3Fphp|base64_decode\(|eval\(|system\(|passthru\(|shell_exec\(|php://input|php://filter|\$_(GET|POST|REQUEST)\[)`),
		Text{"en": "PHP code in request URLs", "zh": "请求 URL 中带有 PHP 代码"},
		Text{"en": "Injection attempts; a 200 response deserves a closer look.", "zh": "属于注入尝试；返回 200 的请求值得仔细排查。"}},
	{"log.command-param", Medium, regexp.MustCompile(`(?i)[?&](cmd|exec|command|shell|c|e|x)=[^&\s]*(whoami|uname|\bid\b|cat%20/etc|cat\+/etc|/etc/passwd|wget|curl|bash|/bin/sh|ifconfig|netstat)`),
		Text{"en": "Shell commands passed as request parameters", "zh": "请求参数中携带 Shell 命令"},
		Text{"en": "Typical of interacting with a webshell.", "zh": "这是操作 Webshell 的典型特征。"}},
	{"log.webshell-name", Low, regexp.MustCompile(`(?i)/(shell|cmd|c99|r57|wso|b374k|alfa|indoxploit|webshell|x-?shell)\.php\d?\b`),
		Text{"en": "Requests for common webshell file names", "zh": "请求常见的 Webshell 文件名"},
		Text{"en": "Usually scanners; a 200 response means the file exists.", "zh": "通常来自扫描器；如果返回 200，说明文件确实存在。"}},
}

var reUploadPHP = regexp.MustCompile(`(?i)/(wp-content/uploads|uploads?|upload_files|attachments?|images|cache)/[^?\s]*\.(php\d?|phtml|phar)\b`)

type logAgg struct {
	f       Finding
	first   time.Time
	last    time.Time
	ips     map[string]int
	statusc map[string]int
	samples []string
}

func (a *logAgg) hit(tm time.Time, ip, status, line string) {
	a.f.Count++
	if !tm.IsZero() {
		if a.first.IsZero() || tm.Before(a.first) {
			a.first = tm
		}
		if tm.After(a.last) {
			a.last = tm
		}
	}
	if ip != "" {
		a.ips[ip]++
	}
	if status != "" {
		a.statusc[status]++
	}
	if len(a.samples) < 3 {
		a.samples = append(a.samples, clip(line, 220))
	}
}

func (t *tracer) logFiles() (access, errs []string) {
	seen := map[string]bool{}
	add := func(list *[]string, p string) {
		rp, err := t.root.Resolve(p)
		if err != nil || seen[rp] {
			return
		}
		fi, err := os.Stat(t.root.Real(rp))
		if err != nil || fi.IsDir() || fi.ModTime().Before(t.opt.Now.Add(-t.opt.Since)) {
			return
		}
		seen[rp] = true
		*list = append(*list, rp)
	}
	for _, g := range errorGlobs {
		for _, p := range t.root.Glob(g) {
			add(&errs, p)
		}
	}
	for _, g := range accessGlobs {
		for _, p := range t.root.Glob(g) {
			if strings.Contains(path.Base(p), "error") {
				add(&errs, p)
				continue
			}
			add(&access, p)
		}
	}
	for _, p := range t.opt.Logs {
		for _, m := range t.root.Glob(p + "*") {
			if strings.Contains(path.Base(m), "error") {
				add(&errs, m)
			} else {
				add(&access, m)
			}
		}
	}
	sort.Strings(access)
	sort.Strings(errs)
	return
}

func openLog(p string) (io.ReadCloser, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(p, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return struct {
			io.Reader
			io.Closer
		}{gz, f}, nil
	}
	return f, nil
}

func (t *tracer) scanLogs(ctx context.Context) {
	access, errs := t.logFiles()
	since := t.opt.Now.Add(-t.opt.Since)
	aggs := map[string]*logAgg{}
	get := func(sig logSignal, p string) *logAgg {
		k := sig.rule + "\x00" + p
		a, ok := aggs[k]
		if !ok {
			a = &logAgg{f: Finding{Category: "log", Rule: sig.rule, Severity: sig.sev, Title: sig.title, Why: sig.why, Path: p}, ips: map[string]int{}, statusc: map[string]int{}}
			aggs[k] = a
		}
		return a
	}
	// URL paths of flagged files, relative to each web root.
	urlToFile := map[string]string{}
	for p := range t.flagged {
		for _, w := range t.res.Webroots {
			if strings.HasPrefix(p, w.Path+"/") {
				urlToFile[strings.TrimPrefix(p, w.Path)] = p
			}
		}
	}

	for _, p := range errs {
		t.opt.progress("reading %s", p)
		t.readLines(ctx, p, func(line string) {
			for _, sig := range errorSignals {
				if !sig.re.MatchString(line) {
					continue
				}
				tm := parseLogTime(line, t.opt.Now)
				if !tm.IsZero() && tm.Before(since) {
					return
				}
				get(sig, p).hit(tm, "", "", line)
			}
		})
	}
	for _, p := range access {
		t.opt.progress("reading %s", p)
		t.readLines(ctx, p, func(line string) {
			m := reAccess.FindStringSubmatch(line)
			if m == nil {
				return
			}
			ip, ts, method, target, status := m[1], m[2], m[3], m[4], m[5]
			tm, _ := time.Parse("02/Jan/2006:15:04:05 -0700", ts)
			if !tm.IsZero() && tm.Before(since) {
				return
			}
			pathOnly, _, _ := strings.Cut(target, "?")
			if dec, err := url.PathUnescape(pathOnly); err == nil {
				pathOnly = dec
			}
			if file, ok := urlToFile[pathOnly]; ok {
				sig := logSignal{rule: "log.flagged-file-access", sev: High, title: Text{"en": "Requests to a flagged file", "zh": "有请求访问了被标记的文件"}, why: Text{"en": "The file " + file + " was flagged by the file scan and was requested over HTTP.", "zh": "文件扫描标记的 " + file + " 曾被 HTTP 请求访问。"}}
				if !strings.HasPrefix(status, "2") {
					sig.sev = Medium
				}
				a := get(sig, p)
				a.f.Details = appendOnce(a.f.Details, "file "+file)
				a.hit(tm, ip, status, line)
				if i, ok := t.flagged[file]; ok {
					t.res.Findings[i].Details = appendOnce(t.res.Findings[i].Details, "requested over HTTP (see "+p+")")
				}
			}
			if method == "POST" && strings.HasPrefix(status, "2") && reUploadPHP.MatchString(pathOnly) {
				sig := logSignal{rule: "log.post-upload-php", sev: High, title: Text{"en": "Successful POST to a PHP file in an upload directory", "zh": "成功 POST 到上传目录中的 PHP 文件"}, why: Text{"en": "Legitimate applications do not execute PHP from upload directories.", "zh": "正常应用不会执行上传目录中的 PHP 文件。"}}
				get(sig, p).hit(tm, ip, status, line)
			}
			for _, sig := range accessSignals {
				if sig.re.MatchString(target) {
					s := sig
					if sig.rule == "log.webshell-name" && strings.HasPrefix(status, "2") {
						s.sev = Medium
					}
					get(s, p).hit(tm, ip, status, line)
				}
			}
		})
	}

	keys := make([]string, 0, len(aggs))
	for k := range aggs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := aggs[k]
		f := a.f
		if !a.last.IsZero() {
			last := a.last.UTC()
			f.Time = &last
			f.Details = append(f.Details, "first "+a.first.UTC().Format(time.RFC3339)+", last "+last.Format(time.RFC3339))
			t.event(a.first, "log", f.Severity, f.Title["en"]+" — first seen ("+itoa(f.Count)+" total)", f.Path)
			if a.last.Sub(a.first) > time.Minute {
				t.event(a.last, "log", f.Severity, f.Title["en"]+" — last seen", f.Path)
			}
		}
		if len(a.ips) > 0 {
			f.Details = append(f.Details, "top clients: "+topN(a.ips, 5))
		}
		if len(a.statusc) > 0 {
			f.Details = append(f.Details, "status codes: "+topN(a.statusc, 5))
		}
		f.Details = append(f.Details, a.samples...)
		if len(a.samples) > 0 {
			f.Snippet = a.samples[0]
		}
		t.add(f)
	}
}

func appendOnce(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

func topN(m map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	var l []kv
	for k, v := range m {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].v != l[j].v {
			return l[i].v > l[j].v
		}
		return l[i].k < l[j].k
	})
	var parts []string
	for i, e := range l {
		if i == n {
			break
		}
		parts = append(parts, e.k+"×"+itoa(e.v))
	}
	return strings.Join(parts, ", ")
}

const maxLogBytes = 2 << 30

func (t *tracer) readLines(ctx context.Context, p string, fn func(string)) {
	rc, err := openLog(t.root.Real(p))
	if err != nil {
		return
	}
	defer rc.Close()
	t.res.Stats.LogFiles++
	sc := bufio.NewScanner(io.LimitReader(rc, maxLogBytes))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	n := int64(0)
	for sc.Scan() {
		n++
		if n%100000 == 0 && ctx.Err() != nil {
			break
		}
		fn(sc.Text())
	}
	t.res.Stats.LogLines += n
}

var timeFormats = []struct {
	re     *regexp.Regexp
	layout string
	noYear bool
}{
	{regexp.MustCompile(`\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}`), "02/Jan/2006:15:04:05 -0700", false},
	{regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})`), time.RFC3339, false},
	{regexp.MustCompile(`\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}`), "2006/01/02 15:04:05", false},
	{regexp.MustCompile(`\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2}`), "02-Jan-2006 15:04:05", false},
	{regexp.MustCompile(`[A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2}(\.\d+)? \d{4}`), "Mon Jan 02 15:04:05 2006", false},
	{regexp.MustCompile(`^[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}`), "Jan _2 15:04:05", true},
}

// parseLogTime finds the first timestamp in a log line. Times without a
// zone are taken as UTC; syslog lines without a year get the current one.
func parseLogTime(line string, now time.Time) time.Time {
	for _, f := range timeFormats {
		s := f.re.FindString(line)
		if s == "" {
			continue
		}
		layout := f.layout
		if strings.Contains(s, ".") && !strings.Contains(layout, "T") {
			s = regexp.MustCompile(`\.\d+`).ReplaceAllString(s, "")
		}
		if layout == time.RFC3339 {
			s = strings.Replace(s, "+0000", "+00:00", 1)
		}
		tm, err := time.Parse(layout, s)
		if err != nil {
			continue
		}
		if f.noYear {
			tm = tm.AddDate(now.Year(), 0, 0)
			if tm.After(now.Add(48 * time.Hour)) {
				tm = tm.AddDate(-1, 0, 0)
			}
		}
		return tm
	}
	return time.Time{}
}
