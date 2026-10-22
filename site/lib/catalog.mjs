// The trace rule catalogue shown on the website: content signatures come
// from internal/trace/rules/content.json; built-in checks are listed here
// and cross-checked against the Go source so the two cannot drift.
import { readFileSync, readdirSync } from "node:fs";

const repo = new URL("../../", import.meta.url);

// severity: the level the check reports at (some escalate with context).
const BUILTIN = [
  ["file.php-in-image", "file", "medium–high", "PHP code inside an image file"],
  ["file.php-in-uploads", "file", "medium", "PHP file in wp-content/uploads"],
  ["file.double-extension", "file", "medium", "PHP code in a double-extension file (x.php.jpg)"],
  ["file.webshell-name", "file", "low", "File name of a public webshell kit"],
  ["file.hidden-php", "file", "low", "Hidden PHP file"],
  ["config.auto-prepend", "config", "high", "auto_prepend_file / auto_append_file in .user.ini, .htaccess or php.ini"],
  ["config.htaccess-php-handler", "config", "high", ".htaccess makes non-PHP files execute as PHP"],
  ["config.extension-from-tmp", "config", "high", "PHP extension loaded from a temp directory"],
  ["persist.cron", "persistence", "medium–high", "Cron entries that download-and-run, open shells, mine or run from /tmp"],
  ["persist.systemd", "persistence", "medium–high", "systemd units with the same patterns"],
  ["persist.profile", "persistence", "medium–high", "Shell start-up scripts and rc.local with the same patterns"],
  ["persist.ld-preload", "persistence", "high", "Non-empty /etc/ld.so.preload"],
  ["persist.uid0", "persistence", "high", "Extra account with UID 0"],
  ["persist.web-ssh-key", "persistence", "medium", "SSH key for the web server account"],
  ["persist.web-shell-login", "persistence", "low", "Web server account with a login shell"],
  ["persist.tmp-elf", "persistence", "medium–high", "Executable in /tmp, /var/tmp or /dev/shm"],
  ["log.flagged-file-access", "log", "high", "HTTP requests to a file flagged by the file scan"],
  ["log.post-upload-php", "log", "high", "Successful POST to PHP in an upload directory"],
  ["log.command-param", "log", "medium", "Shell commands in request parameters"],
  ["log.code-in-request", "log", "medium", "PHP code or stream wrappers in request URLs"],
  ["log.php-cgi-arg-injection", "log", "medium", "php-cgi argument injection probes"],
  ["log.worker-crash", "log", "medium", "PHP worker segfaults and heap corruption"],
  ["log.early-oom", "log", "medium", "Out-of-memory during request start-up (the CVE-2026-109618 trigger)"],
  ["log.hard-oom", "log", "low", "Patched hard memory limit reached"],
  ["log.multipart-limits", "log", "low", "Request parsing limits hit"],
  ["log.webshell-name", "log", "low–medium", "Requests for webshell file names"],
];

export function catalog() {
  const rules = JSON.parse(readFileSync(new URL("internal/trace/rules/content.json", repo), "utf8")).rules;
  const dir = new URL("internal/trace/", repo);
  const goIDs = new Set();
  for (const f of readdirSync(dir).filter((f) => f.endsWith(".go") && !f.endsWith("_test.go"))) {
    for (const m of readFileSync(new URL(f, dir), "utf8").matchAll(/"((?:file|persist|log|config)\.[a-z0-9-]+)"/g)) goIDs.add(m[1]);
  }
  const listed = new Set(BUILTIN.map((b) => b[0]));
  const missing = [...goIDs].filter((id) => !listed.has(id));
  const stale = [...listed].filter((id) => !goIDs.has(id));
  if (missing.length || stale.length) throw new Error(`catalog out of sync: unlisted ${missing.join(", ")} / not in Go ${stale.join(", ")}`);
  return {
    signatures: rules.map((r) => ({ id: r.id, category: "signature", severity: r.severity, title: r.title.en })),
    builtin: BUILTIN.map(([id, category, severity, title]) => ({ id, category, severity, title })),
  };
}
