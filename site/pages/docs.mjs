import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { layout, REPO } from "../lib/layout.mjs";
import { codebox, esc, icon, statusTag, INSTALL } from "./common.mjs";
import { highlightJSON } from "../lib/highlight.mjs";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));

// flagsFor runs the real binary's -h so the tables cannot drift from the code.
function flagsFor(cmd) {
  const bin = process.env.BASTION_BIN || (existsSync(repoRoot + "bastion") ? repoRoot + "bastion" : "");
  // flag's usage goes to stderr.
  const r = bin
    ? spawnSync(bin, [cmd, "-h"], { encoding: "utf8" })
    : spawnSync("go", ["run", "./cmd/bastion", cmd, "-h"], { cwd: repoRoot, encoding: "utf8" });
  const out = (r.stdout || "") + (r.stderr || "");
  const rows = [];
  const lines = out.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^  -(\S+)(?: (\S+))?$/.exec(lines[i]);
    if (!m) continue;
    let desc = "";
    while (i + 1 < lines.length && /^\s{4,}/.test(lines[i + 1])) desc += " " + lines[++i].trim();
    let def = "";
    const d = /\(default (.*)\)\s*$/.exec(desc);
    if (d) { def = d[1]; desc = desc.slice(0, d.index); }
    rows.push({ flag: "--" + m[1], type: m[2] === "value" ? "string" : m[2] || "", desc: desc.trim(), def });
  }
  if (!rows.length) {
    if (process.argv.includes("--preview")) {
      console.warn(`preview: flags for "${cmd}" unavailable; build ./bastion or install Go for the full command reference`);
      return [];
    }
    throw new Error(`docs: could not read flags for "${cmd}"; build ./bastion or install Go`);
  }
  return rows;
}

function flagTable(cmd) {
  const rows = flagsFor(cmd);
  if (!rows.length) return '<p class="note">The command reference is unavailable in this local preview.</p>';
  return `<div class="panel tbl-wrap"><table class="tbl"><thead><tr><th>Flag</th><th>Description</th><th>Default</th></tr></thead><tbody>${rows
    .map((r) => `<tr><td class="mono" style="white-space:nowrap">${esc(r.flag)}${r.type ? ` <span class="bx-faint">${esc(r.type)}</span>` : ""}</td><td>${esc(r.desc)}</td><td class="mono bx-faint">${esc(r.def)}</td></tr>`)
    .join("")}</tbody></table></div>`;
}

export function render(ctx) {
  const faq = [
    ["Does Bastion change anything on the server?", "No. It opens files and reads <code>/proc</code>. It never writes outside the report file you ask for, never restarts services, never deletes or quarantines. When a binary cannot be read statically it may run <code>php -v</code>, and when a container filesystem is not readable it may use <code>docker exec</code>; <code>--no-exec</code> turns both off. Image scanning uses <code>docker save</code>, which creates no container."],
    ["Does it send data anywhere?", "No. <code>scan</code>, <code>trace</code>, <code>check</code> and <code>report</code> make no network connections; the Docker and Podman CLIs only talk to the local daemon. The vulnerability data is compiled in. The website's online check also runs in your browser."],
    ["Why does it need root?", "To see other users' processes (php-fpm workers, Apache), container filesystems under <code>/proc/&lt;pid&gt;/root</code>, crontabs and web server logs. Without root it still runs and lists what it could not see."],
    ["Why is a build reported as unknown?", "Bastion could not prove it either way. Typically this is a distribution package from a vendor without fixed-version data whose changelog is not installed. Ask the vendor whether CVE-2026-109618 and CVE-2026-109619 are fixed in that package."],
    ["I built PHP 8.1 from the official backport branch. Why likely vulnerable?", "The backport branches keep the version string (8.1.34) and add no marker that can be read from the binary, so a patched build is indistinguishable from an unpatched one. Bastion reports what it can prove."],
    ["If trace finds nothing, is the server clean?", "Not necessarily. Signatures miss novel backdoors, and an attacker with root can hide from any on-host tool. A clean trace lowers the odds; it is not proof. If you suspect a breach, image the disk and investigate offline: <code>--sysroot</code> works on a mounted image."],
    ["What about false positives?", "File signatures were tuned against about 33,000 PHP files from WordPress, Drupal, phpMyAdmin, Laravel, Symfony, phpseclib and PHPMailer with no high or medium matches; CI repeats the check on every change. Weak signals are only reported when several appear in one file. Each finding names its rule and shows the matching line."],
    ["Containers, images, Kubernetes, LXC?", "Running Docker and Podman containers are read through <code>/proc/&lt;pid&gt;/root</code>. Any other process with its own root filesystem (Kubernetes pods via containerd or CRI-O, LXC, chroots) is found in <code>/proc</code> and scanned the same way. Images are scanned with <code>--image REF</code> or <code>--images</code>."],
    ["Windows?", "<code>scan</code> and <code>trace</code> run on Linux and macOS. For Windows, use the <a href=\"" + ctx.href("check") + "\">online check</a> with <code>php -v</code>."],
    ["How current is the vulnerability data?", "It is compiled into each release and reflects official sources at that time. PHP2Shell data comes from php.net, the GitHub advisories, the Ubuntu and Debian trackers, Red Hat errata, Alpine's secdb and Plesk's advisory, as of 22 October 2026. Newer data can be loaded without upgrading with <code>--db &lt;dir&gt;</code>."],
  ];
  const advExample = `{
  "schema": "bastion.advisory/v1",
  "id": "EXAMPLE-2027",
  "name": "Example",
  "product": "php",
  "published": "2027-01-01",
  "severity": "high",
  "cvss": { "version": "4.0", "score": 8.1, "vector": "CVSS:4.0/…" },
  "aliases": ["CVE-2027-0001"],
  "vulnerabilities": [{ "cve": "CVE-2027-0001", "ghsa": "", "title": { "en": "…" }, "url": "https://…" }],
  "summary": { "en": "…" },
  "branches": [
    { "branch": "8.5", "fixed": "8.5.20", "status": "supported" },
    { "branch": "8.1", "status": "eol" }
  ],
  "older_branches": "affected",
  "newer_branches": "fixed",
  "vendor_fixes": [
    { "distro": "ubuntu", "release": "24.04", "package": "php8.3", "fixed": "8.3.6-0ubuntu0.24.04.20", "format": "dpkg", "advisory": "USN-…", "url": "https://…" },
    { "distro": "rhel", "release": "9", "branch": "8.2", "package": "php", "fixed": "8.2.40-1.module+el9…", "format": "rpm", "advisory": "RHSA-…", "url": "https://…" }
  ],
  "vendor_policies": [{ "distro": "alpine", "source": "Alpine secdb", "checked": "2027-01-02", "url": "https://…" }],
  "build_date_fixes": [{ "environment": "Plesk", "branches": ["8.1"], "fixed_on": "2027-01-01", "source": "…", "url": "https://…" }],
  "changelog_markers": ["CVE-2027-0001"],
  "fingerprints": [],
  "mitigations": [{ "en": "…" }],
  "config_checks": [{ "setting": "memory_limit", "default": "128M", "safe": "-1", "text": { "en": "…" } }],
  "references": [{ "title": "…", "url": "https://…" }]
}`;
  const fields = [
    ["branches", "Fixed upstream release per branch; branches without one have no release."],
    ["vendor_fixes", "Exact fixed package versions. A release without a dot (\"9\") matches every minor release; branch limits the entry to one upstream branch."],
    ["vendor_policies", "Vendors whose security database was checked and records no backport below the upstream fix."],
    ["build_date_fixes", "Vendor rebuilds that kept the version number and are identified by compile date."],
    ["changelog_markers", "Strings that, found in an installed package's changelog, prove a backport."],
    ["fingerprints", "Byte strings that only patched binaries contain."],
    ["config_checks", "php.ini directives audited for unfixed builds. safe is off, an exact value, or a size bound like <=32M."],
  ];
  const body = `
<header class="phead">
  <div class="bx-wrap">
    <div class="crumbs">${icon("book-open")}Bastion <span>/</span> Documentation</div>
    <h1>Install, run and read the results</h1>
    <p>Reference for the <code>bastion</code> command line. Flag tables on this page are generated from the binary's own help output.</p>
  </div>
</header>
<div class="bx-wrap docs-grid">
  <nav class="toc" aria-label="On this page">
    <span class="label">Start</span>
    <a href="#install">${icon("download")}Install</a><a href="#quickstart">${icon("terminal")}Quick start</a>
    <span class="label">Commands</span>
    <a href="#commands">${icon("scan-search")}scan</a><a href="#trace">${icon("radar")}trace</a><a href="#report">${icon("file-text")}report</a><a href="#check">${icon("list-checks")}check</a><a href="#output">${icon("braces")}Output, exit codes</a>
    <span class="label">Reference</span>
    <a href="#statuses">${icon("shield")}Statuses</a><a href="#data">${icon("file-json")}Advisory data</a><a href="#faq">${icon("circle-help")}FAQ</a>
  </nav>
  <div class="docs">
    <section id="install">
      <h2>${icon("download")}Install</h2>
      <p>One static binary for Linux and macOS, amd64 and arm64. The script picks the build for your platform from the latest release, checks its SHA-256 against <code>SHA256SUMS</code> and, if <code>cosign</code> is installed, verifies the Sigstore signature of that file. It installs to <code>/usr/local/bin</code> (or <code>~/.local/bin</code> without root) and changes nothing else.</p>
      ${codebox(INSTALL)}
      <div class="panel tbl-wrap"><table class="tbl"><thead><tr><th>Variable</th><th>Effect</th></tr></thead><tbody>
        <tr><td class="mono">BASTION_VERSION</td><td>Release tag to install, for example <code>v0.1.0</code>. Default: latest.</td></tr>
        <tr><td class="mono">BASTION_INSTALL_DIR</td><td>Target directory.</td></tr>
        <tr><td class="mono">BASTION_REQUIRE_SIGNATURE=1</td><td>Fail if <code>cosign</code> is missing instead of skipping the signature check.</td></tr>
        <tr><td class="mono">BASTION_DOWNLOAD_URL</td><td>A mirror with the same release files. Checksum and signature checks still apply.</td></tr>
      </tbody></table></div>
      <h3>Verify by hand</h3>
      ${codebox(`VERSION=v0.1.0\nBASE=${REPO}/releases/download/$VERSION\ncurl -fsSLO $BASE/bastion_linux_amd64.tar.gz -O $BASE/SHA256SUMS -O $BASE/SHA256SUMS.sigstore.json\nsha256sum --ignore-missing -c SHA256SUMS\ncosign verify-blob --bundle SHA256SUMS.sigstore.json \\\n  --certificate-identity-regexp '^https://github.com/BastionPHP/Bastion/.github/workflows/release.yml@refs/tags/v' \\\n  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS\ngh attestation verify bastion_linux_amd64.tar.gz --repo BastionPHP/Bastion   # build provenance`)}
      <h3>From source</h3>
      ${codebox("go install github.com/larptard/bastion/cmd/bastion@latest   # Go 1.24+\n# or\ngit clone https://github.com/BastionPHP/Bastion && cd Bastion && make build")}
    </section>

    <section id="quickstart">
      <h2>${icon("terminal")}Quick start</h2>
      ${codebox("sudo bastion scan                       # every PHP build: patched or not\nsudo bastion scan --images              # also every local container image\nsudo bastion trace                      # signs of compromise in web roots, persistence, logs\nsudo bastion report                     # both, as one offline HTML file\nphp -v | bastion check                  # assess pasted output, no root needed")}
      <p>Run as root for full coverage. Nothing is modified; remediation steps are printed for you to apply.</p>
    </section>

    <section id="commands">
      <h2>${icon("scan-search")}bastion scan</h2>
      <p>Finds PHP builds in the standard locations of distributions and hosting panels, in <code>$PATH</code>, in running processes (php-fpm, php-cgi, lsphp, FrankenPHP, Apache with mod_php, including processes still running a replaced binary), in Docker and Podman containers and other mount namespaces, and, on request, in container images. For each build it reads the version and build date from the binary, looks up the owning dpkg, rpm or apk package and its changelog, evaluates every advisory and, for builds that are not fixed, audits the interim mitigation settings in php.ini and PHP-FPM pools.</p>
      ${flagTable("scan")}
    </section>

    <section id="trace">
      <h2>${icon("radar")}bastion trace [dir…]</h2>
      <p>Discovers web roots from nginx, Apache, LiteSpeed and Caddy configuration and the default paths of common panels, plus any directories you pass. It reports webshell signatures, PHP in uploads and images, <code>.user.ini</code> and <code>.htaccess</code> abuse, suspicious cron, systemd and shell start-up entries, <code>/etc/ld.so.preload</code>, extra UID 0 accounts, SSH keys for web users, executables in temp directories, global <code>auto_prepend_file</code>, and log indicators, then builds a timeline. The <a href="${ctx.href("home", "#trace")}">rule catalogue</a> lists every check.</p>
      ${flagTable("trace")}
    </section>

    <section id="report">
      <h2>${icon("file-text")}bastion report</h2>
      <p>Runs <code>scan</code> and <code>trace</code> and writes <code>bastion-report-&lt;host&gt;-&lt;time&gt;.html</code>: one file with inline styles, icons and data, no external requests, printable. It contains host details, so share it deliberately. Use <code>--scan</code> and <code>--trace</code> to build a report from saved JSON, for example collected from several servers. <a href="${ctx.root}demo/report.html">Sample report</a>.</p>
      ${flagTable("report")}
    </section>

    <section id="check">
      <h2>${icon("list-checks")}bastion check</h2>
      <p>Assesses text instead of the machine: the output of <code>php -v</code>, optionally with <code>dpkg-query -W 'php*'</code>, <code>rpm -qa 'php*'</code>, <code>apk info -v</code> or <code>/etc/os-release</code>. It uses the same engine as the online check, and recognises Plesk builds from <code>/opt/plesk/php/</code> paths.</p>
      ${codebox("ssh web-01 'php -v; dpkg-query -W \"php*\"' | bastion check\nbastion check --os ubuntu:24.04 'PHP 8.3.6 (cli)'")}
      ${flagTable("check")}
    </section>

    <section id="output">
      <h2>${icon("braces")}Output formats and exit codes</h2>
      <div class="panel tbl-wrap"><table class="tbl"><thead><tr><th>Format</th><th>Description</th></tr></thead><tbody>
        <tr><td class="mono">--format text</td><td>Terminal view, the default. Colour follows <code>--color</code>, <code>NO_COLOR</code> and whether output is a terminal.</td></tr>
        <tr><td class="mono">--format json</td><td>Versioned documents: <code>bastion.scan/v1</code> and <code>bastion.trace/v1</code>. <code>--json</code> is a shorthand.</td></tr>
        <tr><td class="mono">--format sarif</td><td>SARIF 2.1.0 with <code>security-severity</code>, for GitHub code scanning and other dashboards. Fixed builds are omitted.</td></tr>
      </tbody></table></div>
      <div class="panel tbl-wrap"><table class="tbl"><thead><tr><th>Exit code</th><th>Meaning</th></tr></thead><tbody>
        <tr><td class="mono">0</td><td>No affected builds, no indicators.</td></tr>
        <tr><td class="mono">1</td><td>A vulnerable or likely vulnerable build, or high-severity indicators.</td></tr>
        <tr><td class="mono">2</td><td>Some builds could not be verified, or only medium indicators.</td></tr>
        <tr><td class="mono">64, 70</td><td>Usage error, runtime error.</td></tr>
      </tbody></table></div>
      ${codebox(`sudo bastion scan --json | jq -r '.instances[] | select(.assessments[0].status != "fixed") | "\\(.target) \\(.path) \\(.assessments[0].status)"'\nsudo bastion trace --format sarif > trace.sarif`)}
    </section>

    <section id="statuses">
      <h2>${icon("shield")}Statuses</h2>
      <div class="panel tbl-wrap"><table class="tbl"><tbody>
        <tr><td>${statusTag("fixed")}</td><td>Proven: upstream version at or above the fix, a vendor package at or above the vendor's fixed version, a dated vendor rebuild, a changelog naming the CVE, or code only the fix contains.</td></tr>
        <tr><td>${statusTag("vulnerable")}</td><td>Proven: below the upstream fix with no package manager involved, a vendor package older than the vendor's fixed version, or a vendor build dated before its fixed rebuild.</td></tr>
        <tr><td>${statusTag("likely-vulnerable")}</td><td>No evidence of a fix where evidence would be expected: an end-of-life branch with only a source backport, a package whose vendor database or changelog is silent, or a process still running a replaced binary.</td></tr>
        <tr><td>${statusTag("unknown")}</td><td>Not enough information to decide either way.</td></tr>
      </tbody></table></div>
    </section>

    <section id="data">
      <h2>${icon("file-json")}Advisory data</h2>
      <p>Each vulnerability is one JSON document in <a href="${REPO}/tree/main/internal/advisory/data"><code>internal/advisory/data/</code></a>, validated on load. Add a file and rebuild, or point <code>--db</code> at a directory to add or override advisories at run time. <code>bastion advisories</code> prints what is loaded.</p>
      <div class="panel tbl-wrap"><table class="tbl"><thead><tr><th>Field</th><th>Meaning</th></tr></thead><tbody>${fields.map(([f, d]) => `<tr><td class="mono">${f}</td><td>${esc(d)}</td></tr>`).join("")}</tbody></table></div>
      <pre class="code">${highlightJSON(advExample)}</pre>
      <p>Webshell and obfuscation signatures follow the same approach in <code>internal/trace/rules/content.json</code>.</p>
    </section>

    <section id="faq" class="faq">
      <h2>${icon("circle-help")}FAQ</h2>
      <div>${faq.map(([q, a]) => `<details><summary>${q}${icon("chevron-right")}</summary><p>${a}</p></details>`).join("")}</div>
    </section>
  </div>
</div>
`;
  return layout(ctx, {
    title: "Docs",
    description: "Install Bastion, run scan, trace, report and check, read the statuses and extend the advisory data.",
    body,
  });
}
