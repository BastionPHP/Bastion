import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { layout, REPO } from "../lib/layout.mjs";
import { codebox, esc, INSTALL } from "./common.mjs";
import { highlightJSON } from "../lib/highlight.mjs";

const repoRoot = new URL("../../", import.meta.url).pathname;

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
  if (!rows.length) throw new Error(`docs: could not read flags for "${cmd}" — build ./bastion or install Go`);
  return rows;
}

function flagTable(ctx, cmd) {
  const rows = flagsFor(cmd);
  return `<div class="bx-card bx-table-wrap"><table class="bx-table"><thead><tr><th>Flag</th><th>Description</th><th>Default</th></tr></thead><tbody>${rows
    .map((r) => `<tr><td class="mono">${esc(r.flag)}${r.type ? ` <span class="bx-faint">${esc(r.type)}</span>` : ""}</td><td>${esc(r.desc)}</td><td class="mono bx-faint">${esc(r.def)}</td></tr>`)
    .join("")}</tbody></table></div>`;
}

export function render(ctx) {
  const faq = [
    ["Does Bastion change anything on my server?", "No. It opens files and reads <code>/proc</code>. It never writes outside the report file you ask for, never restarts services, never deletes or quarantines. By default it may run <code>php -v</code> when a binary can't be read statically, and <code>docker exec</code> when a container filesystem isn't readable; <code>--no-exec</code> turns both off."],
    ["Does it send data anywhere?", "No. <code>scan</code>, <code>trace</code>, <code>check</code> and <code>report</code> make no network connections (the Docker/Podman CLI talks to the local daemon only). The vulnerability data is compiled in. The website's online check also runs locally in your browser."],
    ["Why does it need root?", "To see other users' processes (php-fpm workers, Apache), container filesystems under <code>/proc/&lt;pid&gt;/root</code>, crontabs and web server logs. Without root it still runs and tells you what it could not see."],
    ["Why is my build “unknown”?", "Because Bastion could not prove it either way: typically a distribution package from a vendor without fixed-version data whose changelog isn't installed. Ask the vendor whether CVE-2026-109618/109619 are fixed in that package; Bastion won't guess."],
    ["I built PHP 8.1 from the official backport branch. Why “likely vulnerable”?", "The backport branches keep the version string (8.1.34) and add no distinctive marker, so a patched build is indistinguishable from an unpatched one. Bastion reports what it can prove; you know what you built."],
    ["If trace finds nothing, am I safe?", "Not necessarily. Signatures miss novel backdoors and an attacker with root can hide from any on-host tool. A clean trace lowers the odds; it isn't proof. If you suspect a breach, image the disk and investigate offline (<code>--sysroot</code> works on a mounted image)."],
    ["What about false positives?", "File signatures were tuned against about 33,000 PHP files from WordPress, Drupal, phpMyAdmin, Laravel, Symfony, phpseclib and PHPMailer with zero high or medium hits; CI re-checks WordPress and Drupal on every change. Weak signals are only reported when several appear together. Each finding names its rule and shows the matching line so you can judge it."],
    ["Containers, Kubernetes, LXC?", "Running Docker and Podman containers are listed through their CLI and read via <code>/proc/&lt;pid&gt;/root</code>. Any other process with its own root filesystem (Kubernetes pods via containerd/CRI-O, LXC, chroots) is found from <code>/proc</code> and scanned the same way. Images that aren't running are not scanned."],
    ["Windows?", "Not supported for <code>scan</code>/<code>trace</code>. Use the <a href=\"" + ctx.href("check") + "\">online check</a> with <code>php -v</code>."],
    ["How current is the vulnerability data?", "It is compiled into each release and reflects official sources at release time (PHP2Shell data: php.net, GitHub advisories, Ubuntu and Debian trackers as of 22 Oct 2026). Newer data can be loaded without upgrading using <code>--db &lt;dir&gt;</code>."],
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
    { "distro": "ubuntu", "release": "24.04", "package": "php8.3", "fixed": "8.3.6-0ubuntu0.24.04.20", "format": "dpkg", "advisory": "USN-…", "url": "https://…" }
  ],
  "changelog_markers": ["CVE-2027-0001"],
  "fingerprints": [],
  "mitigations": [{ "en": "…" }],
  "references": [{ "title": "…", "url": "https://…" }]
}`;
  const body = `
<header class="phead">
  <div class="bx-grid-bg" aria-hidden="true"></div>
  <div class="bx-wrap phead-in">
    <div class="bx-eyebrow">Documentation</div>
    <h1>Install, run, read the results</h1>
    <p>Everything about the <code>bastion</code> command line. Flag tables on this page are generated from the binary itself.</p>
  </div>
</header>
<div class="bx-wrap docs-grid">
  <nav class="docs-toc" aria-label="On this page">
    <span class="bx-eyebrow">Start</span>
    <a href="#install">Install</a><a href="#quickstart">Quick start</a>
    <span class="bx-eyebrow">Commands</span>
    <a href="#commands">scan</a><a href="#trace">trace</a><a href="#report">report</a><a href="#check">check</a><a href="#exit">Exit codes & JSON</a>
    <span class="bx-eyebrow">More</span>
    <a href="#statuses">Statuses</a><a href="#data">Advisory data</a><a href="#faq">FAQ</a>
  </nav>
  <div class="docs">
    <section id="install">
      <h2>Install</h2>
      <p>Bastion is one static binary for Linux and macOS (amd64, arm64). The script picks the right build from the latest GitHub release, checks its SHA-256 against <code>SHA256SUMS</code> and, if <code>cosign</code> is installed, verifies the Sigstore signature of that file. It installs to <code>/usr/local/bin</code> (or <code>~/.local/bin</code> without root) and changes nothing else.</p>
      ${codebox(INSTALL)}
      <p>Options (environment variables):</p>
      <div class="bx-card bx-table-wrap"><table class="bx-table"><tbody>
        <tr><td class="mono">BASTION_VERSION</td><td>release tag to install, e.g. <code>v0.1.0</code> (default: latest)</td></tr>
        <tr><td class="mono">BASTION_INSTALL_DIR</td><td>target directory</td></tr>
        <tr><td class="mono">BASTION_REQUIRE_SIGNATURE=1</td><td>fail if <code>cosign</code> is missing instead of skipping the signature check</td></tr>
      </tbody></table></div>
      <h3>Verify by hand</h3>
      ${codebox(`VERSION=v0.1.0\nBASE=https://github.com/larptard/bastion/releases/download/$VERSION\ncurl -fsSLO $BASE/bastion_linux_amd64.tar.gz -O $BASE/SHA256SUMS -O $BASE/SHA256SUMS.sigstore.json\nsha256sum --ignore-missing -c SHA256SUMS\ncosign verify-blob --bundle SHA256SUMS.sigstore.json \\\n  --certificate-identity-regexp '^https://github.com/larptard/bastion/.github/workflows/release.yml@refs/tags/v' \\\n  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS\ngh attestation verify bastion_linux_amd64.tar.gz --repo larptard/bastion   # build provenance`)}
      <h3>From source</h3>
      ${codebox("go install github.com/larptard/bastion/cmd/bastion@latest   # Go 1.24+\n# or\ngit clone https://github.com/larptard/bastion && cd bastion && make build")}
    </section>

    <section id="quickstart">
      <h2>Quick start</h2>
      ${codebox("sudo bastion scan              # every PHP build: patched or not\nsudo bastion trace             # signs of compromise in web roots, persistence, logs\nsudo bastion report            # both, as one offline HTML file\nphp -v | bastion check         # assess pasted output (no root needed)")}
      <p>Run as root for full coverage. Nothing is modified; remediation steps are printed for you to apply.</p>
    </section>

    <section id="commands">
      <h2><code>bastion scan</code></h2>
      <p>Finds PHP builds in the standard locations of distributions and hosting panels (BaoTa/aaPanel, cPanel EA4, CloudLinux alt-php, Plesk, Remi, LiteSpeed, Homebrew, XAMPP, Bitnami, <code>/usr/local/php*</code>), in <code>$PATH</code>, in running processes (php-fpm, php-cgi, lsphp, FrankenPHP and Apache with mod_php) and in Docker/Podman containers and other mount namespaces. For each build it reads the version from the binary, looks up the owning dpkg/rpm/apk package and its changelog, and evaluates every advisory.</p>
      ${flagTable(ctx, "scan")}
    </section>

    <section id="trace">
      <h2><code>bastion trace [dir…]</code></h2>
      <p>Discovers web roots from nginx, Apache, LiteSpeed and Caddy configuration and the default paths of common panels, plus any directories you pass. It reports webshell signatures, PHP in uploads and images, <code>.user.ini</code>/<code>.htaccess</code> abuse, suspicious cron/systemd/profile entries, <code>/etc/ld.so.preload</code>, extra UID 0 accounts, SSH keys for web users, executables in temp directories, global <code>auto_prepend_file</code>, and log indicators: requests to flagged files, successful POSTs to PHP in upload folders, command parameters, php-cgi argument injection, worker segfaults and out-of-memory during request start-up.</p>
      ${flagTable(ctx, "trace")}
    </section>

    <section id="report">
      <h2><code>bastion report</code></h2>
      <p>Runs <code>scan</code> and <code>trace</code> and writes <code>bastion-report-&lt;host&gt;-&lt;time&gt;.html</code>: one file with inline styles and data, no external requests, printable. It contains host details — share it deliberately. Use <code>--scan</code>/<code>--trace</code> to build a report from saved JSON, e.g. collected from several servers. <a href="${ctx.root}demo/report.html">Sample report →</a></p>
      ${flagTable(ctx, "report")}
    </section>

    <section id="check">
      <h2><code>bastion check</code></h2>
      <p>Assesses text instead of the machine: the output of <code>php -v</code>, optionally with <code>dpkg-query -W 'php*'</code>, <code>rpm -qa 'php*'</code>, <code>apk info -v</code> or <code>/etc/os-release</code>. It is the same engine as the online check.</p>
      ${codebox("ssh web-01 'php -v; dpkg-query -W \"php*\"' | bastion check\nbastion check --os ubuntu:24.04 'PHP 8.3.6 (cli)'")}
      ${flagTable(ctx, "check")}
    </section>

    <section id="exit">
      <h2>Exit codes & JSON</h2>
      <div class="bx-card bx-table-wrap"><table class="bx-table"><tbody>
        <tr><td class="mono">0</td><td>nothing affected / no indicators</td></tr>
        <tr><td class="mono">1</td><td>a vulnerable or likely vulnerable build, or high-severity indicators</td></tr>
        <tr><td class="mono">2</td><td>some builds unknown, or only medium indicators</td></tr>
        <tr><td class="mono">64 / 70</td><td>usage error / runtime error</td></tr>
      </tbody></table></div>
      <p><code>--json</code> prints a versioned document (<code>bastion.scan/v1</code>, <code>bastion.trace/v1</code>) for fleets and CI:</p>
      ${codebox(`sudo bastion scan --json | jq -r '.instances[] | select(.assessments[0].status != "fixed") | "\\(.target) \\(.path) \\(.assessments[0].status)"'`)}
    </section>

    <section id="statuses">
      <h2>What the statuses mean</h2>
      <div class="bx-card bx-table-wrap"><table class="bx-table"><tbody>
        <tr><td><span class="bx-badge" data-status="fixed">fixed</span></td><td>Proven: upstream version at or above the fix, vendor package at or above the vendor's fixed version, a changelog naming the CVE, or code only the fix contains.</td></tr>
        <tr><td><span class="bx-badge" data-status="vulnerable">vulnerable</span></td><td>Proven: below the upstream fix with no package manager involved, or a vendor package older than the vendor's fixed version.</td></tr>
        <tr><td><span class="bx-badge" data-status="likely-vulnerable">likely-vulnerable</span></td><td>No evidence of a fix where evidence would be expected: an end-of-life branch with only a source backport, a package whose changelog doesn't mention the CVE, or a process still running a replaced binary.</td></tr>
        <tr><td><span class="bx-badge" data-status="unknown">unknown</span></td><td>Not enough information. Bastion will not turn this into a guess.</td></tr>
      </tbody></table></div>
    </section>

    <section id="data">
      <h2>Advisory data</h2>
      <p>${"Each vulnerability is one JSON document in <a href=\"" + REPO + "/tree/main/internal/advisory/data\"><code>internal/advisory/data/</code></a>, validated on load. Drop a file there and rebuild, or point <code>--db</code> at a directory to add or override advisories at run time. <code>bastion advisories</code> prints what is loaded."}</p>
      <pre class="bx-code">${highlightJSON(advExample)}</pre>
      <p>Webshell and obfuscation signatures follow the same idea in <code>internal/trace/rules/content.json</code>.</p>
    </section>

    <section id="faq" class="faq">
      <h2>FAQ</h2>
      ${faq.map(([q, a]) => `<details><summary>${q}</summary><p>${a}</p></details>`).join("")}
    </section>
  </div>
</div>
`;
  return layout(ctx, {
    title: "Docs",
    description: "Install Bastion, run scan/trace/report/check, read the statuses and extend the advisory data.",
    body,
  });
}
