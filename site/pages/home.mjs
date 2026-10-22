import { layout, REPO } from "../lib/layout.mjs";
import { catalog } from "../lib/catalog.mjs";
import { evidenceMap } from "../lib/evidence-map.mjs";
import { terminal, recording, codebox, copyBtn, statusTag, sevTag, INSTALL, esc, icon } from "./common.mjs";

// What scan covers, per environment. Every claim here maps to code:
// discover.Patterns, pkgdb, the advisory's vendor_fixes / policies / build
// date rules, and remedy.Steps.
const COVERAGE = [
  ["package", "Debian, Ubuntu", "/usr/bin, /usr/sbin, Apache modules", "Vendor fix table (Ubuntu 14.04–26.10, Debian 12–13), changelog.Debian.gz, fix fingerprint", "apt"],
  ["package", "RHEL, AlmaLinux, Rocky", "/usr/bin, php-fpm, httpd modules", "Vendor fix table (RHEL 8, 9, 10 errata), rpm changelog, fix fingerprint", "dnf"],
  ["package", "Alpine", "/usr/bin/phpNN", "secdb policy: stable branches carry no backport", "apk"],
  ["container", "Docker official images", "/usr/local/bin, /usr/local/sbin", "Upstream version", "Rebuild on a patched tag"],
  ["boxes", "Running containers, pods", "/proc/<pid>/root of each container", "Same evidence as the base distribution", "Per base image"],
  ["layers", "Container images", "docker / podman save, never run", "Same evidence as the base distribution", "Rebuild"],
  ["server", "BaoTa / aaPanel", "/www/server/php/*", "Upstream version", "App Store → Installed"],
  ["server", "cPanel EasyApache 4", "/opt/cpanel/ea-php*", "rpm changelog", "dnf ea-php*"],
  ["server", "CloudLinux alt-php", "/opt/alt/php*", "rpm changelog", "yum alt-php*"],
  ["server", "Plesk", "/opt/plesk/php/*", "Build date for the 7.4–8.1 rebuilds", "plesk installer"],
  ["hard-drive", "Remi, LiteSpeed, Homebrew, XAMPP, Bitnami, source builds", "Standard prefixes, $PATH", "Upstream version, changelog where packaged", "Per environment"],
  ["rotate-ccw", "Workers running replaced code", "/proc/<pid>/exe, Apache memory maps", "Version and fingerprint of the old image", "Restart the service"],
];

export function render(ctx, { advisory }) {
  const rec = recording();
  const cat = catalog();
  const supported = advisory.branches.filter((b) => b.fixed);
  const eol = advisory.branches.filter((b) => !b.fixed);
  const vendors = advisory.vendor_fixes;
  const vendorRows = vendors
    .map((f) => `<tr><td style="white-space:nowrap">${esc(f.distro === "rhel" ? "RHEL" : f.distro[0].toUpperCase() + f.distro.slice(1))} ${esc(f.release)}</td><td class="mono">${esc(f.package)}${f.branch ? ` <span class="bx-faint">${esc(f.channel || "PHP " + f.branch)}</span>` : f.channel ? ` <span class="bx-faint">${esc(f.channel)}</span>` : ""}</td><td class="mono fix-ok">${esc(f.fixed)}</td><td><a href="${f.url}">${esc(f.advisory)}</a></td></tr>`)
    .join("");

  const body = `
<section class="hero">
  <div class="bx-wrap hero-grid">
    <div class="hero-intro">
    <div class="hero-text">
      <a class="hero-alert" href="#php2shell">${icon("shield-alert")}PHP2Shell · CVE-2026-109618 · CVE-2026-109619 · CVSS 9.2</a>
      <h1>Find every PHP build on a server and prove which ones are patched.</h1>
      <p class="hero-sub"><strong>Open-source PHP assessment, on your own machine.</strong> Inventory system packages, hosting panels, containers and images. Verify patches, including distribution backports, and look for signs of intrusion left behind before you patched.</p>
      <div class="cmd"><span class="p">$</span><code id="hero-install">${esc(INSTALL)}</code>${copyBtn("hero-install")}</div>
      <div class="hero-actions">
        <a class="btn is-primary" href="${ctx.href("check")}">${icon("scan-search")}Check php -v in the browser</a>
        <a class="btn" href="${ctx.href("docs")}">${icon("book-open")}Documentation</a>
      </div>
      <ul class="facts-line">
        <li>${icon("eye-off")}Read-only</li>
        <li>${icon("wifi-off")}No network calls</li>
        <li>${icon("box")}Single static binary</li>
        <li>${icon("cpu")}Linux and macOS, amd64 and arm64</li>
        <li>${icon("scale")}MIT</li>
      </ul>
    </div>
    ${evidenceMap()}
    </div>
    <div class="scan-preview">
      <div class="scan-preview-head">
        <span>Command-line preview</span>
        <a href="${ctx.root}demo/report.html">Sample report ${icon("arrow-up-right")}</a>
      </div>
      ${terminal(ctx, { title: "sudo bastion scan", file: "scan.ansi", cmd: "sudo bastion scan" })}
      <p class="term-cap">${esc(rec.host)}${rec.containers ? " · containers: " + esc(rec.containers) : ""} · ${esc(rec.version)} · ${esc(rec.at)}</p>
    </div>
  </div>
</section>

<section class="sect" id="php2shell">
  <div class="bx-wrap sect-grid">
    <div class="sect-side">
      <h2>The advisory</h2>
      <p>Two memory-safety bugs in the PHP engine, fixed upstream on 21 October 2026. Bastion's data is taken from php.net, the GitHub advisories and the vendors' own trackers.</p>
      <a class="side-link" href="${ctx.href("how")}">How the bugs work ${icon("arrow-right")}</a>
    </div>
    <div class="sect-main">
      <div class="adv-head"><span class="tag is-red">${icon("triangle-alert")}critical</span><h3>${esc(advisory.name)}</h3></div>
      <dl class="rec">
        <div><dt>Identifiers</dt><dd class="ids">${advisory.vulnerabilities.map((v) => `<a class="chip" href="${v.url}">${esc(v.cve)}</a><span class="chip">${esc(v.ghsa)}</span>`).join("")}</dd></div>
        <div><dt>Weakness</dt><dd>${advisory.vulnerabilities.map((v) => `<b>${esc(v.cve)}</b> ${esc(v.title.en)}`).join("<br>")} <span class="bx-faint">(${esc(advisory.vulnerabilities[0].weaknesses.join(", "))})</span></dd></div>
        <div><dt>Severity</dt><dd>CVSS ${advisory.cvss.version} base score <b>${advisory.cvss.score}</b><br><span class="vector">${esc(advisory.cvss.vector)}</span></dd></div>
        <div><dt>Exposure</dt><dd>Unauthenticated remote code execution as the web server account. Demonstrated against Apache mod_php before application code runs; PHP-FPM, FrankenPHP and LiteSpeed considered likely susceptible.</dd></div>
        <div><dt>Affected</dt><dd>Every release below ${supported.filter((b) => b.status === "supported").map((b) => `<code>${b.fixed}</code>`).join(", ")}. Branches ${eol.map((b) => b.branch).join(", ")} and older receive no upstream release.</dd></div>
        <div><dt>Timeline</dt><dd><ul class="dates"><li><time>2026-10-20</time><span>Advance notice of a security release.</span></li><li><time>2026-10-21</time><span>PHP ${supported.filter((b) => b.status === "supported").map((b) => b.fixed).join(", ")} released with source backport branches for 7.4, 8.0 and 8.1; vendor updates follow the same day.</span></li></ul></dd></div>
        <div><dt>Sources</dt><dd>${advisory.references.map((r) => `<a href="${r.url}">${esc(r.title)}</a>`).join(" · ")}</dd></div>
      </dl>
      <div class="cols-2 cols-wide">
        <div class="panel">
          <div class="panel-head"><span class="title">${icon("git-branch")}Upstream branches</span></div>
          <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Branch</th><th>Fixed in</th><th>Status</th></tr></thead><tbody>
            ${advisory.branches.map((b) => `<tr><td class="mono">${b.branch}</td><td class="mono ${b.fixed ? "fix-ok" : "fix-none"}">${b.fixed ? "≥ " + b.fixed : "no release"}</td><td class="bx-muted">${b.fixed ? (b.status === "prerelease" ? "pre-release" : "supported") : `<a href="${b.source_backport}">source backport</a>`}</td></tr>`).join("")}
          </tbody></table></div>
        </div>
        <div class="panel">
          <div class="panel-head"><span class="title">${icon("package-check")}Vendor backports in Bastion's data</span><span class="label">${vendors.length}</span></div>
          <div class="tbl-wrap" style="max-height:330px;overflow-y:auto"><table class="tbl"><thead><tr><th>Release</th><th>Package</th><th>Fixed version</th><th>Advisory</th></tr></thead><tbody>${vendorRows}</tbody></table></div>
        </div>
      </div>
    </div>
  </div>
</section>

<section class="sect" id="coverage">
  <div class="bx-wrap sect-grid">
    <div class="sect-side">
      <h2>Coverage</h2>
      <p>Where <code>scan</code> looks for PHP, and what evidence it can use to tell a patched build from a vulnerable one in each environment.</p>
      <a class="side-link" href="${ctx.href("docs", "#commands")}">scan reference ${icon("arrow-right")}</a>
    </div>
    <div class="sect-main">
      <div class="panel tbl-wrap"><table class="tbl">
        <thead><tr><th></th><th>Environment</th><th>Found at</th><th>Evidence beyond the version string</th><th>Fix guidance</th></tr></thead>
        <tbody>${COVERAGE.map(([ic, env, where, ev, fix]) => `<tr><td class="ico">${icon(ic)}</td><td>${esc(env)}</td><td class="mono bx-muted">${esc(where)}</td><td class="bx-muted">${esc(ev)}</td><td class="mono bx-muted">${esc(fix)}</td></tr>`).join("")}</tbody>
      </table></div>
      <div class="note">${icon("sliders-horizontal")}<p>For builds that are not fixed, <code>scan</code> also reads the php.ini, scan-dir and PHP-FPM pool files that apply to them and reports which official interim mitigations are in place: <code>session.upload_progress.enabled</code>, <code>memory_limit</code>, <code>post_max_size</code> and, on 8.5, <code>fatal_error_backtraces</code>.</p></div>
    </div>
  </div>
</section>

<section class="sect" id="verdict">
  <div class="bx-wrap sect-grid">
    <div class="sect-side">
      <h2>How a verdict is reached</h2>
      <p>The version string alone is not evidence for a distribution package. Bastion works down this list and stops at the first proof. If nothing proves the build either way, it says so.</p>
      <a class="side-link" href="${ctx.href("how", "#decide")}">Annotated source ${icon("arrow-right")}</a>
    </div>
    <div class="sect-main">
      <ol class="pipe">
        <li>${icon("file-search")}<b>Read the binary</b><span>Version and build date from the file itself; nothing is executed.</span></li>
        <li>${icon("git-branch")}<b>Upstream release</b><span>At or above the branch's fixed release.</span></li>
        <li>${icon("package-check")}<b>Vendor fix table</b><span>Exact fixed package versions from Ubuntu, Debian and Red Hat.</span></li>
        <li>${icon("scroll-text")}<b>Package changelog</b><span>The vendor recorded the CVE in the installed package.</span></li>
        <li>${icon("fingerprint")}<b>Fix fingerprint</b><span>Code only the patch adds, or a vendor's dated rebuild.</span></li>
        <li>${icon("list-checks")}<b>Verdict</b><span class="out"><span class="st" data-status="fixed">${icon("shield-check")}fixed</span><span class="st" data-status="vulnerable">${icon("shield-x")}vulnerable</span><span class="st" data-status="likely-vulnerable">${icon("shield-alert")}likely</span><span class="st" data-status="unknown">${icon("shield-question")}unknown</span></span></li>
      </ol>
      <div class="note is-warn">${icon("triangle-alert")}<p>Ubuntu 24.04 reports <code>PHP 8.3.6</code> both before and after its fix; only the package revision (<code>…24.04.12</code> → <code>…24.04.13</code>) changes. Comparing against upstream 8.3.36 gets both builds wrong.</p></div>
    </div>
  </div>
</section>

<section class="sect" id="trace">
  <div class="bx-wrap sect-grid">
    <div class="sect-side">
      <h2>Intrusion trace</h2>
      <p>A patch does not remove a webshell, a cron job or an SSH key planted before it was applied. <code>trace</code> checks web roots, persistence points and logs, and builds a timeline.</p>
      <a class="side-link" href="${ctx.href("docs", "#trace")}">trace reference ${icon("arrow-right")}</a>
    </div>
    <div class="sect-main">
      <div class="panel" data-tabs>
        <div class="tabs-bar" role="tablist" style="padding:0 6px">
          <button role="tab" aria-selected="true" data-tab="r-builtin">${icon("radar")}Checks <span class="bx-faint">${cat.builtin.length}</span></button>
          <button role="tab" aria-selected="false" data-tab="r-sig">${icon("search-code")}Content signatures <span class="bx-faint">${cat.signatures.length}</span></button>
          <button role="tab" aria-selected="false" data-tab="r-demo">${icon("terminal")}Example run</button>
        </div>
        <div data-panel="r-builtin" class="tbl-wrap"><table class="tbl"><thead><tr><th>Rule</th><th>Area</th><th>Severity</th><th>Indicator</th></tr></thead><tbody>
          ${cat.builtin.map((r) => `<tr><td class="mono">${r.id}</td><td class="bx-muted">${r.category}</td><td>${sevTag(r.severity)}</td><td class="bx-muted">${esc(r.title)}</td></tr>`).join("")}
        </tbody></table></div>
        <div data-panel="r-sig" class="tbl-wrap" hidden><table class="tbl"><thead><tr><th>Rule</th><th>Severity</th><th>Matches</th></tr></thead><tbody>
          ${cat.signatures.map((r) => `<tr><td class="mono">${r.id}</td><td>${sevTag(r.severity)}</td><td class="bx-muted">${esc(r.title)}</td></tr>`).join("")}
        </tbody></table></div>
        <div data-panel="r-demo" class="panel-body" hidden>
          ${terminal(ctx, { title: "sudo bastion trace --sysroot /tmp/bastion-lab", file: "trace.ansi", cmd: "sudo bastion trace --sysroot /tmp/bastion-lab" })}
          <p class="term-cap">Lab tree from scripts/demo/lab.sh. Planted samples are inert (wrapped in if (false)); IPs are documentation ranges.</p>
        </div>
      </div>
      <div class="note">${icon("list-checks")}<p>Signatures are tested against about 33,000 legitimate PHP files from WordPress, Drupal, phpMyAdmin, Laravel, Symfony, phpseclib and PHPMailer with no high or medium matches, and CI repeats the check on every change.</p></div>
    </div>
  </div>
</section>

<section class="sect" id="output">
  <div class="bx-wrap sect-grid">
    <div class="sect-side">
      <h2>Output and integration</h2>
      <p>Readable in a terminal, parseable in a pipeline, importable into a security dashboard.</p>
    </div>
    <div class="sect-main">
      <div class="panel tbl-wrap"><table class="tbl">
        <thead><tr><th></th><th>Format</th><th>Use</th><th>Flag</th></tr></thead>
        <tbody>
          <tr><td class="ico">${icon("terminal")}</td><td>Terminal</td><td class="bx-muted">Status colours, aligned tables, evidence and fix steps per build, timeline</td><td class="mono bx-muted">default</td></tr>
          <tr><td class="ico">${icon("braces")}</td><td>JSON</td><td class="bx-muted">Versioned documents <code>bastion.scan/v1</code>, <code>bastion.trace/v1</code> for fleets and scripts</td><td class="mono bx-muted">--format json</td></tr>
          <tr><td class="ico">${icon("shield")}</td><td>SARIF 2.1.0</td><td class="bx-muted">GitHub code scanning and other security dashboards, with security-severity</td><td class="mono bx-muted">--format sarif</td></tr>
          <tr><td class="ico">${icon("file-text")}</td><td>HTML report</td><td class="bx-muted">One self-contained file, works offline, both scan and trace, printable · <a href="${ctx.root}demo/report.html">sample</a></td><td class="mono bx-muted">bastion report</td></tr>
        </tbody>
      </table></div>
      <div class="panel tbl-wrap"><table class="tbl">
        <thead><tr><th>Exit code</th><th>Meaning</th></tr></thead>
        <tbody><tr><td class="mono">0</td><td class="bx-muted">No affected builds, no indicators</td></tr><tr><td class="mono">1</td><td class="bx-muted">A vulnerable or likely vulnerable build, or high-severity indicators</td></tr><tr><td class="mono">2</td><td class="bx-muted">Some builds could not be verified, or only medium indicators</td></tr></tbody>
      </table></div>
    </div>
  </div>
</section>

<section class="sect" id="roadmap">
  <div class="bx-wrap sect-grid">
    <div class="sect-side">
      <h2>Modules</h2>
      <p>Bastion is planned as five modules. Everything planned stays read-only by default; anything that changes a system will be a separate, explicit command.</p>
    </div>
    <div class="sect-main">
      <div class="panel tbl-wrap"><table class="tbl">
        <thead><tr><th></th><th>Module</th><th>Scope</th><th>Status</th></tr></thead>
        <tbody>
          <tr><td class="ico">${icon("radar")}</td><td><b>Sense</b></td><td class="bx-muted">Inventory and exposure: <code>scan</code>, <code>check</code>, <code>report</code>, mitigation audit, image scanning</td><td><span class="st is-green">${icon("circle-check")}shipped</span></td></tr>
          <tr><td class="ico">${icon("history")}</td><td><b>Trace</b></td><td class="bx-muted">Indicators of compromise and a timeline: <code>trace</code></td><td><span class="st is-green">${icon("circle-check")}shipped</span></td></tr>
          <tr><td class="ico">${icon("anvil")}</td><td><b>Forge</b></td><td class="bx-muted">Reproducible patched packages for end-of-life PHP from the official backport branches</td><td><span class="st is-gray">${icon("circle-dashed")}planned</span></td></tr>
          <tr><td class="ico">${icon("route")}</td><td><b>Shift</b></td><td class="bx-muted">Compatibility checks and rehearsed upgrades to a supported branch</td><td><span class="st is-gray">${icon("circle-dashed")}planned</span></td></tr>
          <tr><td class="ico">${icon("activity")}</td><td><b>Guard</b></td><td class="bx-muted">Runtime detection of exploitation attempts</td><td><span class="st is-gray">${icon("circle-dashed")}planned</span></td></tr>
        </tbody>
      </table></div>
    </div>
  </div>
</section>

<section class="sect" id="install">
  <div class="bx-wrap sect-grid">
    <div class="sect-side">
      <h2>Install</h2>
      <p>The installer verifies the SHA-256 checksum of the download and, when <code>cosign</code> is available, the Sigstore signature of the release.</p>
      <a class="side-link" href="${REPO}/blob/main/scripts/install.sh">Read install.sh ${icon("arrow-up-right")}</a>
    </div>
    <div class="sect-main" data-tabs>
      <div class="tabs-bar" role="tablist">
        <button role="tab" aria-selected="true" data-tab="i-script">${icon("download")}Install script</button>
        <button role="tab" aria-selected="false" data-tab="i-manual">${icon("key-round")}Manual, verified</button>
        <button role="tab" aria-selected="false" data-tab="i-src">${icon("hammer")}From source</button>
      </div>
      <div class="tab-panel" data-panel="i-script">
        ${codebox(INSTALL + "\nsudo bastion scan\nsudo bastion trace\nsudo bastion report")}
      </div>
      <div class="tab-panel" data-panel="i-manual" hidden>
        ${codebox(`VERSION=v0.1.0   # see ${REPO}/releases\nBASE=${REPO}/releases/download/$VERSION\ncurl -fsSLO $BASE/bastion_linux_amd64.tar.gz -O $BASE/SHA256SUMS -O $BASE/SHA256SUMS.sigstore.json\nsha256sum --ignore-missing -c SHA256SUMS\ncosign verify-blob --bundle SHA256SUMS.sigstore.json \\\n  --certificate-identity-regexp '^https://github.com/BastionPHP/Bastion/.github/workflows/release.yml@refs/tags/v' \\\n  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS\ntar xzf bastion_linux_amd64.tar.gz && sudo install -m 0755 bastion /usr/local/bin/`)}
      </div>
      <div class="tab-panel" data-panel="i-src" hidden>
        ${codebox("go install github.com/BastionPHP/Bastion/cmd/bastion@latest   # Go 1.24+\n# or\ngit clone https://github.com/BastionPHP/Bastion && cd Bastion && make build")}
      </div>
    </div>
  </div>
</section>
`;
  return layout(ctx, {
    title: "Bastion",
    description: "Open-source, local, read-only PHP exposure and compromise assessment: inventory every PHP build, verify PHP2Shell (CVE-2026-109618/109619) patches including distribution backports, and trace intrusions.",
    body,
  });
}
