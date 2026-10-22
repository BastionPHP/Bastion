import { layout } from "../lib/layout.mjs";
import { terminal, recording, codebox, copyBtn, INSTALL, esc } from "./common.mjs";

export function render(ctx, { advisory }) {
  const rec = recording();
  const fixed = advisory.branches.filter((b) => b.fixed && b.status !== "prerelease");
  const body = `
<section class="hero">
  <div class="bx-grid-bg" aria-hidden="true"></div>
  <div class="bx-wrap hero-in">
    <a class="hero-chip" href="${ctx.href("how")}"><span class="bx-badge is-red">Critical</span>PHP2Shell · CVE-2026-109618 / 109619 · patched 21 Oct 2026 →</a>
    <h1>Is your PHP still exposed?<br><span class="dim">Has someone already got in?</span></h1>
    <p class="hero-sub">Bastion is an open-source security tool that runs on your own server and only reads. It finds every PHP build — distro packages, BaoTa, cPanel, Docker containers — tells you which ones are <em>really</em> patched, and looks for the traces an intrusion leaves behind.</p>
    <div class="hero-cta">
      <div class="cmd"><span class="p">$</span><code id="hero-install">${esc(INSTALL)}</code>${copyBtn("hero-install")}</div>
      <a class="bx-btn" href="${ctx.href("check")}">Check a <code>php -v</code> in the browser →</a>
    </div>
    <div class="term-stack">
      ${terminal(ctx, { title: "bastion scan", file: "scan.ansi", cmd: "sudo bastion scan" })}
      <div class="term-caption"><span>Real output, not a mock-up: ${esc(rec.host)}${rec.containers ? " · containers: " + esc(rec.containers) : ""}</span><span>recorded ${esc(rec.at)} · ${esc(rec.version)}</span></div>
    </div>
  </div>
</section>

<section class="sec" id="php2shell">
  <div class="bx-wrap">
    <div class="sec-head">
      <div class="bx-eyebrow">Background</div>
      <h2>PHP2Shell: unauthenticated remote code execution in PHP itself</h2>
      <p>On 21 October 2026 the PHP project shipped emergency releases for two critical memory-safety bugs in the engine. A single crafted HTTP request can lead to code execution as the web server user — before your application code even runs.</p>
    </div>
    <div class="facts">
      <div class="fact"><b class="red">9.2</b><span>CVSS v4.0 score, both CVEs</span></div>
      <div class="fact"><b>No auth</b><span>Reachable by any HTTP client; demonstrated against Apache mod_php</span></div>
      <div class="fact"><b>All SAPIs</b><span>mod_php, PHP-FPM, php-cgi, FrankenPHP and LiteSpeed serve web requests and are in scope</span></div>
      <div class="fact"><b>≤ 8.1</b><span>No official release for end-of-life branches — only source backports</span></div>
    </div>
    <div class="split" style="margin-top:44px">
      <ol class="vtl">
        <li><time>2026-10-20</time><strong>Advance notice</strong><p>The PHP security team announces a release for 21 Oct, 14:00 UTC, fixing two critical bugs rated CVSS v4 9.2.</p></li>
        <li class="hot"><time>2026-10-21</time><strong>Fixed releases</strong><p>${fixed.map((b) => `<code>${b.fixed}</code>`).join(" ")} — plus source backport branches for 7.4, 8.0 and 8.1, and 8.6.0 RC4.</p></li>
        <li><time>2026-10-21</time><strong>Distributions follow</strong><p>Ubuntu (USN-8948-1/-2, including PHP 5.5–7.4 via Ubuntu Pro), Debian (DSA-6574-1, DLA-4848-1) and Red Hat (RHSB-2026-013) publish backports — usually <strong>without changing the PHP version number</strong>.</p></li>
        <li><time>now</time><strong>The hard part</strong><p>Finding every PHP on every server, knowing which builds really carry the fix, restarting what still runs old code, and checking whether anyone got in first.</p></li>
      </ol>
      <div>
        <div class="bx-card">
          <div class="bx-card-head"><span class="bx-eyebrow">Fixed upstream releases</span><span class="bx-faint mono" style="font-size:12px">CVE-2026-109618 · CVE-2026-109619</span></div>
          <div class="bx-table-wrap"><table class="bx-table fix-table">
            <thead><tr><th>Branch</th><th>Fixed in</th><th>Status</th></tr></thead>
            <tbody>
              ${advisory.branches.map((b) => `<tr><td>PHP ${b.branch}</td><td class="mono">${b.fixed ? `<span style="color:var(--green)">≥ ${b.fixed}</span>` : `<span style="color:var(--red)">no release</span>`}</td><td class="bx-muted">${b.fixed ? (b.status === "prerelease" ? "pre-release" : "supported") : `<a href="${b.source_backport}">source backport</a>`}</td></tr>`).join("")}
              <tr><td>PHP ≤ 7.3</td><td class="mono"><span style="color:var(--red)">none</span></td><td class="bx-muted">vendor backports only</td></tr>
            </tbody>
          </table></div>
        </div>
        <p class="src-list">Sources: <a href="https://www.php.net/">php.net</a> · <a href="https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w">GHSA-w8hw-w9fx-j79w</a> · <a href="https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp">GHSA-6wmf-4rv5-p3rp</a> · <a href="https://ubuntu.com/security/CVE-2026-109618">Ubuntu</a> · <a href="https://security-tracker.debian.org/tracker/CVE-2026-109618">Debian</a> · <a href="https://access.redhat.com/security/vulnerabilities/RHSB-2026-013">Red Hat</a></p>
      </div>
    </div>
  </div>
</section>

<section class="sec" id="what">
  <div class="bx-wrap">
    <div class="sec-head">
      <div class="bx-eyebrow">What it does</div>
      <h2>Three commands. One honest answer.</h2>
      <p>A single static binary. No agent, no account, no network calls. When Bastion cannot prove something, it says <code>unknown</code> instead of guessing.</p>
    </div>
    <div class="caps">
      <article class="bx-card cap">
        <h3><code>scan</code> Exposure</h3>
        <p>Every PHP build on the box and whether it is really fixed.</p>
        <ul>
          <li>Distro packages, BaoTa/aaPanel, cPanel EA4, CloudLinux, Plesk, Remi, LiteSpeed, source builds</li>
          <li>Docker/Podman containers and Kubernetes pods, read through their root filesystem</li>
          <li>Running workers that still execute a replaced binary</li>
          <li>Backports: vendor fix tables, package changelogs, fix fingerprints</li>
        </ul>
      </article>
      <article class="bx-card cap">
        <h3><code>trace</code> Intrusion</h3>
        <p>Patching does not evict an attacker who is already in.</p>
        <ul>
          <li>Webshell signatures (Chopper/AntSword, Behinder, Godzilla, WSO…), tuned on 33k legitimate PHP files</li>
          <li>PHP in uploads and images, <code>.user.ini</code>/<code>.htaccess</code> tricks</li>
          <li>Cron, systemd, <code>ld.so.preload</code>, SSH keys, UID 0 accounts</li>
          <li>Log traces: requests to flagged files, worker segfaults, start-up OOM</li>
        </ul>
      </article>
      <article class="bx-card cap">
        <h3><code>report</code> Evidence</h3>
        <p>One self-contained HTML file you can hand to a colleague or a client.</p>
        <ul>
          <li>Works offline, no external assets</li>
          <li>Every verdict with its evidence and the fix for that environment</li>
          <li>Timeline, prints to PDF</li>
          <li><a href="${ctx.root}demo/report.html">Open a sample report →</a></li>
        </ul>
      </article>
    </div>
    <div class="bx-card" style="margin-top:16px" data-tabs>
      <div class="tabs-bar" role="tablist" style="padding:0 10px">
        <button role="tab" aria-selected="true" data-tab="t-trace"><code>trace</code></button>
        <button role="tab" aria-selected="false" data-tab="t-check"><code>check</code></button>
      </div>
      <div class="bx-card-body">
        <div data-panel="t-trace">${terminal(ctx, { title: "bastion trace", file: "trace.ansi", cmd: "sudo bastion trace --sysroot /tmp/bastion-lab" })}<p class="term-caption">Real output on a lab tree built by <code>scripts/demo/lab.sh</code>: the planted backdoors are inert (wrapped in <code>if (false)</code>) and IPs are from documentation ranges.</p></div>
        <div data-panel="t-check" hidden>${terminal(ctx, { title: "bastion check", file: "check.ansi", cmd: "dpkg-query -W php8.3-cli | bastion check" })}</div>
      </div>
    </div>
  </div>
</section>

<section class="sec" id="roadmap">
  <div class="bx-wrap">
    <div class="sec-head">
      <div class="bx-eyebrow">Product</div>
      <h2>From knowing, to fixing, to never again.</h2>
      <p>Bastion is built in modules. Two ship today; the rest are on the roadmap and will stay read-only by default.</p>
    </div>
    <div class="road">
      <div class="road-item is-live"><span class="k">01 · SENSE</span><h3>Sense<small>Perception</small></h3><p>Inventory every PHP build and decide whether it is affected — <code>bastion scan</code>, <code>check</code>, <code>report</code>.</p><span class="bx-badge is-green">available</span></div>
      <div class="road-item is-plan"><span class="k">02 · FORGE</span><h3>Forge<small>Patch forging</small></h3><p>Build patched packages for end-of-life PHP (7.4/8.0/8.1) from the official backport branches, reproducibly.</p><span class="bx-badge">roadmap</span></div>
      <div class="road-item is-plan"><span class="k">03 · SHIFT</span><h3>Shift<small>Safe migration</small></h3><p>Plan and rehearse moving sites to a supported PHP branch: compatibility checks and rollback.</p><span class="bx-badge">roadmap</span></div>
      <div class="road-item is-plan"><span class="k">04 · GUARD</span><h3>Guard<small>Runtime protection</small></h3><p>Detect exploitation attempts as they happen: request-shape limits and worker crash correlation.</p><span class="bx-badge">roadmap</span></div>
      <div class="road-item is-live"><span class="k">05 · TRACE</span><h3>Trace<small>Intrusion forensics</small></h3><p>Find what an attacker left behind and when — <code>bastion trace</code>.</p><span class="bx-badge is-green">available</span></div>
    </div>
  </div>
</section>

<section class="sec" id="principles">
  <div class="bx-wrap">
    <div class="sec-head">
      <div class="bx-eyebrow">Principles</div>
      <h2>A security tool you can run on production.</h2>
    </div>
    <div class="princ">
      <div><h3>Read-only</h3><p>Bastion never writes, quarantines, restarts or deletes anything. Remediation is printed, never executed.</p></div>
      <div><h3>Local</h3><p>No telemetry, no cloud, no account. Results stay on your machine unless you share the report.</p></div>
      <div><h3>Honest</h3><p>Every verdict shows its evidence. Unverifiable builds are reported as <code>unknown</code>, never as safe.</p></div>
      <div><h3>Data-driven</h3><p>Vulnerabilities and signatures are JSON. The next PHP bug is a data file, not a new release of the logic.</p></div>
    </div>
  </div>
</section>

<section class="sec" id="install">
  <div class="bx-wrap">
    <div class="sec-head">
      <div class="bx-eyebrow">Install</div>
      <h2>Thirty seconds to a first answer.</h2>
      <p>Linux and macOS, amd64 and arm64. The installer verifies the SHA-256 checksum, and the Sigstore signature when <code>cosign</code> is available.</p>
    </div>
    <div data-tabs>
      <div class="tabs-bar" role="tablist">
        <button role="tab" aria-selected="true" data-tab="i-script">Install script</button>
        <button role="tab" aria-selected="false" data-tab="i-manual">Manual + verify</button>
        <button role="tab" aria-selected="false" data-tab="i-go">From source</button>
      </div>
      <div class="tab-panel" data-panel="i-script">
        <p>Prefer to read it first? Download, inspect, then run.</p>
        ${codebox(INSTALL + "\nsudo bastion scan\nsudo bastion trace\nsudo bastion report")}
      </div>
      <div class="tab-panel" data-panel="i-manual" hidden>
        ${codebox(`VERSION=v0.1.0   # see https://github.com/larptard/bastion/releases\ncurl -fsSLO https://github.com/larptard/bastion/releases/download/$VERSION/bastion_linux_amd64.tar.gz\ncurl -fsSLO https://github.com/larptard/bastion/releases/download/$VERSION/SHA256SUMS\ncurl -fsSLO https://github.com/larptard/bastion/releases/download/$VERSION/SHA256SUMS.sigstore.json\nsha256sum --ignore-missing -c SHA256SUMS\ncosign verify-blob --bundle SHA256SUMS.sigstore.json \\\n  --certificate-identity-regexp '^https://github.com/larptard/bastion/.github/workflows/release.yml@refs/tags/v' \\\n  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS\ntar xzf bastion_linux_amd64.tar.gz && sudo install -m 0755 bastion /usr/local/bin/`)}
      </div>
      <div class="tab-panel" data-panel="i-go" hidden>
        ${codebox("go install github.com/larptard/bastion/cmd/bastion@latest\n# or\ngit clone https://github.com/larptard/bastion && cd bastion && make build")}
      </div>
    </div>
  </div>
</section>
`;
  return layout(ctx, {
    title: "Bastion — is your PHP exposed? has someone got in?",
    description: "Open-source, local, read-only PHP security tool: find every PHP build, verify PHP2Shell (CVE-2026-109618/109619) patches including distro backports, and trace intrusions.",
    body,
  });
}
