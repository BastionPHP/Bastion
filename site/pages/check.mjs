import { layout } from "../lib/layout.mjs";
import { codebox, esc, icon } from "./common.mjs";

const EXAMPLES = [
  { id: "noble-old", label: "Ubuntu 24.04 · .12", text: "PHP 8.3.6 (cli) (built: Oct  7 2026 18:06:38) (NTS)\nCopyright (c) The PHP Group\nZend Engine v4.3.6, Copyright (c) Zend Technologies\nphp8.3-cli\t8.3.6-0ubuntu0.24.04.12" },
  { id: "noble-new", label: "Ubuntu 24.04 · .13", text: "PHP 8.3.6 (cli) (built: Oct 19 2026 15:16:58) (NTS)\nCopyright (c) The PHP Group\nZend Engine v4.3.6, Copyright (c) Zend Technologies\nphp8.3-cli\t8.3.6-0ubuntu0.24.04.13" },
  { id: "rhel9", label: "RHEL 9 · php 8.0", text: "PHP 8.0.30 (cli) (built: Oct 20 2026 00:00:00) ( NTS gcc x86_64 )\nID=\"rhel\"\nVERSION_ID=\"9.8\"\nphp-cli-8.0.30-8.el9_8.1.x86_64" },
  { id: "plesk", label: "Plesk · PHP 8.1", text: "$ /opt/plesk/php/8.1/bin/php -v\nPHP 8.1.34 (cli) (built: Jul  3 2026 11:40:02) (NTS)" },
  { id: "docker-old", label: "php:8.3.35-fpm", text: "PHP 8.3.35 (cli) (built: Sep 25 2026 22:15:04) (NTS)\nCopyright (c) The PHP Group\nZend Engine v4.3.35, Copyright (c) Zend Technologies" },
  { id: "eol", label: "PHP 7.4.33", text: "PHP 7.4.33 (cli) (built: Nov  4 2022 00:00:00) ( NTS )" },
];

const GUIDES = [
  { id: "apt", icon: "package", label: "Ubuntu / Debian", body: () => `
    <p>Upgrade every package of your PHP branch, then restart the services that run it.</p>
    ${codebox("sudo apt update\nsudo apt install --only-upgrade 'php8.3*'      # use your branch: php8.1, php8.2, php8.4 …\ndpkg-query -W 'php8.3*'                      # compare with the table below\nsudo systemctl restart php8.3-fpm apache2    # whichever you run")}
    <div class="note is-warn">${icon("info")}<p>Ubuntu 20.04 and older receive the fix through Ubuntu Pro only (<code>sudo pro attach</code>). Debian 11 is outside Debian LTS.</p></div>` },
  { id: "dnf", icon: "package", label: "RHEL / Alma / Rocky", body: () => `
    <p>Red Hat published fixes for RHEL 8 (php:7.4, php:8.2), RHEL 9 (php 8.0, php:8.2, php:8.3) and RHEL 10 (php, php8.4). Rebuilds such as AlmaLinux and Rocky follow; their changelogs name the CVEs.</p>
    ${codebox("sudo dnf upgrade --refresh 'php*'\nrpm -q php-cli                                              # compare with the table below\nrpm -q --changelog php-cli | grep -E 'CVE-2026-10961[89]'   # rebuilds: no output = not fixed\nsudo systemctl restart php-fpm httpd")}` },
  { id: "apk", icon: "package", label: "Alpine", body: () => `
    <p>Alpine's security database records the fix only for edge (php83 8.3.36-r0, php84 8.4.27-r0, php85 8.5.12-r0). Stable branches carry no backport: move to a release that ships the fixed upstream version, or use the official <code>php</code> images.</p>
    ${codebox("apk update && apk upgrade php83\nphp83 -v | head -1   # needs 8.3.36 or later")}` },
  { id: "docker", icon: "container", label: "Docker images", body: () => `
    <p>Official <code>php</code> images are built from upstream releases. Rebuild on a fresh base and redeploy; running containers never update themselves.</p>
    ${codebox("docker pull php:8.3-fpm                    # tags now resolve to 8.3.36+\ndocker build --pull -t myapp .              # --pull refreshes FROM php:…\nsudo bastion scan --image myapp:latest      # verify before deploying")}` },
  { id: "panel", icon: "server", label: "BaoTa / aaPanel", body: () => `
    <p>Panel-managed PHP lives in <code>/www/server/php/&lt;ver&gt;</code> and is built from upstream sources, so the version number is reliable.</p>
    <ul><li>App Store → Installed → update each PHP version to 8.2.35, 8.3.36, 8.4.27 or 8.5.12, then restart PHP.</li><li>aaPanel's notice covers 8.2–8.5 only. Move sites on PHP 8.1 and older to 8.2 or later and apply the interim mitigations until then.</li></ul>` },
  { id: "cpanel", icon: "server", label: "cPanel / Plesk", body: () => `
    <p>Both ship their own PHP builds. Update through the panel's package channel.</p>
    ${codebox("# cPanel EasyApache 4 (EOL ea-php: confirm the CVE in the changelog)\nsudo dnf upgrade 'ea-php*'\nrpm -q --changelog ea-php81-php-cli | grep -E 'CVE-2026-10961[89]'\n# Plesk: 7.4/8.0/8.1 were rebuilt on 21 Oct 2026 with unchanged versions\nplesk installer --select-release-current --upgrade-installed-components\n/opt/plesk/php/8.1/bin/php -v | head -1     # built: Oct 21 2026 or later")}` },
  { id: "src", icon: "hammer", label: "Source / Windows", body: () => `
    <p>Build the fixed release from php.net; Windows binaries are on the same downloads page. For 7.4, 8.0 and 8.1 the PHP team published minimal backport branches.</p>
    ${codebox("git clone --depth 1 -b PHP-8.1-CVE-2026-109618-109619 https://github.com/php/php-src\n# also: PHP-8.0-CVE-2026-109618-109619, PHP-7.4-CVE-2026-109618-109619")}
    <p>Builds from these branches keep their old version string. Record that you built them; no tool can tell from outside.</p>` },
];

export function render(ctx, { advisories, iconSet }) {
  const adv = advisories.find((a) => a.id === "PHP2SHELL-2026");
  const osOptions = adv.vendor_fixes.map((f) => `${f.distro}:${f.release}`).filter((v, i, a) => a.indexOf(v) === i);
  const body = `
<header class="phead">
  <div class="bx-wrap">
    <div class="crumbs">${icon("scan-search")}Bastion <span>/</span> Online check</div>
    <h1>Check a php -v output against PHP2Shell</h1>
    <p>Runs in your browser with the same rules as the command-line tool. Nothing you paste leaves this page.</p>
  </div>
</header>
<section class="bx-wrap" style="padding-block:28px 64px">
  <div class="check-grid">
    <div class="panel check-input">
      <div class="panel-head"><span class="title">${icon("terminal")}Input</span><span class="privacy" style="margin:0">${icon("lock")}local only</span></div>
      <div class="panel-body">
        <label class="field-label" for="paste">Output of <code>php -v</code>. For distribution packages, add the package line.</label>
        <textarea id="paste" spellcheck="false" autocomplete="off" placeholder="PHP 8.3.6 (cli) (built: Oct  7 2026 18:06:38) (NTS)&#10;php8.3-cli	8.3.6-0ubuntu0.24.04.12"></textarea>
        <div class="check-row">
          <select id="os" aria-label="Environment">
            <option value="">Environment: detect from text</option>
            ${osOptions.map((v) => { const [d, r] = v.split(":"); return `<option value="${v}">${d === "rhel" ? "RHEL" : d[0].toUpperCase() + d.slice(1)} ${r}</option>`; }).join("")}
            <option value="env:Plesk">Plesk-managed PHP</option>
            <option value="other:">Not a distribution package</option>
          </select>
          <button class="btn is-primary" type="button" id="run">${icon("shield-check")}Check</button>
        </div>
        <div class="examples" aria-label="Examples">
          <span class="label">Examples</span>
          ${EXAMPLES.map((e) => `<button class="chip" type="button" data-example="${e.id}">${esc(e.label)}</button>`).join("")}
        </div>
        <p class="hint">Package line from one of: <code>dpkg-query -W 'php*'</code> · <code>rpm -qa 'php*'</code> · <code>apk info -v | grep php</code> · <code>cat /etc/os-release</code></p>
      </div>
    </div>
    <div class="panel" id="result" aria-live="polite">
      <div class="result-empty">${icon("shield-question")}Paste output on the left, or pick an example.</div>
    </div>
  </div>
  <div class="note" style="margin-top:16px">${icon("server")}<p>This page sees only what you paste. A server usually has several PHP builds, and running workers may still use old code. <code>sudo bastion scan</code> checks all of them, including containers and images, and reports which interim mitigations are in place.</p></div>
</section>

<section class="sect" id="upgrade">
  <div class="bx-wrap sect-grid">
    <div class="sect-side">
      <h2>Upgrade guide</h2>
      <p>Per environment. Whatever you upgrade, restart every PHP worker afterwards and check again.</p>
    </div>
    <div class="sect-main">
      <div data-tabs>
        <div class="tabs-bar" role="tablist">${GUIDES.map((g, i) => `<button role="tab" aria-selected="${i === 0}" data-tab="g-${g.id}">${icon(g.icon)}${g.label}</button>`).join("")}</div>
        ${GUIDES.map((g, i) => `<div class="tab-panel prose" style="max-width:none" data-panel="g-${g.id}"${i ? " hidden" : ""}>${g.body()}</div>`).join("")}
      </div>
      <div class="panel">
        <div class="panel-head"><span class="title">${icon("package-check")}Fixed package versions published by vendors</span></div>
        <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Release</th><th>Package</th><th>Fixed in</th><th>Advisory</th></tr></thead><tbody>
          ${adv.vendor_fixes.map((f) => `<tr><td>${esc(f.distro === "rhel" ? "RHEL" : f.distro)} ${esc(f.release)}</td><td class="mono">${esc(f.package)}${f.channel ? ` <span class="bx-faint">${esc(f.channel)}</span>` : ""}</td><td class="mono fix-ok">${esc(f.fixed)}</td><td><a href="${f.url}">${esc(f.advisory)}</a></td></tr>`).join("")}
        </tbody></table></div>
      </div>
      <div class="panel">
        <div class="panel-head"><span class="title">${icon("sliders-horizontal")}If you cannot update today</span><span class="tag is-amber">partial</span></div>
        <div class="panel-body prose" style="max-width:none"><ol>${adv.mitigations.map((m) => `<li>${esc(m.en)}</li>`).join("")}</ol><p class="bx-faint" style="font-size:13px;margin:0">From the official PHP advisory. These reduce exposure to known paths; they do not make an installation safe.</p></div>
      </div>
    </div>
  </div>
</section>
<script type="application/json" id="adv-data">${JSON.stringify(advisories).replace(/</g, "\\u003c")}</script>
<script type="application/json" id="examples">${JSON.stringify(Object.fromEntries(EXAMPLES.map((e) => [e.id, e.text]))).replace(/</g, "\\u003c")}</script>
<script type="application/json" id="icon-data">${JSON.stringify(iconSet).replace(/</g, "\\u003c")}</script>
`;
  return layout(ctx, {
    title: "Online check",
    description: "Paste php -v and package output to check PHP2Shell (CVE-2026-109618/109619) locally in your browser, including Ubuntu, Debian and RHEL backports.",
    body,
    scripts: ["engine.js", "check.js"],
  });
}
