import { layout } from "../lib/layout.mjs";
import { codebox, esc } from "./common.mjs";

const EXAMPLES = [
  { id: "noble-old", label: "Ubuntu 24.04 (.12)", text: "PHP 8.3.6 (cli) (built: Oct  7 2026 18:06:38) (NTS)\nCopyright (c) The PHP Group\nZend Engine v4.3.6, Copyright (c) Zend Technologies\nphp8.3-cli\t8.3.6-0ubuntu0.24.04.12" },
  { id: "noble-new", label: "Ubuntu 24.04 (.13)", text: "PHP 8.3.6 (cli) (built: Oct 19 2026 15:16:58) (NTS)\nCopyright (c) The PHP Group\nZend Engine v4.3.6, Copyright (c) Zend Technologies\nphp8.3-cli\t8.3.6-0ubuntu0.24.04.13" },
  { id: "jammy", label: "Ubuntu 22.04", text: "PHP 8.1.2-1ubuntu2.28 (cli) (built: Oct 20 2026 12:00:00) (NTS)" },
  { id: "docker-old", label: "php:8.3.35-fpm", text: "PHP 8.3.35 (cli) (built: Sep 25 2026 22:15:04) (NTS)\nCopyright (c) The PHP Group\nZend Engine v4.3.35, Copyright (c) Zend Technologies" },
  { id: "eol", label: "PHP 7.4.33", text: "PHP 7.4.33 (cli) (built: Nov  4 2022 00:00:00) ( NTS )" },
  { id: "rhel", label: "RHEL 9 rpm", text: "PHP 8.0.30 (cli) (built: Aug  3 2026 00:00:00) ( NTS gcc x86_64 )\nphp-cli-8.0.30-4.el9_6.x86_64" },
];

const GUIDES = [
  { id: "apt", label: "Ubuntu / Debian", body: () => `
    <p>Upgrade every package of your PHP branch, then restart the services that run it.</p>
    ${codebox("sudo apt update\nsudo apt install --only-upgrade 'php8.3*'      # use your branch: php8.1, php8.2, php8.4 …\ndpkg-query -W 'php8.3*'                      # compare with the fixed versions below\nsudo systemctl restart php8.3-fpm apache2    # whichever you run")}
    <p>Fixed package versions published by the vendors:</p>
    <div class="bx-table-wrap"><table class="bx-table"><thead><tr><th>Release</th><th>Package</th><th>Fixed in</th><th>Advisory</th></tr></thead><tbody data-vendor-table></tbody></table></div>
    <p>Ubuntu 20.04 and older receive the fix only through Ubuntu Pro (<code>sudo pro attach</code>). Debian 11 is outside Debian LTS; check Freexian ELTS or migrate.</p>` },
  { id: "dnf", label: "RHEL / Alma / Rocky", body: () => `
    <p>Red Hat lists RHEL 8, 9 and 10 as affected (RHSB-2026-013) and is releasing updates per module stream. The changelog tells you whether yours is in.</p>
    ${codebox("sudo dnf upgrade --refresh 'php*'\nrpm -q --changelog php-cli | grep -E 'CVE-2026-10961[89]'   # no output = not fixed yet\nsudo systemctl restart php-fpm httpd")}` },
  { id: "docker", label: "Docker images", body: () => `
    <p>Official <code>php</code> images are built from upstream releases. Rebuild on a fresh base and redeploy — a running container never updates itself.</p>
    ${codebox("docker pull php:8.3-fpm                    # tags now resolve to 8.3.36+\ndocker run --rm php:8.3-fpm php -v | head -1\ndocker build --pull -t myapp .              # --pull refreshes FROM php:…\n# then redeploy (compose up -d / kubectl rollout restart …)")}` },
  { id: "panel", label: "BaoTa / aaPanel", body: () => `
    <p>Panel-managed PHP lives in <code>/www/server/php/&lt;ver&gt;</code> and is built from upstream sources, so the version number is reliable here.</p>
    <ul><li>In the panel's App Store, update the installed PHP version once the panel offers 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, then restart PHP.</li><li>PHP 5.x–8.1 have no upstream fix: switch each site to PHP 8.2+ in the site settings.</li><li>Verify with Bastion: <code>sudo bastion scan</code> lists every <code>/www/server/php/*</code> build.</li></ul>` },
  { id: "cpanel", label: "cPanel / Plesk", body: () => `
    <p>Both ship their own PHP builds; update through the panel's package channel.</p>
    ${codebox("# cPanel EasyApache 4\nsudo dnf upgrade 'ea-php8*'        # or yum; WHM » EasyApache 4 shows the same\n# CloudLinux alt-php\nsudo yum update 'alt-php*'\n# Plesk\nplesk installer --select-release-current --upgrade-installed-components")}` },
  { id: "src", label: "Source / Windows", body: () => `
    <p>Build the fixed release from php.net; Windows binaries are on the same downloads page. For 7.4/8.0/8.1 the PHP team published minimal backport branches:</p>
    ${codebox("git clone --depth 1 -b PHP-8.1-CVE-2026-109618-109619 https://github.com/php/php-src\n# also: PHP-8.0-CVE-2026-109618-109619, PHP-7.4-CVE-2026-109618-109619")}
    <p>Builds from these branches keep their old version string — record that you built them, because no tool can tell from outside.</p>` },
];

export function render(ctx, { advisories }) {
  const adv = advisories.find((a) => a.id === "PHP2SHELL-2026");
  const body = `
<header class="phead">
  <div class="bx-grid-bg" aria-hidden="true"></div>
  <div class="bx-wrap phead-in">
    <div class="bx-eyebrow">Online check</div>
    <h1>Paste <code>php -v</code>. Get an honest answer.</h1>
    <p>Runs entirely in your browser with the same rules as the CLI. Nothing you paste leaves this page.</p>
  </div>
</header>
<section class="bx-wrap" style="padding-bottom:72px">
  <div class="check-grid">
    <div class="bx-card check-input">
      <label for="paste">Output of <code>php -v</code> — add package info for distro builds</label>
      <textarea id="paste" spellcheck="false" autocomplete="off" placeholder="PHP 8.3.6 (cli) (built: Oct  7 2026 18:06:38) (NTS)&#10;php8.3-cli	8.3.6-0ubuntu0.24.04.12"></textarea>
      <div class="check-row">
        <select id="os" aria-label="Operating system">
          <option value="">OS: detect from text</option>
          ${adv.vendor_fixes.map((f) => `${f.distro}:${f.release}`).filter((v, i, a) => a.indexOf(v) === i).map((v) => `<option value="${v}">${v.replace(":", " ")}</option>`).join("")}
          <option value="other:">other / not a distro package</option>
        </select>
        <button class="bx-btn is-primary" type="button" id="run">Check</button>
      </div>
      <div class="examples" aria-label="Examples">
        <span class="bx-faint" style="font-size:12px;align-self:center">Try:</span>
        ${EXAMPLES.map((e) => `<button class="bx-chip" type="button" data-example="${e.id}">${esc(e.label)}</button>`).join("")}
      </div>
      <p class="hint">Distro packages keep the old version number after a backport. Add one of: <code>dpkg-query -W 'php*'</code> · <code>rpm -qa 'php*'</code> · <code>apk info -v | grep php</code> · <code>cat /etc/os-release</code></p>
      <div class="privacy"><svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.5 2.5 3.8v3.7c0 3.2 2.3 6 5.5 7 3.2-1 5.5-3.8 5.5-7V3.8L8 1.5Z" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="m5.5 8 1.8 1.8L10.8 6.3" fill="none" stroke="currentColor" stroke-width="1.4"/></svg>Local only: no request is made when you press Check.</div>
    </div>
    <div class="bx-card result" id="result" aria-live="polite">
      <div class="result-empty">Paste output on the left, or pick an example.</div>
    </div>
  </div>
  <div class="callout is-info" style="margin-top:18px"><p>This page sees only what you paste. A server usually has several PHP builds and running workers that may still use old code — <code>sudo bastion scan</code> checks all of them, including containers.</p></div>
</section>

<section class="sec" id="upgrade">
  <div class="bx-wrap">
    <div class="sec-head">
      <div class="bx-eyebrow">Upgrade guide</div>
      <h2>Fixing it, environment by environment</h2>
      <p>Whatever you upgrade: restart every PHP worker afterwards, then run the check again.</p>
    </div>
    <div data-tabs>
      <div class="tabs-bar" role="tablist">${GUIDES.map((g, i) => `<button role="tab" aria-selected="${i === 0}" data-tab="g-${g.id}">${g.label}</button>`).join("")}</div>
      ${GUIDES.map((g, i) => `<div class="tab-panel prose" style="max-width:860px" data-panel="g-${g.id}"${i ? " hidden" : ""}>${g.body()}</div>`).join("")}
    </div>
    <div class="bx-card" style="margin-top:36px">
      <div class="bx-card-head"><span class="bx-eyebrow">Can't update today?</span><span class="bx-badge is-amber">partial</span></div>
      <div class="bx-card-body prose" style="max-width:none"><ol>${adv.mitigations.map((m) => `<li>${esc(m.en)}</li>`).join("")}</ol><p class="bx-faint" style="font-size:13px;margin:0">From the official PHP advisory. These reduce exposure to known paths; they do not make an installation safe.</p></div>
    </div>
  </div>
</section>
<script type="application/json" id="adv-data">${JSON.stringify(advisories).replace(/</g, "\\u003c")}</script>
<script type="application/json" id="examples">${JSON.stringify(Object.fromEntries(EXAMPLES.map((e) => [e.id, e.text]))).replace(/</g, "\\u003c")}</script>
`;
  return layout(ctx, {
    title: "Online check",
    description: "Paste php -v and package output to check PHP2Shell (CVE-2026-109618/109619) locally in your browser, including Ubuntu/Debian backports.",
    body,
    scripts: ["engine.js", "check.js"],
  });
}
