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
  { id: "apt", label: { en: "Ubuntu / Debian", zh: "Ubuntu / Debian" }, body: (t) => `
    <p>${t("Upgrade every package of your PHP branch, then restart the services that run it.", "升级该 PHP 分支的所有软件包，然后重启运行它的服务。")}</p>
    ${codebox("sudo apt update\nsudo apt install --only-upgrade 'php8.3*'      # use your branch: php8.1, php8.2, php8.4 …\ndpkg-query -W 'php8.3*'                      # compare with the fixed versions below\nsudo systemctl restart php8.3-fpm apache2    # whichever you run")}
    <p>${t("Fixed package versions published by the vendors:", "官方公布的修复包版本：")}</p>
    <div class="bx-table-wrap"><table class="bx-table"><thead><tr><th>${t("Release", "发行版")}</th><th>${t("Package", "源码包")}</th><th>${t("Fixed in", "修复版本")}</th><th>${t("Advisory", "公告")}</th></tr></thead><tbody data-vendor-table></tbody></table></div>
    <p>${t("Ubuntu 20.04 and older receive the fix only through Ubuntu Pro (<code>sudo pro attach</code>). Debian 11 is outside Debian LTS; check Freexian ELTS or migrate.", "Ubuntu 20.04 及更早版本只能通过 Ubuntu Pro 获取修复（<code>sudo pro attach</code>）。Debian 11 已不在 Debian LTS 范围内，请查看 Freexian ELTS 或进行迁移。")}</p>` },
  { id: "dnf", label: { en: "RHEL / Alma / Rocky", zh: "RHEL / Alma / Rocky" }, body: (t) => `
    <p>${t("Red Hat lists RHEL 8, 9 and 10 as affected (RHSB-2026-013) and is releasing updates per module stream. The changelog tells you whether yours is in.", "Red Hat 将 RHEL 8、9、10 列为受影响（RHSB-2026-013），并按模块流陆续发布更新。查看变更日志即可知道你的版本是否已修复。")}</p>
    ${codebox("sudo dnf upgrade --refresh 'php*'\nrpm -q --changelog php-cli | grep -E 'CVE-2026-10961[89]'   # no output = not fixed yet\nsudo systemctl restart php-fpm httpd")}` },
  { id: "docker", label: { en: "Docker images", zh: "Docker 镜像" }, body: (t) => `
    <p>${t("Official <code>php</code> images are built from upstream releases. Rebuild on a fresh base and redeploy — a running container never updates itself.", "官方 <code>php</code> 镜像基于上游版本构建。请基于新的基础镜像重新构建并重新部署——运行中的容器不会自己更新。")}</p>
    ${codebox("docker pull php:8.3-fpm                    # tags now resolve to 8.3.36+\ndocker run --rm php:8.3-fpm php -v | head -1\ndocker build --pull -t myapp .              # --pull refreshes FROM php:…\n# then redeploy (compose up -d / kubectl rollout restart …)")}` },
  { id: "panel", label: { en: "BaoTa / aaPanel", zh: "宝塔 / aaPanel" }, body: (t) => `
    <p>${t("Panel-managed PHP lives in <code>/www/server/php/&lt;ver&gt;</code> and is built from upstream sources, so the version number is reliable here.", "面板管理的 PHP 位于 <code>/www/server/php/&lt;版本&gt;</code>，基于上游源码编译，因此这里的版本号是可靠的。")}</p>
    <ul><li>${t("In the panel's App Store, update the installed PHP version once the panel offers 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, then restart PHP.", "在面板的软件商店中，等面板提供 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 后更新对应的 PHP 版本，然后重启 PHP。")}</li><li>${t("PHP 5.x–8.1 have no upstream fix: switch each site to PHP 8.2+ in the site settings.", "PHP 5.x–8.1 没有上游修复：在网站设置中把每个站点切换到 PHP 8.2 或更高版本。")}</li><li>${t("Verify with Bastion: <code>sudo bastion scan</code> lists every <code>/www/server/php/*</code> build.", "用 Bastion 验证：<code>sudo bastion scan</code> 会列出所有 <code>/www/server/php/*</code> 构建。")}</li></ul>` },
  { id: "cpanel", label: { en: "cPanel / Plesk", zh: "cPanel / Plesk" }, body: (t) => `
    <p>${t("Both ship their own PHP builds; update through the panel's package channel.", "两者都自带 PHP 构建，请通过面板自己的软件包渠道更新。")}</p>
    ${codebox("# cPanel EasyApache 4\nsudo dnf upgrade 'ea-php8*'        # or yum; WHM » EasyApache 4 shows the same\n# CloudLinux alt-php\nsudo yum update 'alt-php*'\n# Plesk\nplesk installer --select-release-current --upgrade-installed-components")}` },
  { id: "src", label: { en: "Source / Windows", zh: "源码 / Windows" }, body: (t) => `
    <p>${t("Build the fixed release from php.net; Windows binaries are on the same downloads page. For 7.4/8.0/8.1 the PHP team published minimal backport branches:", "从 php.net 构建修复版本；Windows 二进制也在同一个下载页面。对于 7.4/8.0/8.1，PHP 团队提供了最小化的回溯分支：")}</p>
    ${codebox("git clone --depth 1 -b PHP-8.1-CVE-2026-109618-109619 https://github.com/php/php-src\n# also: PHP-8.0-CVE-2026-109618-109619, PHP-7.4-CVE-2026-109618-109619")}
    <p>${t("Builds from these branches keep their old version string — record that you built them, because no tool can tell from outside.", "从这些分支构建的 PHP 会保留原来的版本号——请自己记录下来，因为从外部没有任何工具能分辨。")}</p>` },
];

export function render(ctx, { advisories }) {
  const { t, lang } = ctx;
  const adv = advisories.find((a) => a.id === "PHP2SHELL-2026");
  const body = `
<header class="phead">
  <div class="bx-grid-bg" aria-hidden="true"></div>
  <div class="bx-wrap phead-in">
    <div class="bx-eyebrow">${t("Online check", "在线自查")}</div>
    <h1>${t("Paste <code>php -v</code>. Get an honest answer.", "粘贴 <code>php -v</code>，得到一个诚实的答案。")}</h1>
    <p>${t("Runs entirely in your browser with the same rules as the CLI. Nothing you paste leaves this page.", "完全在浏览器本地运行，判断规则与命令行工具相同。你粘贴的内容不会离开这个页面。")}</p>
  </div>
</header>
<section class="bx-wrap" style="padding-bottom:72px">
  <div class="check-grid">
    <div class="bx-card check-input">
      <label for="paste">${t("Output of <code>php -v</code> — add package info for distro builds", "<code>php -v</code> 的输出——发行版构建请附上软件包信息")}</label>
      <textarea id="paste" spellcheck="false" autocomplete="off" placeholder="PHP 8.3.6 (cli) (built: Oct  7 2026 18:06:38) (NTS)&#10;php8.3-cli	8.3.6-0ubuntu0.24.04.12"></textarea>
      <div class="check-row">
        <select id="os" aria-label="${t("Operating system", "操作系统")}">
          <option value="">${t("OS: detect from text", "系统：从文本识别")}</option>
          ${adv.vendor_fixes.map((f) => `${f.distro}:${f.release}`).filter((v, i, a) => a.indexOf(v) === i).map((v) => `<option value="${v}">${v.replace(":", " ")}</option>`).join("")}
          <option value="other:">${t("other / not a distro package", "其他 / 非发行版软件包")}</option>
        </select>
        <button class="bx-btn is-primary" type="button" id="run">${t("Check", "检查")}</button>
      </div>
      <div class="examples" aria-label="${t("Examples", "示例")}">
        <span class="bx-faint" style="font-size:12px;align-self:center">${t("Try:", "示例：")}</span>
        ${EXAMPLES.map((e) => `<button class="bx-chip" type="button" data-example="${e.id}">${esc(e.label)}</button>`).join("")}
      </div>
      <p class="hint">${t("Distro packages keep the old version number after a backport. Add one of:", "发行版打回溯补丁后版本号不变，请再附上以下任意一条的输出：")} <code>dpkg-query -W 'php*'</code> · <code>rpm -qa 'php*'</code> · <code>apk info -v | grep php</code> · <code>cat /etc/os-release</code></p>
      <div class="privacy"><svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.5 2.5 3.8v3.7c0 3.2 2.3 6 5.5 7 3.2-1 5.5-3.8 5.5-7V3.8L8 1.5Z" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="m5.5 8 1.8 1.8L10.8 6.3" fill="none" stroke="currentColor" stroke-width="1.4"/></svg>${t("Local only: no request is made when you press Check.", "仅在本地运行：点击“检查”不会发出任何网络请求。")}</div>
    </div>
    <div class="bx-card result" id="result" aria-live="polite">
      <div class="result-empty">${t("Paste output on the left, or pick an example.", "在左侧粘贴输出，或选择一个示例。")}</div>
    </div>
  </div>
  <div class="callout is-info" style="margin-top:18px"><p>${t("This page sees only what you paste. A server usually has several PHP builds and running workers that may still use old code — <code>sudo bastion scan</code> checks all of them, including containers.", "这个页面只能看到你粘贴的内容。一台服务器上通常有多个 PHP 构建，运行中的进程也可能仍在使用旧代码——<code>sudo bastion scan</code> 会把它们全部检查一遍，包括容器。")}</p></div>
</section>

<section class="sec" id="upgrade">
  <div class="bx-wrap">
    <div class="sec-head">
      <div class="bx-eyebrow">${t("Upgrade guide", "升级指引")}</div>
      <h2>${t("Fixing it, environment by environment", "按环境逐一修复")}</h2>
      <p>${t("Whatever you upgrade: restart every PHP worker afterwards, then run the check again.", "无论升级的是什么，之后都要重启所有 PHP 工作进程，然后再检查一次。")}</p>
    </div>
    <div data-tabs>
      <div class="tabs-bar" role="tablist">${GUIDES.map((g, i) => `<button role="tab" aria-selected="${i === 0}" data-tab="g-${g.id}">${g.label[lang]}</button>`).join("")}</div>
      ${GUIDES.map((g, i) => `<div class="tab-panel prose" style="max-width:860px" data-panel="g-${g.id}"${i ? " hidden" : ""}>${g.body(t)}</div>`).join("")}
    </div>
    <div class="bx-card" style="margin-top:36px">
      <div class="bx-card-head"><span class="bx-eyebrow">${t("Can't update today?", "今天没法升级？")}</span><span class="bx-badge is-amber">${t("partial", "仅部分缓解")}</span></div>
      <div class="bx-card-body prose" style="max-width:none"><ol>${adv.mitigations.map((m) => `<li>${esc(m[lang] || m.en)}</li>`).join("")}</ol><p class="bx-faint" style="font-size:13px;margin:0">${t("From the official PHP advisory. These reduce exposure to known paths; they do not make an installation safe.", "摘自 PHP 官方公告。这些措施只能减少已知路径的暴露，不能让系统变安全。")}</p></div>
    </div>
  </div>
</section>
<script type="application/json" id="adv-data">${JSON.stringify(advisories).replace(/</g, "\\u003c")}</script>
<script type="application/json" id="examples">${JSON.stringify(Object.fromEntries(EXAMPLES.map((e) => [e.id, e.text]))).replace(/</g, "\\u003c")}</script>
`;
  return layout(ctx, {
    title: t("Online check", "在线自查"),
    description: t("Paste php -v and package output to check PHP2Shell (CVE-2026-109618/109619) locally in your browser, including Ubuntu/Debian backports.", "粘贴 php -v 和软件包信息，在浏览器本地检查 PHP2Shell（CVE-2026-109618/109619），支持 Ubuntu/Debian 回溯补丁识别。"),
    body,
    scripts: ["engine.js", "check.js"],
  });
}
