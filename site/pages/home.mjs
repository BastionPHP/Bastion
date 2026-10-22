import { layout } from "../lib/layout.mjs";
import { terminal, recording, codebox, copyBtn, INSTALL, esc } from "./common.mjs";

export function render(ctx, { advisory }) {
  const { t } = ctx;
  const rec = recording();
  const fixed = advisory.branches.filter((b) => b.fixed && b.status !== "prerelease");
  const body = `
<section class="hero">
  <div class="bx-grid-bg" aria-hidden="true"></div>
  <div class="bx-wrap hero-in">
    <a class="hero-chip" href="${ctx.href("how")}"><span class="bx-badge is-red">${t("Critical", "严重")}</span>PHP2Shell · CVE-2026-109618 / 109619 · ${t("patched 21 Oct 2026", "2026-10-21 已发布修复")} →</a>
    <h1>${t("Is your PHP still exposed?<br><span class=\"dim\">Has someone already got in?</span>", "你的 PHP 还暴露着吗？<br><span class=\"dim\">网站是不是已经被黑了？</span>")}</h1>
    <p class="hero-sub">${t(
      "Bastion is an open-source security tool that runs on your own server and only reads. It finds every PHP build — distro packages, BaoTa, cPanel, Docker containers — tells you which ones are <em>really</em> patched, and looks for the traces an intrusion leaves behind.",
      "Bastion 是一个开源、在你自己服务器上运行、只读不改的安全工具。它会找出机器上所有的 PHP——系统软件包、宝塔、cPanel、Docker 容器——告诉你哪些是<em>真的</em>打好了补丁，并排查入侵留下的痕迹。"
    )}</p>
    <div class="hero-cta">
      <div class="cmd"><span class="p">$</span><code id="hero-install">${esc(INSTALL)}</code>${copyBtn("hero-install")}</div>
      <a class="bx-btn" href="${ctx.href("check")}">${t("Check a <code>php -v</code> in the browser", "在浏览器里检查 <code>php -v</code>")} →</a>
    </div>
    <div class="term-stack">
      ${terminal(ctx, { title: "bastion scan", file: "scan.ansi", cmd: "sudo bastion scan" })}
      <div class="term-caption"><span>${t("Real output, not a mock-up", "真实输出，不是效果图")}: ${esc(rec.host)}${rec.containers ? " · containers: " + esc(rec.containers) : ""}</span><span>${t("recorded", "录制于")} ${esc(rec.at)} · ${esc(rec.version)}</span></div>
    </div>
  </div>
</section>

<section class="sec" id="php2shell">
  <div class="bx-wrap">
    <div class="sec-head">
      <div class="bx-eyebrow">${t("Background", "背景")}</div>
      <h2>${t("PHP2Shell: unauthenticated remote code execution in PHP itself", "PHP2Shell：PHP 自身的未授权远程代码执行")}</h2>
      <p>${t(
        "On 21 October 2026 the PHP project shipped emergency releases for two critical memory-safety bugs in the engine. A single crafted HTTP request can lead to code execution as the web server user — before your application code even runs.",
        "2026 年 10 月 21 日，PHP 官方针对引擎中的两个严重内存安全漏洞发布了紧急版本。一个精心构造的 HTTP 请求就可能以 Web 服务账号的身份执行任意代码——甚至在你的应用代码运行之前。"
      )}</p>
    </div>
    <div class="facts">
      <div class="fact"><b class="red">9.2</b><span>${t("CVSS v4.0 score, both CVEs", "CVSS v4.0 评分（两个 CVE 相同）")}</span></div>
      <div class="fact"><b>${t("No auth", "无需认证")}</b><span>${t("Reachable by any HTTP client; demonstrated against Apache mod_php", "任何 HTTP 客户端都能触达；已在 Apache mod_php 上演示利用")}</span></div>
      <div class="fact"><b>${t("All SAPIs", "所有 SAPI")}</b><span>${t("mod_php, PHP-FPM, php-cgi, FrankenPHP and LiteSpeed serve web requests and are in scope", "mod_php、PHP-FPM、php-cgi、FrankenPHP、LiteSpeed 都在影响范围内")}</span></div>
      <div class="fact"><b>≤ 8.1</b><span>${t("No official release for end-of-life branches — only source backports", "已停止维护的分支没有官方发布，只有源码回溯")}</span></div>
    </div>
    <div class="split" style="margin-top:44px">
      <ol class="vtl">
        <li><time>2026-10-20</time><strong>${t("Advance notice", "提前预告")}</strong><p>${t("The PHP security team announces a release for 21 Oct, 14:00 UTC, fixing two critical bugs rated CVSS v4 9.2.", "PHP 安全团队预告将于 10 月 21 日 14:00 UTC 发布安全版本，修复两个 CVSS v4 9.2 的严重漏洞。")}</p></li>
        <li class="hot"><time>2026-10-21</time><strong>${t("Fixed releases", "修复版本发布")}</strong><p>${fixed.map((b) => `<code>${b.fixed}</code>`).join(" ")} — ${t("plus source backport branches for 7.4, 8.0 and 8.1, and 8.6.0 RC4.", "同时提供 7.4、8.0、8.1 的源码回溯分支，以及 8.6.0 RC4。")}</p></li>
        <li><time>2026-10-21</time><strong>${t("Distributions follow", "发行版跟进")}</strong><p>${t("Ubuntu (USN-8948-1/-2, including PHP 5.5–7.4 via Ubuntu Pro), Debian (DSA-6574-1, DLA-4848-1) and Red Hat (RHSB-2026-013) publish backports — usually <strong>without changing the PHP version number</strong>.", "Ubuntu（USN-8948-1/-2，通过 Ubuntu Pro 覆盖 PHP 5.5–7.4）、Debian（DSA-6574-1、DLA-4848-1）和 Red Hat（RHSB-2026-013）陆续发布回溯补丁——通常<strong>不会改变 PHP 的版本号</strong>。")}</p></li>
        <li><time>${t("now", "现在")}</time><strong>${t("The hard part", "真正难的部分")}</strong><p>${t("Finding every PHP on every server, knowing which builds really carry the fix, restarting what still runs old code, and checking whether anyone got in first.", "找出每台服务器上的每一个 PHP，判断哪些构建真的包含修复，重启仍在运行旧代码的进程，并确认在此之前有没有人已经进来了。")}</p></li>
      </ol>
      <div>
        <div class="bx-card">
          <div class="bx-card-head"><span class="bx-eyebrow">${t("Fixed upstream releases", "上游修复版本")}</span><span class="bx-faint mono" style="font-size:12px">CVE-2026-109618 · CVE-2026-109619</span></div>
          <div class="bx-table-wrap"><table class="bx-table fix-table">
            <thead><tr><th>${t("Branch", "分支")}</th><th>${t("Fixed in", "修复版本")}</th><th>${t("Status", "状态")}</th></tr></thead>
            <tbody>
              ${advisory.branches.map((b) => `<tr><td>PHP ${b.branch}</td><td class="mono">${b.fixed ? `<span style="color:var(--green)">≥ ${b.fixed}</span>` : `<span style="color:var(--red)">${t("no release", "无官方发布")}</span>`}</td><td class="bx-muted">${b.fixed ? (b.status === "prerelease" ? t("pre-release", "预发布") : t("supported", "受支持")) : `<a href="${b.source_backport}">${t("source backport", "源码回溯")}</a>`}</td></tr>`).join("")}
              <tr><td>PHP ≤ 7.3</td><td class="mono"><span style="color:var(--red)">${t("none", "无")}</span></td><td class="bx-muted">${t("vendor backports only", "仅发行版回溯")}</td></tr>
            </tbody>
          </table></div>
        </div>
        <p class="src-list">${t("Sources", "来源")}: <a href="https://www.php.net/">php.net</a> · <a href="https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w">GHSA-w8hw-w9fx-j79w</a> · <a href="https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp">GHSA-6wmf-4rv5-p3rp</a> · <a href="https://ubuntu.com/security/CVE-2026-109618">Ubuntu</a> · <a href="https://security-tracker.debian.org/tracker/CVE-2026-109618">Debian</a> · <a href="https://access.redhat.com/security/vulnerabilities/RHSB-2026-013">Red Hat</a></p>
      </div>
    </div>
  </div>
</section>

<section class="sec" id="what">
  <div class="bx-wrap">
    <div class="sec-head">
      <div class="bx-eyebrow">${t("What it does", "能做什么")}</div>
      <h2>${t("Three commands. One honest answer.", "三个命令，一个诚实的答案。")}</h2>
      <p>${t("A single static binary. No agent, no account, no network calls. When Bastion cannot prove something, it says <code>unknown</code> instead of guessing.", "单个静态二进制文件。无需代理、无需账号、不联网。Bastion 无法确认的事情，会直接告诉你 <code>unknown</code>，而不是瞎猜。")}</p>
    </div>
    <div class="caps">
      <article class="bx-card cap">
        <h3><code>scan</code> ${t("Exposure", "暴露面")}</h3>
        <p>${t("Every PHP build on the box and whether it is really fixed.", "找出机器上所有 PHP 构建，判断是否真正修复。")}</p>
        <ul>
          <li>${t("Distro packages, BaoTa/aaPanel, cPanel EA4, CloudLinux, Plesk, Remi, LiteSpeed, source builds", "系统软件包、宝塔/aaPanel、cPanel EA4、CloudLinux、Plesk、Remi、LiteSpeed、源码编译")}</li>
          <li>${t("Docker/Podman containers and Kubernetes pods, read through their root filesystem", "Docker/Podman 容器和 Kubernetes Pod，直接读取其根文件系统")}</li>
          <li>${t("Running workers that still execute a replaced binary", "仍在运行已被替换的旧二进制的工作进程")}</li>
          <li>${t("Backports: vendor fix tables, package changelogs, fix fingerprints", "回溯补丁：发行版修复版本表、软件包变更日志、补丁指纹")}</li>
        </ul>
      </article>
      <article class="bx-card cap">
        <h3><code>trace</code> ${t("Intrusion", "入侵溯源")}</h3>
        <p>${t("Patching does not evict an attacker who is already in.", "打补丁赶不走已经进来的攻击者。")}</p>
        <ul>
          <li>${t("Webshell signatures (Chopper/AntSword, Behinder, Godzilla, WSO…), tuned on 33k legitimate PHP files", "Webshell 特征（菜刀/蚁剑、冰蝎、哥斯拉、WSO 等），在 3.3 万个正常 PHP 文件上调校误报")}</li>
          <li>${t("PHP in uploads and images, <code>.user.ini</code>/<code>.htaccess</code> tricks", "上传目录和图片中的 PHP、<code>.user.ini</code>/<code>.htaccess</code> 手法")}</li>
          <li>${t("Cron, systemd, <code>ld.so.preload</code>, SSH keys, UID 0 accounts", "计划任务、systemd、<code>ld.so.preload</code>、SSH 公钥、UID 0 账号")}</li>
          <li>${t("Log traces: requests to flagged files, worker segfaults, start-up OOM", "日志痕迹：对可疑文件的请求、进程段错误、请求启动阶段内存耗尽")}</li>
        </ul>
      </article>
      <article class="bx-card cap">
        <h3><code>report</code> ${t("Evidence", "报告")}</h3>
        <p>${t("One self-contained HTML file you can hand to a colleague or a client.", "一个可以直接交给同事或客户的独立 HTML 文件。")}</p>
        <ul>
          <li>${t("Works offline, no external assets", "离线可用，不依赖任何外部资源")}</li>
          <li>${t("Every verdict with its evidence and the fix for that environment", "每个结论都附带证据和对应环境的修复步骤")}</li>
          <li>${t("Timeline, bilingual, prints to PDF", "时间线、中英双语、可打印为 PDF")}</li>
          <li><a href="${ctx.root}demo/report.html">${t("Open a sample report", "查看示例报告")} →</a></li>
        </ul>
      </article>
    </div>
    <div class="bx-card" style="margin-top:16px" data-tabs>
      <div class="tabs-bar" role="tablist" style="padding:0 10px">
        <button role="tab" aria-selected="true" data-tab="t-trace"><code>trace</code></button>
        <button role="tab" aria-selected="false" data-tab="t-check"><code>check</code></button>
      </div>
      <div class="bx-card-body">
        <div data-panel="t-trace">${terminal(ctx, { title: "bastion trace", file: "trace.ansi", cmd: "sudo bastion trace --sysroot /tmp/bastion-lab" })}<p class="term-caption">${t("Real output on a lab tree built by <code>scripts/demo/lab.sh</code>: the planted backdoors are inert (wrapped in <code>if (false)</code>) and IPs are from documentation ranges.", "真实输出，目标是 <code>scripts/demo/lab.sh</code> 生成的实验目录：其中植入的后门均为无害样本（包在 <code>if (false)</code> 中），IP 来自文档保留地址段。")}</p></div>
        <div data-panel="t-check" hidden>${terminal(ctx, { title: "bastion check", file: "check.ansi", cmd: "dpkg-query -W php8.3-cli | bastion check" })}</div>
      </div>
    </div>
  </div>
</section>

<section class="sec" id="roadmap">
  <div class="bx-wrap">
    <div class="sec-head">
      <div class="bx-eyebrow">${t("Product", "产品路线")}</div>
      <h2>${t("From knowing, to fixing, to never again.", "从“知道”，到“修好”，再到“不再发生”。")}</h2>
      <p>${t("Bastion is built in modules. Two ship today; the rest are on the roadmap and will stay read-only by default.", "Bastion 按模块构建。两个模块现已可用，其余在路线图上，并且默认同样只读。")}</p>
    </div>
    <div class="road">
      <div class="road-item is-live"><span class="k">01 · SENSE</span><h3>Sense<small>${t("Perception", "感知")}</small></h3><p>${t("Inventory every PHP build and decide whether it is affected — <code>bastion scan</code>, <code>check</code>, <code>report</code>.", "盘点所有 PHP 构建并判断是否受影响——<code>bastion scan</code>、<code>check</code>、<code>report</code>。")}</p><span class="bx-badge is-green">${t("available", "已可用")}</span></div>
      <div class="road-item is-plan"><span class="k">02 · FORGE</span><h3>Forge<small>${t("Patch forging", "补丁锻造")}</small></h3><p>${t("Build patched packages for end-of-life PHP (7.4/8.0/8.1) from the official backport branches, reproducibly.", "基于官方回溯分支，为已停止维护的 PHP（7.4/8.0/8.1）可复现地构建补丁包。")}</p><span class="bx-badge">${t("roadmap", "路线图")}</span></div>
      <div class="road-item is-plan"><span class="k">03 · SHIFT</span><h3>Shift<small>${t("Safe migration", "安全迁移")}</small></h3><p>${t("Plan and rehearse moving sites to a supported PHP branch: compatibility checks and rollback.", "规划并演练将网站迁移到受支持的 PHP 分支：兼容性检查与回滚。")}</p><span class="bx-badge">${t("roadmap", "路线图")}</span></div>
      <div class="road-item is-plan"><span class="k">04 · GUARD</span><h3>Guard<small>${t("Runtime protection", "运行时防护")}</small></h3><p>${t("Detect exploitation attempts as they happen: request-shape limits and worker crash correlation.", "在攻击发生时识别利用尝试：请求形态限制与进程崩溃关联分析。")}</p><span class="bx-badge">${t("roadmap", "路线图")}</span></div>
      <div class="road-item is-live"><span class="k">05 · TRACE</span><h3>Trace<small>${t("Intrusion forensics", "入侵溯源")}</small></h3><p>${t("Find what an attacker left behind and when — <code>bastion trace</code>.", "找出攻击者留下了什么、何时留下——<code>bastion trace</code>。")}</p><span class="bx-badge is-green">${t("available", "已可用")}</span></div>
    </div>
  </div>
</section>

<section class="sec" id="principles">
  <div class="bx-wrap">
    <div class="sec-head">
      <div class="bx-eyebrow">${t("Principles", "原则")}</div>
      <h2>${t("A security tool you can run on production.", "一个敢放到生产环境运行的安全工具。")}</h2>
    </div>
    <div class="princ">
      <div><h3>${t("Read-only", "只读")}</h3><p>${t("Bastion never writes, quarantines, restarts or deletes anything. Remediation is printed, never executed.", "Bastion 不写入、不隔离、不重启、不删除任何东西。修复建议只会打印出来，绝不自动执行。")}</p></div>
      <div><h3>${t("Local", "本地")}</h3><p>${t("No telemetry, no cloud, no account. Results stay on your machine unless you share the report.", "没有遥测、没有云端、没有账号。除非你主动分享报告，结果只留在你的机器上。")}</p></div>
      <div><h3>${t("Honest", "诚实")}</h3><p>${t("Every verdict shows its evidence. Unverifiable builds are reported as <code>unknown</code>, never as safe.", "每个结论都给出证据。无法验证的构建会标记为 <code>unknown</code>，绝不会被说成安全。")}</p></div>
      <div><h3>${t("Data-driven", "数据驱动")}</h3><p>${t("Vulnerabilities and signatures are JSON. The next PHP bug is a data file, not a new release of the logic.", "漏洞与特征都是 JSON 数据。下一个 PHP 漏洞只需加一个数据文件，而不必重写逻辑。")}</p></div>
    </div>
  </div>
</section>

<section class="sec" id="install">
  <div class="bx-wrap">
    <div class="sec-head">
      <div class="bx-eyebrow">${t("Install", "安装")}</div>
      <h2>${t("Thirty seconds to a first answer.", "三十秒得到第一个答案。")}</h2>
      <p>${t("Linux and macOS, amd64 and arm64. The installer verifies the SHA-256 checksum, and the Sigstore signature when <code>cosign</code> is available.", "支持 Linux 和 macOS 的 amd64 与 arm64。安装脚本会校验 SHA-256，若系统中有 <code>cosign</code> 还会校验 Sigstore 签名。")}</p>
    </div>
    <div data-tabs>
      <div class="tabs-bar" role="tablist">
        <button role="tab" aria-selected="true" data-tab="i-script">${t("Install script", "安装脚本")}</button>
        <button role="tab" aria-selected="false" data-tab="i-manual">${t("Manual + verify", "手动下载并校验")}</button>
        <button role="tab" aria-selected="false" data-tab="i-go">${t("From source", "从源码构建")}</button>
      </div>
      <div class="tab-panel" data-panel="i-script">
        <p>${t("Prefer to read it first? Download, inspect, then run.", "想先看一眼脚本？下载、检查，再执行。")}</p>
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
    title: t("Bastion — is your PHP exposed? has someone got in?", "Bastion —— 你的 PHP 安全吗？网站被黑了吗？"),
    description: t("Open-source, local, read-only PHP security tool: find every PHP build, verify PHP2Shell (CVE-2026-109618/109619) patches including distro backports, and trace intrusions.", "开源、本地运行、只读的 PHP 安全工具：找出所有 PHP 构建，验证 PHP2Shell（CVE-2026-109618/109619）补丁（含发行版回溯），并排查入侵痕迹。"),
    body,
  });
}
