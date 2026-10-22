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
  return `<div class="bx-card bx-table-wrap"><table class="bx-table"><thead><tr><th>${ctx.t("Flag", "参数")}</th><th>${ctx.t("Description", "说明")}</th><th>${ctx.t("Default", "默认值")}</th></tr></thead><tbody>${rows
    .map((r) => `<tr><td class="mono">${esc(r.flag)}${r.type ? ` <span class="bx-faint">${esc(r.type)}</span>` : ""}</td><td>${esc(r.desc)}</td><td class="mono bx-faint">${esc(r.def)}</td></tr>`)
    .join("")}</tbody></table></div>`;
}

export function render(ctx) {
  const { t } = ctx;
  const faq = [
    [t("Does Bastion change anything on my server?", "Bastion 会修改服务器上的东西吗？"), t("No. It opens files and reads <code>/proc</code>. It never writes outside the report file you ask for, never restarts services, never deletes or quarantines. By default it may run <code>php -v</code> when a binary can't be read statically, and <code>docker exec</code> when a container filesystem isn't readable; <code>--no-exec</code> turns both off.", "不会。它只打开文件和读取 <code>/proc</code>。除了你要求生成的报告文件，它不会写入任何东西，也不会重启服务、删除或隔离文件。默认情况下，只有在无法静态读取二进制时才会运行 <code>php -v</code>，在无法读取容器文件系统时才会使用 <code>docker exec</code>；加上 <code>--no-exec</code> 可以把这两项都关掉。")],
    [t("Does it send data anywhere?", "它会把数据发送到别处吗？"), t("No. <code>scan</code>, <code>trace</code>, <code>check</code> and <code>report</code> make no network connections (the Docker/Podman CLI talks to the local daemon only). The vulnerability data is compiled in. The website's online check also runs locally in your browser.", "不会。<code>scan</code>、<code>trace</code>、<code>check</code>、<code>report</code> 不发起任何网络连接（Docker/Podman 命令行只与本机守护进程通信）。漏洞数据编译在二进制里。网站的在线自查同样在你的浏览器本地运行。")],
    [t("Why does it need root?", "为什么需要 root？"), t("To see other users' processes (php-fpm workers, Apache), container filesystems under <code>/proc/&lt;pid&gt;/root</code>, crontabs and web server logs. Without root it still runs and tells you what it could not see.", "为了看到其他用户的进程（php-fpm 工作进程、Apache）、位于 <code>/proc/&lt;pid&gt;/root</code> 的容器文件系统、计划任务以及 Web 服务器日志。没有 root 也能运行，并会告诉你哪些内容没能看到。")],
    [t("Why is my build “unknown”?", "为什么我的构建显示“无法判断”？"), t("Because Bastion could not prove it either way: typically a distribution package from a vendor without fixed-version data whose changelog isn't installed. Ask the vendor whether CVE-2026-109618/109619 are fixed in that package; Bastion won't guess.", "因为 Bastion 无法证明它是否已修复：常见情况是某个发行版软件包，Bastion 没有该发行版的修复版本数据，而它的变更日志又没有安装。请向供应商确认该软件包是否已修复 CVE-2026-109618/109619；Bastion 不会替你猜。")],
    [t("I built PHP 8.1 from the official backport branch. Why “likely vulnerable”?", "我用官方回溯分支编译了 PHP 8.1，为什么还是“很可能存在漏洞”？"), t("The backport branches keep the version string (8.1.34) and add no distinctive marker, so a patched build is indistinguishable from an unpatched one. Bastion reports what it can prove; you know what you built.", "回溯分支保留了原来的版本号（8.1.34），也没有加入任何可识别的标记，因此打过补丁的构建与没打补丁的完全无法区分。Bastion 只报告能证明的内容；你自己清楚编译的是什么。")],
    [t("If trace finds nothing, am I safe?", "如果 trace 什么都没发现，我就安全了吗？"), t("Not necessarily. Signatures miss novel backdoors and an attacker with root can hide from any on-host tool. A clean trace lowers the odds; it isn't proof. If you suspect a breach, image the disk and investigate offline (<code>--sysroot</code> works on a mounted image).", "不一定。特征检测会漏掉新型后门，拿到 root 的攻击者也能躲过任何本机工具。没有发现只是降低了可能性，并不是证明。如果怀疑被入侵，请对磁盘做镜像后离线排查（<code>--sysroot</code> 可以检查挂载的镜像）。")],
    [t("What about false positives?", "误报怎么办？"), t("File signatures were tuned against about 33,000 PHP files from WordPress, Drupal, phpMyAdmin, Laravel, Symfony, phpseclib and PHPMailer with zero high or medium hits; CI re-checks WordPress and Drupal on every change. Weak signals are only reported when several appear together. Each finding names its rule and shows the matching line so you can judge it.", "文件特征在约 33,000 个来自 WordPress、Drupal、phpMyAdmin、Laravel、Symfony、phpseclib 和 PHPMailer 的 PHP 文件上调校过，没有任何高危或中危误报；CI 会在每次改动时重新检查 WordPress 和 Drupal。弱信号只有在多个同时出现时才会报告。每条结果都会注明规则并展示命中的那一行，方便你自行判断。")],
    [t("Containers, Kubernetes, LXC?", "容器、Kubernetes、LXC 呢？"), t("Running Docker and Podman containers are listed through their CLI and read via <code>/proc/&lt;pid&gt;/root</code>. Any other process with its own root filesystem (Kubernetes pods via containerd/CRI-O, LXC, chroots) is found from <code>/proc</code> and scanned the same way. Images that aren't running are not scanned.", "运行中的 Docker 和 Podman 容器通过其命令行列出，并经由 <code>/proc/&lt;pid&gt;/root</code> 读取。其他拥有独立根文件系统的进程（通过 containerd/CRI-O 运行的 Kubernetes Pod、LXC、chroot）会从 <code>/proc</code> 中发现并以同样方式扫描。未运行的镜像不会被扫描。")],
    [t("Windows?", "Windows 呢？"), t("Not supported for <code>scan</code>/<code>trace</code>. Use the <a href=\"" + ctx.href("check") + "\">online check</a> with <code>php -v</code>.", "<code>scan</code>/<code>trace</code> 暂不支持 Windows。请使用<a href=\"" + ctx.href("check") + "\">在线自查</a>并粘贴 <code>php -v</code>。")],
    [t("How current is the vulnerability data?", "漏洞数据有多新？"), t("It is compiled into each release and reflects official sources at release time (PHP2Shell data: php.net, GitHub advisories, Ubuntu and Debian trackers as of 22 Oct 2026). Newer data can be loaded without upgrading using <code>--db &lt;dir&gt;</code>.", "数据随每个版本编译进二进制，反映发布时官方来源的情况（PHP2Shell 数据截至 2026 年 10 月 22 日，来自 php.net、GitHub 安全公告以及 Ubuntu、Debian 安全追踪器）。不升级也可以用 <code>--db &lt;目录&gt;</code> 加载更新的数据。")],
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
  "vulnerabilities": [{ "cve": "CVE-2027-0001", "ghsa": "", "title": { "en": "…", "zh": "…" }, "url": "https://…" }],
  "summary": { "en": "…", "zh": "…" },
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
  "mitigations": [{ "en": "…", "zh": "…" }],
  "references": [{ "title": "…", "url": "https://…" }]
}`;
  const body = `
<header class="phead">
  <div class="bx-grid-bg" aria-hidden="true"></div>
  <div class="bx-wrap phead-in">
    <div class="bx-eyebrow">${t("Documentation", "文档")}</div>
    <h1>${t("Install, run, read the results", "安装、运行、读懂结果")}</h1>
    <p>${t("Everything about the <code>bastion</code> command line. Flag tables on this page are generated from the binary itself.", "关于 <code>bastion</code> 命令行的一切。本页的参数表直接由二进制生成。")}</p>
  </div>
</header>
<div class="bx-wrap docs-grid">
  <nav class="docs-toc" aria-label="${t("On this page", "本页目录")}">
    <span class="bx-eyebrow">${t("Start", "开始")}</span>
    <a href="#install">${t("Install", "安装")}</a><a href="#quickstart">${t("Quick start", "快速开始")}</a>
    <span class="bx-eyebrow">${t("Commands", "命令")}</span>
    <a href="#commands">scan</a><a href="#trace">trace</a><a href="#report">report</a><a href="#check">check</a><a href="#exit">${t("Exit codes & JSON", "退出码与 JSON")}</a>
    <span class="bx-eyebrow">${t("More", "更多")}</span>
    <a href="#statuses">${t("Statuses", "状态说明")}</a><a href="#data">${t("Advisory data", "漏洞数据")}</a><a href="#faq">FAQ</a>
  </nav>
  <div class="docs">
    <section id="install">
      <h2>${t("Install", "安装")}</h2>
      <p>${t("Bastion is one static binary for Linux and macOS (amd64, arm64). The script picks the right build from the latest GitHub release, checks its SHA-256 against <code>SHA256SUMS</code> and, if <code>cosign</code> is installed, verifies the Sigstore signature of that file. It installs to <code>/usr/local/bin</code> (or <code>~/.local/bin</code> without root) and changes nothing else.", "Bastion 是适用于 Linux 和 macOS（amd64、arm64）的单个静态二进制文件。安装脚本会从最新的 GitHub Release 中选择对应的构建，对照 <code>SHA256SUMS</code> 校验 SHA-256；如果安装了 <code>cosign</code>，还会校验该文件的 Sigstore 签名。它会安装到 <code>/usr/local/bin</code>（没有 root 时为 <code>~/.local/bin</code>），不改动其他任何东西。")}</p>
      ${codebox(INSTALL)}
      <p>${t("Options (environment variables):", "可选项（环境变量）：")}</p>
      <div class="bx-card bx-table-wrap"><table class="bx-table"><tbody>
        <tr><td class="mono">BASTION_VERSION</td><td>${t("release tag to install, e.g. <code>v0.1.0</code> (default: latest)", "要安装的版本标签，例如 <code>v0.1.0</code>（默认：最新版）")}</td></tr>
        <tr><td class="mono">BASTION_INSTALL_DIR</td><td>${t("target directory", "安装目录")}</td></tr>
        <tr><td class="mono">BASTION_REQUIRE_SIGNATURE=1</td><td>${t("fail if <code>cosign</code> is missing instead of skipping the signature check", "如果缺少 <code>cosign</code> 就直接失败，而不是跳过签名校验")}</td></tr>
      </tbody></table></div>
      <h3>${t("Verify by hand", "手动校验")}</h3>
      ${codebox(`VERSION=v0.1.0\nBASE=https://github.com/larptard/bastion/releases/download/$VERSION\ncurl -fsSLO $BASE/bastion_linux_amd64.tar.gz -O $BASE/SHA256SUMS -O $BASE/SHA256SUMS.sigstore.json\nsha256sum --ignore-missing -c SHA256SUMS\ncosign verify-blob --bundle SHA256SUMS.sigstore.json \\\n  --certificate-identity-regexp '^https://github.com/larptard/bastion/.github/workflows/release.yml@refs/tags/v' \\\n  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS\ngh attestation verify bastion_linux_amd64.tar.gz --repo larptard/bastion   # build provenance`)}
      <h3>${t("From source", "从源码构建")}</h3>
      ${codebox("go install github.com/larptard/bastion/cmd/bastion@latest   # Go 1.24+\n# or\ngit clone https://github.com/larptard/bastion && cd bastion && make build")}
    </section>

    <section id="quickstart">
      <h2>${t("Quick start", "快速开始")}</h2>
      ${codebox("sudo bastion scan              # every PHP build: patched or not\nsudo bastion trace             # signs of compromise in web roots, persistence, logs\nsudo bastion report            # both, as one offline HTML file\nphp -v | bastion check         # assess pasted output (no root needed)")}
      <p>${t("Run as root for full coverage. Nothing is modified; remediation steps are printed for you to apply.", "以 root 运行可获得完整覆盖。不会修改任何东西；修复步骤只会打印出来，由你自己执行。")}</p>
    </section>

    <section id="commands">
      <h2><code>bastion scan</code></h2>
      <p>${t("Finds PHP builds in the standard locations of distributions and hosting panels (BaoTa/aaPanel, cPanel EA4, CloudLinux alt-php, Plesk, Remi, LiteSpeed, Homebrew, XAMPP, Bitnami, <code>/usr/local/php*</code>), in <code>$PATH</code>, in running processes (php-fpm, php-cgi, lsphp, FrankenPHP and Apache with mod_php) and in Docker/Podman containers and other mount namespaces. For each build it reads the version from the binary, looks up the owning dpkg/rpm/apk package and its changelog, and evaluates every advisory.", "在发行版和主机面板的标准位置（宝塔/aaPanel、cPanel EA4、CloudLinux alt-php、Plesk、Remi、LiteSpeed、Homebrew、XAMPP、Bitnami、<code>/usr/local/php*</code>）、<code>$PATH</code>、运行中的进程（php-fpm、php-cgi、lsphp、FrankenPHP 以及加载了 mod_php 的 Apache）以及 Docker/Podman 容器和其他挂载命名空间中查找 PHP 构建。对每个构建，它会从二进制读取版本号，查找所属的 dpkg/rpm/apk 软件包及其变更日志，并逐一评估所有漏洞公告。")}</p>
      ${flagTable(ctx, "scan")}
    </section>

    <section id="trace">
      <h2><code>bastion trace [dir…]</code></h2>
      <p>${t("Discovers web roots from nginx, Apache, LiteSpeed and Caddy configuration and the default paths of common panels, plus any directories you pass. It reports webshell signatures, PHP in uploads and images, <code>.user.ini</code>/<code>.htaccess</code> abuse, suspicious cron/systemd/profile entries, <code>/etc/ld.so.preload</code>, extra UID 0 accounts, SSH keys for web users, executables in temp directories, global <code>auto_prepend_file</code>, and log indicators: requests to flagged files, successful POSTs to PHP in upload folders, command parameters, php-cgi argument injection, worker segfaults and out-of-memory during request start-up.", "从 nginx、Apache、LiteSpeed 和 Caddy 的配置以及常见面板的默认路径中发现网站根目录，也可以手动传入目录。它会报告：Webshell 特征、上传目录和图片中的 PHP、<code>.user.ini</code>/<code>.htaccess</code> 滥用、可疑的计划任务/systemd/Shell 启动项、<code>/etc/ld.so.preload</code>、额外的 UID 0 账号、Web 账号的 SSH 公钥、临时目录中的可执行文件、全局 <code>auto_prepend_file</code>，以及日志线索：对可疑文件的请求、成功 POST 到上传目录中的 PHP、命令参数、php-cgi 参数注入、工作进程段错误和请求启动阶段的内存耗尽。")}</p>
      ${flagTable(ctx, "trace")}
    </section>

    <section id="report">
      <h2><code>bastion report</code></h2>
      <p>${t("Runs <code>scan</code> and <code>trace</code> and writes <code>bastion-report-&lt;host&gt;-&lt;time&gt;.html</code>: one file with inline styles and data, no external requests, bilingual, printable. It contains host details — share it deliberately. Use <code>--scan</code>/<code>--trace</code> to build a report from saved JSON, e.g. collected from several servers.", "运行 <code>scan</code> 和 <code>trace</code>，生成 <code>bastion-report-&lt;主机&gt;-&lt;时间&gt;.html</code>：单个文件，样式和数据全部内联，不发起任何外部请求，中英双语，可打印。报告中包含主机细节，请有意识地分享。使用 <code>--scan</code>/<code>--trace</code> 可以基于保存的 JSON 生成报告，例如从多台服务器收集的结果。")} <a href="${ctx.root}demo/report.html">${t("Sample report", "示例报告")} →</a></p>
      ${flagTable(ctx, "report")}
    </section>

    <section id="check">
      <h2><code>bastion check</code></h2>
      <p>${t("Assesses text instead of the machine: the output of <code>php -v</code>, optionally with <code>dpkg-query -W 'php*'</code>, <code>rpm -qa 'php*'</code>, <code>apk info -v</code> or <code>/etc/os-release</code>. It is the same engine as the online check.", "评估文本而不是机器：<code>php -v</code> 的输出，可附加 <code>dpkg-query -W 'php*'</code>、<code>rpm -qa 'php*'</code>、<code>apk info -v</code> 或 <code>/etc/os-release</code>。它与在线自查使用同一个引擎。")}</p>
      ${codebox("ssh web-01 'php -v; dpkg-query -W \"php*\"' | bastion check\nbastion check --os ubuntu:24.04 'PHP 8.3.6 (cli)'")}
      ${flagTable(ctx, "check")}
    </section>

    <section id="exit">
      <h2>${t("Exit codes & JSON", "退出码与 JSON")}</h2>
      <div class="bx-card bx-table-wrap"><table class="bx-table"><tbody>
        <tr><td class="mono">0</td><td>${t("nothing affected / no indicators", "没有受影响的构建 / 没有入侵迹象")}</td></tr>
        <tr><td class="mono">1</td><td>${t("a vulnerable or likely vulnerable build, or high-severity indicators", "存在有漏洞或很可能有漏洞的构建，或存在高危入侵迹象")}</td></tr>
        <tr><td class="mono">2</td><td>${t("some builds unknown, or only medium indicators", "部分构建无法判断，或只有中危迹象")}</td></tr>
        <tr><td class="mono">64 / 70</td><td>${t("usage error / runtime error", "用法错误 / 运行错误")}</td></tr>
      </tbody></table></div>
      <p>${t("<code>--json</code> prints a versioned document (<code>bastion.scan/v1</code>, <code>bastion.trace/v1</code>) for fleets and CI:", "<code>--json</code> 会输出带版本号的文档（<code>bastion.scan/v1</code>、<code>bastion.trace/v1</code>），便于批量和 CI 使用：")}</p>
      ${codebox(`sudo bastion scan --json | jq -r '.instances[] | select(.assessments[0].status != "fixed") | "\\(.target) \\(.path) \\(.assessments[0].status)"'`)}
    </section>

    <section id="statuses">
      <h2>${t("What the statuses mean", "状态说明")}</h2>
      <div class="bx-card bx-table-wrap"><table class="bx-table"><tbody>
        <tr><td><span class="bx-badge" data-status="fixed">fixed</span></td><td>${t("Proven: upstream version at or above the fix, vendor package at or above the vendor's fixed version, a changelog naming the CVE, or code only the fix contains.", "已证实：上游版本不低于修复版本、发行版软件包不低于官方修复版本、变更日志写明了该 CVE，或二进制中含有只有补丁才有的代码。")}</td></tr>
        <tr><td><span class="bx-badge" data-status="vulnerable">vulnerable</span></td><td>${t("Proven: below the upstream fix with no package manager involved, or a vendor package older than the vendor's fixed version.", "已证实：不受包管理器管理且低于上游修复版本，或发行版软件包低于官方修复版本。")}</td></tr>
        <tr><td><span class="bx-badge" data-status="likely-vulnerable">likely-vulnerable</span></td><td>${t("No evidence of a fix where evidence would be expected: an end-of-life branch with only a source backport, a package whose changelog doesn't mention the CVE, or a process still running a replaced binary.", "在理应有证据的地方找不到修复证据：只有源码回溯的停止维护分支、变更日志未提及该 CVE 的软件包，或仍在运行已被替换的二进制的进程。")}</td></tr>
        <tr><td><span class="bx-badge" data-status="unknown">unknown</span></td><td>${t("Not enough information. Bastion will not turn this into a guess.", "信息不足。Bastion 不会把它变成一个猜测。")}</td></tr>
      </tbody></table></div>
    </section>

    <section id="data">
      <h2>${t("Advisory data", "漏洞数据")}</h2>
      <p>${t("Each vulnerability is one JSON document in <a href=\"" + REPO + "/tree/main/internal/advisory/data\"><code>internal/advisory/data/</code></a>, validated on load. Drop a file there and rebuild, or point <code>--db</code> at a directory to add or override advisories at run time. <code>bastion advisories</code> prints what is loaded.", "每个漏洞是 <a href=\"" + REPO + "/tree/main/internal/advisory/data\"><code>internal/advisory/data/</code></a> 中的一个 JSON 文档，加载时会做校验。把文件放进去重新编译即可，也可以用 <code>--db</code> 指向一个目录，在运行时添加或覆盖漏洞数据。<code>bastion advisories</code> 会打印当前加载的内容。")}</p>
      <pre class="bx-code">${highlightJSON(advExample)}</pre>
      <p>${t("Webshell and obfuscation signatures follow the same idea in <code>internal/trace/rules/content.json</code>.", "Webshell 与混淆特征同样采用这种方式，位于 <code>internal/trace/rules/content.json</code>。")}</p>
    </section>

    <section id="faq" class="faq">
      <h2>FAQ</h2>
      ${faq.map(([q, a]) => `<details><summary>${q}</summary><p>${a}</p></details>`).join("")}
    </section>
  </div>
</div>
`;
  return layout(ctx, {
    title: t("Docs", "文档"),
    description: t("Install Bastion, run scan/trace/report/check, read the statuses and extend the advisory data.", "安装 Bastion，运行 scan/trace/report/check，理解各状态含义并扩展漏洞数据。"),
    body,
  });
}
