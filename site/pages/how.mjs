import { layout, REPO } from "../lib/layout.mjs";
import { renderAnnotated } from "../lib/snippets.mjs";
import { esc } from "./common.mjs";

const src = (p) => new URL("../../" + p, import.meta.url);

function walk(ctx, spec) {
  const { t } = ctx;
  const w = renderAnnotated({ ...spec, file: src(spec.repoPath) });
  const steps = w.parts
    .map((p, i) => {
      const code = p.code
        .split("\n")
        .map((l, k) => `<span class="ln">${p.line + k}</span>${w.highlight(l)}`)
        .join("\n");
      return `<div class="walk-step"><pre class="bx-code">${code}</pre><div class="walk-note"><span class="step-n">${String(i + 1).padStart(2, "0")}</span><b>${t(p.title.en, p.title.zh)}</b>${t(p.note.en, p.note.zh)}</div></div>`;
    })
    .join("");
  return `<figure class="walk"><figcaption class="walk-head"><a href="${REPO}/blob/main/${w.file}#L${w.startLine}-L${w.endLine}">${w.file}#L${w.startLine}–${w.endLine}</a><span>${t("excerpt taken from the source at build time", "片段在构建时直接取自源码")}</span></figcaption>${steps}</figure>`;
}

const S = (en, zh) => ({ en, zh });

export function render(ctx) {
  const { t } = ctx;
  const evaluate = walk(ctx, {
    repoPath: "internal/advisory/evaluate.go",
    signature: "func (a *Advisory) Evaluate(",
    omitDocComment: true,
    steps: [
      { anchor: "out := Assessment", title: S("Collect evidence as you go", "边判断边记录证据"), note: S("Every rule appends an <code>Evidence</code> entry. The verdict is never a bare word: the report and terminal show exactly which observation decided it.", "每条规则都会追加一条 <code>Evidence</code>。结论从来不是一个孤零零的词，报告和终端都会展示到底是哪条观察决定了结果。") },
      { anchor: "v, err := version.ParsePHP(s.Version)", title: S("Parse the upstream version", "解析上游版本号"), note: S("The version comes from the binary itself (see below). If it is missing, the package version is used instead.", "版本号直接读自二进制文件本身（见下文）。如果读不到，就退而使用软件包版本。") },
      { anchor: "upstream := \"\"", title: S("Rule 1 — upstream release", "规则 1：上游版本"), note: S("At or above the branch's fixed release (8.3.36, 8.4.27…) means fixed, done. Below it is <em>not</em> conclusive for distribution packages, so the evidence is recorded as neutral and the search goes on.", "不低于该分支的修复版本（8.3.36、8.4.27……）即判定已修复。低于它，对于发行版软件包来说<em>并不能</em>下结论，因此只记为中性证据，继续往下判断。") },
      { anchor: "if f := a.VendorFixFor(s.OS, s.Package)", title: S("Rule 2 — vendor fix table", "规则 2：发行版修复表"), note: S("For Ubuntu and Debian, Bastion carries the exact fixed package versions from the vendors' trackers and compares them with dpkg's algorithm. This is the strongest signal a backport exists.", "对于 Ubuntu 和 Debian，Bastion 内置了从官方安全追踪器获取的精确修复版本，并用 dpkg 的算法进行比较。这是判断回溯补丁是否存在的最强信号。") },
      { anchor: "if len(s.ChangelogHits) > 0", title: S("Rule 3 — the package changelog", "规则 3：软件包变更日志"), note: S("Vendors name the CVEs they fix in the package changelog (<code>changelog.Debian.gz</code>, <code>rpm -q --changelog</code>). This covers distributions Bastion has no table for.", "发行版会在软件包变更日志（<code>changelog.Debian.gz</code>、<code>rpm -q --changelog</code>）里写明修复了哪些 CVE。这一条覆盖了 Bastion 没有修复表的发行版。") },
      { anchor: "for _, fp := range a.Fingerprints", title: S("Rule 4 — code only the fix contains", "规则 4：只有补丁才有的代码"), note: S("The fix adds a hard memory limit with a new error message. If those bytes are in the binary, the patch is in the build — whatever the version says.", "修复引入了硬内存上限和一条新的错误消息。只要二进制里有这串字节，补丁就一定在这个构建里——不管版本号怎么写。") },
      { anchor: "if s.Package != nil {", title: S("Rule 5 — say what you can't prove", "规则 5：证明不了就直说"), note: S("A package whose changelog is readable but silent is <em>likely vulnerable</em>. If nothing could be read, the answer is <em>unknown</em> — never a guess dressed up as a verdict.", "变更日志可读但没有记录的软件包，判定为<em>很可能存在漏洞</em>。什么都读不到时，答案就是<em>无法判断</em>——绝不把猜测包装成结论。") },
      { anchor: "switch upstream {", title: S("Builds outside a package manager", "不受包管理器管理的构建"), note: S("Docker official images, BaoTa and source builds follow upstream versions, so the version alone decides. End-of-life branches with only a source backport cannot be told apart and are reported as likely vulnerable.", "Docker 官方镜像、宝塔和源码编译遵循上游版本号，因此只看版本即可。只有源码回溯的停止维护分支无法区分，会被标记为很可能存在漏洞。") },
    ],
  });
  const probe = walk(ctx, {
    repoPath: "internal/discover/probe.go",
    signature: "func StaticProbe(",
    steps: [
      { anchor: "func StaticProbe(", title: S("Never execute what you inspect", "不执行被检查的程序"), note: S("Running an unknown binary as root to ask its version is a bad habit for a security tool. Bastion opens the file and reads it.", "以 root 身份运行一个来历不明的程序去问它的版本号，对安全工具来说是坏习惯。Bastion 只是打开文件读取内容。") },
      { anchor: "for _, m := range magics", title: S("Only real executables", "只处理真正的可执行文件"), note: S("ELF and Mach-O headers are checked first, so wrapper scripts called <code>php</code> are skipped.", "先检查 ELF 和 Mach-O 文件头，名叫 <code>php</code> 的包装脚本会被跳过。") },
      { anchor: "all := append([]string{poweredBy}, needles...)", title: S("The version is compiled in", "版本号是编译进去的"), note: S("Every PHP SAPI — CLI, FPM, CGI, mod_php's <code>libphp.so</code> — contains the literal <code>X-Powered-By: PHP/</code> + <code>PHP_VERSION</code>. The same pass looks for the fix fingerprint.", "所有 PHP SAPI——CLI、FPM、CGI，以及 mod_php 的 <code>libphp.so</code>——都包含字面量 <code>X-Powered-By: PHP/</code> + <code>PHP_VERSION</code>。同一遍扫描里还会查找补丁指纹。") },
      { anchor: "for {", title: S("Stream, don't load", "流式读取"), note: S("The file is read in 1 MiB chunks with an overlap, so a needle spanning two chunks is still found and memory stays flat.", "文件按 1 MiB 分块读取并保留重叠区，跨块的字符串也能找到，内存占用保持平稳。") },
    ],
  });
  const dpkg = walk(ctx, {
    repoPath: "internal/pkgdb/pkgdb.go",
    signature: "func (d *DB) dpkgLookup(",
    steps: [
      { anchor: "d.dpkgIndex()", title: S("Who owns this file?", "这个文件属于哪个包？"), note: S("dpkg's own database is parsed directly — no <code>dpkg</code> binary needed — so the same code works on a container's root filesystem.", "直接解析 dpkg 自己的数据库，不需要调用 <code>dpkg</code>，因此同一段代码也能用于容器的根文件系统。") },
      { anchor: "info := Info{Package:", title: S("Source package and version", "源码包与版本"), note: S("Vendors publish fixes per <em>source</em> package (<code>php8.3</code>), not per binary package (<code>php8.3-cli</code>).", "发行版按<em>源码包</em>（<code>php8.3</code>）而不是二进制包（<code>php8.3-cli</code>）发布修复。") },
      { anchor: "for _, doc := range", title: S("Read the changelog", "读取变更日志"), note: S("The installed package's changelog only contains entries up to the installed version, so a CVE id in it means the fix is installed.", "已安装软件包的变更日志只包含到当前安装版本为止的记录，所以只要里面出现 CVE 编号，就说明修复已安装。") },
    ],
  });

  const body = `
<header class="phead">
  <div class="bx-grid-bg" aria-hidden="true"></div>
  <div class="bx-wrap phead-in">
    <div class="bx-eyebrow">${t("How it works", "原理")}</div>
    <h1>${t("Why “just check the version” gets PHP2Shell wrong", "为什么“看一眼版本号”判断不了 PHP2Shell")}</h1>
    <p>${t("What the vulnerability is, why installing the patch is only half the job, and exactly how Bastion decides — with the real code.", "这个漏洞是什么，为什么装上补丁只完成了一半，以及 Bastion 究竟如何判断——附真实代码。")}</p>
  </div>
</header>

<section class="chapter" id="vuln">
  <div class="bx-wrap chapter-grid">
    <div class="chapter-label"><span class="num">01</span><h2>${t("The vulnerability", "漏洞是什么")}</h2></div>
    <div class="prose">
      <h2>${t("Two ways to make PHP trust memory it shouldn't", "两种让 PHP 信任不该信任的内存的方法")}</h2>
      <p>${t("PHP handles each web request in a short life cycle: set up request data, run your script, clean up. PHP2Shell breaks the assumptions between those steps.", "PHP 处理每个 Web 请求都有一个简短的生命周期：准备请求数据、运行脚本、清理。PHP2Shell 打破的正是这几步之间的假设。")}</p>
      <h3>CVE-2026-109618 · ${t("out-of-memory corruption", "内存耗尽导致的状态损坏")}</h3>
      <p>${t("When PHP runs out of its memory budget it doesn't return an error; it <strong>jumps out</strong> of whatever it was doing (a <code>longjmp</code> “bailout”). If that happens while request data is half built — for example while parsing an upload — the clean-up step later reads that half-built data as if it were valid. An attacker can push request parsing into out-of-memory while staying inside the apparent PHP limits: multipart bodies without a usable length, unlimited headers per part, empty file fields that don't count towards <code>max_file_uploads</code>.", "PHP 内存超出预算时并不返回错误，而是从正在做的事情中<strong>直接跳出</strong>（一次 <code>longjmp</code>“bailout”）。如果这发生在请求数据只构建了一半的时候——比如正在解析上传——稍后的清理步骤就会把这些半成品数据当成有效数据来读。攻击者可以在看似不超过 PHP 限制的情况下，把请求解析推向内存耗尽：没有可用长度的 multipart 请求体、每段不限数量的头部、不计入 <code>max_file_uploads</code> 的空文件字段。")}</p>
      <h3>CVE-2026-109619 · ${t("stale global state", "残留的全局状态")}</h3>
      <p>${t("PHP-FPM and mod_php reuse one worker process for many requests. A fatal error can leave global state pointing at memory that has already been freed; the <strong>next request on the same worker</strong> can touch it before normal initialisation resets it — a use-after-free. Confirmed paths include INI diagnostics raised before request start-up and session upload progress.", "PHP-FPM 和 mod_php 会用同一个工作进程处理很多请求。一次致命错误可能让全局状态仍然指向已经释放的内存；<strong>同一工作进程上的下一个请求</strong>可能在正常初始化重置它之前就用到它——这就是释放后使用。已确认的路径包括请求启动前产生的 INI 诊断信息，以及会话上传进度。")}</p>
      <div class="bx-card diagram">${diagram(ctx)}</div>
      <p>${t("Both are rated CVSS v4.0 9.2. The official advisory demonstrated unauthenticated code execution against Apache mod_php with default limits; PHP-FPM, FrankenPHP and LiteSpeed are considered likely susceptible. The fix removes <code>longjmp</code> from out-of-memory handling: PHP now stops at the next safe point (soft limit) or exits the worker (hard limit).", "两个漏洞的 CVSS v4.0 评分均为 9.2。官方公告已在默认限制下对 Apache mod_php 演示了未授权代码执行；PHP-FPM、FrankenPHP 和 LiteSpeed 被认为同样可能受影响。修复方案是在内存耗尽处理中去掉 <code>longjmp</code>：PHP 现在会在下一个安全点停止（软上限），或直接退出工作进程（硬上限）。")}</p>
    </div>
  </div>
</section>

<section class="chapter" id="not-enough">
  <div class="bx-wrap chapter-grid">
    <div class="chapter-label"><span class="num">02</span><h2>${t("Why patching isn't enough", "为什么打了补丁还不够")}</h2></div>
    <div class="prose">
      <h2>${t("Six ways a “patched” server is still exposed", "“已打补丁”的服务器仍然暴露的六种情况")}</h2>
      <ol class="ladder">
        <li><div><strong>${t("The old code is still running", "旧代码还在运行")}</strong>${t("<code>apt upgrade</code> replaces files on disk. php-fpm and Apache workers keep executing the old build until they are restarted. Bastion finds processes whose binary was replaced and reads the old image from <code>/proc/&lt;pid&gt;/exe</code>.", "<code>apt upgrade</code> 替换的是磁盘上的文件。php-fpm 和 Apache 工作进程会继续执行旧的构建，直到被重启。Bastion 会找出二进制已被替换的进程，并通过 <code>/proc/&lt;pid&gt;/exe</code> 读取旧的映像。")}</div><span class="bx-badge is-amber">restart</span></li>
        <li><div><strong>${t("There is more than one PHP", "机器上不止一个 PHP")}</strong>${t("A system PHP, two panel-managed versions and a Homebrew build on the same box are common. Patching the one in <code>$PATH</code> leaves the one serving the site untouched.", "同一台机器上同时有系统 PHP、两个面板管理的版本、外加一个 Homebrew 构建很常见。给 <code>$PATH</code> 里的那个打补丁，真正在跑网站的那个可能根本没动。")}</div><span class="bx-badge">inventory</span></li>
        <li><div><strong>${t("Containers were built yesterday", "容器是昨天构建的")}</strong>${t("Host updates don't reach containers. Each image must be rebuilt on a patched base and redeployed. Bastion reads running containers' filesystems directly.", "主机更新不会进入容器。每个镜像都必须基于已修复的基础镜像重新构建并重新部署。Bastion 会直接读取运行中容器的文件系统。")}</div><span class="bx-badge">rebuild</span></li>
        <li><div><strong>${t("End-of-life branches have no release", "停止维护的分支没有发布")}</strong>${t("PHP ≤ 8.1 gets no official release. The source backports for 7.4/8.0/8.1 don't change the version string, so a patched build and a vulnerable one look identical from outside.", "PHP 8.1 及以下没有官方发布。7.4/8.0/8.1 的源码回溯不会改变版本号，因此从外面看，打过补丁的构建和有漏洞的构建一模一样。")}</div><span class="bx-badge is-red">no fix</span></li>
        <li><div><strong>${t("Mitigations are partial", "缓解措施并不完整")}</strong>${t("<code>memory_limit=-1</code>, low <code>post_max_size</code> and <code>session.upload_progress.enabled=0</code> close known paths only. The PHP project is explicit: updating is the only complete fix.", "<code>memory_limit=-1</code>、调低 <code>post_max_size</code>、<code>session.upload_progress.enabled=0</code> 只能封堵已知路径。PHP 官方说得很明确：升级是唯一完整的修复。")}</div><span class="bx-badge">partial</span></li>
        <li><div><strong>${t("Someone got in before you patched", "在你打补丁之前已经有人进来了")}</strong>${t("A patch closes the door; it doesn't evict a webshell in <code>uploads/</code>, a cron job or an SSH key. That's what <code>bastion trace</code> is for.", "补丁只是关上了门，赶不走 <code>uploads/</code> 里的 Webshell、计划任务或 SSH 公钥。这正是 <code>bastion trace</code> 要做的事。")}</div><span class="bx-badge is-red">trace</span></li>
      </ol>
    </div>
  </div>
</section>

<section class="chapter" id="decide">
  <div class="bx-wrap chapter-grid">
    <div class="chapter-label"><span class="num">03</span><h2>${t("How Bastion decides", "Bastion 如何判断")}</h2></div>
    <div class="prose" style="max-width:none">
      <div style="max-width:760px">
      <h2>${t("The version number lies — on purpose", "版本号会“说谎”——而且是故意的")}</h2>
      <p>${t("Upstream fixed PHP 8.3 in <strong>8.3.36</strong>. Ubuntu 24.04 ships PHP <strong>8.3.6</strong> and will keep calling it 8.3.6 for its whole life. Instead of jumping to a new upstream release, Ubuntu took the fix and applied it to its own 8.3.6 — a <strong>backport</strong>. The only visible change is the package revision.", "上游在 <strong>8.3.36</strong> 中修复了 PHP 8.3。Ubuntu 24.04 带的是 PHP <strong>8.3.6</strong>，而且在整个生命周期里都会一直叫 8.3.6。Ubuntu 并没有升级到新的上游版本，而是把修复补丁打到了自己的 8.3.6 上——这就是<strong>回溯补丁（backport）</strong>。唯一可见的变化是软件包修订号。")}</p>
      </div>
      <div class="compare">
        <div class="bx-card"><h4>${t("Vulnerable", "有漏洞")} · Ubuntu 24.04</h4><pre class="bx-code">$ php -v | head -1
PHP 8.3.6 (cli) (built: Oct  7 2026 18:06:38) (NTS)
$ dpkg-query -W php8.3-cli
php8.3-cli  8.3.6-0ubuntu0.24.04.<b style="color:var(--red)">12</b></pre></div>
        <div class="bx-card"><h4>${t("Fixed", "已修复")} · Ubuntu 24.04</h4><pre class="bx-code">$ php -v | head -1
PHP 8.3.6 (cli) (built: Oct 19 2026 15:16:58) (NTS)
$ dpkg-query -W php8.3-cli
php8.3-cli  8.3.6-0ubuntu0.24.04.<b style="color:var(--green)">13</b></pre></div>
      </div>
      <div style="max-width:760px">
      <p>${t("Both outputs were captured on real Ubuntu 24.04 systems while building Bastion. A version-only checker calls both vulnerable (8.3.6 &lt; 8.3.36) — or, worse, calls both safe. The fixed package's changelog says why:", "这两段输出都是在构建 Bastion 时从真实的 Ubuntu 24.04 系统上采集的。只看版本号的检查器会把两者都判为有漏洞（8.3.6 &lt; 8.3.36）——更糟的情况是把两者都判为安全。已修复软件包的变更日志说明了原因：")}</p>
      <pre class="bx-code">php8.3 (8.3.6-0ubuntu0.24.04.13) noble-security; urgency=medium

  * SECURITY UPDATE: Remote RCE via state corruption issue
    - debian/patches/CVE-2026-109618_109619.patch: Avoid state corruption via
      bailout in Zend/tests/bug40770.phpt, …</pre>
      <p>${t("So Bastion checks, in order: the upstream version, the vendor's published fixed version, the changelog, and finally the compiled code itself. Here is the engine — the same logic runs in the binary and, ported to JavaScript, in the <a href=\"" + ctx.href("check") + "\">online check</a>; both are tested against one shared set of vectors.", "因此 Bastion 依次检查：上游版本、发行版公布的修复版本、变更日志，最后是编译后的代码本身。下面就是判断引擎——同样的逻辑运行在二进制里，也被移植成 JavaScript 运行在<a href=\"" + ctx.href("check") + "\">在线自查</a>页面中；两者共用同一套测试向量。")}</p>
      </div>
      ${evaluate}
      <div style="max-width:760px">
      <h3>${t("Reading the version without running PHP", "不运行 PHP 也能读出版本号")}</h3>
      <p>${t("Bastion never executes the binaries it inspects (unless static reading fails and you allow it). That also makes it work on container filesystems, mounted backups and mod_php modules, which can't be run on their own.", "Bastion 不会执行它检查的二进制文件（除非静态读取失败且你允许执行）。这也让它能够检查容器文件系统、挂载的备份以及无法单独运行的 mod_php 模块。")}</p>
      </div>
      ${probe}
      <div style="max-width:760px">
      <h3>${t("Asking the package database", "查询软件包数据库")}</h3>
      </div>
      ${dpkg}
      <div style="max-width:760px">
      <h3>${t("Adding the next vulnerability", "加入下一个漏洞")}</h3>
      <p>${t("Nothing above is specific to PHP2Shell. Branch fixes, vendor tables, changelog markers and fingerprints all live in <a href=\"" + REPO + "/blob/main/internal/advisory/data/php2shell-2026.json\"><code>internal/advisory/data/php2shell-2026.json</code></a>. A new advisory is a new JSON file — or a directory passed with <code>--db</code> without rebuilding.", "上面的逻辑没有任何一处是专门为 PHP2Shell 写的。分支修复版本、发行版修复表、变更日志标记和指纹都放在 <a href=\"" + REPO + "/blob/main/internal/advisory/data/php2shell-2026.json\"><code>internal/advisory/data/php2shell-2026.json</code></a> 中。新漏洞就是一个新的 JSON 文件，甚至可以不重新编译，直接用 <code>--db</code> 传入一个目录。")}</p>
      </div>
    </div>
  </div>
</section>
`;
  return layout(ctx, {
    title: t("How it works", "原理"),
    description: t("What PHP2Shell is, why patching is not enough, and how Bastion detects distro backports instead of trusting version numbers.", "PHP2Shell 是什么、为什么打补丁还不够，以及 Bastion 如何识别发行版回溯补丁而不是盲信版本号。"),
    body,
  });
}

function diagram(ctx) {
  const { t } = ctx;
  const box = (x, y, w, label, sub, tone = "") => `<g transform="translate(${x} ${y})"><rect width="${w}" height="58" rx="8" fill="var(--bg-2)" stroke="${tone || "var(--line-3)"}"/><text x="14" y="25" font-size="13" fill="var(--text)">${esc(label)}</text><text x="14" y="43" font-size="11" fill="var(--text-3)">${esc(sub)}</text></g>`;
  return `<svg viewBox="0 0 760 230" role="img" aria-label="${t("Request lifecycle and where PHP2Shell breaks it", "请求生命周期以及 PHP2Shell 破坏它的位置")}">
  <defs><marker id="ar" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L8 4L0 8z" fill="var(--text-3)"/></marker></defs>
  ${box(0, 20, 170, t("1 · parse request", "1 · 解析请求"), t("multipart, headers", "multipart、请求头"))}
  ${box(220, 20, 150, t("2 · run script", "2 · 运行脚本"), "index.php")}
  ${box(420, 20, 150, t("3 · shutdown", "3 · 清理"), t("free request data", "释放请求数据"))}
  ${box(610, 20, 150, t("next request", "下一个请求"), t("same worker", "同一工作进程"))}
  <path d="M170 49H214M370 49H414M570 49H604" stroke="var(--text-3)" stroke-width="1.2" marker-end="url(#ar)"/>
  <path d="M85 78V128H480V84" fill="none" stroke="var(--red)" stroke-width="1.4" stroke-dasharray="4 4" marker-end="url(#ar)"/>
  <text x="96" y="122" font-size="11.5" fill="var(--red)">${t("OOM → longjmp skips step 2; cleanup trusts half-built data", "内存耗尽 → longjmp 跳过第 2 步；清理时信任了半成品数据")}</text>
  <text x="96" y="146" font-size="11" fill="var(--text-3)">CVE-2026-109618</text>
  <path d="M495 78V188H685V84" fill="none" stroke="var(--amber)" stroke-width="1.4" stroke-dasharray="4 4" marker-end="url(#ar)"/>
  <text x="506" y="182" font-size="11.5" fill="var(--amber)">${t("stale pointer survives into next request", "残留指针进入下一个请求")}</text>
  <text x="506" y="206" font-size="11" fill="var(--text-3)">CVE-2026-109619</text>
</svg>`;
}
