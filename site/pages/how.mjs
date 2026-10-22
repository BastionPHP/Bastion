import { layout, REPO } from "../lib/layout.mjs";
import { renderAnnotated } from "../lib/snippets.mjs";
import { esc } from "./common.mjs";

const src = (p) => new URL("../../" + p, import.meta.url);

function walk(ctx, spec) {
  const w = renderAnnotated({ ...spec, file: src(spec.repoPath) });
  const steps = w.parts
    .map((p, i) => {
      const code = p.code
        .split("\n")
        .map((l, k) => `<span class="ln">${p.line + k}</span>${w.highlight(l)}`)
        .join("\n");
      return `<div class="walk-step"><pre class="bx-code">${code}</pre><div class="walk-note"><span class="step-n">${String(i + 1).padStart(2, "0")}</span><b>${p.title.en}</b>${p.note.en}</div></div>`;
    })
    .join("");
  return `<figure class="walk"><figcaption class="walk-head"><a href="${REPO}/blob/main/${w.file}#L${w.startLine}-L${w.endLine}">${w.file}#L${w.startLine}–${w.endLine}</a><span>excerpt taken from the source at build time</span></figcaption>${steps}</figure>`;
}

const S = (en) => ({ en });

export function render(ctx) {
  const evaluate = walk(ctx, {
    repoPath: "internal/advisory/evaluate.go",
    signature: "func (a *Advisory) Evaluate(",
    omitDocComment: true,
    steps: [
      { anchor: "out := Assessment", title: S("Collect evidence as you go"), note: S("Every rule appends an <code>Evidence</code> entry. The verdict is never a bare word: the report and terminal show exactly which observation decided it.") },
      { anchor: "v, err := version.ParsePHP(s.Version)", title: S("Parse the upstream version"), note: S("The version comes from the binary itself (see below). If it is missing, the package version is used instead.") },
      { anchor: "upstream := \"\"", title: S("Rule 1 — upstream release"), note: S("At or above the branch's fixed release (8.3.36, 8.4.27…) means fixed, done. Below it is <em>not</em> conclusive for distribution packages, so the evidence is recorded as neutral and the search goes on.") },
      { anchor: "if f := a.VendorFixFor(s.OS, s.Package)", title: S("Rule 2 — vendor fix table"), note: S("For Ubuntu and Debian, Bastion carries the exact fixed package versions from the vendors' trackers and compares them with dpkg's algorithm. This is the strongest signal a backport exists.") },
      { anchor: "if len(s.ChangelogHits) > 0", title: S("Rule 3 — the package changelog"), note: S("Vendors name the CVEs they fix in the package changelog (<code>changelog.Debian.gz</code>, <code>rpm -q --changelog</code>). This covers distributions Bastion has no table for.") },
      { anchor: "for _, fp := range a.Fingerprints", title: S("Rule 4 — code only the fix contains"), note: S("The fix adds a hard memory limit with a new error message. If those bytes are in the binary, the patch is in the build — whatever the version says.") },
      { anchor: "if s.Package != nil {", title: S("Rule 5 — say what you can't prove"), note: S("A package whose changelog is readable but silent is <em>likely vulnerable</em>. If nothing could be read, the answer is <em>unknown</em> — never a guess dressed up as a verdict.") },
      { anchor: "switch upstream {", title: S("Builds outside a package manager"), note: S("Docker official images, BaoTa and source builds follow upstream versions, so the version alone decides. End-of-life branches with only a source backport cannot be told apart and are reported as likely vulnerable.") },
    ],
  });
  const probe = walk(ctx, {
    repoPath: "internal/discover/probe.go",
    signature: "func StaticProbe(",
    steps: [
      { anchor: "func StaticProbe(", title: S("Never execute what you inspect"), note: S("Running an unknown binary as root to ask its version is a bad habit for a security tool. Bastion opens the file and reads it.") },
      { anchor: "for _, m := range magics", title: S("Only real executables"), note: S("ELF and Mach-O headers are checked first, so wrapper scripts called <code>php</code> are skipped.") },
      { anchor: "all := append([]string{poweredBy}, needles...)", title: S("The version is compiled in"), note: S("Every PHP SAPI — CLI, FPM, CGI, mod_php's <code>libphp.so</code> — contains the literal <code>X-Powered-By: PHP/</code> + <code>PHP_VERSION</code>. The same pass looks for the fix fingerprint.") },
      { anchor: "for {", title: S("Stream, don't load"), note: S("The file is read in 1 MiB chunks with an overlap, so a needle spanning two chunks is still found and memory stays flat.") },
    ],
  });
  const dpkg = walk(ctx, {
    repoPath: "internal/pkgdb/pkgdb.go",
    signature: "func (d *DB) dpkgLookup(",
    steps: [
      { anchor: "d.dpkgIndex()", title: S("Who owns this file?"), note: S("dpkg's own database is parsed directly — no <code>dpkg</code> binary needed — so the same code works on a container's root filesystem.") },
      { anchor: "info := Info{Package:", title: S("Source package and version"), note: S("Vendors publish fixes per <em>source</em> package (<code>php8.3</code>), not per binary package (<code>php8.3-cli</code>).") },
      { anchor: "for _, doc := range", title: S("Read the changelog"), note: S("The installed package's changelog only contains entries up to the installed version, so a CVE id in it means the fix is installed.") },
    ],
  });

  const body = `
<header class="phead">
  <div class="bx-grid-bg" aria-hidden="true"></div>
  <div class="bx-wrap phead-in">
    <div class="bx-eyebrow">How it works</div>
    <h1>Why “just check the version” gets PHP2Shell wrong</h1>
    <p>What the vulnerability is, why installing the patch is only half the job, and exactly how Bastion decides — with the real code.</p>
  </div>
</header>

<section class="chapter" id="vuln">
  <div class="bx-wrap chapter-grid">
    <div class="chapter-label"><span class="num">01</span><h2>The vulnerability</h2></div>
    <div class="prose">
      <h2>Two ways to make PHP trust memory it shouldn't</h2>
      <p>PHP handles each web request in a short life cycle: set up request data, run your script, clean up. PHP2Shell breaks the assumptions between those steps.</p>
      <h3>CVE-2026-109618 · out-of-memory corruption</h3>
      <p>When PHP runs out of its memory budget it doesn't return an error; it <strong>jumps out</strong> of whatever it was doing (a <code>longjmp</code> “bailout”). If that happens while request data is half built — for example while parsing an upload — the clean-up step later reads that half-built data as if it were valid. An attacker can push request parsing into out-of-memory while staying inside the apparent PHP limits: multipart bodies without a usable length, unlimited headers per part, empty file fields that don't count towards <code>max_file_uploads</code>.</p>
      <h3>CVE-2026-109619 · stale global state</h3>
      <p>PHP-FPM and mod_php reuse one worker process for many requests. A fatal error can leave global state pointing at memory that has already been freed; the <strong>next request on the same worker</strong> can touch it before normal initialisation resets it — a use-after-free. Confirmed paths include INI diagnostics raised before request start-up and session upload progress.</p>
      <div class="bx-card diagram">${diagram(ctx)}</div>
      <p>Both are rated CVSS v4.0 9.2. The official advisory demonstrated unauthenticated code execution against Apache mod_php with default limits; PHP-FPM, FrankenPHP and LiteSpeed are considered likely susceptible. The fix removes <code>longjmp</code> from out-of-memory handling: PHP now stops at the next safe point (soft limit) or exits the worker (hard limit).</p>
    </div>
  </div>
</section>

<section class="chapter" id="not-enough">
  <div class="bx-wrap chapter-grid">
    <div class="chapter-label"><span class="num">02</span><h2>Why patching isn't enough</h2></div>
    <div class="prose">
      <h2>Six ways a “patched” server is still exposed</h2>
      <ol class="ladder">
        <li><div><strong>The old code is still running</strong><code>apt upgrade</code> replaces files on disk. php-fpm and Apache workers keep executing the old build until they are restarted. Bastion finds processes whose binary was replaced and reads the old image from <code>/proc/&lt;pid&gt;/exe</code>.</div><span class="bx-badge is-amber">restart</span></li>
        <li><div><strong>There is more than one PHP</strong>A system PHP, two panel-managed versions and a Homebrew build on the same box are common. Patching the one in <code>$PATH</code> leaves the one serving the site untouched.</div><span class="bx-badge">inventory</span></li>
        <li><div><strong>Containers were built yesterday</strong>Host updates don't reach containers. Each image must be rebuilt on a patched base and redeployed. Bastion reads running containers' filesystems directly.</div><span class="bx-badge">rebuild</span></li>
        <li><div><strong>End-of-life branches have no release</strong>PHP ≤ 8.1 gets no official release. The source backports for 7.4/8.0/8.1 don't change the version string, so a patched build and a vulnerable one look identical from outside.</div><span class="bx-badge is-red">no fix</span></li>
        <li><div><strong>Mitigations are partial</strong><code>memory_limit=-1</code>, low <code>post_max_size</code> and <code>session.upload_progress.enabled=0</code> close known paths only. The PHP project is explicit: updating is the only complete fix.</div><span class="bx-badge">partial</span></li>
        <li><div><strong>Someone got in before you patched</strong>A patch closes the door; it doesn't evict a webshell in <code>uploads/</code>, a cron job or an SSH key. That's what <code>bastion trace</code> is for.</div><span class="bx-badge is-red">trace</span></li>
      </ol>
    </div>
  </div>
</section>

<section class="chapter" id="decide">
  <div class="bx-wrap chapter-grid">
    <div class="chapter-label"><span class="num">03</span><h2>How Bastion decides</h2></div>
    <div class="prose" style="max-width:none">
      <div style="max-width:760px">
      <h2>The version number lies — on purpose</h2>
      <p>Upstream fixed PHP 8.3 in <strong>8.3.36</strong>. Ubuntu 24.04 ships PHP <strong>8.3.6</strong> and will keep calling it 8.3.6 for its whole life. Instead of jumping to a new upstream release, Ubuntu took the fix and applied it to its own 8.3.6 — a <strong>backport</strong>. The only visible change is the package revision.</p>
      </div>
      <div class="compare">
        <div class="bx-card"><h4>Vulnerable · Ubuntu 24.04</h4><pre class="bx-code">$ php -v | head -1
PHP 8.3.6 (cli) (built: Oct  7 2026 18:06:38) (NTS)
$ dpkg-query -W php8.3-cli
php8.3-cli  8.3.6-0ubuntu0.24.04.<b style="color:var(--red)">12</b></pre></div>
        <div class="bx-card"><h4>Fixed · Ubuntu 24.04</h4><pre class="bx-code">$ php -v | head -1
PHP 8.3.6 (cli) (built: Oct 19 2026 15:16:58) (NTS)
$ dpkg-query -W php8.3-cli
php8.3-cli  8.3.6-0ubuntu0.24.04.<b style="color:var(--green)">13</b></pre></div>
      </div>
      <div style="max-width:760px">
      <p>Both outputs were captured on real Ubuntu 24.04 systems while building Bastion. A version-only checker calls both vulnerable (8.3.6 &lt; 8.3.36) — or, worse, calls both safe. The fixed package's changelog says why:</p>
      <pre class="bx-code">php8.3 (8.3.6-0ubuntu0.24.04.13) noble-security; urgency=medium

  * SECURITY UPDATE: Remote RCE via state corruption issue
    - debian/patches/CVE-2026-109618_109619.patch: Avoid state corruption via
      bailout in Zend/tests/bug40770.phpt, …</pre>
      <p>${"So Bastion checks, in order: the upstream version, the vendor's published fixed version, the changelog, and finally the compiled code itself. Here is the engine — the same logic runs in the binary and, ported to JavaScript, in the <a href=\"" + ctx.href("check") + "\">online check</a>; both are tested against one shared set of vectors."}</p>
      </div>
      ${evaluate}
      <div style="max-width:760px">
      <h3>Reading the version without running PHP</h3>
      <p>Bastion never executes the binaries it inspects (unless static reading fails and you allow it). That also makes it work on container filesystems, mounted backups and mod_php modules, which can't be run on their own.</p>
      </div>
      ${probe}
      <div style="max-width:760px">
      <h3>Asking the package database</h3>
      </div>
      ${dpkg}
      <div style="max-width:760px">
      <h3>Adding the next vulnerability</h3>
      <p>${"Nothing above is specific to PHP2Shell. Branch fixes, vendor tables, changelog markers and fingerprints all live in <a href=\"" + REPO + "/blob/main/internal/advisory/data/php2shell-2026.json\"><code>internal/advisory/data/php2shell-2026.json</code></a>. A new advisory is a new JSON file — or a directory passed with <code>--db</code> without rebuilding."}</p>
      </div>
    </div>
  </div>
</section>
`;
  return layout(ctx, {
    title: "How it works",
    description: "What PHP2Shell is, why patching is not enough, and how Bastion detects distro backports instead of trusting version numbers.",
    body,
  });
}

function diagram(ctx) {
  const box = (x, y, w, label, sub, tone = "") => `<g transform="translate(${x} ${y})"><rect width="${w}" height="58" rx="8" fill="var(--bg-2)" stroke="${tone || "var(--line-3)"}"/><text x="14" y="25" font-size="13" fill="var(--text)">${esc(label)}</text><text x="14" y="43" font-size="11" fill="var(--text-3)">${esc(sub)}</text></g>`;
  return `<svg viewBox="0 0 760 230" role="img" aria-label="Request lifecycle and where PHP2Shell breaks it">
  <defs><marker id="ar" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L8 4L0 8z" fill="var(--text-3)"/></marker></defs>
  ${box(0, 20, 170, "1 · parse request", "multipart, headers")}
  ${box(220, 20, 150, "2 · run script", "index.php")}
  ${box(420, 20, 150, "3 · shutdown", "free request data")}
  ${box(610, 20, 150, "next request", "same worker")}
  <path d="M170 49H214M370 49H414M570 49H604" stroke="var(--text-3)" stroke-width="1.2" marker-end="url(#ar)"/>
  <path d="M85 78V128H480V84" fill="none" stroke="var(--red)" stroke-width="1.4" stroke-dasharray="4 4" marker-end="url(#ar)"/>
  <text x="96" y="122" font-size="11.5" fill="var(--red)">OOM → longjmp skips step 2; cleanup trusts half-built data</text>
  <text x="96" y="146" font-size="11" fill="var(--text-3)">CVE-2026-109618</text>
  <path d="M495 78V188H685V84" fill="none" stroke="var(--amber)" stroke-width="1.4" stroke-dasharray="4 4" marker-end="url(#ar)"/>
  <text x="506" y="182" font-size="11.5" fill="var(--amber)">stale pointer survives into next request</text>
  <text x="506" y="206" font-size="11" fill="var(--text-3)">CVE-2026-109619</text>
</svg>`;
}
