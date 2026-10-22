import { layout, REPO } from "../lib/layout.mjs";
import { renderAnnotated } from "../lib/snippets.mjs";
import { esc, icon } from "./common.mjs";

const src = (p) => new URL("../../" + p, import.meta.url);

function walk(spec) {
  const w = renderAnnotated({ ...spec, file: src(spec.repoPath) });
  const steps = w.parts
    .map((p, i) => {
      const code = p.code
        .split("\n")
        .map((l, k) => `<span class="ln">${p.line + k}</span>${w.highlight(l)}`)
        .join("\n");
      return `<div class="walk-step"><pre class="code">${code}</pre><div class="walk-note"><span class="step-n">step ${i + 1} of ${w.parts.length}</span><b>${p.title.en}</b>${p.note.en}</div></div>`;
    })
    .join("");
  return `<figure class="walk"><figcaption class="walk-head"><a href="${REPO}/blob/main/${w.file}#L${w.startLine}-L${w.endLine}">${icon("file-code")}${w.file} · lines ${w.startLine}–${w.endLine}</a><span>extracted from the source when the site is built</span></figcaption>${steps}</figure>`;
}

const S = (en) => ({ en });

export function render(ctx) {
  const evaluate = walk({
    repoPath: "internal/advisory/evaluate.go",
    signature: "func (a *Advisory) Evaluate(",
    omitDocComment: true,
    steps: [
      { anchor: "out := Assessment", title: S("Record evidence as you go"), note: S("Every rule appends an <code>Evidence</code> entry. A verdict is never a bare word: the report shows which observation decided it.") },
      { anchor: "v, err := version.ParsePHP(s.Version)", title: S("Parse the upstream version"), note: S("The version comes from the binary itself (see below). If it cannot be read, the package version is used instead.") },
      { anchor: "upstream := \"\"", title: S("Upstream release"), note: S("At or above the branch's fixed release (8.3.36, 8.4.27, …) is fixed. Below it is <em>not</em> conclusive for a distribution package, so that evidence is recorded as neutral and the search continues.") },
      { anchor: "if f := a.VendorFixFor(s.OS, s.Package)", title: S("Vendor fix table"), note: S("Exact fixed package versions from the Ubuntu, Debian and Red Hat trackers, compared with dpkg's or rpm's own ordering. Entries can be limited to one upstream branch, because RHEL ships several PHP module streams under the same package name.") },
      { anchor: "if err == nil && s.BuildDate != \"\"", title: S("Dated vendor rebuilds"), note: S("Plesk rebuilt PHP 7.4, 8.0 and 8.1 on 21 October 2026 without changing the version. For those builds the compile date read from the binary decides.") },
      { anchor: "if len(s.ChangelogHits) > 0", title: S("Package changelog"), note: S("Vendors list the CVEs they fix in the package changelog (<code>changelog.Debian.gz</code>, <code>rpm -q --changelog</code>). This covers distributions with no fix table in Bastion's data.") },
      { anchor: "for _, fp := range a.Fingerprints", title: S("Code only the fix contains"), note: S("The fix adds a hard memory limit with a new error message. If those bytes are in the binary, the patch is in the build, whatever the version says.") },
      { anchor: "if s.Package != nil {", title: S("Say what cannot be proven"), note: S("A package whose vendor database or changelog was readable and silent is <em>likely vulnerable</em>. If nothing could be read, the answer is <em>unknown</em>.") },
      { anchor: "switch upstream {", title: S("Builds outside a package manager"), note: S("Docker official images, BaoTa and source builds follow upstream versions, so the version decides. End-of-life branches with only a source backport cannot be told apart and are reported as likely vulnerable.") },
    ],
  });
  const probe = walk({
    repoPath: "internal/discover/probe.go",
    signature: "func StaticProbe(",
    steps: [
      { anchor: "func StaticProbe(", title: S("Never execute what you inspect"), note: S("Running an unknown binary as root to ask for its version is a bad habit for a security tool. Bastion opens the file and reads it.") },
      { anchor: "for _, m := range magics", title: S("Only real executables"), note: S("ELF and Mach-O headers are checked first, so wrapper scripts named <code>php</code> are skipped.") },
      { anchor: "all := append([]string{poweredBy}, needles...)", title: S("The version is compiled in"), note: S("Every SAPI (CLI, FPM, CGI, mod_php's <code>libphp.so</code>) contains the literal <code>X-Powered-By: PHP/</code> followed by <code>PHP_VERSION</code>. The same pass reads the build timestamp and looks for fix fingerprints.") },
      { anchor: "for {", title: S("Stream the file"), note: S("1 MiB chunks with an overlap: a string that spans two chunks is still found and memory use stays flat.") },
    ],
  });
  const dpkg = walk({
    repoPath: "internal/pkgdb/pkgdb.go",
    signature: "func (d *DB) dpkgLookup(",
    steps: [
      { anchor: "d.dpkgIndex()", title: S("Which package owns the file"), note: S("dpkg's database is parsed directly, without the <code>dpkg</code> binary, so the same code works on a container's root filesystem or an extracted image.") },
      { anchor: "info := Info{Package:", title: S("Source package and version"), note: S("Vendors publish fixes per <em>source</em> package (<code>php8.3</code>), not per binary package (<code>php8.3-cli</code>).") },
      { anchor: "for _, doc := range", title: S("Read the changelog"), note: S("An installed package's changelog stops at the installed version, so a CVE id in it means the fix is installed.") },
    ],
  });

  const body = `
<header class="phead">
  <div class="bx-wrap">
    <div class="crumbs">${icon("book-open")}Bastion <span>/</span> How it works</div>
    <h1>Why checking the version number gets PHP2Shell wrong</h1>
    <p>What the two bugs are, why installing the update is only part of the job, and how Bastion decides whether a build is fixed. Code excerpts are taken from the source when the site is built.</p>
  </div>
</header>

<section class="sect" id="vuln" style="border-top:0">
  <div class="bx-wrap sect-grid">
    <div class="sect-side"><h2>The vulnerability</h2><p>Two ways to make PHP trust memory it should not.</p></div>
    <div class="sect-main prose">
      <p>PHP handles each web request in a short life cycle: set up request data, run the script, clean up. Both bugs break assumptions between those steps.</p>
      <h3>${icon("database")}CVE-2026-109618 · out-of-memory corruption</h3>
      <p>When PHP runs out of its memory budget it does not return an error. It jumps out of whatever it was doing (a <code>longjmp</code> bailout). If that happens while request data is half built, for example while parsing an upload, clean-up later reads that data as if it were valid. An attacker can push request parsing into out-of-memory while staying inside PHP's apparent limits: multipart bodies without a usable length, unlimited headers per part, empty file fields that do not count towards <code>max_file_uploads</code>.</p>
      <h3>${icon("history")}CVE-2026-109619 · stale global state</h3>
      <p>PHP-FPM and mod_php reuse one worker process for many requests. A fatal error can leave global state pointing at memory that has already been freed, and the <strong>next request on the same worker</strong> can use it before normal initialisation resets it. Confirmed paths include INI diagnostics raised before request start-up and session upload progress.</p>
      <div class="panel diagram">${diagram()}</div>
      <p>Both are rated CVSS 4.0 9.2. The advisory demonstrated unauthenticated code execution against Apache mod_php with default limits; PHP-FPM, FrankenPHP and LiteSpeed are considered likely susceptible. Upstream removed <code>longjmp</code> from out-of-memory handling: PHP now stops at the next safe point (soft limit) or exits the worker (hard limit).</p>
    </div>
  </div>
</section>

<section class="sect" id="not-enough">
  <div class="bx-wrap sect-grid">
    <div class="sect-side"><h2>Why updating is not enough</h2><p>Six ways a server that “has the update” is still exposed, and what Bastion does about each.</p></div>
    <div class="sect-main">
      <ul class="risk-list">
        <li>${icon("rotate-ccw")}<div><b>The old code is still running</b><p><code>apt upgrade</code> replaces files on disk. php-fpm and Apache workers keep executing the old build until they restart. Bastion finds processes whose binary was replaced and reads the old image from <code>/proc/&lt;pid&gt;/exe</code>.</p></div></li>
        <li>${icon("boxes")}<div><b>There is more than one PHP</b><p>A system PHP, two panel versions and a Homebrew build on one host are common. Updating the one in <code>$PATH</code> can leave the one serving the site untouched. Bastion inventories all of them.</p></div></li>
        <li>${icon("layers")}<div><b>Containers and images are separate</b><p>Host updates do not reach containers, and running containers do not update when their image is rebuilt. Bastion reads running containers and, with <code>--image</code>, images that are not running.</p></div></li>
        <li>${icon("calendar-clock")}<div><b>End-of-life branches have no release</b><p>PHP 8.1 and older get no official release. Source backports and some vendor rebuilds keep the version string, so a patched build and a vulnerable one can look identical.</p></div></li>
        <li>${icon("sliders-horizontal")}<div><b>Mitigations are partial</b><p><code>memory_limit=-1</code>, a low <code>post_max_size</code> and <code>session.upload_progress.enabled=0</code> close known paths only. Bastion reports which are in place for every unfixed build.</p></div></li>
        <li>${icon("bug")}<div><b>Someone got in before the update</b><p>An update does not remove a webshell in <code>uploads/</code>, a cron job or an SSH key. That is what <code>bastion trace</code> is for.</p></div></li>
      </ul>
    </div>
  </div>
</section>

<section class="sect" id="decide">
  <div class="bx-wrap sect-grid">
    <div class="sect-side"><h2>How Bastion decides</h2><p>Distribution packages carry fixes without changing the upstream version. The decision ladder, as code.</p></div>
    <div class="sect-main">
      <div class="prose">
        <p>Upstream fixed PHP 8.3 in <strong>8.3.36</strong>. Ubuntu 24.04 ships PHP <strong>8.3.6</strong> and keeps that number for its whole life. Instead of moving to a new upstream release, Ubuntu applied the fix to its own 8.3.6: a <strong>backport</strong>. The only visible change is the package revision.</p>
      </div>
      <div class="compare">
        <div class="panel"><div class="panel-head"><span class="title">${icon("shield-x")}Vulnerable</span><span class="label">Ubuntu 24.04</span></div><div class="panel-body"><pre class="code">$ php -v | head -1
PHP 8.3.6 (cli) (built: Oct  7 2026 18:06:38) (NTS)
$ dpkg-query -W php8.3-cli
php8.3-cli  8.3.6-0ubuntu0.24.04.<span style="color:var(--red)">12</span></pre></div></div>
        <div class="panel"><div class="panel-head"><span class="title">${icon("shield-check")}Fixed</span><span class="label">Ubuntu 24.04</span></div><div class="panel-body"><pre class="code">$ php -v | head -1
PHP 8.3.6 (cli) (built: Oct 19 2026 15:16:58) (NTS)
$ dpkg-query -W php8.3-cli
php8.3-cli  8.3.6-0ubuntu0.24.04.<span style="color:var(--green)">13</span></pre></div></div>
      </div>
      <div class="prose">
        <p>Both outputs were captured on Ubuntu 24.04 systems while building Bastion. A version-only checker calls both vulnerable, or calls both safe. The fixed package's changelog records why:</p>
      </div>
      <pre class="code">php8.3 (8.3.6-0ubuntu0.24.04.13) noble-security; urgency=medium

  * SECURITY UPDATE: Remote RCE via state corruption issue
    - debian/patches/CVE-2026-109618_109619.patch: Avoid state corruption via
      bailout in Zend/tests/bug40770.phpt, …</pre>
      <h3>${icon("workflow")}The decision engine</h3>
      <p class="lede">The same logic runs in the binary and, ported to JavaScript, in the <a href="${ctx.href("check")}">online check</a>. Both implementations are tested against one shared set of vectors.</p>
      ${evaluate}
      <h3>${icon("file-search")}Reading the version without running PHP</h3>
      <p class="lede">This also makes container filesystems, extracted images, mounted backups and mod_php modules readable; none of them can be run on their own.</p>
      ${probe}
      <h3>${icon("database")}Asking the package database</h3>
      ${dpkg}
      <h3>${icon("file-json")}Adding the next vulnerability</h3>
      <p class="lede">None of this is specific to PHP2Shell. Fixed branches, vendor tables, vendor policies, build-date rules, changelog markers, fingerprints and the mitigation checks all live in <a href="${REPO}/blob/main/internal/advisory/data/php2shell-2026.json"><code>internal/advisory/data/php2shell-2026.json</code></a>. A new advisory is a new JSON file, or a directory passed with <code>--db</code> without rebuilding.</p>
    </div>
  </div>
</section>
`;
  return layout(ctx, {
    title: "How it works",
    description: "What PHP2Shell is, why updating is not enough, and how Bastion identifies distribution backports instead of trusting version numbers.",
    body,
  });
}

function diagram() {
  const box = (x, y, w, label, sub) => `<g transform="translate(${x} ${y})"><rect width="${w}" height="56" rx="4" fill="var(--bg-2)" stroke="var(--line-3)"/><text x="12" y="24" font-size="13" fill="var(--text)">${esc(label)}</text><text x="12" y="42" font-size="11" fill="var(--text-3)">${esc(sub)}</text></g>`;
  return `<svg viewBox="0 0 760 228" role="img" aria-label="Request lifecycle and where each bug breaks it">
  <defs><marker id="ar" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L8 4L0 8z" fill="var(--text-3)"/></marker></defs>
  ${box(0, 20, 170, "1 · parse request", "multipart, headers")}
  ${box(220, 20, 150, "2 · run script", "index.php")}
  ${box(420, 20, 150, "3 · shutdown", "free request data")}
  ${box(610, 20, 150, "next request", "same worker")}
  <path d="M170 48H214M370 48H414M570 48H604" stroke="var(--text-3)" stroke-width="1.2" marker-end="url(#ar)"/>
  <path d="M85 76V126H480V82" fill="none" stroke="var(--red)" stroke-width="1.4" stroke-dasharray="4 4" marker-end="url(#ar)"/>
  <text x="96" y="120" font-size="11.5" fill="var(--red)">OOM → longjmp skips step 2; shutdown trusts half-built data</text>
  <text x="96" y="144" font-size="11" fill="var(--text-3)">CVE-2026-109618</text>
  <path d="M495 76V186H685V82" fill="none" stroke="var(--amber)" stroke-width="1.4" stroke-dasharray="4 4" marker-end="url(#ar)"/>
  <text x="506" y="180" font-size="11.5" fill="var(--amber)">stale pointer survives</text>
  <text x="506" y="204" font-size="11" fill="var(--text-3)">CVE-2026-109619</text>
</svg>`;
}
