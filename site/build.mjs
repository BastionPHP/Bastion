// Builds the static website into site/dist. No dependencies beyond Node 20+.
//   node build.mjs            build
//   node build.mjs --serve    build and serve on http://localhost:4321
import { mkdirSync, rmSync, writeFileSync, readFileSync, readdirSync, copyFileSync, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { join, extname } from "node:path";
import { pages, makeCtx, layout } from "./lib/layout.mjs";
import * as home from "./pages/home.mjs";
import * as how from "./pages/how.mjs";
import * as check from "./pages/check.mjs";
import * as docs from "./pages/docs.mjs";

const here = new URL(".", import.meta.url).pathname;
const repo = join(here, "..");
const dist = join(here, "dist");

const advDir = join(repo, "internal/advisory/data");
const advisories = readdirSync(advDir).filter((f) => f.endsWith(".json")).map((f) => JSON.parse(readFileSync(join(advDir, f), "utf8")));
const advisory = advisories.find((a) => a.id === "PHP2SHELL-2026");
if (!advisory) throw new Error("PHP2Shell advisory data missing");

const renderers = { home, how, check, docs };

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

let count = 0;
for (const page of pages) {
  const ctx = makeCtx(page);
  const html = renderers[page.id].render(ctx, { advisory, advisories });
  const dir = join(dist, page.dir);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "index.html"), html);
  count++;
}

// 404 page (GitHub Pages serves /404.html for every missing path).
{
  const ctx = makeCtx({ id: "404", dir: "", nav: "" });
  ctx.href = (id, hash = "") => "/bastion/" + (pages.find((p) => p.id === id)?.dir || "") + hash;
  ctx.asset = (p) => "/bastion/assets/" + p;
  writeFileSync(join(dist, "404.html"), layout(ctx, { title: "Not found", description: "Page not found", body: `<header class="phead"><div class="bx-wrap phead-in"><div class="bx-eyebrow">404</div><h1>Not found</h1><p><a href="/bastion/">← Bastion</a></p></div></header>` }));
}

// Assets: shared design system, site assets, advisory data, demo output.
mkdirSync(join(dist, "assets"), { recursive: true });
copyFileSync(join(repo, "design/bastion.css"), join(dist, "assets/bastion.css"));
for (const f of readdirSync(join(here, "assets"))) copyFileSync(join(here, "assets", f), join(dist, "assets", f));
writeFileSync(join(dist, "assets/advisories.json"), JSON.stringify(advisories));
mkdirSync(join(dist, "demo"), { recursive: true });
if (existsSync(join(here, "demo/report.html"))) copyFileSync(join(here, "demo/report.html"), join(dist, "demo/report.html"));
copyFileSync(join(repo, "scripts/install.sh"), join(dist, "install.sh"));
writeFileSync(join(dist, ".nojekyll"), "");
writeFileSync(join(dist, "robots.txt"), "User-agent: *\nAllow: /\nDisallow: /demo/\n");

// Sanity checks: every relative link and asset in the output must exist.
const missing = [];
function walk(dir) {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) walk(p);
    else if (f.endsWith(".html") && f !== "404.html" && !p.includes("/demo/")) {
      const html = readFileSync(p, "utf8");
      for (const m of html.matchAll(/(?:href|src)="([^"#]+)(?:#[^"]*)?"/g)) {
        const u = m[1];
        if (/^(https?:|mailto:|data:)/.test(u)) continue;
        let target = join(dir, u);
        if (u.endsWith("/")) target = join(target, "index.html");
        if (!existsSync(target)) missing.push(`${p.replace(dist, "")} → ${u}`);
      }
    }
  }
}
walk(dist);
if (missing.length) {
  console.error("broken links:\n  " + missing.join("\n  "));
  process.exit(1);
}
console.log(`built ${count} pages into ${dist}`);

if (process.argv.includes("--serve")) {
  const types = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml", ".json": "application/json", ".png": "image/png", ".sh": "text/plain" };
  createServer((req, res) => {
    let p = decodeURIComponent(new URL(req.url, "http://x").pathname).replace(/^\/bastion/, "");
    let f = join(dist, p);
    if (existsSync(f) && statSync(f).isDirectory()) f = join(f, "index.html");
    if (!existsSync(f)) { res.writeHead(404); res.end(readFileSync(join(dist, "404.html"))); return; }
    res.writeHead(200, { "content-type": types[extname(f)] || "application/octet-stream" });
    res.end(readFileSync(f));
  }).listen(4321, () => console.log("http://localhost:4321/bastion/"));
}
