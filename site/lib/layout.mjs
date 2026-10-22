// Page shell: <head>, navigation, footer. Every link is relative so the site
// works under any base path (GitHub Pages serves it from /<repo>/).
import { readFileSync } from "node:fs";
import { icon } from "./icons.mjs";

const logo = readFileSync(new URL("../../design/logo.svg", import.meta.url), "utf8");
export const REPO = "https://github.com/larptard/bastion";
export const SITE = "https://larptard.github.io/bastion/";

export const pages = [
  { id: "home", dir: "", nav: "Overview" },
  { id: "how", dir: "how-it-works/", nav: "How it works" },
  { id: "check", dir: "check/", nav: "Online check" },
  { id: "docs", dir: "docs/", nav: "Docs" },
];

export function makeCtx(page) {
  const depth = page.dir.split("/").filter(Boolean).length;
  const root = depth === 0 ? "./" : "../".repeat(depth);
  return {
    page,
    root,
    href: (id, hash = "") => root + pages.find((x) => x.id === id).dir + hash,
    asset: (p) => root + "assets/" + p,
  };
}

const ghMark = `<svg class="i" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>`;

export function layout(ctx, { title, description, body, scripts = [] }) {
  const { page } = ctx;
  const nav = pages
    .map((p) => `<a href="${ctx.href(p.id)}"${p.id === page.id ? ' aria-current="page"' : ""}>${p.nav}</a>`)
    .join("");
  const fullTitle = page.id === "home" ? "Bastion" : `${title} · Bastion`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${fullTitle}</title>
<meta name="description" content="${description}">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#0c0f13">
<link rel="canonical" href="${SITE}${page.dir}">
<meta property="og:title" content="${fullTitle}">
<meta property="og:description" content="${description}">
<meta property="og:type" content="website">
<meta property="og:image" content="${SITE}assets/og.png">
<link rel="icon" href="${ctx.asset("favicon.svg")}" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans+Condensed:wght@500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap">
<link rel="stylesheet" href="${ctx.asset("bastion.css")}">
<link rel="stylesheet" href="${ctx.asset("site.css")}">
<script>try{var th=localStorage.getItem("bastion-theme");if(th)document.documentElement.setAttribute("data-theme",th);}catch(e){}</script>
</head>
<body class="page-${page.id}">
<a class="skip" href="#main">Skip to content</a>
<header class="hdr">
  <div class="bx-wrap hdr-in">
    <a class="logo" href="${ctx.href("home")}">${logo}<span>Bastion</span></a>
    <nav class="hdr-nav" aria-label="Main">${nav}</nav>
    <div class="hdr-tools">
      <button class="hdr-btn" type="button" data-theme-toggle aria-label="Switch between light and dark theme">${icon("sun", "only-dark")}${icon("moon", "only-light")}</button>
      <a class="hdr-btn hdr-gh" href="${REPO}">${ghMark}<span>Source</span></a>
    </div>
  </div>
  <nav class="hdr-nav-m bx-wrap" aria-label="Main">${nav}</nav>
</header>
<main id="main">
${body}
</main>
<footer class="ftr">
  <div class="bx-wrap ftr-in">
    <div class="ftr-brand">
      <a class="logo" href="${ctx.href("home")}">${logo}<span>Bastion</span></a>
      <p>Local, read-only PHP exposure and compromise assessment. MIT licensed.</p>
    </div>
    <dl class="ftr-cols">
      <div><dt>Product</dt><dd><a href="${ctx.href("how")}">How it works</a></dd><dd><a href="${ctx.href("check")}">Online check</a></dd><dd><a href="${ctx.root}demo/report.html">Sample report</a></dd></div>
      <div><dt>Use</dt><dd><a href="${ctx.href("docs", "#install")}">Install</a></dd><dd><a href="${ctx.href("docs", "#commands")}">Command reference</a></dd><dd><a href="${ctx.href("docs", "#faq")}">FAQ</a></dd></div>
      <div><dt>Project</dt><dd><a href="${REPO}">Source code</a></dd><dd><a href="${REPO}/releases">Releases</a></dd><dd><a href="${REPO}/blob/main/SECURITY.md">Security policy</a></dd></div>
    </dl>
  </div>
  <div class="bx-wrap ftr-note">${icon("eye-off")} Bastion reads files and process metadata only. It never modifies, uploads or deletes anything on the systems it inspects.</div>
</footer>
<script src="${ctx.asset("site.js")}" defer></script>
${scripts.map((s) => `<script src="${ctx.asset(s)}" defer></script>`).join("\n")}
</body>
</html>
`;
}
