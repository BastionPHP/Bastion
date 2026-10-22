// Page shell: <head>, navigation, footer. Every link is relative so the site
// works under any base path (GitHub Pages serves it from /<repo>/).
import { readFileSync } from "node:fs";

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
  const ctx = {
    page,
    root,
    href: (id, hash = "") => {
      const p = pages.find((x) => x.id === id);
      return root + p.dir + hash;
    },
    asset: (p) => root + "assets/" + p,
  };
  return ctx;
}

export function layout(ctx, { title, description, body, scripts = [] }) {
  const { page } = ctx;
  const nav = pages
    .map((p) => `<a href="${ctx.href(p.id)}"${p.id === page.id ? ' aria-current="page"' : ""}>${p.nav}</a>`)
    .join("");
  const fullTitle = page.id === "home" ? title : `${title} · Bastion`;
  const canonical = SITE + page.dir;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${fullTitle}</title>
<meta name="description" content="${description}">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#08090b">
<link rel="canonical" href="${canonical}">
<meta property="og:title" content="${fullTitle}">
<meta property="og:description" content="${description}">
<meta property="og:type" content="website">
<meta property="og:image" content="${SITE}assets/og.png">
<link rel="icon" href="${ctx.asset("favicon.svg")}" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap">
<link rel="stylesheet" href="${ctx.asset("bastion.css")}">
<link rel="stylesheet" href="${ctx.asset("site.css")}">
<script>try{var th=localStorage.getItem("bastion-theme");if(th)document.documentElement.setAttribute("data-theme",th);}catch(e){}</script>
</head>
<body class="page-${page.id}">
<a class="skip" href="#main">${"Skip to content"}</a>
<header class="nav">
  <div class="bx-wrap nav-in">
    <a class="bx-logo" href="${ctx.href("home")}" aria-label="Bastion">${logo}<span>Bastion</span></a>
    <nav class="nav-links" aria-label="${"Main"}">${nav}</nav>
    <div class="nav-right">
      <button class="nav-theme" type="button" data-theme-toggle aria-label="${"Toggle theme"}"><svg viewBox="0 0 16 16" width="15" height="15" aria-hidden="true"><circle cx="8" cy="8" r="6.2" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M8 1.8a6.2 6.2 0 0 1 0 12.4Z" fill="currentColor"/></svg></button>
      <a class="nav-gh" href="${REPO}" aria-label="GitHub"><svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg><span>GitHub</span></a>
    </div>
  </div>
  <nav class="nav-mobile bx-wrap" aria-label="${"Main"}">${nav}</nav>
</header>
<main id="main">
${body}
</main>
<footer class="foot">
  <div class="bx-wrap foot-in">
    <div class="foot-brand">
      <span class="bx-logo">${logo}<span>Bastion</span></span>
      <p class="bx-faint">${"Open-source, local, read-only PHP security. MIT licensed."}</p>
    </div>
    <div class="foot-cols">
      <div><h4>${"Product"}</h4><a href="${ctx.href("home", "#roadmap")}">${"Roadmap"}</a><a href="${ctx.href("how")}">${"How it works"}</a><a href="${ctx.href("check")}">${"Online check"}</a></div>
      <div><h4>${"Use"}</h4><a href="${ctx.href("docs", "#install")}">${"Install"}</a><a href="${ctx.href("docs", "#commands")}">${"Commands"}</a><a href="${ctx.href("docs", "#faq")}">FAQ</a></div>
      <div><h4>${"Project"}</h4><a href="${REPO}">GitHub</a><a href="${REPO}/releases">${"Releases"}</a><a href="${REPO}/blob/main/SECURITY.md">${"Security policy"}</a></div>
    </div>
  </div>
  <div class="bx-wrap foot-note bx-faint mono">${"Bastion only reads. It never changes, uploads or deletes anything on your server."}</div>
</footer>
<script src="${ctx.asset("site.js")}" defer></script>
${scripts.map((s) => `<script src="${ctx.asset(s)}" defer></script>`).join("\n")}
</body>
</html>
`;
}
