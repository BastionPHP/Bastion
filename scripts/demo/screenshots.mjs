// Captures README / social images from the locally served site and the
// sample report: node scripts/demo/screenshots.mjs <site-url> <out-dir>
// Needs the `playwright` package (NODE_PATH or a global install).
import { createRequire } from "node:module";
import { mkdirSync, copyFileSync } from "node:fs";
const require = createRequire(process.env.NODE_PATH ? process.env.NODE_PATH + "/" : import.meta.url);
const { chromium } = require("playwright");

const [, , base = "http://localhost:4321/bastion/", out = "docs/assets"] = process.argv;
mkdirSync(out, { recursive: true });
const browser = await chromium.launch();
async function page(w, h, scheme = "dark") {
  const p = await browser.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: 2, colorScheme: scheme });
  p.on("pageerror", (e) => { console.error("page error:", e.message); process.exitCode = 1; });
  return p;
}
async function el(url, sel, file, w = 1280) {
  const p = await page(w, 900);
  await p.goto(url, { waitUntil: "networkidle" });
  await p.addStyleTag({ content: ".bx-term pre{max-height:none!important}" });
  await (await p.$(sel)).screenshot({ path: `${out}/${file}` });
  await p.close();
  console.log("wrote", file);
}

await el(base, ".term-stack .bx-term", "scan.png", 1180);
await el(base, "[data-panel='t-trace'] .bx-term", "trace.png", 1180);

let p = await page(1440, 900);
await p.goto(base, { waitUntil: "networkidle" });
await p.screenshot({ path: `${out}/site.png` });
await p.close();

p = await page(1440, 1000);
await p.goto(base + "demo/report.html", { waitUntil: "networkidle" });
await p.screenshot({ path: `${out}/report.png` });
await p.close();

p = await page(1280, 900);
await p.goto(base + "check/", { waitUntil: "networkidle" });
await p.click('[data-example="noble-old"]');
await p.waitForTimeout(300);
await (await p.$(".check-grid")).screenshot({ path: `${out}/check.png` });
await p.close();

p = await page(390, 844);
await p.goto(base, { waitUntil: "networkidle" });
await p.screenshot({ path: `${out}/mobile.png` });
await p.close();

// Social card (1200x630, 1x).
const og = await browser.newPage({ viewport: { width: 1200, height: 630 }, colorScheme: "dark" });
await og.goto(base, { waitUntil: "networkidle" });
await og.addStyleTag({ content: ".hero{padding-top:40px}.hero-cta,.nav,.term-stack{display:none!important}" });
await og.screenshot({ path: `${out}/og.png` });
await browser.close();
copyFileSync(`${out}/og.png`, new URL("../../site/assets/og.png", import.meta.url).pathname);
console.log("done");
