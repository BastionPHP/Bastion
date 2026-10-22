// Render a compact README image from the recorded scan; no invented output.
// Requires playwright. NODE_PATH may point to its installed module directory.
// Optionally set BASTION_CHROME to a local Chromium/Chrome executable.
// Run: node scripts/demo/readme-preview.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ansiToHtml } from "../../site/lib/ansi.mjs";

const require = createRequire(process.env.NODE_PATH ? process.env.NODE_PATH + "/" : import.meta.url);
const { chromium } = require("playwright");
const lines = readFileSync(new URL("../../site/demo/scan.ansi", import.meta.url), "utf8").split(/\r?\n/);
const details = lines.findIndex((line) => line.includes("DETAILS"));
const summary = lines.findIndex((line) => line.includes("SUMMARY"));
if (details < 0 || summary < 0) throw new Error("Recording is missing the expected sections");
const excerpt = lines.slice(0, details).join("\n").trimEnd();
const result = lines.slice(summary).join("\n").trimEnd();
const css = readFileSync(new URL("../../design/bastion.css", import.meta.url), "utf8");
const browser = await chromium.launch({
  ...(process.env.BASTION_CHROME ? { executablePath: process.env.BASTION_CHROME } : {}),
});
try {
  const page = await browser.newPage({ viewport: { width: 1160, height: 760 }, deviceScaleFactor: 2, colorScheme: "dark" });
  await page.setContent(`<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><style>${css}
    body{margin:0;background:#0c0f13;padding:0}
    figure{margin:0;padding:0;border:1px solid #303944;border-radius:10px;overflow:hidden;background:#0c0f13}
    header{padding:20px 28px;border-bottom:1px solid #27313b;display:flex;justify-content:space-between;font:14px Consolas,monospace;color:#b7c6d6}
    header span{color:#8b9aab}
    pre{padding:20px 22px;margin:0;font:14px/1.7 Consolas,"Liberation Mono",monospace;white-space:pre;color:#dfe4ea}
    .summary{background:#111820;border-top:1px solid #27313b;padding-top:18px;padding-bottom:18px}
    footer{padding:14px 28px;color:#a5afbb;font:12px/1.5 system-ui;border-top:1px solid #27313b}
  </style></head><body><figure>
    <header><b>$ sudo bastion scan</b><span>Recorded output · inventory and summary excerpt</span></header>
    <pre>${ansiToHtml(excerpt)}</pre>
    <pre class="summary">${ansiToHtml(result)}</pre>
    <footer>Full per-build evidence is available in the linked recording. Details omitted here for readability.</footer>
  </figure></body></html>`);
  await page.locator("figure").screenshot({ path: fileURLToPath(new URL("../../docs/assets/readme-scan.png", import.meta.url)) });
  console.log("Rendered docs/assets/readme-scan.png from site/demo/scan.ansi");
} finally {
  await browser.close();
}
