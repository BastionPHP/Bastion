import { readFileSync, existsSync } from "node:fs";
import { ansiToHtml } from "../lib/ansi.mjs";
import { highlightShell, esc } from "../lib/highlight.mjs";
import { icon } from "../lib/icons.mjs";

const demoDir = new URL("../demo/", import.meta.url);

export function demo(name) {
  const p = new URL(name, demoDir);
  if (!existsSync(p)) return null;
  return readFileSync(p, "utf8");
}

export function recording() {
  const txt = demo("RECORDING.txt") || "";
  const get = (k) => (txt.match(new RegExp("^" + k + ": (.*)$", "m")) || [])[1] || "";
  return { at: get("recorded"), host: get("host"), containers: get("containers").trim(), version: get("bastion") };
}

// terminal renders a real recording from site/demo/*.ansi.
export function terminal(_ctx, { title, file, cmd }) {
  const raw = demo(file);
  const body = raw
    ? `<span class="fg-240">$</span> ${esc(cmd)}\n${ansiToHtml(raw)}`
    : `<span class="fg-245">Recording missing: run scripts/demo/record.sh.</span>`;
  return `<figure class="term" style="margin:0" aria-label="${esc(title)}"><figcaption class="term-bar">${icon("terminal")}<span class="grow">${esc(title)}</span><span>recorded output</span></figcaption><pre>${body}</pre></figure>`;
}

let n = 0;
export function codebox(src, lang = "shell") {
  const id = "cb" + ++n;
  const html = lang === "shell" ? highlightShell(src) : esc(src);
  return `<div class="codebox"><pre class="code" id="${id}">${html}</pre>${copyBtn(id)}</div>`;
}

export function copyBtn(id) {
  return `<button class="copy" type="button" data-copy="${id}" aria-label="Copy to clipboard">${icon("copy", "cp")}${icon("check", "ok")}</button>`;
}

// statusTag renders an engine status as an icon tag.
export function statusTag(status, text) {
  const ic = { fixed: "shield-check", vulnerable: "shield-x", "likely-vulnerable": "shield-alert", unknown: "shield-question" }[status];
  return `<span class="tag" data-status="${status}">${icon(ic)}${text || status.replace("-", " ")}</span>`;
}

export function sevTag(sev) {
  const base = sev.split("–")[0];
  const ic = { high: "triangle-alert", medium: "circle-dot", low: "circle-dashed", info: "info" }[base] || "circle-dot";
  return `<span class="st" data-sev="${base}">${icon(ic)}${esc(sev)}</span>`;
}

export const INSTALL = "curl -fsSL https://www.bastionphp.com/install.sh | sh";
export { esc, icon };
