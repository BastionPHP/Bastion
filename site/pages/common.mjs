import { readFileSync, existsSync } from "node:fs";
import { ansiToHtml } from "../lib/ansi.mjs";
import { highlightShell, esc } from "../lib/highlight.mjs";

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

export function terminal(ctx, { title, file, cmd }) {
  const raw = demo(file);
  const body = raw
    ? `<span class="fg-240">$</span> ${esc(cmd)}\n${ansiToHtml(raw)}`
    : `<span class="fg-245">${ctx.t("Recording pending — run scripts/demo/record.sh to generate it.", "录制待补充：运行 scripts/demo/record.sh 生成。")}</span>`;
  return `<div class="bx-term" role="img" aria-label="${esc(title)}"><div class="bx-term-bar"><span class="bx-term-dots"><i></i><i></i><i></i></span><span class="bx-term-title">${esc(title)}</span></div><pre>${body}</pre></div>`;
}

let n = 0;
export function codebox(src, lang = "shell") {
  const id = "cb" + ++n;
  const html = lang === "shell" ? highlightShell(src) : esc(src);
  return `<div class="codebox"><pre class="bx-code" id="${id}">${html}</pre>${copyBtn(id)}</div>`;
}

export function copyBtn(id) {
  return `<button class="copy" type="button" data-copy="${id}" aria-label="Copy"><svg class="cp" width="15" height="15" viewBox="0 0 16 16" aria-hidden="true"><rect x="5" y="5" width="9" height="9" rx="2" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M11 5V3.5A1.5 1.5 0 0 0 9.5 2h-6A1.5 1.5 0 0 0 2 3.5v6A1.5 1.5 0 0 0 3.5 11H5" fill="none" stroke="currentColor" stroke-width="1.4"/></svg><svg class="ok" width="15" height="15" viewBox="0 0 16 16" aria-hidden="true"><path d="M3 8.5l3 3 7-7" fill="none" stroke="currentColor" stroke-width="1.6"/></svg></button>`;
}

export const INSTALL = "curl -fsSL https://larptard.github.io/bastion/install.sh | sh";
export { esc };
