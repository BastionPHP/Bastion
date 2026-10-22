// Inline SVG icons from design/icons.json (Lucide, ISC licence).
import { readFileSync } from "node:fs";

const icons = JSON.parse(readFileSync(new URL("../../design/icons.json", import.meta.url), "utf8"));

export function icon(name, cls = "") {
  const inner = icons[name];
  if (!inner) throw new Error(`unknown icon "${name}"`);
  return `<svg class="i i-${name}${cls ? " " + cls : ""}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${inner}</svg>`;
}
