// Pulls real code out of the Go sources so the "how it works" page always
// shows what the binary actually does. The build fails when a function or
// an annotation anchor can no longer be found.
import { readFileSync } from "node:fs";
import { highlightGo, esc } from "./highlight.mjs";

export function extractFunc(file, signature) {
  const src = readFileSync(file, "utf8");
  const lines = src.split("\n");
  const start = lines.findIndex((l) => l.startsWith(signature));
  if (start < 0) throw new Error(`snippet: "${signature}" not found in ${file}`);
  // Include the doc comment directly above.
  let from = start;
  while (from > 0 && lines[from - 1].startsWith("//")) from--;
  let end = start;
  while (end < lines.length && lines[end] !== "}") end++;
  return { code: lines.slice(from, end + 1).join("\n"), startLine: from + 1 };
}

// renderAnnotated returns highlighted code split into steps. Each step names
// an anchor (a substring of the first line of the step) and bilingual notes.
export function renderAnnotated({ file, signature, steps, omitDocComment = false, repoPath }) {
  let { code, startLine } = extractFunc(file, signature);
  let lines = code.split("\n");
  if (omitDocComment) {
    const first = lines.findIndex((l) => !l.startsWith("//"));
    startLine += first;
    lines = lines.slice(first);
  }
  // Each anchor is searched after the previous one, so repeated lines work.
  const idx = [];
  let from0 = 0;
  for (const s of steps) {
    const i = lines.findIndex((l, n) => n >= from0 && l.includes(s.anchor));
    if (i < 0) throw new Error(`snippet ${signature}: anchor "${s.anchor}" not found after line ${from0}`);
    idx.push(i);
    from0 = i + 1;
  }
  const parts = steps.map((s, k) => {
    const from = k === 0 ? 0 : idx[k];
    const to = k + 1 < idx.length ? idx[k + 1] : lines.length;
    return { ...s, code: lines.slice(from, to).join("\n"), line: startLine + from };
  });
  return { parts, file: repoPath, startLine, endLine: startLine + lines.length - 1, highlight: highlightGo, esc };
}
