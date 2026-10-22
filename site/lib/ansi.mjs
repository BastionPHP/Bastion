// Converts the ANSI output of `bastion … --color always` into HTML using the
// .fg-N / .bg-N / .ansi-N classes from design/bastion.css. Only the SGR codes
// Bastion emits (bold, dim, 38;5;N, 48;5;N, reset) are supported.
import { esc } from "./highlight.mjs";

export function ansiToHtml(text) {
  text = text.replace(/\r?\x1b\[2K/g, "").replace(/\r/g, "");
  let out = "";
  let open = 0;
  const re = /\x1b\[([0-9;]*)m/g;
  let last = 0;
  let m;
  while ((m = re.exec(text))) {
    out += esc(text.slice(last, m.index));
    last = re.lastIndex;
    const codes = m[1] === "" ? [0] : m[1].split(";").map(Number);
    if (codes[0] === 0 && codes.length === 1) {
      out += "</span>".repeat(open);
      open = 0;
      continue;
    }
    const cls = [];
    for (let i = 0; i < codes.length; i++) {
      const c = codes[i];
      if (c === 1 || c === 2) cls.push("ansi-" + c);
      else if ((c === 38 || c === 48) && codes[i + 1] === 5) {
        cls.push((c === 38 ? "fg-" : "bg-") + codes[i + 2]);
        i += 2;
      }
    }
    if (cls.length) {
      out += `<span class="${cls.join(" ")}">`;
      open++;
    }
  }
  out += esc(text.slice(last));
  out += "</span>".repeat(open);
  return out;
}
