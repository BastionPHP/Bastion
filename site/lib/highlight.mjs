// Minimal, dependency-free syntax highlighters for the languages the site
// shows: Go (real source excerpts), shell and JSON. Output uses the .bx-code
// token classes from design/bastion.css.
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const GO_KW = new Set("break case chan const continue default defer else fallthrough for func go goto if import interface map package range return select struct switch type var".split(" "));
const GO_TYPES = new Set("bool byte error float32 float64 int int8 int16 int32 int64 rune string uint uint8 uint16 uint32 uint64 uintptr any".split(" "));
const GO_CONST = new Set("true false nil iota".split(" "));

function tokenize(src, rules) {
  let out = "";
  let i = 0;
  outer: while (i < src.length) {
    for (const [re, cls] of rules) {
      re.lastIndex = i;
      const m = re.exec(src);
      if (m && m.index === i && m[0].length > 0) {
        const t = typeof cls === "function" ? cls(m[0], src, i + m[0].length) : cls;
        out += t ? `<span class="${t}">${esc(m[0])}</span>` : esc(m[0]);
        i += m[0].length;
        continue outer;
      }
    }
    out += esc(src[i]);
    i++;
  }
  return out;
}

export function highlightGo(src) {
  return tokenize(src, [
    [/\/\/[^\n]*/y, "c"],
    [/\/\*[\s\S]*?\*\//y, "c"],
    [/`[^`]*`/y, "s"],
    [/"(?:\\.|[^"\\\n])*"/y, "s"],
    [/'(?:\\.|[^'\\\n])+'/y, "s"],
    [/\b\d+(?:\.\d+)?\b/y, "n"],
    [/[A-Za-z_][A-Za-z0-9_]*/y, (w, s, end) => {
      if (GO_KW.has(w)) return "k";
      if (GO_TYPES.has(w)) return "t";
      if (GO_CONST.has(w)) return "n";
      if (s[end] === "(") return "f";
      if (/^[A-Z]/.test(w) && s[end] === "{") return "t";
      return "";
    }],
  ]);
}

export function highlightShell(src) {
  return tokenize(src, [
    [/#[^\n]*/y, "c"],
    [/"(?:\\.|[^"\\])*"|'[^']*'/y, "s"],
    [/(?<=^|\n|\|\s?|&&\s?|\$\s)(sudo|curl|sh|bastion|go|cosign|sha256sum|tar|install|docker|apt|dnf|chmod|wget|grep|php|dpkg-query|rpm|apk|git|make|node|npm)\b/y, "f"],
    [/--?[A-Za-z][A-Za-z0-9-]*/y, "k"],
    [/\$[A-Za-z_][A-Za-z0-9_]*|\$\{[^}]*\}/y, "t"],
  ]);
}

export function highlightJSON(src) {
  return tokenize(src, [
    [/"(?:\\.|[^"\\])*"(?=\s*:)/y, "f"],
    [/"(?:\\.|[^"\\])*"/y, "s"],
    [/-?\b\d+(?:\.\d+)?\b/y, "n"],
    [/\b(true|false|null)\b/y, "k"],
  ]);
}

export { esc };
