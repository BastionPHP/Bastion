import { icon } from "./icons.mjs";

// A schematic of the existing evaluator, not a live scan or fabricated result.
export function evidenceMap() {
  const steps = [
    ["git-branch", "Upstream release", "Compare the binary’s version with the fixed release in its PHP branch."],
    ["package-check", "Vendor backport", "Check the full package revision. A vendor can patch PHP without changing its upstream version."],
    ["scroll-text", "Package changelog", "Look for the advisory identifiers in the installed package’s changelog."],
    ["fingerprint", "Fix fingerprint", "Look for bytes introduced by the patch, or evidence of a vendor’s dated rebuild."],
  ];
  return `<aside class="evidence-map" aria-labelledby="evidence-map-title">
    <div class="evidence-map-head"><span id="evidence-map-title">Inside the assessment</span>${icon("scan-search")}</div>
    <div class="evidence-source">${icon("file-search")}<span>PHP binary<small>read without executing</small></span></div>
    <div class="evidence-branches" aria-hidden="true"><span>version</span><span>package</span><span>build</span></div>
    <ol class="evidence-steps">${steps.map(([glyph, title, detail], i) => `<li><button type="button" class="evidence-step" aria-pressed="${i === 1}" aria-controls="evidence-detail" data-evidence-detail="${detail}" data-evidence-title="${title}"><span class="evidence-index" aria-hidden="true">0${i + 1}</span>${icon(glyph)}<span>${title}</span><span class="evidence-node" aria-hidden="true"></span></button></li>`).join("")}</ol>
    <div class="evidence-detail" id="evidence-detail" aria-live="polite"><span class="evidence-detail-title">Vendor backport</span><p>${steps[1][2]}</p></div>
    <a class="evidence-more" href="#verdict">Follow the evidence ${icon("arrow-right")}</a>
  </aside>`;
}
