(function () {
  "use strict";
  var E = window.BastionEngine;
  var advisories = JSON.parse(document.getElementById("adv-data").textContent);
  var examples = JSON.parse(document.getElementById("examples").textContent);
  var adv = advisories.filter(function (a) { return a.id === "PHP2SHELL-2026"; })[0];
  var $ = function (id) { return document.getElementById(id); };
  var paste = $("paste"), os = $("os"), out = $("result");

  var tb = document.querySelector("[data-vendor-table]");
  if (tb) tb.innerHTML = adv.vendor_fixes.map(function (f) {
    return "<tr><td>" + esc(f.distro + " " + f.release) + "</td><td class=mono>" + esc(f.package) + "</td><td class=mono>" + esc(f.fixed) + "</td><td>" + esc(f.advisory) + (f.channel ? " <span class=bx-faint>(" + esc(f.channel) + ")</span>" : "") + "</td></tr>";
  }).join("");

  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  var LABEL = {
    fixed: ["Fixed", "This build carries the fix."],
    vulnerable: ["Vulnerable", "Upgrade now and restart every PHP worker."],
    "likely-vulnerable": ["Likely vulnerable", "Nothing proves this build is patched."],
    unknown: ["Unknown", "Not enough information to decide — see below."]
  };

  function run() {
    var text = paste.value;
    if (!text.trim()) { out.innerHTML = '<div class="result-empty">' + "Paste output on the left, or pick an example." + "</div>"; return; }
    var p = E.parse(text);
    if (os.value) {
      var parts = os.value.split(":");
      p.os = { id: parts[0] === "other" ? "" : parts[0], version_id: parts[1] || "" };
      if (parts[0] === "other") p.package = null;
    }
    E.infer(p, adv);
    if (!p.version && !p.package) {
      out.innerHTML = '<div class="result-empty">' + "No PHP version found. Paste the full output of <code>php -v</code>." + "</div>";
      return;
    }
    var r = E.evaluate(adv, E.subject(p));
    var l = LABEL[r.status];
    var html = '<div class="result-head"><span class="bx-badge" data-status="' + r.status + '">' + l[0] + "</span>" +
      "<h3>" + esc(adv.name) + " · " + adv.vulnerabilities.map(function (v) { return v.cve; }).join(" / ") + "</h3><p>" + l[1] + " <span class=bx-faint>(" + esc(r.reason) + ")</span></p></div>";
    var facts = [];
    if (p.version) facts.push(["php", p.version + (p.sapi ? " · " + p.sapi : "")]);
    if (p.package) facts.push(["package", p.package.name + " " + p.package.version + " (" + p.package.manager + ")"]);
    if (p.os.id) facts.push(["system", p.os.id + " " + p.os.version_id]);
    if (p.inferred.length) facts.push(["inferred", p.inferred.join(", ")]);
    html += '<div class="result-sec"><h4>' + "What we read" + '</h4><dl class="bx-kv">' + facts.map(function (f) { return "<dt>" + esc(f[0]) + '</dt><dd class="mono">' + esc(f[1]) + "</dd>"; }).join("") + "</dl></div>";
    html += '<div class="result-sec"><h4>' + "Evidence" + '</h4><ul class="ev">' + r.evidence.map(function (e) {
      var m = e.verdict === "fixed" ? "✓" : e.verdict === "vulnerable" ? "✗" : "·";
      return '<li data-v="' + e.verdict + '"><span class="m">' + m + '</span><span class="kd">' + esc(e.kind) + "</span><span>" + esc(e.detail) + "</span></li>";
    }).join("") + "</ul></div>";
    var notes = [];
    if (!p.package && r.status !== "fixed" && p.version && !/ubuntu|deb/.test(p.version))
      notes.push("If this PHP comes from your distribution (apt, dnf, apk), the version alone is not enough: distributions patch without changing it. Add the output of <code>dpkg-query -W 'php*'</code> or <code>rpm -qa 'php*'</code> and check again.");
    if (r.status === "unknown" && p.package)
      notes.push("Bastion has no fixed-version data for this distribution. On the server, <code>sudo bastion scan</code> also reads the package changelog, which usually settles it.");
    if (r.status !== "fixed") notes.push("See the upgrade guide below for your environment.");
    if (r.status === "fixed") notes.push("Make sure the running workers use this build: restart php-fpm / Apache after upgrading.");
    html += '<div class="result-sec">' + notes.map(function (n) { return '<div class="callout' + (r.status === "fixed" ? " is-info" : "") + '" style="margin-bottom:8px"><p>' + n + "</p></div>"; }).join("") + "</div>";
    out.innerHTML = html;
  }

  $("run").addEventListener("click", run);
  os.addEventListener("change", function () { if (paste.value.trim()) run(); });
  var timer;
  paste.addEventListener("input", function () { clearTimeout(timer); timer = setTimeout(run, 250); });
  document.querySelectorAll("[data-example]").forEach(function (b) {
    b.addEventListener("click", function () { paste.value = examples[b.getAttribute("data-example")]; os.value = ""; run(); });
  });
})();
