(function () {
  "use strict";
  var E = window.BastionEngine;
  var advisories = JSON.parse(document.getElementById("adv-data").textContent);
  var examples = JSON.parse(document.getElementById("examples").textContent);
  var icons = JSON.parse(document.getElementById("icon-data").textContent);
  var adv = advisories.filter(function (a) { return a.id === "PHP2SHELL-2026"; })[0];
  var $ = function (id) { return document.getElementById(id); };
  var paste = $("paste"), os = $("os"), out = $("result");

  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function icon(name) {
    return '<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (icons[name] || "") + "</svg>";
  }

  var LABEL = {
    fixed: ["shield-check", "Fixed", "This build carries the fix."],
    vulnerable: ["shield-x", "Vulnerable", "Update now and restart every PHP worker."],
    "likely-vulnerable": ["shield-alert", "Likely vulnerable", "Nothing proves this build is patched."],
    unknown: ["shield-question", "Unknown", "Not enough information to decide. See below."]
  };
  var MARK = { fixed: "check", vulnerable: "x", neutral: "circle-dot" };

  function empty(msg) { out.innerHTML = '<div class="result-empty">' + icon("shield-question") + msg + "</div>"; }

  function run() {
    var text = paste.value;
    if (!text.trim()) { empty("Paste output on the left, or pick an example."); return; }
    var p = E.parse(text);
    if (os.value) {
      var parts = os.value.split(":");
      if (parts[0] === "env") p.environment = parts[1];
      else if (parts[0] === "other") { p.os = { id: "", version_id: "" }; p.package = null; }
      else p.os = { id: parts[0], version_id: parts[1] || "" };
    }
    E.infer(p, adv);
    if (!p.version && !p.package) { empty("No PHP version found. Paste the full output of <code>php -v</code>."); return; }
    var r = E.evaluate(adv, E.subject(p));
    var l = LABEL[r.status];
    var html = '<div class="result-head"><div><span class="tag" data-status="' + r.status + '">' + icon(l[0]) + l[1] + "</span></div>" +
      "<h3>" + esc(adv.name) + " · " + adv.vulnerabilities.map(function (v) { return v.cve; }).join(" · ") + "</h3><p>" + l[2] + ' <span class="bx-faint">(' + esc(r.reason) + ")</span></p></div>";
    var facts = [];
    if (p.version) facts.push(["php", p.version + (p.sapi ? " · " + p.sapi : "")]);
    if (p.build_date) facts.push(["built", p.build_date]);
    if (p.package) facts.push(["package", p.package.name + " " + p.package.version + " (" + p.package.manager + ")"]);
    if (p.os.id) facts.push(["system", p.os.id + " " + p.os.version_id]);
    if (p.environment) facts.push(["environment", p.environment]);
    if (p.inferred.length) facts.push(["inferred", p.inferred.join(", ")]);
    html += '<div class="result-sec"><span class="label">What was read</span><dl class="rec">' + facts.map(function (f) { return "<div><dt>" + esc(f[0]) + '</dt><dd class="mono">' + esc(f[1]) + "</dd></div>"; }).join("") + "</dl></div>";
    html += '<div class="result-sec"><span class="label">Evidence</span><ul class="ev">' + r.evidence.map(function (e) {
      return '<li data-v="' + e.verdict + '"><span class="m">' + icon(MARK[e.verdict] || "circle-dot") + '</span><span class="kd">' + esc(e.kind) + "</span><span>" + esc(e.detail) + "</span></li>";
    }).join("") + "</ul></div>";
    var notes = [];
    if (!p.package && !p.environment && r.status !== "fixed" && p.version && !/ubuntu|deb/.test(p.version))
      notes.push(["is-warn", "triangle-alert", "If this PHP comes from your distribution (apt, dnf, apk), the version alone is not enough: distributions patch without changing it. Add the output of <code>dpkg-query -W 'php*'</code> or <code>rpm -qa 'php*'</code> and check again."]);
    if (r.status === "unknown" && p.package)
      notes.push(["is-warn", "info", "Bastion has no fixed-version data for this distribution. On the server, <code>sudo bastion scan</code> also reads the package changelog, which usually settles it."]);
    if (r.status !== "fixed") notes.push(["is-bad", "arrow-right", "See the upgrade guide below for your environment. Until you can update, apply the interim mitigations."]);
    else notes.push(["is-ok", "rotate-ccw", "Make sure running workers use this build: restart php-fpm or Apache after upgrading."]);
    html += '<div class="result-sec">' + notes.map(function (n) { return '<div class="note ' + n[0] + '">' + icon(n[1]) + "<p>" + n[2] + "</p></div>"; }).join("") + "</div>";
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
