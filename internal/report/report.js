(function () {
  "use strict";
  var root = document.documentElement;
  function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } }

  function setTheme(t) {
    if (t) root.setAttribute("data-theme", t); else root.removeAttribute("data-theme");
    var cur = t || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
    document.querySelectorAll("[data-set-theme]").forEach(function (b) { b.setAttribute("aria-pressed", String(b.getAttribute("data-set-theme") === cur)); });
  }
  setTheme(store("bastion-theme"));

  document.addEventListener("click", function (e) {
    var t = e.target.closest("button");
    if (!t) return;
    if (t.hasAttribute("data-set-theme")) { var th = t.getAttribute("data-set-theme"); setTheme(th); store("bastion-theme", th); }
    if (t.hasAttribute("data-print")) { document.querySelectorAll("details").forEach(function (d) { d.open = true; }); window.print(); }
    if (t.hasAttribute("data-filter")) {
      var f = t.getAttribute("data-filter");
      document.querySelectorAll("[data-filter]").forEach(function (b) { b.setAttribute("aria-pressed", String(b === t)); });
      document.querySelectorAll(".r-inst").forEach(function (row) {
        var s = row.getAttribute("data-status");
        row.hidden = f === "attention" ? s === "fixed" : f === "fixed" ? s !== "fixed" : false;
      });
    }
  });
})();
