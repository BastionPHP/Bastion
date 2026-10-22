(function () {
  "use strict";
  var root = document.documentElement;
  function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } }

  document.addEventListener("click", function (e) {
    var el = e.target.closest("[data-theme-toggle],[data-copy],[data-tab]");
    if (!el) return;
    if (el.hasAttribute("data-theme-toggle")) {
      var cur = root.getAttribute("data-theme") || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
      var next = cur === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      store("bastion-theme", next);
    }
    if (el.hasAttribute("data-copy")) {
      var src = document.getElementById(el.getAttribute("data-copy"));
      var text = src ? src.innerText.replace(/^\$ /gm, "") : "";
      var ok = function () { el.classList.add("is-done"); setTimeout(function () { el.classList.remove("is-done"); }, 1400); };
      if (navigator.clipboard) navigator.clipboard.writeText(text).then(ok, function () {});
    }
    if (el.hasAttribute("data-tab")) {
      var group = el.closest("[data-tabs]");
      var id = el.getAttribute("data-tab");
      group.querySelectorAll("[data-tab]").forEach(function (b) { b.setAttribute("aria-selected", String(b === el)); });
      group.querySelectorAll("[data-panel]").forEach(function (p) { p.hidden = p.getAttribute("data-panel") !== id; });
    }
  });

  // Highlight the docs section in view.
  var toc = document.querySelector(".toc");
  if (toc && "IntersectionObserver" in window) {
    var links = {};
    toc.querySelectorAll("a[href^='#']").forEach(function (a) { links[a.getAttribute("href").slice(1)] = a; });
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting && links[en.target.id]) {
          Object.keys(links).forEach(function (k) { links[k].removeAttribute("aria-current"); });
          links[en.target.id].setAttribute("aria-current", "true");
        }
      });
    }, { rootMargin: "-30% 0px -60% 0px" });
    Object.keys(links).forEach(function (id) { var s = document.getElementById(id); if (s) io.observe(s); });
  }
})();
