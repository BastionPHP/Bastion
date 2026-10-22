(function () {
  "use strict";
  var root = document.documentElement;
  function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } }

  var systemTheme = matchMedia("(prefers-color-scheme: light)");
  function syncTheme() {
    var theme = root.getAttribute("data-theme") || (systemTheme.matches ? "light" : "dark");
    document.querySelectorAll("[data-theme-toggle]").forEach(function (button) {
      button.setAttribute("aria-label", "Switch to " + (theme === "dark" ? "light" : "dark") + " theme");
    });
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = getComputedStyle(root).getPropertyValue("--bg").trim();
  }
  syncTheme();
  systemTheme.addEventListener("change", syncTheme);

  // Link tabs to their panels and provide one tab stop per tablist.
  document.querySelectorAll("[data-tabs]").forEach(function (group, groupIndex) {
    var tabs = Array.from(group.querySelectorAll("[data-tab]"));
    tabs.forEach(function (tab, index) {
      var panel = Array.from(group.querySelectorAll("[data-panel]")).find(function (item) {
        return item.getAttribute("data-panel") === tab.getAttribute("data-tab");
      });
      if (!panel) return;
      tab.id = tab.id || "tab-" + groupIndex + "-" + index;
      panel.id = panel.id || "panel-" + groupIndex + "-" + index;
      tab.setAttribute("aria-controls", panel.id);
      tab.tabIndex = tab.getAttribute("aria-selected") === "true" ? 0 : -1;
      panel.setAttribute("role", "tabpanel");
      panel.setAttribute("aria-labelledby", tab.id);
      panel.tabIndex = 0;
      tab.addEventListener("keydown", function (event) {
        var next;
        if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
        else if (event.key === "ArrowLeft") next = (index + tabs.length - 1) % tabs.length;
        else if (event.key === "Home") next = 0;
        else if (event.key === "End") next = tabs.length - 1;
        else return;
        event.preventDefault();
        tabs[next].click();
        tabs[next].focus();
      });
    });
  });

  // The schematic explains real checks. Selection never implies a live scan.
  document.querySelectorAll(".evidence-map").forEach(function (map) {
    var title = map.querySelector(".evidence-detail-title");
    var detail = map.querySelector(".evidence-detail p");
    var steps = map.querySelectorAll(".evidence-step");
    function select(step) {
      if (step.getAttribute("aria-pressed") === "true") return;
      steps.forEach(function (item) { item.setAttribute("aria-pressed", String(item === step)); });
      title.textContent = step.getAttribute("data-evidence-title");
      detail.textContent = step.getAttribute("data-evidence-detail");
    }
    steps.forEach(function (step) {
      step.addEventListener("click", function () { select(step); });
    });
  });

  // Share a section directly without adding another navigation rail.
  document.querySelectorAll(".sect[id] > .sect-grid > .sect-side > h2, .docs section[id] > h2").forEach(function (heading) {
    var section = heading.closest("section[id]");
    var link = document.createElement("a");
    link.className = "section-anchor";
    link.href = "#" + section.id;
    link.setAttribute("aria-label", "Link to " + heading.textContent.trim());
    link.textContent = "#";
    heading.appendChild(link);
  });

  document.addEventListener("click", function (e) {
    var el = e.target.closest("[data-theme-toggle],[data-copy],[data-tab]");
    if (!el) return;
    if (el.hasAttribute("data-theme-toggle")) {
      var cur = root.getAttribute("data-theme") || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
      var next = cur === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      store("bastion-theme", next);
      syncTheme();
    }
    if (el.hasAttribute("data-copy")) {
      var src = document.getElementById(el.getAttribute("data-copy"));
      var text = src ? src.innerText.replace(/^\$ /gm, "") : "";
      var container = el.closest(".codebox, .cmd");
      var feedback = container.querySelector(".copy-feedback");
      if (!feedback) {
        feedback = document.createElement("span");
        feedback.className = "copy-feedback";
        feedback.setAttribute("role", "status");
        container.appendChild(feedback);
      }
      clearTimeout(el.copyTimer);
      var ok = function () {
        el.classList.add("is-done");
        el.setAttribute("aria-label", "Copied to clipboard");
        feedback.textContent = "Copied to clipboard";
        el.copyTimer = setTimeout(function () {
          el.classList.remove("is-done");
          el.setAttribute("aria-label", "Copy to clipboard");
          feedback.textContent = "";
        }, 1800);
      };
      var failed = function () {
        el.classList.remove("is-done");
        el.setAttribute("aria-label", "Copy to clipboard");
        feedback.textContent = "Copy unavailable. Select the command and copy it manually.";
      };
      if (navigator.clipboard) navigator.clipboard.writeText(text).then(ok, failed);
      else failed();
    }
    if (el.hasAttribute("data-tab")) {
      var group = el.closest("[data-tabs]");
      var id = el.getAttribute("data-tab");
      group.querySelectorAll("[data-tab]").forEach(function (b) {
        b.setAttribute("aria-selected", String(b === el));
        b.tabIndex = b === el ? 0 : -1;
      });
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
