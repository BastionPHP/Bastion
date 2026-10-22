// Bastion browser engine — a line-for-line port of internal/version,
// internal/advisory (Evaluate) and internal/check (Parse/Infer). It runs
// entirely in the page; nothing is sent anywhere. Kept in sync with the Go
// code by testdata/vectors.json and testdata/paste.json (site/test/).
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.BastionEngine = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // ---- versions ------------------------------------------------------------
  var phpRe = /^(\d+)\.(\d+)(?:\.(\d+))?(?:[-.]?(dev|alpha|beta|a|b|RC|rc|pl|p)(\d*))?(.*)$/;
  var preNorm = { a: "alpha", b: "beta", rc: "RC", p: "pl" };
  var preRankMap = { dev: 0, alpha: 1, beta: 2, RC: 3, "": 4, pl: 5 };

  function parsePHP(s) {
    var raw = String(s).trim();
    var m = phpRe.exec(raw);
    if (!m) return null;
    var pre = m[4] || "";
    pre = preNorm[pre] || pre;
    return { major: +m[1], minor: +m[2], patch: m[3] ? +m[3] : 0, pre: pre, preNum: m[5] ? +m[5] : 0, extra: m[6], raw: raw };
  }
  function branch(v) { return v.major + "." + v.minor; }
  function upstream(v) { return v.major + "." + v.minor + "." + v.patch + (v.pre ? v.pre + (v.preNum > 0 ? v.preNum : "") : ""); }
  function sign(n) { return n < 0 ? -1 : n > 0 ? 1 : 0; }
  function rank(p) { return p in preRankMap ? preRankMap[p] : 4; }
  function comparePHP(a, b) {
    var d = [[a.major, b.major], [a.minor, b.minor], [a.patch, b.patch], [rank(a.pre), rank(b.pre)], [a.preNum, b.preNum]];
    for (var i = 0; i < d.length; i++) if (d[i][0] !== d[i][1]) return d[i][0] < d[i][1] ? -1 : 1;
    return 0;
  }
  function compareBranch(a, b) {
    var pa = parsePHP(a), pb = parsePHP(b);
    if (!pa || !pb) return a < b ? -1 : a > b ? 1 : 0;
    if (pa.major !== pb.major) return sign(pa.major - pb.major);
    return sign(pa.minor - pb.minor);
  }

  function isDigit(c) { return c >= "0" && c <= "9"; }
  function isLetter(c) { return /[A-Za-z]/.test(c); }
  function order(c) {
    if (c === undefined) return 0;
    if (isDigit(c)) return 0;
    if (isLetter(c)) return c.charCodeAt(0);
    if (c === "~") return -1;
    return c.charCodeAt(0) + 256;
  }
  function verrevcmp(a, b) {
    var i = 0, j = 0;
    while (i < a.length || j < b.length) {
      var firstDiff = 0;
      while ((i < a.length && !isDigit(a[i])) || (j < b.length && !isDigit(b[j]))) {
        var ac = order(a[i]), bc = order(b[j]);
        if (ac !== bc) return sign(ac - bc);
        i++; j++;
      }
      while (a[i] === "0") i++;
      while (b[j] === "0") j++;
      while (i < a.length && isDigit(a[i]) && j < b.length && isDigit(b[j])) {
        if (!firstDiff) firstDiff = a.charCodeAt(i) - b.charCodeAt(j);
        i++; j++;
      }
      if (i < a.length && isDigit(a[i])) return 1;
      if (j < b.length && isDigit(b[j])) return -1;
      if (firstDiff) return sign(firstDiff);
    }
    return 0;
  }
  function splitDpkg(v) {
    v = String(v).trim();
    var epoch = 0, i = v.indexOf(":");
    if (i >= 0) { epoch = parseInt(v.slice(0, i), 10) || 0; v = v.slice(i + 1); }
    i = v.lastIndexOf("-");
    return i >= 0 ? [epoch, v.slice(0, i), v.slice(i + 1)] : [epoch, v, ""];
  }
  function compareDpkg(a, b) {
    var x = splitDpkg(a), y = splitDpkg(b);
    if (x[0] !== y[0]) return sign(x[0] - y[0]);
    return verrevcmp(x[1], y[1]) || verrevcmp(x[2], y[2]);
  }

  function isAlnum(c) { return c !== undefined && /[0-9A-Za-z]/.test(c); }
  function rpmvercmp(a, b) {
    if (a === b) return 0;
    var i = 0, j = 0;
    while (i < a.length || j < b.length) {
      while (i < a.length && !isAlnum(a[i]) && a[i] !== "~" && a[i] !== "^") i++;
      while (j < b.length && !isAlnum(b[j]) && b[j] !== "~" && b[j] !== "^") j++;
      if (a[i] === "~" || b[j] === "~") {
        if (a[i] !== "~") return 1;
        if (b[j] !== "~") return -1;
        i++; j++; continue;
      }
      if (a[i] === "^" || b[j] === "^") {
        if (i >= a.length) return -1;
        if (j >= b.length) return 1;
        if (a[i] !== "^") return 1;
        if (b[j] !== "^") return -1;
        i++; j++; continue;
      }
      if (i >= a.length || j >= b.length) break;
      var si = i, sj = j, numeric = isDigit(a[i]);
      if (numeric) { while (i < a.length && isDigit(a[i])) i++; while (j < b.length && isDigit(b[j])) j++; }
      else { while (i < a.length && isLetter(a[i])) i++; while (j < b.length && isLetter(b[j])) j++; }
      var x = a.slice(si, i), y = b.slice(sj, j);
      if (y === "") return numeric ? 1 : -1;
      if (numeric) {
        x = x.replace(/^0+/, ""); y = y.replace(/^0+/, "");
        if (x.length !== y.length) return sign(x.length - y.length);
      }
      if (x !== y) return x < y ? -1 : 1;
    }
    if (i >= a.length && j >= b.length) return 0;
    return i >= a.length ? -1 : 1;
  }
  function splitRPM(v) {
    v = String(v).trim();
    var epoch = 0, i = v.indexOf(":");
    if (i >= 0) { epoch = parseInt(v.slice(0, i), 10) || 0; v = v.slice(i + 1); }
    i = v.lastIndexOf("-");
    return i >= 0 ? [epoch, v.slice(0, i), v.slice(i + 1)] : [epoch, v, ""];
  }
  function compareRPM(a, b) {
    var x = splitRPM(a), y = splitRPM(b);
    if (x[0] !== y[0]) return sign(x[0] - y[0]);
    var c = rpmvercmp(x[1], y[1]);
    if (c) return c;
    if (!x[2] || !y[2]) return 0;
    return rpmvercmp(x[2], y[2]);
  }
  function compareVendor(format, a, b) { return format === "rpm" || format === "apk" ? compareRPM(a, b) : compareDpkg(a, b); }

  function upstreamOf(pkgVersion) {
    var s = String(pkgVersion), i = s.indexOf(":");
    if (i >= 0) s = s.slice(i + 1);
    var m = s.search(/[-+~]/);
    return m >= 0 ? s.slice(0, m) : s;
  }

  // ---- evaluate (mirror of advisory.Evaluate) ----------------------------
  function findBranch(adv, name) {
    for (var i = 0; i < adv.branches.length; i++) if (adv.branches[i].branch === name) return adv.branches[i];
    return null;
  }
  function branchPosition(adv, name) {
    var older = true, newer = true;
    adv.branches.forEach(function (b) {
      var c = compareBranch(name, b.branch);
      if (c >= 0) older = false;
      if (c <= 0) newer = false;
    });
    return older ? -1 : newer ? 1 : 0;
  }
  function vendorFixFor(adv, os, pkg) {
    if (!pkg) return null;
    var list = adv.vendor_fixes || [];
    for (var i = 0; i < list.length; i++) {
      var f = list[i];
      if (f.distro !== os.id || f.release !== os.version_id || f.format !== pkg.manager) continue;
      if (f.package === pkg.source || f.package === pkg.name) return f;
    }
    return null;
  }

  function evaluate(adv, s) {
    var out = { advisory: adv.id, evidence: [] };
    var os = s.os || {};
    function add(kind, verdict, detail) { out.evidence.push({ kind: kind, verdict: verdict, detail: detail }); }
    function done(st, conf, reason) { out.status = st; out.confidence = conf; out.reason = reason; return out; }

    var v = s.version ? parsePHP(s.version) : null;
    if (!v) {
      if (!s.package) { add("version", "neutral", "could not determine the PHP version"); return done("unknown", "low", "PHP version could not be determined"); }
      v = parsePHP(upstreamOf(s.package.version));
      if (v) add("version", "neutral", "version taken from package " + s.package.name + " " + s.package.version);
    }
    var up = "", br = null;
    if (v) {
      br = findBranch(adv, branch(v));
      if (br && br.fixed) {
        out.fixed_in = br.fixed;
        if (comparePHP(v, parsePHP(br.fixed)) >= 0) {
          add("version", "fixed", "PHP " + upstream(v) + " is at or above the fixed release " + br.fixed);
          return done("fixed", "high", "running " + upstream(v) + ", fixed in " + br.fixed);
        }
        up = "vulnerable";
        if (s.package) add("version", "neutral", "PHP " + upstream(v) + " is below the fixed release " + br.fixed + ", but distribution packages often carry backports");
        else add("version", "vulnerable", "PHP " + upstream(v) + " is below the fixed release " + br.fixed);
      } else if (br) {
        up = "no-release";
        add("version", "vulnerable", "PHP " + branch(v) + " has no fixed upstream release (branch status: " + br.status + ")");
      } else {
        var pos = branchPosition(adv, branch(v));
        if (pos > 0 && adv.newer_branches === "fixed") {
          add("version", "fixed", "PHP " + branch(v) + " is newer than every branch covered by this advisory");
          return done("fixed", "medium", "branch " + branch(v) + " postdates the fix");
        } else if (pos < 0 && adv.older_branches === "affected") {
          up = "no-release";
          add("version", "vulnerable", "PHP " + branch(v) + " is an end-of-life branch with no upstream fix");
        } else add("version", "neutral", "branch " + branch(v) + " is not covered by this advisory's data");
      }
    }

    var f = vendorFixFor(adv, os, s.package);
    if (f) {
      out.vendor_fix = f; out.fixed_in = f.fixed;
      var tag = " (" + f.advisory + ", " + f.distro + " " + f.release + ")";
      if (compareVendor(f.format, s.package.version, f.fixed) >= 0) {
        add("vendor", "fixed", s.package.name + " " + s.package.version + " ≥ " + f.fixed + tag);
        return done("fixed", "high", "vendor backport " + f.fixed + " in " + f.advisory);
      }
      add("vendor", "vulnerable", s.package.name + " " + s.package.version + " < " + f.fixed + tag);
      return done("vulnerable", "high", "package " + s.package.version + " is older than the vendor fix " + f.fixed);
    }

    if (s.changelog_hits && s.changelog_hits.length) {
      add("changelog", "fixed", "package changelog mentions " + s.changelog_hits.join(", "));
      return done("fixed", "high", "vendor changelog records the fix");
    }

    var fps = adv.fingerprints || [];
    for (var i = 0; i < fps.length; i++) {
      var fp = fps[i];
      if (!s.fingerprints || s.fingerprints.indexOf(fp.value) < 0) continue;
      if (fp.min_branch && v && compareBranch(branch(v), fp.min_branch) < 0) continue;
      add("fingerprint", fp.indicates, 'binary contains "' + fp.value + '", which only patched builds include');
      if (fp.indicates === "fixed") return done("fixed", "medium", "binary contains code introduced by the fix");
    }

    if (s.package) {
      if (!up) return done("unknown", "low", "packaged build with an unrecognised version");
      if (s.changelog_checked) {
        add("changelog", "vulnerable", s.package.name + " changelog does not mention " + adv.changelog_markers.slice(0, 2).join(" / "));
        return done("likely-vulnerable", "medium", "distribution package without a recorded backport");
      }
      add("note", "neutral", "distributions backport fixes without changing the upstream version; no changelog was readable and " + (os.id || "?") + " " + (os.version_id || "") + " is not in Bastion's vendor data");
      return done("unknown", "low", "packaged build; backport status cannot be verified");
    }
    if (up === "vulnerable") return done("vulnerable", "high", "PHP " + upstream(v) + " is below " + out.fixed_in);
    if (up === "no-release") {
      if (br && br.source_backport) {
        add("note", "neutral", "upstream published a source-only backport branch (" + br.source_backport + "); builds from it keep the version string, so Bastion cannot tell them apart");
        return done("likely-vulnerable", "medium", "end-of-life branch; only a source backport exists");
      }
      return done("vulnerable", "high", "end-of-life branch " + branch(v) + " with no upstream fix");
    }
    return done("unknown", "low", "not enough information");
  }

  // ---- paste parser (mirror of internal/check) ----------------------------
  var rePHPv = /PHP ([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+~-]*) \(([a-z0-9-]+)\)(?: \(built: ([^)]*)\))?/m;
  var reDpkgL = /^[a-z][a-z]\s+((?:lib)?[a-z0-9.+-]*php[a-z0-9.+-]*)(?::[a-z0-9]+)?\s+([0-9][^\s]*)\s/gm;
  var reDpkgW = /^((?:lib)?[a-z0-9.+-]*php[a-z0-9.+-]*)(?::[a-z0-9]+)?\t([0-9][^\s]*)\s*$/gm;
  var reRPM = /^((?:[a-z0-9_]+-)*php[a-z0-9_]*(?:-[a-z][a-z0-9_]*)*)-([0-9][^-\s]*)-([^-\s]+)\.(x86_64|aarch64|noarch|i686|ppc64le|s390x)$/;
  var reAPK = /^(php[0-9]*[a-z0-9-]*?)-([0-9][^-\s]*-r[0-9]+)\b/;
  var reOSID = /^ID="?([a-z0-9._-]+)"?\s*$/m;
  var reOSVer = /^VERSION_ID="?([0-9.]+)"?\s*$/m;
  var reLSBRel = /^Release:\s+([0-9.]+)\s*$/m;
  var reLSBID = /^Distributor ID:\s+(\S+)\s*$/m;
  var reUbuRel = /ubuntu[0-9.]*?\b(1[4-9]|2[0-9])\.(04|10)\b/;
  var reDebRel = /~deb([0-9]{2})u/;

  function preferred(name) {
    if (/-cli$/.test(name)) return 3;
    if (/-fpm$/.test(name) || name.indexOf("mod-php") >= 0) return 2;
    if (/-common$/.test(name)) return 1;
    return 0;
  }
  function debSource(name) {
    var m = /^libapache2-mod-(php[0-9.]*)$/.exec(name);
    if (m) return m[1];
    m = /^(php[0-9]+(?:\.[0-9]+)?)(?:-|$)/.exec(name);
    return m ? m[1] : name;
  }

  function parse(text) {
    text = String(text).replace(/\r\n/g, "\n");
    var p = { version: "", sapi: "", built: "", package: null, os: { id: "", version_id: "" }, inferred: [] };
    var m = rePHPv.exec(text);
    if (m) { p.version = m[1]; p.sapi = m[2]; p.built = m[3] || ""; }
    var best = -1;
    function consider(pkg) {
      if (pkg.manager === "dpkg" && debSource(pkg.name).indexOf("php") !== 0) return;
      var r = preferred(pkg.name);
      if (r > best) { best = r; p.package = pkg; }
    }
    var mm;
    reDpkgL.lastIndex = 0;
    while ((mm = reDpkgL.exec(text))) consider({ manager: "dpkg", name: mm[1], version: mm[2], source: debSource(mm[1]) });
    reDpkgW.lastIndex = 0;
    while ((mm = reDpkgW.exec(text))) consider({ manager: "dpkg", name: mm[1], version: mm[2], source: debSource(mm[1]) });
    text.split("\n").forEach(function (line) {
      line = line.trim();
      var r = reRPM.exec(line);
      if (r) {
        var i = r[1].indexOf("-php");
        consider({ manager: "rpm", name: r[1], version: r[2] + "-" + r[3], source: i > 0 ? r[1].slice(0, i) : "php" });
        return;
      }
      var a = reAPK.exec(line);
      if (a && line.indexOf(".x86_64") < 0) consider({ manager: "apk", name: a[1], version: a[2], source: a[1] });
    });
    if ((m = reOSID.exec(text))) {
      p.os.id = m[1];
      var vv = reOSVer.exec(text);
      if (vv) p.os.version_id = vv[1];
    } else if ((m = reLSBID.exec(text))) {
      p.os.id = m[1].toLowerCase();
      var lr = reLSBRel.exec(text);
      if (lr) p.os.version_id = lr[1];
    }
    if (!p.os.id) {
      var probe = p.version + (p.package ? " " + p.package.version : "");
      if ((m = reUbuRel.exec(probe))) { p.os = { id: "ubuntu", version_id: m[1] + "." + m[2] }; p.inferred.push("os from package version"); }
      else if ((m = reDebRel.exec(probe))) { p.os = { id: "debian", version_id: m[1].replace(/^0+/, "") }; p.inferred.push("os from package version"); }
    }
    return p;
  }

  function infer(p, adv) {
    if (p.package || !p.version) return p;
    var v = parsePHP(p.version);
    if (!v || v.extra.indexOf("ubuntu") < 0) return p;
    var src = v.major === 5 ? "php5" : "php" + branch(v);
    if (!p.os.id) {
      var list = adv.vendor_fixes || [];
      for (var i = 0; i < list.length; i++) {
        var f = list[i];
        if (f.distro === "ubuntu" && f.package === src && upstreamOf(f.fixed) === upstream(v)) {
          p.os = { id: "ubuntu", version_id: f.release };
          p.inferred.push("Ubuntu release from the package version");
          break;
        }
      }
    }
    if (p.os.id === "ubuntu") {
      p.package = { manager: "dpkg", name: src, version: p.version, source: src };
      p.inferred.push("package version from php -v");
    }
    return p;
  }

  function subject(p) { return { version: p.version, package: p.package, os: p.os }; }

  return {
    parsePHP: parsePHP, comparePHP: comparePHP, compareDpkg: compareDpkg, compareRPM: compareRPM,
    evaluate: evaluate, parse: parse, infer: infer, subject: subject, branch: branch, upstream: upstream
  };
});
