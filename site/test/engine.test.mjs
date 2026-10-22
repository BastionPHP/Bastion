// Runs the shared Go/JS vectors against the browser engine: node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const E = require("../assets/engine.js");
const here = new URL(".", import.meta.url);
const read = (p) => JSON.parse(readFileSync(new URL(p, here), "utf8"));
const advDir = new URL("../../internal/advisory/data/", here);
const advisories = readdirSync(advDir).filter((f) => f.endsWith(".json")).map((f) => JSON.parse(readFileSync(new URL(f, advDir), "utf8")));
const adv = (id) => advisories.find((a) => a.id === id);

test("engine vectors match Go", () => {
  const vf = read("../../testdata/vectors.json");
  const a = adv(vf.advisory);
  for (const c of vf.cases) {
    const s = c.subject;
    const got = E.evaluate(a, { version: s.version, package: s.package || null, os: s.os || {}, changelog_checked: !!s.changelog_checked, changelog_hits: s.changelog_hits || [], fingerprints: s.fingerprints || [] });
    assert.equal(got.status, c.status, `${c.name}: ${got.reason}`);
    assert.ok(got.evidence.length > 0, c.name);
  }
});

test("paste vectors match Go", () => {
  const vf = read("../../testdata/paste.json");
  const a = adv("PHP2SHELL-2026");
  for (const c of vf.cases) {
    const p = E.infer(E.parse(c.text), a);
    const got = { version: p.version, sapi: p.sapi };
    if (p.package) { got.package = p.package.name; got.package_version = p.package.version; }
    if (p.os.id) got.os = p.os.id + " " + p.os.version_id;
    for (const [k, v] of Object.entries(c.expect)) assert.equal(got[k], v, `${c.name}: ${k}`);
    assert.equal(E.evaluate(a, E.subject(p)).status, c.status, c.name);
  }
});

test("version comparisons", () => {
  assert.equal(E.compareDpkg("8.3.6-0ubuntu0.24.04.12", "8.3.6-0ubuntu0.24.04.13"), -1);
  assert.equal(E.compareDpkg("8.2.35-1~deb12u1", "8.2.35-1"), -1);
  assert.equal(E.compareDpkg("7.4.3-4ubuntu2.29+esm5", "7.4.3-4ubuntu2.29"), 1);
  assert.equal(E.compareRPM("8.0.30-1.el9_2", "8.0.30-1.el9_2.1"), -1);
  assert.equal(E.compareRPM("1.0~rc1-1", "1.0-1"), -1);
  assert.equal(E.comparePHP(E.parsePHP("8.6.0RC3"), E.parsePHP("8.6.0RC4")), -1);
});
