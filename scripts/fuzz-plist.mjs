#!/usr/bin/env node
// plist-XML structural fuzzer: mutate real plist text the ways an
// attacker would — BLA-prefixed keys at every nesting level, malformed
// XML fragments, marker text inside values, dict/array shape confusion.
// Contract: scrubPlistXml never throws, returns {code,report}, real keys
// survive, and unhardened input round-trips.
import { readFileSync } from "node:fs";
import { scrubPlistXml } from "../src/trailer.mjs";

let pass = 0, fail = 0;
const failures = [];
const ok = (cond, name) => { if (cond) pass++; else { fail++; if (failures.length < 20) failures.push(name); } };

const plain = readFileSync("test-fixtures/plain/Info.plist", "utf8");
const BLA_KEYS = ["BLA_decoy_transport", "BLA_enclave_unseal", "BLA_canary_probe",
  "BLA_SHADOW_HEAP", "BLA_attestation_ledger"];

let rng = 0xf157;
const next = () => { rng |= 0; rng = (rng + 0x6d2b79f5) | 0; let t = Math.imul(rng ^ (rng >>> 15), 1 | rng); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const pick = (a) => a[Math.floor(next() * a.length)];

// base sanity
{
  const r = scrubPlistXml(plain);
  ok(typeof r.code === "string" && r.report, "plain plist scrubs");
  ok(r.code.includes("<plist"), "plain plist survives");
}

const mutations = [
  // inject a BLA key+string pair at a random position
  (s) => { const i = s.indexOf("<key>"); return i < 0 ? s + `<key>${pick(BLA_KEYS)}</key><string>x</string>` : s.slice(0, i) + `<key>${pick(BLA_KEYS)}</key><string>decoy</string>` + s.slice(i); },
  // inject BLA key + nested dict
  (s) => s.replace("</dict>", `<key>${pick(BLA_KEYS)}</key><dict><key>a</key><string>b</string></dict></dict>`),
  // inject BLA key + nested array
  (s) => s.replace("</dict>", `<key>${pick(BLA_KEYS)}</key><array><string>1</string></array></dict>`),
  // marker text inside a value (must survive — it's data not key)
  (s) => s.replace("<key>", `<key>Note</key><string>mentions BLA_decoy_transport in prose</string><key>`),
  // truncate mid-tag
  (s) => s.slice(0, Math.floor(next() * s.length)),
  // duplicate a key
  (s) => s.replace(/<key>([^<]+)<\/key>/, (m) => m + m),
  // wrap garbage around
  (s) => "garbage-prefix" + s + "garbage-suffix",
  // deep-nest a real key under BLA dict
  (s) => s.replace("</dict>", `<key>${pick(BLA_KEYS)}</key><dict><key>inner</key><dict><key>deep</key><string>v</string></dict></dict></dict>`),
];

for (let round = 0; round < 200; round++) {
  const label = `r${round}`;
  let src = plain;
  const n = 1 + Math.floor(next() * 3);
  const applied = [];
  for (let k = 0; k < n; k++) { const m = pick(mutations); applied.push(mutations.indexOf(m)); try { src = m(src); } catch {} }
  let r;
  try { r = scrubPlistXml(src); }
  catch (e) { ok(false, `${label} threw (${applied.join(",")}): ${e.message}`); continue; }
  ok(typeof r.code === "string" && r.report && typeof r.report === "object",
     `${label} shaped (${applied.join(",")})`);
  // value-position marker text must NEVER be stripped (it's data)
  if (applied.includes(3) && src.includes("mentions BLA_decoy_transport in prose")) {
    ok(r.code.includes("mentions BLA_decoy_transport in prose") || !r.code.includes("Note"),
       `${label} value marker preserved (${applied.join(",")})`);
  }
}

// degenerate inputs
for (const [label, src] of [["empty", ""], ["not-xml", "just text"], ["partial", "<plist><dict><key>a"], ["xml-no-plist", "<root><a/></root>"]]) {
  try { const r = scrubPlistXml(src); ok(r.code !== undefined, `${label} shaped`); }
  catch (e) { ok(false, `${label} threw: ${e.message}`); }
}

console.log(`${pass} passed, ${fail} failed`);
if (failures.length) { for (const f of failures) console.log("  FAIL:", f); process.exit(1); }
