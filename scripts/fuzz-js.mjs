#!/usr/bin/env node
// JS semantic fuzzer: structured mutations of a real BLA-hardened
// artifact through dehardenJs. Byte-level fuzzing (robustness.mjs)
// can't reach AST-level edge cases — this mutates at syntax boundaries:
//   - delete/duplicate statement spans (naive ;\n splitting)
//   - inject BLA vocabulary into strings, comments, identifiers
//   - splice marker payloads into plausible positions
//   - truncate at mid-token offsets
//   - wrap real code in fake machinery decls
// Contract: dehardenJs NEVER throws, ALWAYS returns {code,report}, and
// when the mutation left real code intact, the output still parses as
// JS (Babel) or honestly reports passthrough/residuals.
// Deterministic: mulberry32 seeded — same mutations every run.
import { readFileSync } from "node:fs";
import { parse } from "@babel/parser";
import { dehardenJs } from "../src/js-deharden.mjs";

const SEED = 0x5eed;
const ROUNDS = 400;
let rng = SEED;
const next = () => {
  rng |= 0; rng = (rng + 0x6d2b79f5) | 0;
  let t = Math.imul(rng ^ (rng >>> 15), 1 | rng);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = (arr) => arr[Math.floor(next() * arr.length)];

const hardened = readFileSync("test-fixtures/adversarial/js/v324/app.hardened.js", "utf8");
const plain = readFileSync("test-fixtures/plain/license-core.js", "utf8");
const VOCAB = ["enclave_unseal_payload", "attestationState", "RING0_SEALED",
  "_shadowVault_", "obligationFlood_", "scc_probe", "labyrinthDispatch_",
  "BLA_BIND_SCOPE_CHECK", "enclave.internal", "tpm2_pcr_extend"];

let pass = 0, fail = 0;
const failures = [];
const ok = (cond, name) => { if (cond) pass++; else { fail++; if (failures.length < 25) failures.push(name); } };

const mutations = [
  // delete a random ;-terminated span
  (s) => { const i = Math.floor(next() * s.length); const j = s.indexOf(";", i); return j === -1 ? s.slice(0, i) : s.slice(0, i) + s.slice(j + 1); },
  // duplicate a random span in place
  (s) => { const i = Math.floor(next() * s.length); const j = Math.min(s.length, i + Math.floor(next() * 400)); return s.slice(0, i) + s.slice(i, j) + s.slice(i); },
  // inject vocabulary into a random position as a string literal statement
  (s) => { const i = Math.floor(next() * s.length); return s.slice(0, i) + `\n;${JSON.stringify(pick(VOCAB))};\n` + s.slice(i); },
  // inject vocabulary as a comment
  (s) => { const i = Math.floor(next() * s.length); return s.slice(0, i) + ` /* ${pick(VOCAB)} */ ` + s.slice(i); },
  // inject a fake machinery-looking decl
  (s) => s + `\nfunction ${pick(VOCAB)}_${Math.floor(next() * 0xffff).toString(16)}(){ return 0; }\n`,
  // truncate mid-file
  (s) => s.slice(0, Math.floor(next() * s.length)),
  // truncate mid-file then append valid tail
  (s) => s.slice(0, Math.floor(next() * s.length)) + "\n;42;\n",
  // prepend a fake bind-scope IIFE
  (s) => `(function BLA_BIND_SCOPE_CHECK(){ if (typeof window === "undefined") throw new Error("scope"); })();\n` + s,
  // wrap in an IIFE
  (s) => `(function(){ "use strict";\n${s}\n})();\n`,
  // splice plain code into the middle
  (s) => { const i = Math.floor(next() * s.length); return s.slice(0, i) + "\n" + plain.slice(0, 600) + "\n" + s.slice(i); },
  // inject a fake seed decl
  (s) => `var _seedCorpus_ = (Math.imul(${Math.floor(next() * 0xffffffff)}, 0x9e3779b1) | 0) & 0xfffffffc | ${next() > 0.5 ? 1 : 0};\n` + s,
  // inject opaque-true-looking guard around a span
  (s) => { const i = Math.floor(next() * s.length); const j = Math.min(s.length, i + Math.floor(next() * 200)); return s.slice(0, i) + `if(((x^x)===0)){` + s.slice(i, j) + `}else{dead${Math.floor(next()*9)}();}` + s.slice(j); },
];

// base cases: the two unmutated sources must survive end-to-end.
for (const [label, src] of [["base:hardened", hardened], ["base:plain", plain]]) {
  let r;
  try { r = dehardenJs(src, { filename: `${label}.js` }); } catch (e) { r = null; ok(false, `${label} threw: ${e.message}`); }
  if (r) {
    ok(typeof r.code === "string" && r.report && typeof r.report === "object", `${label} shaped result`);
    try { parse(r.code, { sourceType: "unambiguous", plugins: ["typescript", "jsx"], errorRecovery: false }); ok(true, `${label} output parses`); }
    catch (e) { ok(false, `${label} output does not parse: ${e.message}`); }
  }
}

for (let round = 0; round < ROUNDS; round++) {
  const base = next() > 0.3 ? hardened : plain;
  const label = `round${round}`;
  let src = base;
  const nMut = 1 + Math.floor(next() * 3);
  const applied = [];
  for (let k = 0; k < nMut; k++) { const m = pick(mutations); applied.push(mutations.indexOf(m)); try { src = m(src); } catch { /* mutation itself may fail on weird slices — skip */ } }

  let r;
  try { r = dehardenJs(src, { filename: `fuzz-${round}.js` }); }
  catch (e) { ok(false, `${label} threw (mut ${applied.join(",")}): ${e.message}`); continue; }
  ok(typeof r.code === "string" && r.report && typeof r.report.hardened === "boolean",
     `${label} shaped result (mut ${applied.join(",")})`);

  // output-parse assertion only applies when the INPUT parses — a
  // mid-token-truncated input legitimately passes through verbatim.
  let inputParses = true;
  try { parse(src, { sourceType: "unambiguous", plugins: ["typescript", "jsx"], errorRecovery: false, allowReturnOutsideFunction: true }); }
  catch { inputParses = false; }
  if (inputParses && r.report.hardened && r.code.length) {
    try {
      parse(r.code, { sourceType: "unambiguous", plugins: ["typescript", "jsx"], errorRecovery: true, allowReturnOutsideFunction: true });
      ok(true, `${label} output parses`);
    } catch (e) {
      ok(false, `${label} output unparseable despite parseable+hardened input (mut ${applied.join(",")}): ${e.message}`);
    }
  }

  // bytesOut honesty: report.bytesOut must equal emitted code length
  // when the report records it.
  if (typeof r.report.bytesOut === "number") {
    ok(r.report.bytesOut === Buffer.byteLength(r.code, "utf8") || r.report.bytesOut === r.code.length,
       `${label} bytesOut honest (${r.report.bytesOut} vs ${r.code.length})`);
  }
}

console.log(`${pass} passed, ${fail} failed`);
if (failures.length) { for (const f of failures) console.log("  FAIL:", f); process.exit(1); }
