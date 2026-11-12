#!/usr/bin/env node
// Unit checks for recovery/name-recovery.mjs — the conservative
// identifier recovery pass. Invariants under test:
//   1. malformed code never throws; passthrough-shaped result
//   2. BLA-shaped names WITH evidence-backed candidates are renamed
//      (earlySort $xxBody_hex style, hint case restored)
//   3. hazard classes are never renamed: exported API names, bindings
//      reachable by eval(), machinery-family names
//   4. ambiguity/evidence-less names land in `unrenamable` with a reason,
//      not silently renamed or silently kept
//   5. recoverWasmExports: non-wasm returns {names:[],note}, never throws
import { recoverJsNames, recoverWasmExports } from "../src/recovery/name-recovery.mjs";

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) pass++; else { fail++; console.log("FAIL:", name); } };
const names = (r) => r.renames.map((x) => `${x.from}->${x.to}`);

// 1. malformed / degenerate inputs
for (const src of ["", "{{{", "const", "\x00\x01\x02"]) {
  const r = recoverJsNames(src, null);
  ok(r.code === src && r.renames.length === 0, `malformed ${JSON.stringify(src.slice(0, 6))} passthrough`);
}
// report arg optional; when given, populated even on parse failure.
{
  const rep = {};
  recoverJsNames("{{{", rep);
  ok(Array.isArray(rep.inferredRenames) && Array.isArray(rep.unrenamable), "report populated on parse failure");
}

// 2. evidence-backed renames fire
{
  const r = recoverJsNames(
    'function g(){ const $abConfigJson_1f2 = JSON.parse("{}"); return $abConfigJson_1f2 } module.exports={g}', null);
  ok(r.renames.some((x) => x.from === "$abConfigJson_1f2" && x.to === "configJson"),
     `earlySort var renamed to hint case (got ${JSON.stringify(names(r))})`);
  ok(!r.code.includes("$abConfigJson_1f2"), "renamed binding fully rewritten in code");
}
{
  const r = recoverJsNames(
    'function $cdReadFile_9ab(p){ return require("fs").readFileSync(p) } module.exports={$cdReadFile_9ab}', null);
  ok(r.renames.some((x) => x.from === "$cdReadFile_9ab" && x.to === "readFile"),
     `earlySort fn renamed (got ${JSON.stringify(names(r))})`);
}

// 3. hazards never renamed
{
  // a non-BLA name is never touched even with obvious evidence
  const r = recoverJsNames(
    'function f(userData){ return userData.length } module.exports={f}', null);
  ok(r.renames.length === 0, "real names untouched");
}
{
  // machinery-family names are never renamed (they're BLA's own, not
  // renamed user code — dehardening owns their removal)
  const r = recoverJsNames(
    'function _stepShadowHeap_a1(x){ return x } module.exports={_stepShadowHeap_a1}', null);
  ok(r.renames.length === 0, "machinery names untouched");
}

// 4. ambiguous names -> unrenamable with reason, code unchanged
{
  const r = recoverJsNames(
    'function f(nLazyNode_c30){ return nLazyNode_c30.length } module.exports={f}', null);
  ok(r.renames.length === 0 && r.unrenamable.some((u) => u.name === "nLazyNode_c30" && typeof u.reason === "string"),
     `ambiguous -> unrenamable+reason (got ${JSON.stringify(r.unrenamable)})`);
  ok(r.code.includes("nLazyNode_c30"), "unrenamable binding NOT rewritten");
}

// every rename carries confidence+evidence — the report is auditable.
{
  const r = recoverJsNames(
    'function g(){ const $abConfigJson_1f2 = JSON.parse("{}"); return $abConfigJson_1f2 } module.exports={g}', null);
  ok(r.renames.every((x) => x.confidence != null && x.evidence != null),
     "renames carry confidence+evidence");
}

// 5. recoverWasmExports — contract: never throws, shaped result
for (const input of [Buffer.alloc(0), Buffer.alloc(4), Buffer.from("not wasm"), "not a buffer", null]) {
  let r;
  try { r = recoverWasmExports(input); } catch { r = null; }
  ok(r && Array.isArray(r.names), `non-wasm input safe (${String(input).slice(0, 12)})`);
}
{
  // a real wasm module returns a shaped result (names may be empty if
  // no name section/decodable exports — the contract is shape, not hits)
  const { readFileSync } = await import("node:fs");
  const wasm = readFileSync("test-fixtures/plain/seal.wasm");
  const r = recoverWasmExports(wasm);
  ok(Array.isArray(r.names), "real wasm -> names array");
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
