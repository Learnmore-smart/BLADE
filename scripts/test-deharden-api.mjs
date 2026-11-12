#!/usr/bin/env node
// API-level unit checks for dehardenJs — synthetic hardened shapes fed
// through the library directly (no CLI), asserting code+report contract.
import { readFileSync } from "node:fs";
import { dehardenJs } from "../src/js-deharden.mjs";

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) pass++; else { fail++; console.log("FAIL:", name); } };

// --- clean passthrough -----------------------------------------------------
{
  const src = "const x = 1;\nmodule.exports = x;\n";
  const r = dehardenJs(src);
  ok(r.code === src, "clean passthrough byte-exact");
  ok(r.report.hardened === false, "clean not flagged");
  ok(/no BLA markers/.test(r.report.note), "api note populated");
  ok(r.report.bytesIn === src.length && r.report.bytesOut === src.length, "byte accounting");
}

// --- embedded payload flag ---------------------------------------------------
{
  const src = "const x=1;\nPK\x03\x04payload";
  const r = dehardenJs(src);
  ok(r.report.appendedPayload?.kind === "zip", "polyglot flagged");
  ok(/kept verbatim/.test(r.report.note), "payload note");
  ok(r.code === src, "payload bytes kept");
}

// --- unparseable passthrough ---------------------------------------------------
{
  const src = "function {{{ nonsense (\x00\x01\x02";
  const r = dehardenJs(src);
  ok(r.code === src, "unparseable passes through");
  ok(r.report.hardened === false, "unparseable not flagged hardened");
}

// --- bind-scope IIFE removal ---------------------------------------------------
{
  const src = `(function BLA_BIND_SCOPE_CHECK() {
  "use strict";
  const allowed = ["internal.corp.example"];
  const host = typeof location !== "undefined" ? location.hostname : "";
  const today = new Date().toISOString().slice(0, 10);
  if (!allowed.includes(host) || today > "2099-01-01") {
    throw new Error("BLA bind-scope: execution refused outside licensed domain");
  }
})();
const real = 42;
export default real;
`;
  const r = dehardenJs(src);
  ok(!r.code.includes("BLA_BIND_SCOPE_CHECK"), "bind-scope IIFE removed");
  ok(r.code.includes("real"), "real code kept");
  ok(r.report.bindScopeCheckRemoved >= 1, "bind-scope counter");
}

// --- real hardened fixture ---------------------------------------------------
{
  const src = readFileSync("test-fixtures/hardened/electron-bridge.js", "utf8");
  const r = dehardenJs(src, { filename: "electron-bridge.js" });
  ok(r.report.hardened === true, "real hardened flagged");
  ok(r.code.length < src.length * 0.2, `hardened ${src.length} -> ${r.code.length}`);
  ok(!r.code.includes("_interlockSafetyCorpus_"), "corpus gone");
  ok(!r.code.includes("labyrinthDispatch_"), "dispatch gone");
  ok(r.report.bytesOut === Buffer.byteLength(r.code, "utf8") || r.report.bytesOut === r.code.length, "bytesOut consistent");
}

// --- idempotent: cleaning cleaned output is a no-op ---------------------------
{
  const src = readFileSync("test-fixtures/hardened/electron-bridge.js", "utf8");
  const once = dehardenJs(src);
  const twice = dehardenJs(once.code);
  ok(twice.code === once.code, "idempotent second pass");
}

// --- counters shape ------------------------------------------------------------
{
  const r = dehardenJs("const x=1;\n");
  for (const k of ["removedOpaqueFalse", "injectedFunctionsRemoved", "decryptedStrings", "bytesIn", "bytesOut"]) {
    ok(typeof r.report[k] === "number", `report.${k} is number`);
  }
  ok(Array.isArray(r.report.mixedStatementsKept), "mixedStatementsKept array");
  ok(Array.isArray(r.report.renamedBindings), "renamedBindings array");
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
