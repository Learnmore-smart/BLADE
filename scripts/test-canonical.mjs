#!/usr/bin/env node
// Unit checks for canonical.mjs counter-shield + precision.mjs surgical
// splice helpers.
import { emitRuntimeCounterShield } from "../src/recovery/canonical.mjs";
import { pycSurgicalSpans } from "../src/recovery/precision.mjs";

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) pass++; else { fail++; console.log("FAIL:", name); } };

// --- emitRuntimeCounterShield -------------------------------------------------
{
  const r = emitRuntimeCounterShield(["_shadowVault_", "scc_probe", "labyrinthDispatch_7f"]);
  ok(r && typeof r.fridaScript === "string" && typeof r.cdpNotes === "string" && typeof r.teeStubSurface === "string",
     "counter-shield emits three artifacts");
  ok(Array.isArray(r.families), "families array");
  ok(r.families.length > 0, "real machinery hints resolve families");
  ok(r.fridaScript.includes("Interceptor") || r.fridaScript.length > 200, "frida script non-trivial");
}
{
  // orphan hints matching no family -> empty families, artifacts still emit
  const r = emitRuntimeCounterShield(["unknown_thing", "another"]);
  ok(Array.isArray(r.families), "orphan hints -> families array");
}
{
  // empty hints: artifacts still shaped (documented degenerate case)
  const r = emitRuntimeCounterShield([]);
  ok(typeof r.fridaScript === "string" && Array.isArray(r.families), "empty hints safe");
}

// --- pycSurgicalSpans ---------------------------------------------------------
{
  // no removals -> passthrough the ORIGINAL buffer, 100% preserved
  const orig = Buffer.from([0x6f, 0x0d, 0x0a, 0x00, 1, 2, 3, 4]);
  const deh = Buffer.from([9, 9]);
  const r = pycSurgicalSpans(orig, deh, []);
  ok(r.buf === orig && r.bytePreservedPct === 100 && r.spliced === false, "no removals -> orig passthrough");
}
{
  // out-of-bounds removal -> honest fallback to dehardened buf with note
  const orig = Buffer.from([0x6f, 0x0d, 0x0a, 0x00, 1, 2, 3, 4]);
  const deh = Buffer.from([9]);
  const r = pycSurgicalSpans(orig, deh, [[2, 99]]);
  ok(r.buf === deh && typeof r.note === "string" && r.spliced === false, "out-of-bounds -> fallback+note");
}
{
  // overlapping/touching ranges are merged before splicing — must not
  // double-count; either spliced:true or a fallback note.
  const orig = Buffer.concat([Buffer.from([0x6f, 0x0d, 0x0a, 0x00]), Buffer.alloc(60, 7)]);
  const deh = Buffer.alloc(20, 3);
  const r = pycSurgicalSpans(orig, deh, [[10, 20], [18, 30]]);
  ok(r.buf && typeof r.bytePreservedPct === "number", "overlapping ranges handled");
  ok(r.spliced === true || typeof r.note === "string", "merge -> splice-or-note");
}
{
  // non-pyc magic (no 0x0d0a at [2:4]) with removals -> layout fallback
  const orig = Buffer.alloc(64, 0xaa);
  const r = pycSurgicalSpans(orig, Buffer.alloc(8), [[4, 10]]);
  ok(r.spliced === false && typeof r.note === "string", "non-pyc -> layout fallback note");
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
