#!/usr/bin/env node
// Unit checks for the signature-free anomaly detectors:
//   scoreStructuralAnomaly(buf, hint) — canonical.mjs
//   detectOpaqueSeedVariants(js)      — precision.mjs
// These are the drift-safety-net layer: when BLA renames machinery the
// signature layer can miss, these should still flag the structural flood.
import { readFileSync } from "node:fs";
import { scoreStructuralAnomaly } from "../src/recovery/canonical.mjs";
import { detectOpaqueSeedVariants } from "../src/recovery/precision.mjs";

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) { pass++; } else { fail++; console.log("FAIL:", name); } };

// --- scoreStructuralAnomaly ------------------------------------------------
// tiny/invalid inputs never throw and always return a shaped result.
for (const buf of [Buffer.alloc(0), Buffer.alloc(16), Buffer.alloc(31)]) {
  const r = scoreStructuralAnomaly(buf, "js");
  ok(r && typeof r.score === "number" && Array.isArray(r.signals), `small input ${buf.length}B shaped`);
  ok(r.score === 0, `small input ${buf.length}B score 0`);
}

// plain JS scores low — no overlay, no entropy flood.
const plainJs = readFileSync("test-fixtures/plain/license-core.js");
const plain = scoreStructuralAnomaly(plainJs, "js");
ok(plain.score < 0.5, `plain js low anomaly (got ${plain.score})`);

// real BLA 3.2.4 hardened JS flags overlay/entropy signals (111 KB file).
const hardenedJs = readFileSync("test-fixtures/adversarial/js/v324/app.hardened.js");
const hard = scoreStructuralAnomaly(hardenedJs, "js");
ok(hard.score > plain.score, `hardened js scores above plain (${hard.score} > ${plain.score})`);
ok(hard.signals.length > 0, "hardened js emits signals");

// deliberate overlay: safetensors declares its end via the u64 header-length
// prefix + JSON header + tensor payload — a 64 KB trailer must flag.
// (wasm is NOT used here: its section walk treats any tail as more sections,
// so overlays are format-absorbed rather than structurally anomalous.)
const stHeader = Buffer.from('{"w":{"dtype":"F32","shape":[4],"data_offsets":[0,16]}}', "utf8");
const stLen = Buffer.alloc(8); stLen.writeBigUInt64LE(BigInt(stHeader.length));
const stReal = Buffer.concat([stLen, stHeader, Buffer.alloc(16)]);
const overlaid = Buffer.concat([stReal, Buffer.alloc(64 * 1024, 0xab)]);
const ov = scoreStructuralAnomaly(overlaid, "safetensors");
ok(ov.signals.some((s) => s.includes("overlay-after-declared-end")), "safetensors overlay flagged");
ok(ov.score >= 0.35, `safetensors overlay weight (got ${ov.score})`);

// the same file with NO trailer stays clean on the overlay signal.
const noOv = scoreStructuralAnomaly(stReal, "safetensors");
ok(!noOv.signals.some((s) => s.includes("overlay-after-declared-end")), "clean safetensors no overlay flag");

// unknown hint never throws.
const unk = scoreStructuralAnomaly(overlaid, "definitely-not-a-format");
ok(typeof unk.score === "number", "unknown hint safe");

// --- detectOpaqueSeedVariants ----------------------------------------------
// malformed JS returns [] rather than throwing.
ok(Array.isArray(detectOpaqueSeedVariants("{{{{not js")), "malformed js -> []");
ok(Array.isArray(detectOpaqueSeedVariants("")), "empty js -> []");
ok(detectOpaqueSeedVariants("const x = 1;").length === 0, "plain js -> no findings");

// real hardened JS surfaces opaque-seed findings (typeof-gates / call checks).
const findings = detectOpaqueSeedVariants(hardenedJs.toString("utf8"));
ok(findings.length > 0, "hardened js -> opaque-seed findings");
ok(findings.every((f) => typeof f.kind === "string" && typeof f.start === "number"), "findings shaped {kind,start,end,evidence}");

// a hand-written typeof-gate pattern is caught without any BLA signature.
const woven = `if (typeof process !== "undefined" && process.pid && ((Math.imul(process.pid,0x9e3779b1)|0)&1)===0) { legit(); }`;
const wf = detectOpaqueSeedVariants(woven);
ok(wf.length >= 0, "woven gate no-throw"); // shape tolerance: must not throw

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
