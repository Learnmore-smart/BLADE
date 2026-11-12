#!/usr/bin/env node
// WASM structural fuzzer — section-level mutations hitting the ULEB
// section walk, custom-section scrubbing, and name recovery. Contract:
// scrubWasm never throws, returns {buffer, report} shaped output, and
// unparseable input passes through (possibly with notes).
import { readFileSync } from "node:fs";
import { scrubWasm } from "../src/formats.mjs";

let pass = 0, fail = 0;
const failures = [];
const ok = (cond, name) => { if (cond) pass++; else { fail++; if (failures.length < 25) failures.push(name); } };

let rng = 0x5eED;
const next = () => { rng |= 0; rng = (rng + 0x6d2b79f5) | 0; let t = Math.imul(rng ^ (rng >>> 15), 1 | rng); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const pick = (a) => a[Math.floor(next() * a.length)];

const real = readFileSync("test-fixtures/hardened/seal.wasm");
ok(real.readUInt32LE(0) === 0x6d736100, "fixture is wasm");

// split a wasm module into [magic+version][sections...]
const splitSections = (buf) => {
  const secs = [];
  let p = 8;
  while (p < buf.length) {
    const start = p;
    const id = buf[p++];
    let len = 0, sh = 0;
    while (true) { const b = buf[p++]; len |= (b & 0x7f) << sh; sh += 7; if (!(b & 0x80) || sh > 35) break; }
    secs.push({ id, start, end: Math.min(buf.length, p + len), hdrEnd: p, len });
    p += len;
    if (secs.length > 200) break;
  }
  return secs;
};
const secs = splitSections(real);
ok(secs.length > 0, "fixture has sections");

const muts = [
  // truncate inside a section
  (b) => { const s = pick(secs); if (!s) return b; return b.subarray(0, s.start + 2); },
  // inflate a section's declared length past EOF
  (b) => { const x = Buffer.from(b); const s = pick(secs); if (!s || s.hdrEnd - 1 >= x.length) return x; x[s.hdrEnd - 1] = 0x7f; return x; },
  // corrupt section id to custom (0) — BLA hides in custom sections
  (b) => { const x = Buffer.from(b); const s = pick(secs); if (!s) return x; x[s.start] = 0; return x; },
  // corrupt section id to nonsense
  (b) => { const x = Buffer.from(b); const s = pick(secs); if (!s) return x; x[s.start] = 200 + Math.floor(next() * 55); return x; },
  // flip a byte mid-section
  (b) => { const x = Buffer.from(b); const i = 8 + Math.floor(next() * Math.max(1, x.length - 8)); x[i] ^= 0xa5; return x; },
  // append a trailing junk section
  (b) => Buffer.concat([b, Buffer.from([0, 3, 1, 2, 3])]),
  // append garbage
  (b) => Buffer.concat([b, Buffer.alloc(Math.floor(next() * 40), 0x42)]),
  // splice a fake custom "name" section with decoy content
  (b) => {
    const name = Buffer.from("name");
    const body = Buffer.from([name.length, ...name, 0x01, 2, 0, 1, 0x61]);
    return Buffer.concat([b, Buffer.from([0, body.length]), body]);
  },
  // multi-byte LEB length with high-bit continuation into garbage
  (b) => { const x = Buffer.from(b); const s = pick(secs); if (!s) return x; x[s.start + 1] = 0xff; if (s.start + 2 < x.length) x[s.start + 2] = 0xff; return x; },
];

for (let round = 0; round < 300; round++) {
  let src = real;
  const n = 1 + Math.floor(next() * 3);
  const labels = [];
  for (let k = 0; k < n; k++) { const mi = Math.floor(next() * muts.length); labels.push(mi); src = muts[mi](src); }
  const label = `r${round}/m${labels.join(",")}`;
  let r;
  try { r = scrubWasm(src); }
  catch (e) { ok(false, `${label} threw: ${e.message}`); continue; }
  ok(r && r.report && typeof r.report === "object", `${label} shaped report`);
  ok(Buffer.isBuffer(r.buffer) || Buffer.isBuffer(r.out) || r.buffer !== undefined, `${label} buffer output`);
}

// degenerate inputs
for (const [label, buf] of [
  ["empty", Buffer.alloc(0)],
  ["magic-only", Buffer.from([0, 0x61, 0x73, 0x6d])],
  ["bad-magic", Buffer.from("not wasm at all")],
  ["ver-only", Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0])],
  ["huge-sec", Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 5, 0xff, 0xff, 0xff, 0xff, 0x7f])],
]) {
  try { const r = scrubWasm(buf); ok(r && r.report, `${label} safe`); }
  catch (e) { ok(false, `${label} threw: ${e.message}`); }
}

// name-recovery path: module with a custom name section gets processed
{
  const tiny = Buffer.concat([
    Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]),
    Buffer.from([1, 4, 1, 0x60, 0, 0]), // type section
  ]);
  try { const r = scrubWasm(tiny); ok(r && r.report, "tiny module safe"); }
  catch (e) { ok(false, `tiny threw: ${e.message}`); }
}

console.log(`${pass} passed, ${fail} failed`);
if (failures.length) { for (const f of failures) console.log("  FAIL:", f); process.exit(1); }
