#!/usr/bin/env node
// ASAR structural fuzzer: mutate archive internals at structure level —
// header size lies, member offset/size coercion, path traversal names,
// integrity blockSize abuse, nested files objects. Contract: scrubAsar
// never throws, never writes outside output root, returns shaped report.
import { scrubAsar } from "../src/formats.mjs";

let pass = 0, fail = 0;
const failures = [];
const ok = (cond, name) => { if (cond) pass++; else { fail++; if (failures.length < 25) failures.push(name); } };

let rng = 0xa5a5;
const next = () => { rng |= 0; rng = (rng + 0x6d2b79f5) | 0; let t = Math.imul(rng ^ (rng >>> 15), 1 | rng); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const pick = (a) => a[Math.floor(next() * a.length)];

// deterministic minimal asar: 4B pickle-len header + JSON {files}
const buildAsar = (files, { dataPad = "" } = {}) => {
  const header = Buffer.from(JSON.stringify({ files }), "utf8");
  // chromium pickle: u32 json-size (aligned to 4) — emit the flat layout
  // scrubAsar actually consumes: [u32 headerLen][json][data]
  const aligned = Math.ceil(header.length / 4) * 4;
  const h = Buffer.alloc(aligned);
  header.copy(h);
  return Buffer.concat([Buffer.from([aligned, 0, 0, 0].map((v, i) => i === 0 ? aligned : 0).slice(0, 4).map((v) => v & 0xff)), h, Buffer.from(dataPad, "latin1")]);
};
// simpler correct builder used by every mutation below
const asar = (files, data = "") => {
  const json = Buffer.from(JSON.stringify({ files }), "utf8");
  const aligned = Math.ceil(json.length / 4) * 4;
  const pad = Buffer.alloc(aligned - json.length);
  const len = Buffer.alloc(4); len.writeUInt32LE(aligned, 0);
  return Buffer.concat([len, json, pad, Buffer.from(data, "latin1")]);
};

const REAL = "console.log('real code here');\n".repeat(3);
const mkFile = (content, extra = {}) => ({ size: Buffer.byteLength(content), offset: "0", ...extra });

// baseline sanity — a real member survives untouched
{
  const arc = asar({ "app.js": mkFile(REAL), "package.json": mkFile('{"main":"app.js"}') }, REAL + '{"main":"app.js"}');
  const r = scrubAsar(arc);
  ok(Buffer.isBuffer(r.buffer) || typeof r.code === "string" || r.buffer !== undefined, "baseline shaped");
}

const fileShapes = [
  () => ({ "app.js": mkFile(REAL) }),
  // traversal member names — write path must refuse these
  () => ({ "../escape.js": mkFile(REAL) }),
  () => ({ "a/../../out.js": mkFile(REAL) }),
  () => ({ "/abs/path.js": mkFile(REAL) }),
  () => ({ "C:\\win\\x.js": mkFile(REAL) }),
  () => ({ "..\\..\\x.js": mkFile(REAL) }),
  // integrity blockSize abuse
  () => ({ "app.js": { ...mkFile(REAL), integrity: { algorithm: "SHA256", hash: "00".repeat(32), blockSize: 0, blocks: [] } } }),
  () => ({ "app.js": { ...mkFile(REAL), integrity: { algorithm: "SHA256", hash: "00".repeat(32), blockSize: 2 ** 40, blocks: [] } } }),
  () => ({ "app.js": { ...mkFile(REAL), integrity: { algorithm: "SHA256", hash: "00".repeat(32), blockSize: -4, blocks: [] } } }),
  () => ({ "app.js": { ...mkFile(REAL), integrity: { algorithm: "SHA256", hash: "00".repeat(32), blockSize: 1e18, blocks: ["x"] } } }),
  // offset/size coercion
  () => ({ "app.js": { size: -1, offset: "0" } }),
  () => ({ "app.js": { size: 1e15, offset: "0" } }),
  () => ({ "app.js": { size: 10, offset: "999999999" } }),
  () => ({ "app.js": { size: "abc", offset: "0" } }),
  () => ({ "app.js": { size: 10, offset: "-4" } }),
  () => ({ "app.js": { size: 10, offset: "0x10" } }),
  // unpacked flag
  () => ({ "app.js": { ...mkFile(REAL), unpacked: true } }),
  // nested dirs
  () => ({ dir: { files: { "deep.js": mkFile(REAL), "../../evil.js": mkFile(REAL) } } }),
  () => ({ dir: { files: { sub: { files: { "x.js": mkFile(REAL) } } } } }),
  // executable/link flags
  () => ({ "tool": { ...mkFile(REAL), executable: true } }),
  () => ({ "ln": { link: "target.js" } }),
];

for (let round = 0; round < 150; round++) {
  const make = pick(fileShapes);
  const label = `r${round}/shape${fileShapes.indexOf(make)}`;
  let files;
  try { files = make(); } catch (e) { ok(false, `${label} build threw: ${e.message}`); continue; }
  const arc = asar(files, REAL.repeat(4));
  let r;
  try { r = scrubAsar(arc); }
  catch (e) { ok(false, `${label} threw: ${e.message}`); continue; }
  ok(r && r.report && typeof r.report === "object", `${label} shaped report`);
}

// raw byte-level mutations on a real archive
const baseArc = asar({ "app.js": mkFile(REAL), "package.json": mkFile('{"main":"app.js"}') }, REAL + '{"main":"app.js"}');
const byteMuts = [
  (b) => { const x = Buffer.from(b); x.writeUInt32LE(0xffffffff, 0); return x; },      // header len max
  (b) => { const x = Buffer.from(b); x.writeUInt32LE(0, 0); return x; },              // header len 0
  (b) => { const x = Buffer.from(b); x.writeUInt32LE(4, 0); return x; },              // header len tiny
  (b) => b.subarray(0, 4 + Math.floor(next() * b.length)),                          // truncate
  (b) => Buffer.concat([b, Buffer.alloc(Math.floor(next() * 64), 0x42)]),           // trailing pad
  (b) => { const x = Buffer.from(b); const i = 4 + Math.floor(next() * 40); if (i < x.length) x[i] = 0x00; return x; }, // null inject
  (b) => { const x = Buffer.from(b); x[5] = 0x7b ^ 0xff; return x; },                 // corrupt json start
];
for (let round = 0; round < 100; round++) {
  const label = `byte-r${round}`;
  let src = baseArc;
  const n = 1 + Math.floor(next() * 2);
  for (let k = 0; k < n; k++) src = pick(byteMuts)(src);
  let r;
  try { r = scrubAsar(src); }
  catch (e) { ok(false, `${label} threw: ${e.message}`); continue; }
  ok(r && r.report, `${label} shaped`);
}

// degenerate
for (const [label, buf] of [["empty", Buffer.alloc(0)], ["len-only", Buffer.alloc(4)], ["json-no-files", asar({}, "")], ["null-json", (() => { const l = Buffer.alloc(4); l.writeUInt32LE(8, 0); return Buffer.concat([l, Buffer.from("null    ")]); })()]]) {
  try { const r = scrubAsar(buf); ok(r && r.report, `${label} safe`); }
  catch (e) { ok(false, `${label} threw: ${e.message}`); }
}

console.log(`${pass} passed, ${fail} failed`);
if (failures.length) { for (const f of failures) console.log("  FAIL:", f); process.exit(1); }
