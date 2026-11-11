// Adversarial tests for BLADE's WASM scrubber (src/formats.mjs scrubWasm).
// Builds wasm bytes by hand, runs the scrubber, validates IN and OUT with V8.
// Report only — no fixes.
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { scrubWasm } from "../../../src/formats.mjs";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const HEADER = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

// ---------- binary helpers ----------
const u8 = (n) => Buffer.from([n & 0xff]);
const leb = (n) => {
  const out = [];
  let v = n >>> 0;
  do { let b = v & 0x7f; v >>>= 7; if (v) b |= 0x80; out.push(b); } while (v);
  return Buffer.from(out);
};
// Non-canonical 5-byte LEB (spec-legal max length for u32).
const lebPad5 = (n) => {
  const out = [];
  let v = n >>> 0;
  for (let i = 0; i < 4; i++) { out.push((v & 0x7f) | 0x80); v >>>= 7; }
  out.push(v & 0x7f);
  return Buffer.from(out);
};
const name = (s) => Buffer.concat([leb(Buffer.byteLength(s, "utf8")), Buffer.from(s, "utf8")]);
const vec = (items) => Buffer.concat([leb(items.length), ...items]);
const section = (id, payload, sizeOverride) =>
  Buffer.concat([u8(id), leb(sizeOverride ?? payload.length), payload]);
const sectionRawSize = (id, sizeBytes, payload) => Buffer.concat([u8(id), sizeBytes, payload]);
const customSec = (nm, content, sizeOverride) =>
  section(0, Buffer.concat([name(nm), content]), sizeOverride);

const I32 = 0x7f, FUNCREF = 0x70, FUNCTYPE = 0x60;
const typeSec = (types) => section(1, vec(types.map(([p, r]) =>
  Buffer.concat([u8(FUNCTYPE), vec(p.map(u8)), vec(r.map(u8))]))));
const importSec = (imports) => section(2, vec(imports.map(([m, n, kind, desc]) =>
  Buffer.concat([name(m), name(n), u8(kind), desc]))));
const funcSec = (tidx) => section(3, vec(tidx.map(leb)));
const tableSec = (min) => section(4, vec([Buffer.concat([u8(FUNCREF), u8(0x00), leb(min)])]));
const memSec = (min) => section(5, vec([Buffer.concat([u8(0x00), leb(min)])]));
const globalSec = () => section(6, vec([Buffer.from([I32, 0x00, 0x41, 0x00, 0x0b])]));
const exportSec = (entries) => section(7, vec(entries.map(([nm, kind, idx]) =>
  Buffer.concat([name(nm), u8(kind), leb(idx)]))));
const exportSecRaw = (payload) => section(7, payload);
const elemSec = (fidx) => section(9, vec([Buffer.concat([u8(0x00), Buffer.from([0x41, 0x00, 0x0b]), vec(fidx.map(leb))])]));
const codeSec = (bodies) => section(10, vec(bodies.map((b) => Buffer.concat([leb(b.length), b]))));
const fnBody = (instrs) => Buffer.concat([u8(0x00), instrs, u8(0x0b)]); // 0 locals
const BODY_ADD = fnBody(Buffer.from([0x20, 0x00, 0x20, 0x01, 0x6a])); // (i32,i32)->i32
const BODY_42 = fnBody(Buffer.from([0x41, 0x2a]));                    // ()->i32
const TYPES = [[[I32, I32], [I32]], [[], [I32]]];
const wasm = (...secs) => Buffer.concat([HEADER, ...secs]);

// BLA-shaped names (from vendor/bla/src/shields/formats/wasm.ts):
//  decoy export : `enclave_export_${prng.hex(4)}_${i}_${"e".repeat(pad)}`
//  renamed real : `ops_${hex(4)}_${identifier({style:"snake",hint:"dispatch"})}`
const decoy = (tag, i, pad) => `enclave_export_${tag}_${i}_${"e".repeat(pad)}`;

// ---------- fixtures ----------
const fixtures = {};

// CASE 1: real export named `enclave_export_verify` — regex needs hex{4}_digits_epad;
// `verify` is not 4-hex + `_`, so expected KEEP.
fixtures["case1-real-enclave-export"] = wasm(
  typeSec(TYPES), funcSec([0, 1]),
  exportSec([["verify", 0, 0], ["enclave_export_verify", 0, 0]]),
  codeSec([BODY_ADD, BODY_42]),
);

// CASE 1b: real exports that DO match the decoy regex shape — name-only filter drops them.
fixtures["case1b-real-decoy-shaped-exports"] = wasm(
  typeSec(TYPES), funcSec([0, 1]),
  exportSec([
    ["verify", 0, 0],
    ["enclave_export_dead_1_eeeeeeeeeeeeeeee", 0, 0], // real name, decoy shape
    ["enclave_export_AB12_7_eee", 0, 0],              // uppercase hex tag, /i
    ["enclave_unseal_session", 0, 1],                 // ^enclave_unseal_
    ["canary_export_status", 0, 1],                   // ^canary_export
    ["enclave_export_verify_2024", 0, 1],             // near-miss: _2 not hex4_digits
  ]),
  codeSec([BODY_ADD, BODY_42]),
);

// Control: genuine BLA decoys + renamed ops_* exports (case 4 folded in here too)
fixtures["case1c-real-decoys-and-renames"] = wasm(
  typeSec(TYPES), funcSec([0, 1]),
  exportSec([
    ["verify", 0, 0],
    [decoy("9f3a", 0, 16), 0, 0],
    [decoy("9f3a", 1, 12000), 0, 1],   // bankrupt 12KiB pad
    ["ops_9f3a_dispatch_quorum_seal", 0, 0],
    ["ops_7b1c_dispatch_ring_verify", 0, 1],
  ]),
  codeSec([BODY_ADD, BODY_42]),
);

// CASE 2: legit custom section names that collide with BLA namespaces.
const funcNamesSubsec = Buffer.concat([
  u8(1), leb(15),
  vec([Buffer.concat([leb(0), name("verify")]), Buffer.concat([leb(1), name("answer")])]),
]);
fixtures["case2-legit-custom-names"] = wasm(
  typeSec(TYPES), funcSec([0, 1]),
  exportSec([["verify", 0, 0]]),
  codeSec([BODY_ADD, BODY_42]),
  customSec("bla.config", Buffer.from('{"opt":true}')),
  customSec("enclave.flags", Buffer.from("mode=prod")),
  customSec("enclave_flags", Buffer.from("x")),
  customSec("canary.config", Buffer.from("k=v")),
  customSec("name", funcNamesSubsec),          // real WABT name section
  customSec("producers", Buffer.from("\x01\x07\x04lang\x04rust")),
  customSec("foo.bla", Buffer.from("ends-in-dot-bla")),
  customSec("enclaveX", Buffer.from("no-separator")),     // should KEEP
  customSec("names", Buffer.from("not-exact-name")),      // should KEEP
  customSec("dylink.0", Buffer.from("dylink")),
  customSec("target_features", Buffer.from("+simd128")),
);

// CASE 3a: last section declares size past EOF (truncated decoy trailer).
fixtures["case3a-oversize-last"] = wasm(
  typeSec(TYPES), funcSec([0, 1]),
  exportSec([["verify", 0, 0]]),
  codeSec([BODY_ADD, BODY_42]),
  customSec("bla.trunc", Buffer.from("short"), 0xffff), // declared 65535, real 14
);

// CASE 3b: mid-file custom section with oversized declared length swallows
// the code + name sections into its payload. Non-decoy name => kept.
fixtures["case3b-oversize-swallow-keep"] = wasm(
  typeSec(TYPES), funcSec([0, 1]),
  exportSec([["verify", 0, 0]]),
  customSec("zzz.tail", Buffer.from("content"), 0x8000),
  codeSec([BODY_ADD, BODY_42]),
  customSec("name", funcNamesSubsec),
);
// Same but decoy-named => dropped, taking the code section with it.
fixtures["case3c-oversize-swallow-drop"] = wasm(
  typeSec(TYPES), funcSec([0, 1]),
  exportSec([["verify", 0, 0]]),
  customSec("bla.blob", Buffer.from("content"), 0x8000),
  codeSec([BODY_ADD, BODY_42]),
  customSec("name", funcNamesSubsec),
);

// CASE 3d: non-canonical 5-byte LEB section sizes everywhere (spec-legal).
function lebLenAt(buf, off) { // canonical-LEB length reader for the builder
  let i = off;
  while (buf[i++] & 0x80);
  return i - off;
}
{
  const payloadOf = (sec) => sec.subarray(1 + lebLenAt(sec, 1));
  const secP = (id, sec) => sectionRawSize(id, lebPad5(payloadOf(sec).length), payloadOf(sec));
  fixtures["case3d-leb5-padded"] = wasm(
    secP(1, typeSec(TYPES)),
    secP(3, funcSec([0, 1])),
    secP(7, exportSec([["verify", 0, 0]])),
    secP(10, codeSec([BODY_ADD, BODY_42])),
  );
}

// CASE 3e: 6-byte LEB, 6th byte = 0x00 — spec-invalid (u32 LEB max 5 bytes) but
// the scrubber's reader tolerates it and still computes the right value (12).
fixtures["case3e-leb6-zero-sixth"] = wasm(
  typeSec(TYPES), funcSec([0, 1]),
  exportSec([["verify", 0, 0]]),
  sectionRawSize(0, Buffer.from([0x8c, 0x80, 0x80, 0x80, 0x80, 0x00]),
    Buffer.concat([name("zzz"), Buffer.from("12345678")])), // payload len = 12
  codeSec([BODY_ADD, BODY_42]),
);
// CASE 3f: 6-byte LEB with non-zero 6th byte — scrubber's <<35 wraps to <<3,
// mis-sizing the section and derailing the section walk.
fixtures["case3f-leb6-nonzero-sixth"] = wasm(
  typeSec(TYPES), funcSec([0, 1]),
  exportSec([["verify", 0, 0]]),
  sectionRawSize(0, Buffer.from([0x80, 0x80, 0x80, 0x80, 0x80, 0x05]), // => 5<<3 = 40
    Buffer.concat([name("zzz"), Buffer.from("payload-bytes-here!")])),
  codeSec([BODY_ADD, BODY_42]),
);

// CASE 3g: custom sections interleaved between standard sections + empty custom.
fixtures["case3g-interleaved"] = wasm(
  typeSec(TYPES),
  customSec("bla.a", Buffer.from("early-decoy")),
  funcSec([0, 1]),
  customSec("zzz.mid", Buffer.from("mid-keeper")),
  exportSec([["verify", 0, 0]]),
  codeSec([BODY_ADD, BODY_42]),
  customSec("name", funcNamesSubsec),
  section(0, Buffer.from([0x00])),        // custom section with EMPTY name (legal)
  customSec("dylink.0", Buffer.from("d")),
);

// CASE 3h: export section whose count overstates real entries (truncated export).
{
  const good = Buffer.concat([name("verify"), u8(0), leb(0)]);
  const partial = Buffer.concat([name("encl"), u8(0)]); // missing idx LEB
  fixtures["case3h-export-count-overrun"] = wasm(
    typeSec(TYPES), funcSec([0, 1]),
    exportSecRaw(Buffer.concat([leb(5), good, partial])),
    codeSec([BODY_ADD, BODY_42]),
  );
}

// CASE 4: BLA-renamed real exports (ops_*_dispatch_*) must be KEPT — done above
// in case1c; this isolates it on a clean module.
fixtures["case4-renamed-exports"] = wasm(
  typeSec(TYPES), funcSec([0, 1]),
  exportSec([
    ["ops_9f3a_dispatch_quorum_seal", 0, 0],
    ["ops_7b1c_dispatch_ring_verify", 0, 1],
    ["ops_deadbeef", 0, 0],
  ]),
  codeSec([BODY_ADD, BODY_42]),
);

// CASE 5 + 6: table/mem/global exports + active elem referencing func indices
// (incl. an imported func) + decoy exports. Elem refs are index-based, so decoy
// removal cannot orphan them; import/code must pass through byte-identical.
fixtures["case5-elem-table-global-imports"] = wasm(
  typeSec(TYPES),
  importSec([["env", "hook", 0, u8(0)]]), // func index 0 = imported
  funcSec([0, 1]),                         // local funcs = indices 1,2
  tableSec(3), memSec(1), globalSec(),
  exportSec([
    ["tbl", 1, 0], ["mem", 2, 0], ["g", 3, 0],
    ["verify", 0, 1],
    [decoy("c0de", 0, 16), 0, 1],
    [decoy("c0de", 1, 48), 0, 2],
  ]),
  elemSec([0, 1, 2]),
  codeSec([BODY_ADD, BODY_42]),
);

// CASE 5b: export section contains ONLY decoys -> rebuilt with count 0.
fixtures["case5b-only-decoy-exports"] = wasm(
  typeSec(TYPES), funcSec([0, 1]),
  exportSec([[decoy("beef", 0, 16), 0, 0], [decoy("beef", 1, 16), 0, 1]]),
  codeSec([BODY_ADD, BODY_42]),
);

// ---------- runner ----------
function parseExportNames(buf) {
  // cheap export-name lister for verification (uses same loose walk)
  let off = 8; const names = [];
  while (off < buf.length) {
    const id = buf[off++];
    let v = 0, s = 0;
    for (;;) { const b = buf[off++]; v |= (b & 0x7f) << s; if (!(b & 0x80)) break; s += 7; }
    const end = off + (v >>> 0);
    if (id === 7 && end <= buf.length) {
      let p = off;
      let cnt = 0, cs = 0;
      for (;;) { const b = buf[p++]; cnt |= (b & 0x7f) << cs; if (!(b & 0x80)) break; cs += 7; }
      for (let i = 0; i < cnt; i++) {
        let nl = 0, ns = 0;
        for (;;) { const b = buf[p++]; nl |= (b & 0x7f) << ns; if (!(b & 0x80)) break; ns += 7; }
        const nm = buf.subarray(p, p + nl).toString("utf8"); p += nl;
        const kind = buf[p++];
        let idx = 0, is2 = 0;
        for (;;) { const b = buf[p++]; idx |= (b & 0x7f) << is2; if (!(b & 0x80)) break; is2 += 7; }
        names.push(`${nm} (kind ${kind} idx ${idx})`);
      }
    }
    off = end;
  }
  return names;
}
function sectionPayload(buf, wantId) {
  let off = 8;
  while (off < buf.length) {
    const id = buf[off++];
    let v = 0, s = 0;
    for (;;) { const b = buf[off++]; v |= (b & 0x7f) << s; if (!(b & 0x80)) break; s += 7; }
    const end = off + (v >>> 0);
    if (id === wantId) return buf.subarray(off, Math.min(end, buf.length));
    off = end;
  }
  return null;
}

const results = [];
for (const [fname, buf] of Object.entries(fixtures)) {
  const file = path.join(DIR, fname + ".wasm");
  writeFileSync(file, buf);
  const r = { case: fname, bytesIn: buf.length };
  r.inputValid = WebAssembly.validate(buf);
  try {
    const { buffer: out, report } = scrubWasm(buf);
    r.bytesOut = out.length;
    r.report = report;
    r.outputValid = WebAssembly.validate(out);
    if (!r.outputValid) {
      try { new WebAssembly.Module(out); } catch (e) { r.v8Error = e.message; }
    }
    r.exportsOut = parseExportNames(out);
    r.importSecIdentical = (() => {
      const a = sectionPayload(buf, 2), b = sectionPayload(out, 2);
      return a === null ? b === null : b !== null && a.equals(b);
    })();
    r.codeSecIdentical = (() => {
      const a = sectionPayload(buf, 10), b = sectionPayload(out, 10);
      return a === null ? b === null : b !== null && a.equals(b);
    })();
    writeFileSync(file.replace(/\.wasm$/, ".cleaned.wasm"), out);
    r.status = r.outputValid ? "OK" : "INVALID-MODULE";
  } catch (e) {
    r.status = "CRASH";
    r.error = `${e.name}: ${e.message}`;
  }
  results.push(r);
}

for (const r of results) {
  console.log("=".repeat(72));
  console.log(`${r.case}  [${r.status}]`);
  console.log(`  input v8-valid: ${r.inputValid}   output v8-valid: ${r.outputValid ?? "-"}`);
  if (r.error) console.log(`  scrub threw: ${r.error}`);
  if (r.v8Error) console.log(`  v8 rejected output: ${r.v8Error}`);
  if (r.report) {
    console.log(`  bytes ${r.bytesIn} -> ${r.bytesOut} | sectionsIn ${r.report.sectionsIn}` +
      ` | customDropped ${JSON.stringify(r.report.customSectionsDropped)}` +
      ` | decoyExportsDropped ${r.report.exportDecoysDropped} | exportsKept ${r.report.exportsKept}`);
    console.log(`  import-sec byte-identical: ${r.importSecIdentical} | code-sec byte-identical: ${r.codeSecIdentical}`);
    console.log(`  exports out: ${JSON.stringify(r.exportsOut)}`);
  }
}
console.log("=".repeat(72));
