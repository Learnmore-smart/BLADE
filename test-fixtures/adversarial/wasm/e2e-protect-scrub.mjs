// End-to-end: real BLA protectWasmBinary -> BLADE scrubWasm -> V8 validate.
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { scrubWasm } from "../../../src/formats.mjs";
import { protectWasmBinary } from "../../../vendor/bla/dist/shields/formats/wasm.js";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const HEADER = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
const u8 = (n) => Buffer.from([n & 0xff]);
const leb = (n) => { const o = []; let v = n >>> 0; do { let b = v & 0x7f; v >>>= 7; if (v) b |= 0x80; o.push(b); } while (v); return Buffer.from(o); };
const name = (s) => Buffer.concat([leb(Buffer.byteLength(s)), Buffer.from(s)]);
const vec = (a) => Buffer.concat([leb(a.length), ...a]);
const sec = (id, p) => Buffer.concat([u8(id), leb(p.length), p]);
const I32 = 0x7f;
const base = Buffer.concat([
  HEADER,
  sec(1, vec([Buffer.concat([u8(0x60), vec([u8(I32), u8(I32)]), vec([u8(I32)])]),
              Buffer.concat([u8(0x60), vec([]), vec([u8(I32)])])])),
  sec(3, vec([leb(0), leb(1)])),
  sec(7, vec([Buffer.concat([name("unlock"), u8(0), leb(0)]),
              Buffer.concat([name("seal"), u8(0), leb(1)])])),
  sec(10, vec([
    Buffer.concat([leb(7), u8(0), Buffer.from([0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b])]),
    Buffer.concat([leb(4), u8(0), Buffer.from([0x41, 0x2a, 0x0b])]),
  ])),
]);
console.log("base valid:", WebAssembly.validate(base), base.length, "bytes");

for (const intensity of ["maximum", "bankrupt"]) {
  const { buffer: hardened, exportsRenamed, exportDecoysInjected } =
    protectWasmBinary(base, { intensity, seed: "e2e-test" });
  const f = path.join(DIR, `e2e-${intensity}.wasm`);
  writeFileSync(f, hardened);
  console.log(`\n--- ${intensity} ---`);
  console.log("hardened valid:", WebAssembly.validate(hardened), hardened.length,
    "bytes | renames:", exportsRenamed.map((r) => `${r.from}->${r.to}`).join(", "),
    "| decoys:", exportDecoysInjected);
  const { buffer: out, report } = scrubWasm(hardened);
  writeFileSync(f.replace(".wasm", ".cleaned.wasm"), out);
  console.log("cleaned valid:", WebAssembly.validate(out), out.length, "bytes");
  console.log("report:", JSON.stringify({ dropped: report.customSectionsDropped, decoys: report.exportDecoysDropped, kept: report.exportsKept }));
  const names = [...out.toString("latin1").matchAll(/ops_[0-9a-f]{4}_[a-z_]+/g)].map((m) => m[0]);
  console.log("renamed exports surviving in cleaned:", [...new Set(names)]);
}
