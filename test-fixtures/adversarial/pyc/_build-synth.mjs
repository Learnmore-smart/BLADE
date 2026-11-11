// Build synthetic CPython .pyc fixtures for marshal layouts we have no
// interpreter for: py37 (no posonly), py38-310 (posonly + nlocals),
// py311+ (localsplus; nlocals dropped) with an "unknown-to-us" magic.
// Marshal emitted WITHOUT FLAG_REF — still fully parseable by BLA's Reader
// and BLADE's marshalSkip.
import { writeFileSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const T = {
  NULL: 0x30, NONE: 0x4e, FALSE: 0x46, TRUE: 0x54, INT: 0x69,
  BYTES: 0x73, CODE: 0x63, SMALL_TUPLE: 0x29, SHORT_ASCII: 0x7a,
  ASCII: 0x61,
};
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const i32 = (n) => { const b = Buffer.alloc(4); b.writeInt32LE(n); return b; };
const sAscii = (s) => { const b = Buffer.from(s, "utf8"); return b.length <= 255 ? Buffer.concat([Buffer.from([T.SHORT_ASCII, b.length]), b]) : Buffer.concat([Buffer.from([T.ASCII]), u32(b.length), b]); };
const bytes = (d) => Buffer.concat([Buffer.from([T.BYTES]), u32(d.length), d]);
const int = (n) => Buffer.concat([Buffer.from([T.INT]), i32(n)]);
const smTuple = (items) => Buffer.concat([Buffer.from([T.SMALL_TUPLE, items.length]), ...items]);
const NONE = Buffer.from([T.NONE]);

// layout: "py37" | "py38" | "py311"
function code(layout, { name, consts, names = [], varnames = [], freevars = [], cellvars = [], bytecode = Buffer.from([0x64, 0x00, 0x53, 0x00]), filename = "synth.py", firstlineno = 1 }) {
  const parts = [Buffer.from([T.CODE]), u32(0)]; // argcount
  if (layout !== "py37") parts.push(u32(0)); // posonlyargcount
  parts.push(u32(0)); // kwonlyargcount
  if (layout !== "py311") parts.push(u32(varnames.length)); // nlocals
  parts.push(i32(1), i32(0x40)); // stacksize, CO_NOFREE
  parts.push(bytes(bytecode));
  parts.push(smTuple(consts));
  parts.push(smTuple(names.map(sAscii)));
  if (layout === "py311") {
    parts.push(smTuple(varnames.map(sAscii))); // localsplusnames
    parts.push(bytes(Buffer.alloc(varnames.length))); // localspluskinds
  } else {
    parts.push(smTuple(varnames.map(sAscii)));
    parts.push(smTuple(freevars.map(sAscii)));
    parts.push(smTuple(cellvars.map(sAscii)));
  }
  parts.push(sAscii(filename), sAscii(name));
  if (layout === "py311") parts.push(sAscii(name)); // qualname
  parts.push(i32(firstlineno));
  parts.push(bytes(Buffer.alloc(0))); // lnotab / linetable
  if (layout === "py311") parts.push(bytes(Buffer.alloc(0))); // exceptiontable
  return Buffer.concat(parts);
}

function pyc(magic, flags, root) {
  const hdr = Buffer.alloc(16);
  hdr.writeUInt16LE(magic, 0);
  hdr[2] = 0x0d; hdr[3] = 0x0a;
  hdr.writeUInt32LE(flags, 4);
  // bytes 8..16: mtime+size or source hash — arbitrary for our purposes
  return Buffer.concat([hdr, root]);
}

const DIR = fileURLToPath(new URL(".", import.meta.url));

// helper code object reused inside root co_consts for each layout
function moduleRoot(layout) {
  const helper = code(layout, { name: "helper_fn", consts: [NONE, sAscii("helper doc")], varnames: [sAscii("x")] });
  const worker = code(layout, { name: "worker_fn", consts: [NONE], varnames: [sAscii("a"), sAscii("b")] });
  return code(layout, {
    name: "<module>",
    consts: [NONE, int(7), sAscii("module docstring"), helper, worker, sAscii("tail-str")],
    names: [sAscii("helper_fn"), sAscii("worker_fn")],
  });
}

writeFileSync(DIR + "synth-37.pyc", pyc(3394, 0, moduleRoot("py37")));           // CPython 3.7 magic
writeFileSync(DIR + "synth-38.pyc", pyc(3413, 0, moduleRoot("py38")));           // CPython 3.8
writeFileSync(DIR + "synth-310.pyc", pyc(3439, 0, moduleRoot("py38")));          // CPython 3.10
// "Different" py311-family version: real 3.12 fixture, magic patched to 3495 (3.11.0)
const real312 = readFileSync(DIR + "plain-312.pyc");
const fake311 = Buffer.from(real312);
fake311.writeUInt16LE(3495, 0);
writeFileSync(DIR + "synth-311-magic.pyc", fake311);
// Also a genuinely synthetic py311 stream (magic 3650 = hypothetical 3.15 headroom)
writeFileSync(DIR + "synth-315.pyc", pyc(3650, 0, moduleRoot("py311")));
// no-flag vs flag variant of the same synthetic py38 stream
writeFileSync(DIR + "synth-38-hashflag.pyc", pyc(3413, 1, moduleRoot("py38")));

console.log("built synth-37/38/310/311-magic/315/38-hashflag");
