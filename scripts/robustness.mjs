// BLADE robustness harness: feeds degenerate inputs (empty, truncated,
// bit-flipped, all-zero, all-0xFF) through the format detector and every
// scrubber. A scrubber must never throw — malformed input degrades to
// keep+flag, not a crash. Usage: node scripts/robustness.mjs
import { readFileSync, readdirSync, existsSync } from "node:fs";
import path from "node:path";
import { detect } from "../src/detect.mjs";
import { dehardenJs } from "../src/js-deharden.mjs";
import { scrubAsar, scrubWasm, scrubSqlite, scrubSafetensors, scrubGguf } from "../src/formats.mjs";
import {
  scrubNative, scrubDex, scrubIl2cpp, scrubDotnet, scrubEvm, scrubPtx,
  scrubJvm, scrubPlistXml, scrubBplist, scrubPcap, scrubUf2, scrubBeam,
  scrubPyc, scrubZip, scrubPySource, scrubHtml, inspectSourcemap,
} from "../src/trailer.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");
const HARD = path.join(ROOT, "test-fixtures", "hardened");

let pass = 0, fail = 0, rejected = 0;
const failures = [];
// Format-rejection throws are part of the contract: a scrubber may refuse an
// input that fails its own magic/shape check (the CLI routes via detect()
// first). Crashes are everything else — parse errors, range errors, etc.
const REJECTION = /^not [\w ()]+$/;
const check = (name, fn) => {
  try { fn(); pass++; }
  catch (e) {
    if (REJECTION.test(e.message) && e.message.length < 40) { rejected++; return; }
    fail++; failures.push(`${name}: ${e.message}`);
  }
};

// ---- degenerate buffers that must never crash detect() or a scrubber
const degenerates = [
  ["empty", Buffer.alloc(0)],
  ["one-NUL", Buffer.alloc(1)],
  ["four-NUL", Buffer.alloc(4)],
  ["all-0xFF-64", Buffer.alloc(64, 0xff)],
  ["all-zero-1K", Buffer.alloc(1024)],
  ["random-256", (() => { const b = Buffer.alloc(256); for (let i = 0; i < 256; i++) b[i] = (i * 37 + 11) & 0xff; return b; })()],
];

// Exercises the text scrubbers on a garbage string and the binary ones on a
// garbage buffer. The contract is "no throw" — output content is irrelevant.
function exerciseAll(label, buf, ext = "") {
  const kind = detect(buf, ext);
  const src = buf.toString("utf8");
  check(`${label}: detect`, () => kind);
  check(`${label}: js`, () => dehardenJs(src));
  check(`${label}: wasm`, () => scrubWasm(buf));
  check(`${label}: safetensors`, () => scrubSafetensors(buf));
  check(`${label}: gguf`, () => scrubGguf(buf));
  check(`${label}: native`, () => scrubNative(buf));
  check(`${label}: dex`, () => scrubDex(buf));
  check(`${label}: il2cpp`, () => scrubIl2cpp(buf));
  check(`${label}: dotnet`, () => scrubDotnet(buf));
  check(`${label}: evm`, () => scrubEvm(buf));
  check(`${label}: ptx`, () => scrubPtx(src));
  check(`${label}: jvm`, () => scrubJvm(buf));
  check(`${label}: plist-xml`, () => scrubPlistXml(src));
  check(`${label}: bplist`, () => scrubBplist(buf));
  check(`${label}: pcap`, () => scrubPcap(buf));
  check(`${label}: uf2`, () => scrubUf2(buf));
  check(`${label}: beam`, () => scrubBeam(buf));
  check(`${label}: pyc`, () => scrubPyc(buf));
  check(`${label}: zip`, () => scrubZip(buf));
  check(`${label}: py`, () => scrubPySource(src));
  check(`${label}: html`, () => scrubHtml(src));
  check(`${label}: sourcemap`, () => inspectSourcemap(src));
}

for (const [label, buf] of degenerates) exerciseAll(`degenerate:${label}`, buf);

// ---- format-specific malformed variants: headers that route to a scrubber
// but whose record structure is degenerate — the owning scrubber must not
// crash (pcapng block walk and BE pcap records especially).
{
  const pcapHdr = (be, nsec) => {
    const h = Buffer.alloc(24);
    if (be) h.writeUInt32BE(nsec ? 0xa1b23c4d : 0xa1b2c3d4, 0);
    else h.writeUInt32LE(nsec ? 0xa1b23c4d : 0xa1b2c3d4, 0);
    return h;
  };
  const variants = [
    ["pcap-be-nsec-truncated-rec", Buffer.concat([pcapHdr(true, true), Buffer.from([0, 0, 0, 1, 0, 0])])],
    ["pcap-be-huge-incl", Buffer.concat([pcapHdr(true, false), Buffer.alloc(16, 0xff)])],
    ["pcapng-len-overflow", buf2(0x0a0d0d0a, 0xfffffff8)],
    ["pcapng-len-odd", buf2(0x0a0d0d0a, 13)],
    ["pcapng-truncated-block", Buffer.concat([buf2(0x0a0d0d0a, 0x40), Buffer.alloc(8)])],
    ["pcapng-shb-only", buf2(0x0a0d0d0a, 0x1c)],
  ];
  function buf2(magic, len) { const b = Buffer.alloc(12); b.writeUInt32LE(magic, 0); b.writeUInt32LE(len, 4); b.writeUInt32LE(len, 8); return b; }
  for (const [label, b] of variants) {
    check(`malformed:${label}: detect`, () => detect(b, ""));
    check(`malformed:${label}: scrubPcap`, () => scrubPcap(b));
  }
}

// ---- truncated real fixtures: every prefix length step of each hardened
// fixture routed to its own kind must not crash the owning scrubber.
const SCRUBBERS = {
  wasm: (b) => scrubWasm(b), asar: (b) => scrubAsar(b), sqlite: null /* path-based */,
  safetensors: (b) => scrubSafetensors(b), gguf: (b) => scrubGguf(b),
  native: (b) => scrubNative(b), dex: (b) => scrubDex(b), il2cpp: (b) => scrubIl2cpp(b),
  dotnet: (b) => scrubDotnet(b), evm: (b) => scrubEvm(b), jvm: (b) => scrubJvm(b),
  pcap: (b) => scrubPcap(b), uf2: (b) => scrubUf2(b), beam: (b) => scrubBeam(b),
  pyc: (b) => scrubPyc(b), zip: (b) => scrubZip(b),
};

if (existsSync(HARD)) {
  for (const f of readdirSync(HARD)) {
    const buf = readFileSync(path.join(HARD, f));
    const kind = detect(buf, path.extname(f).toLowerCase());
    const scrub = SCRUBBERS[kind];
    if (!scrub) continue;
    for (const frac of [0.01, 0.1, 0.5, 0.9]) {
      const cut = Math.max(1, Math.floor(buf.length * frac));
      check(`truncated:${f}@${cut} (${kind})`, () => scrub(buf.subarray(0, cut)));
    }
    // bit flips at a few positions
    for (const off of [0, Math.floor(buf.length / 2), buf.length - 1]) {
      const mut = Buffer.from(buf);
      mut[off] ^= 0xff;
      check(`bitflip:${f}@${off} (${kind})`, () => scrub(mut));
    }
  }
}

console.log(`${pass} passed, ${fail} failed, ${rejected} format-rejections (ok)`);
if (failures.length) {
  console.log("failures:");
  for (const f of failures.slice(0, 40)) console.log(`  ${f}`);
  if (failures.length > 40) console.log(`  ... and ${failures.length - 40} more`);
  process.exit(1);
}
