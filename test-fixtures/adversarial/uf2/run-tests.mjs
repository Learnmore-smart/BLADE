// Adversarial harness for scrubUf2 — exercises every fixture and prints a
// verdict per case. Read-only: never mutates the scrubber.
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { scrubUf2 } from "../../../src/trailer.mjs";

const dir = dirname(fileURLToPath(import.meta.url));
const M0 = 0x0a324655, M1 = 0x9e5d5157, ME = 0x0ab16f30;
const MARKER = Buffer.from("[BLA-UF2-SHIELD]", "latin1");

function blocksOf(buf) {
  const out = [];
  for (let off = 0; off + 512 <= buf.length; off += 512) {
    const b = buf.subarray(off, off + 512);
    out.push({
      off,
      magicOk: b.readUInt32LE(0) === M0 && b.readUInt32LE(4) === M1 && b.readUInt32LE(508) === ME,
      flags: b.readUInt32LE(8),
      addr: b.readUInt32LE(12),
      blockNo: b.readUInt32LE(20),
      numBlocks: b.readUInt32LE(24),
      hasMarker: b.includes(MARKER),
      sig: b.subarray(32, 48).toString("latin1"),
    });
  }
  return out;
}

const flags = (f) =>
  `0x${f.toString(16).padStart(4, "0")}` +
  `${f & 1 ? "|NMF" : ""}${f & 0x1000 ? "|FC" : ""}${f & 0x2000 ? "|FAM" : ""}`;

for (const name of readdirSync(dir).filter((f) => f.endsWith(".uf2")).sort()) {
  const buf = readFileSync(join(dir, name));
  let r, crashed = null;
  try { r = scrubUf2(buf); } catch (e) { crashed = e; }
  console.log(`\n=== ${name} (${buf.length}B) ===`);
  if (crashed) { console.log(`  CRASH: ${crashed.message}`); continue; }
  console.log(`  report: ${JSON.stringify(r.report)}`);
  const before = blocksOf(buf), after = blocksOf(r.buffer);
  console.log(`  in : ${before.map((b) => `#${b.blockNo}/${b.numBlocks} ${flags(b.flags)} ${b.hasMarker ? "MARKER" : ""} "${b.sig.slice(0, 14)}"`).join("\n        ")}`);
  console.log(`  out: ${after.map((b) => `#${b.blockNo}/${b.numBlocks} ${flags(b.flags)} "${b.sig.slice(0, 14)}"`).join("\n        ") || "(empty)"}`);
  const realIn = before.filter((b) => !b.hasMarker);
  const realOut = after.filter((b) => !b.hasMarker);
  const sigOf = (b) => `${b.addr.toString(16)}:${b.blockNo}:${b.sig}`;
  // every input block absent from output was dropped — show its flags so
  // main-flash drops (real-block over-drop) are visible
  const droppedBlks = before.filter((b) => !after.some((a) => sigOf(a) === sigOf(b)));
  for (const d of droppedBlks) {
    const mainFlash = (d.flags & 0x1001) === 0; // no NOT_MAIN_FLASH / FILE_CONTAINER
    console.log(`  >> DROPPED blk#${d.blockNo} flags=${flags(d.flags)} magicOk=${d.magicOk} marker=${d.hasMarker} ${mainFlash ? "** MAIN-FLASH REAL BLOCK **" : ""} "${d.sig.slice(0, 24)}"`);
  }
  if (realOut.length < realIn.length) {
    const lost = realIn.filter((b) => !after.some((a) => sigOf(a) === sigOf(b)));
    console.log(`  >> REAL (marker-free) BLOCKS DROPPED: ${lost.map((b) => `blk#${b.blockNo}`).join(",")}`);
  }
  // order check: compare the SEQUENCE of kept-block identities, not offsets
  if (JSON.stringify(realIn.map(sigOf)) !== JSON.stringify(realOut.map(sigOf)) && realOut.length === realIn.length)
    console.log(`  >> ORDER CHANGED`);
  // numBlocks consistency in the output image
  const declared = [...new Set(after.map((b) => b.numBlocks))];
  if (after.length && declared.some((n) => n !== after.length))
    console.log(`  >> NUMBLOCKS STALE: kept ${after.length} blocks but fields declare ${declared.join(",")}`);
  if (name === "case8-bla-append-baseline.uf2") {
    const orig = readFileSync(join(dir, "case8-expected-original.uf2"));
    console.log(`  >> byte-exact vs pre-BLA original: ${r.buffer.equals(orig)}`);
  }
}
