// Adversarial UF2 fixtures for BLADE's scrubUf2 (src/trailer.mjs).
// UF2 block layout (512 bytes, all u32 LE):
//   0:  magicStart0 0x0A324655   4: magicStart1 0x9E5D5157
//   8:  flags                  12: targetAddr
//  16:  payloadSize            20: blockNo
//  24:  numBlocks              28: familyID / fileSize
//  32:  data[payloadSize]      508: magicEnd 0x0AB16F30
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dir = dirname(fileURLToPath(import.meta.url));
const M0 = 0x0a324655, M1 = 0x9e5d5157, ME = 0x0ab16f30;
const NOT_MAIN = 0x0001, FILE_CONTAINER = 0x1000, FAMILY = 0x2000;
const RP2040 = 0xe48bff56;
const MARKER = "[BLA-UF2-SHIELD]";

function blk({ flags = FAMILY, addr, payload, blockNo, numBlocks, family = RP2040, payloadSize }) {
  const b = Buffer.alloc(512, 0);
  b.writeUInt32LE(M0, 0); b.writeUInt32LE(M1, 4);
  b.writeUInt32LE(flags >>> 0, 8); b.writeUInt32LE(addr >>> 0, 12);
  b.writeUInt32LE(payloadSize ?? payload.length, 16);
  b.writeUInt32LE(blockNo >>> 0, 20); b.writeUInt32LE(numBlocks >>> 0, 24);
  b.writeUInt32LE(family >>> 0, 28);
  Buffer.from(payload, "latin1").copy(b, 32, 0, Math.min(476, payload.length));
  b.writeUInt32LE(ME, 508);
  return b;
}

// Mimics a BLA-appended decoy (marker at payload start, not-main-flash flags).
function decoy(i, blockNo = 0, numBlocks = 4) {
  return blk({
    flags: FILE_CONTAINER | NOT_MAIN | FAMILY,
    addr: 0x20000000 + i * 512,
    payload: `${MARKER}\nfile-container idx=${i}\nnonce=deadbeef${i}`,
    blockNo, numBlocks, family: 0x57755a57,
  });
}

const fixtures = {};

// Case 1 — REAL UF2 with legitimate flagNotMainFlash + file-container blocks.
// Bootloaders / uf2conv emit these for config sectors, OTP regions and
// embedded FAT file data; no marker anywhere.
fixtures["case1-real-notmain-filecontainer.uf2"] = Buffer.concat([
  blk({ flags: FAMILY, addr: 0x10000000, payload: "REAL_FW_STAGE1_" + "A".repeat(240), blockNo: 0, numBlocks: 4 }),
  blk({ flags: FAMILY, addr: 0x10000100, payload: "REAL_FW_STAGE2_" + "B".repeat(240), blockNo: 1, numBlocks: 4 }),
  // legit not-main-flash: RP2040 OTP / config sector write (real UF2 usage)
  blk({ flags: NOT_MAIN | FAMILY, addr: 0x00f00000, payload: "OTP_CONFIG_WORDS_" + "C".repeat(120), blockNo: 2, numBlocks: 4 }),
  // legit file-container block (UF2 flagFileContainer) — embedded FAT payload
  blk({ flags: FILE_CONTAINER, addr: 0x00000400, payload: "FAT16_FILE_DATA_CURRENTUF2" + "D".repeat(200), blockNo: 3, numBlocks: 4, family: 0 }),
]);

// Case 2 — blockNo shuffled in file order; decoy appended (BLA-style tail).
{
  const mk = (no) => blk({ flags: FAMILY, addr: 0x10000000 + no * 256, payload: `REAL_BLOCK_${no}_` + String(no).repeat(100), blockNo: no, numBlocks: 4 });
  fixtures["case2-shuffled-blockno.uf2"] = Buffer.concat([mk(2), mk(0), mk(3), mk(1), decoy(0)]);
}

// Case 3 — decoys interleaved BETWEEN real blocks (BLA only appends;
// adversarial reorder to check positional assumptions).
{
  const mk = (no) => blk({ flags: FAMILY, addr: 0x10000000 + no * 256, payload: `REAL_${no}_` + "R".repeat(200), blockNo: no, numBlocks: 3 });
  fixtures["case3-interleaved-decoys.uf2"] = Buffer.concat([mk(0), decoy(0), mk(1), decoy(1), mk(2)]);
}

// Case 4 — truncated UF2: 2 real + 1 decoy + 300 stray bytes (partial block).
{
  const real = [
    blk({ flags: FAMILY, addr: 0x10000000, payload: "REAL_T1_" + "T".repeat(200), blockNo: 0, numBlocks: 2 }),
    blk({ flags: FAMILY, addr: 0x10000100, payload: "REAL_T2_" + "U".repeat(200), blockNo: 1, numBlocks: 2 }),
  ];
  fixtures["case4-truncated-tail.uf2"] = Buffer.concat([...real, decoy(0), Buffer.alloc(300, 0xab)]);
  // 4b — decoy itself truncated mid-block
  fixtures["case4b-truncated-mid-decoy.uf2"] = Buffer.concat([...real, decoy(0).subarray(0, 200)]);
  // 4c — truncated with NO decoy in the aligned prefix
  fixtures["case4c-truncated-clean.uf2"] = Buffer.concat([...real, Buffer.alloc(128, 0xcc)]);
}

// Case 5 — numBlocks counts decoys too (adversarial numbering): real blocks
// claim numBlocks=4 with blockNos 0 and 2 — decoys occupy slots 1 and 3.
{
  const mkReal = (no) => blk({ flags: FAMILY, addr: 0x10000000 + (no === 2 ? 256 : 0), payload: `REAL_N${no}_` + "N".repeat(200), blockNo: no, numBlocks: 4 });
  fixtures["case5-stale-numblocks.uf2"] = Buffer.concat([
    mkReal(0), decoy(0, 1, 4), mkReal(2), decoy(1, 3, 4),
  ]);
}

// Case 6 — REAL main-flash payload contains the marker bytes in the flash
// data region (e.g. embedded build string). No decoys at all.
fixtures["case6-marker-in-real-payload.uf2"] = Buffer.concat([
  blk({ flags: FAMILY, addr: 0x10000000, payload: "REAL_CLEAN_" + "E".repeat(200), blockNo: 0, numBlocks: 3 }),
  blk({ flags: FAMILY, addr: 0x10000100, payload: `ver=1.2 sig=${MARKER} buildtag` + "F".repeat(150), blockNo: 1, numBlocks: 3 }),
  blk({ flags: FAMILY, addr: 0x10000200, payload: "REAL_TAIL_" + "G".repeat(200), blockNo: 2, numBlocks: 3 }),
]);
// 6b — marker bytes only in the UNUSED PADDING region of a short-payload
// real block (payloadSize=64; garbage padding beyond it). Spec allows
// arbitrary bytes past payloadSize.
{
  const b = blk({ flags: FAMILY, addr: 0x10000100, payload: "SHORT64_" + "P".repeat(56), blockNo: 1, numBlocks: 2 });
  b.write(MARKER, 400, "latin1"); // padding region, still inside the 512B block
  fixtures["case6b-marker-in-padding.uf2"] = Buffer.concat([
    blk({ flags: FAMILY, addr: 0x10000000, payload: "REAL_A_" + "Q".repeat(200), blockNo: 0, numBlocks: 2 }),
    b,
  ]);
}
// 6c — marker bytes split ACROSS a block boundary (block N payload tail +
// block N+1 payload head). Per-block `includes` cannot see it.
{
  const b0 = blk({ flags: FAMILY, addr: 0x10000000, payload: "X".repeat(460) + "[BLA-UF2-SHIELD", blockNo: 0, numBlocks: 2 });
  const b1 = blk({ flags: FAMILY, addr: 0x100001e0, payload: "]" + "SPLIT_TAIL_" + "Y".repeat(200), blockNo: 1, numBlocks: 2 });
  fixtures["case6c-marker-split-across-blocks.uf2"] = Buffer.concat([b0, b1]);
}

// Case 7 — malformed interior block (bad magics) + appended decoy: no
// per-block magic validation in scrubUf2.
{
  const bad = Buffer.alloc(512, 0x55); // no UF2 magics at all
  bad.writeUInt32LE(ME, 508);
  fixtures["case7-bad-interior-magic.uf2"] = Buffer.concat([
    blk({ flags: FAMILY, addr: 0x10000000, payload: "REAL_H_" + "H".repeat(200), blockNo: 0, numBlocks: 2 }),
    bad,
    decoy(0),
  ]);
}

// Case 8 — genuine BLA-style output: real blocks then appended decoys
// (sanity baseline — should round-trip to the original bytes).
{
  const reals = [
    blk({ flags: FAMILY, addr: 0x10000000, payload: "REAL_BASE1_" + "I".repeat(200), blockNo: 0, numBlocks: 2 }),
    blk({ flags: FAMILY, addr: 0x10000100, payload: "REAL_BASE2_" + "J".repeat(200), blockNo: 1, numBlocks: 2 }),
  ];
  fixtures["case8-bla-append-baseline.uf2"] = Buffer.concat([...reals, decoy(0), decoy(1)]);
  writeFileSync(join(dir, "case8-expected-original.uf2"), Buffer.concat(reals));
}

mkdirSync(dir, { recursive: true });
for (const [name, buf] of Object.entries(fixtures)) {
  writeFileSync(join(dir, name), buf);
  console.log(`wrote ${name} (${buf.length} bytes, ${Math.floor(buf.length / 512)} full blocks +${buf.length % 512})`);
}
