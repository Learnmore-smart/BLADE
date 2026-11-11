// Adversarial tests for scrubEvm (src/trailer.mjs).
// Generates crafted .evm inputs in this directory, runs scrubEvm on each,
// and prints case -> verdict with byte offsets.
//
//   node test-fixtures/adversarial/evm/run.mjs
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { scrubEvm } from "../../../src/trailer.mjs";

const DIR = dirname(fileURLToPath(import.meta.url));
const ROOT = join(DIR, "..", "..", "..");
const require = createRequire(import.meta.url);
const { protectEvmBytecodeBuffer, buildSolidityMetadataTrailer } = require(
  join(ROOT, "vendor", "bla", "dist", "shields", "formats", "evm-bytecode.js"),
);
mkdirSync(DIR, { recursive: true });

// ---------- building blocks ----------
// Real-ish runtime bytecode: constructor-style prologue + selector dispatcher.
const CODE = Buffer.from([
  0x60, 0x80, 0x60, 0x40, 0x52,                   // PUSH1 80 PUSH1 40 MSTORE
  0x34, 0x80, 0x15, 0x60, 0x0e, 0x57,             // CALLVALUE DUP1 ISZERO PUSH1 0e JUMPI
  0x5f, 0x5f, 0xfd,                               // PUSH0 PUSH0 REVERT
  0x5b, 0x50,                                     // JUMPDEST POP
  0x60, 0x04, 0x36, 0x10, 0x60, 0x1c, 0x57,       // PUSH1 04 CALLDATASIZE LT PUSH1 1c JUMPI
  0x5f, 0x35, 0x60, 0xe0, 0x1c,                   // PUSH0 CALLDATALOAD PUSH1 e0 SHR
  0x80, 0x63, 0xa9, 0x05, 0x9c, 0xbb, 0x14, 0x60, 0x2e, 0x57, // DUP1 PUSH4 a9059cbb EQ PUSH1 2e JUMPI
  0x80, 0x63, 0x09, 0x5e, 0xa7, 0xb3, 0x14, 0x60, 0x44, 0x57, // DUP1 PUSH4 095ea7b3 EQ PUSH1 44 JUMPI
  0x5f, 0x5f, 0xfd,                               // PUSH0 PUSH0 REVERT
  0x5b, 0x50, 0x60, 0x44, 0x36, 0x60, 0x1c, 0x56, // JUMPDEST POP PUSH1 44 CALLDATASIZE PUSH1 1c JUMP
  0x5b, 0x50, 0x5f, 0x5f, 0xfd,                   // JUMPDEST POP PUSH0 PUSH0 REVERT
  0x00,                                           // STOP
]); // 65 bytes, ends 0x00

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const auxTrailer = (aux) => Buffer.concat([aux, u16(aux.length)]);

// Modern solc auxdata: a2{ipfs: bytes34, solc: bytes3} = 51 bytes -> len 0x0033
const SOLC_AUX = Buffer.concat([
  Buffer.from([0xa2]),
  Buffer.from([0x64]), Buffer.from("ipfs", "utf8"),
  Buffer.from([0x58, 0x22]), Buffer.alloc(34, 0xab),
  Buffer.from([0x64]), Buffer.from("solc", "utf8"),
  Buffer.from([0x43, 0x00, 0x08, 0x1e]),
]);
// Legacy solc auxdata (pre-0.5.x shape): a3{ipfs:34, bzzr0:32, solc:3} = 91 bytes -> len 0x005B
const LEGACY_AUX_5B = Buffer.concat([
  Buffer.from([0xa3]),
  Buffer.from([0x64]), Buffer.from("ipfs", "utf8"),
  Buffer.from([0x58, 0x22]), Buffer.alloc(34, 0xbc),
  Buffer.from([0x65]), Buffer.from("bzzr0", "utf8"),
  Buffer.from([0x58, 0x20]), Buffer.alloc(32, 0xcd),
  Buffer.from([0x64]), Buffer.from("solc", "utf8"),
  Buffer.from([0x43, 0x00, 0x04, 0x26]),
]);
if (SOLC_AUX.length !== 0x33 || LEGACY_AUX_5B.length !== 0x5b) {
  throw new Error(`aux sizes wrong: ${SOLC_AUX.length} / ${LEGACY_AUX_5B.length}`);
}

// A single BLA-style CBOR trailer (markers present), same shape protect() emits.
const BLA_META = buildSolidityMetadataTrailer([
  ["solc", Buffer.from([0x00, 0x08, 0x1e])],
  ["bla", "[BLA-EVM-SHIELD]"],
  ["bla_evm_canary", "0123456789abcdef0123456789abcdef"],
]);
// Markerless terminal CBOR (stealth-mode hypothetical).
const QUIET_META = buildSolidityMetadataTrailer([
  ["solc", Buffer.from([0x00, 0x08, 0x1e])],
]);

const harden = (buf, intensity) => protectEvmBytecodeBuffer(buf, { intensity, seed: "adv-evm" }).buffer;

// ---------- cases ----------
const cases = [];
const add = (name, expect, input, plain = null) => {
  writeFileSync(join(DIR, `${name}.evm`), input);
  if (plain) writeFileSync(join(DIR, `${name}.expected.evm`), plain);
  cases.push({ name, expect, input, plain });
};

// 1a: real contract w/ unreachable JUMPDEST pad region, no metadata, no BLA
add("case-1a-trailing-jumpdests-no-bla", "PASS",
  Buffer.concat([CODE, Buffer.from([0x00]), Buffer.alloc(48, 0x5b)]));

// 1b: trailing JUMPDESTs + tail bytes that parse as a CBOR-map frame but carry NO marker
// (...0xa1 (LOG1-shaped byte) then u16 len pointing at it)
{
  const body = Buffer.concat([CODE, Buffer.alloc(32, 0x5b), Buffer.from([0xa1])]);
  const len = 1; // off = end-2-1 -> the 0xa1 byte; >>5===5 but no marker text
  add("case-1b-coincidental-map-tail-no-marker", "PASS", Buffer.concat([body, u16(len)]));
}

// 1c: unhardened contract ending with real solc auxdata only
add("case-1c-plain-solc-auxdata-no-bla", "PASS",
  Buffer.concat([CODE, auxTrailer(SOLC_AUX)]));

// 2a: real solc auxdata + real BLA balanced trailer appended after it
{
  const plain = Buffer.concat([CODE, auxTrailer(SOLC_AUX)]);
  add("case-2a-solc-auxdata-then-bla", "PASS", harden(plain, "balanced"), plain);
}

// 2b: legacy auxdata whose u16 length low byte IS 0x5b + BLA trailer
// (pre-4KiB-threshold scrubEvm ate this byte; current code preserves it)
{
  const plain = Buffer.concat([CODE, auxTrailer(LEGACY_AUX_5B)]);
  add("case-2b-auxdata-len-lowbyte-5b-then-bla", "PASS", harden(plain, "balanced"), plain);
}

// 3a: marker string inside PUSH32 immediate mid-code, real solc aux terminal — no BLA trailer
{
  const imm = Buffer.concat([
    Buffer.from("[BLA-EVM-SHIELD]", "utf8"),
    Buffer.from("bla_evm_canary", "utf8"),
    Buffer.alloc(2, 0x42),
  ]); // 32 bytes of immediate data
  const push32 = Buffer.concat([Buffer.from([0x7f]), imm]);
  const file = Buffer.concat([CODE, push32, Buffer.from([0x60, 0x01, 0x5f, 0x52, 0x00]), auxTrailer(SOLC_AUX)]);
  add("case-3a-marker-inside-push32-real-tail", "PASS", file);
}

// 3b: marker inside PUSH data + EOF u16 length that collides with a map-typed byte before it
{
  const offByte = 0xa0; // sits inside the PUSH32 immediate, 0xa0>>5 === 5
  const imm = Buffer.concat([
    Buffer.from([offByte]),
    Buffer.from("[BLA-EVM-SHIELD]", "utf8"),
    Buffer.alloc(32 - 1 - 16, 0x42),
  ]);
  const push32 = Buffer.concat([Buffer.from([0x7f]), imm]);
  const tailCode = Buffer.from([0x60, 0x01, 0x5f, 0x52, 0x60, 0x00, 0x55, 0x00]); // 8 bytes
  // off = CODE.length + 1 (position of 0xa0); len = (fileLen-2) - off = 32 + tailCode.len
  const len = push32.length - 1 + tailCode.length;
  const file = Buffer.concat([CODE, push32, tailCode, u16(len)]);
  add("case-3b-marker-pushdata-length-collision", "PUSH-DATA-CUT", file);
}

// 4a: stealth padding — 0x5b run, no CBOR at all
add("case-4a-pad-only-no-marker", "PASS",
  Buffer.concat([CODE, Buffer.alloc(96, 0x5b)]));

// 4b: 0x5b pad + well-formed terminal CBOR WITHOUT BLA markers
add("case-4b-pad-plus-markerless-cbor", "LEFTOVER-PADDING",
  Buffer.concat([CODE, Buffer.alloc(96, 0x5b), QUIET_META]));

// 4c: BLA maximum padding, contract does NOT end in 0x5b — boundary should be exact
{
  const plain = Buffer.concat([CODE, auxTrailer(SOLC_AUX)]);
  add("case-4c-bla-maximum-pad-clean-boundary", "PASS", harden(plain, "maximum"), plain);
}

// 4d: contract's OWN trailing 0x5b x10 merged with BLA's 64KiB pad.
// Reachable-prefix rule: a JUMPI dest at 0x44 lands inside the run, so the
// owned prefix through it is kept; the provably-dead tail is dropped
// (6 owned dead bytes past the last reachable target are unrecoverable).
{
  const plain = Buffer.concat([CODE, Buffer.alloc(10, 0x5b)]); // no auxdata; ends in real JUMPDESTs
  add("case-4d-own-pad-merged-with-bla-pad", "REACHABLE-PREFIX-KEPT", harden(plain, "maximum"), plain);
}

// 4e: contract's OWN trailing 0x5b x10 + BLA balanced (BLA adds ZERO padding)
// (pre-4KiB-threshold scrubEvm ate the real run; current code preserves it)
{
  const plain = Buffer.concat([CODE, Buffer.alloc(10, 0x5b)]);
  add("case-4e-own-pad-bla-added-none", "PASS", harden(plain, "balanced"), plain);
}

// 4f: own 10x 0x5b + handcrafted sub-threshold BLA pad 4000 => merged run 4010 < 4096
// -> whole run PRESERVED, including all 4000 BLA pad bytes
{
  const plain = Buffer.concat([CODE, Buffer.alloc(10, 0x5b)]);
  add("case-4f-own-pad-plus-subthreshold-bla-pad", "REACHABLE-PREFIX-KEPT",
    Buffer.concat([plain, Buffer.alloc(4000, 0x5b), BLA_META]), plain);
}

// 4g: own 10x 0x5b + handcrafted BLA pad 4086 => merged run 4096 = threshold
// -> whole run stripped, including the contract's own 10 real bytes
{
  const plain = Buffer.concat([CODE, Buffer.alloc(10, 0x5b)]);
  add("case-4g-merged-pad-exactly-at-threshold", "REACHABLE-PREFIX-KEPT",
    Buffer.concat([plain, Buffer.alloc(4086, 0x5b), BLA_META]), plain);
}

// 4h: no own 0x5b tail + handcrafted BLA pad exactly 4096. CODE's JUMPI
// has a dest at 0x44 — dangling in the plain contract (off-EOF) but landing
// on pad bytes post-hardening. Indistinguishable from an owned-pad target,
// so the reachable prefix (4B of BLA pad) is conservatively kept.
{
  const plain = CODE;
  add("case-4h-bla-pad-exactly-4096-clean-boundary", "DANGLING-DEST-RESIDUE",
    Buffer.concat([CODE, Buffer.alloc(4096, 0x5b), BLA_META]), plain);
}

// 5a: two consecutive BLA CBOR trailers — scrubber does only one pass
add("case-5a-double-bla-trailer", "LEFTOVER-TRAILER",
  Buffer.concat([CODE, BLA_META, BLA_META]), CODE);

// 5b: BLA CBOR embedded BEFORE a real solc auxdata (BLA no longer terminal)
add("case-5b-bla-then-real-auxdata", "LEFTOVER-TRAILER",
  Buffer.concat([CODE, BLA_META, auxTrailer(SOLC_AUX)]), CODE);

// 6a/6b: byte-exact checks — real protect() output vs plain
{
  const plain = Buffer.concat([CODE, auxTrailer(SOLC_AUX)]);
  add("case-6a-byte-exact-balanced", "PASS", harden(plain, "balanced"), plain);
  add("case-6b-byte-exact-maximum", "PASS", harden(plain, "maximum"), plain);
}

// ---------- run ----------
const fmt = (b) => `0x${b.toString(16).padStart(2, "0")}`;
const diffInfo = (a, b) => {
  const n = Math.min(a.length, b.length);
  let i = 0;
  while (i < n && a[i] === b[i]) i++;
  if (a.length === b.length && i === a.length) return null;
  return { firstDiff: i, aLen: a.length, bLen: b.length, aByte: a[i], bByte: b[i] };
};

console.log("scrubEvm adversarial results");
console.log("=".repeat(100));
for (const c of cases) {
  const r = scrubEvm(c.input);
  writeFileSync(join(DIR, `${c.name}.cleaned.evm`), r.buffer);
  const out = r.buffer;
  let verdict;
  if (!r.report.hardened) {
    verdict = out.equals(c.input) ? "PASS(passthrough)" : "MODIFIED-WITHOUT-MARKER?";
  } else if (c.plain) {
    const d = diffInfo(out, c.plain);
    verdict = d === null ? "PASS(byte-exact)" : `DIFF@0x${d.firstDiff.toString(16)} out.len=${d.aLen} expected.len=${d.bLen} out[${d.firstDiff}]=${d.aByte === undefined ? "EOF" : fmt(d.aByte)} expected[${d.firstDiff}]=${d.bByte === undefined ? "EOF" : fmt(d.bByte)}`;
  } else {
    verdict = `cut ${c.input.length - out.length}B -> out.len=${out.length}`;
  }
  // leftover-marker check
  const leftover = out.includes(Buffer.from("[BLA-EVM-SHIELD]", "utf8")) || out.includes(Buffer.from("bla_evm_canary", "utf8"));
  console.log(
    `${c.name.padEnd(46)} in=${String(c.input.length).padStart(7)} out=${String(out.length).padStart(7)} ` +
    `hardened=${String(r.report.hardened).padEnd(5)} dropped=${String(r.report.trailerDropped ?? 0).padStart(6)} ` +
    `pad=${String(r.report.jumpdestPadding ?? 0).padStart(6)} leftoverMarker=${leftover}  -> ${verdict}  [expect ${c.expect}]`,
  );
}
