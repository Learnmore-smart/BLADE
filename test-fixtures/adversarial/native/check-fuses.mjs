// Focused checks for scrubNative's Electron-fuse decoy-sentinel removal.
//   [elf][34x42B decoys][\0[BLA-NATIVE-SHIELD-V1]trailer] -> cut, then peel
//   [elf][34x42B decoys]                                 -> peel bare append
//   [elf][1x42B decoy]                                   -> KEPT (conservative)
//   [elf] clean                                          -> untouched
//   real V1 fuse block matching BLA's hardened wire plan -> fuseWireSuspect
// Usage: node test-fixtures/adversarial/native/check-fuses.mjs
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import assert from "node:assert/strict";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");
const { scrubNative } = await import(pathToFileURL(join(root, "src", "trailer.mjs")).href);

// ---------- minimal ELF64 LE builder (same shape as gen.mjs) ----------
function elf64({ extra = [] } = {}) {
  const names = ["", ".shstrtab", ...extra.map((s) => s.name)];
  const nameOff = [];
  let acc = 0;
  for (const n of names) { nameOff.push(acc); acc += Buffer.from(n, "utf8").length + 1; }
  const strtab = Buffer.alloc(acc);
  acc = 0;
  for (const n of names) { strtab.write(n, acc, "utf8"); acc += n.length + 1; }
  const shnum = 1 + names.length;
  const shoff = 0x100, strOff = 0x400;
  const parts = [];
  const push = (b, off) => parts.push({ b, off });
  const hdr = Buffer.alloc(64);
  hdr.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0);
  hdr.writeUInt16LE(3, 16); hdr.writeUInt16LE(0x3e, 18); hdr.writeUInt32LE(1, 20);
  hdr.writeBigUInt64LE(0x400000n, 24);
  hdr.writeBigUInt64LE(64n, 32);
  hdr.writeBigUInt64LE(BigInt(shoff), 40);
  hdr.writeUInt16LE(64, 52); hdr.writeUInt16LE(56, 54); hdr.writeUInt16LE(1, 56);
  hdr.writeUInt16LE(64, 58); hdr.writeUInt16LE(shnum, 60); hdr.writeUInt16LE(1, 62);
  push(hdr, 0);
  push(Buffer.alloc(56), 64);
  const sh = (i, nameIdx, type, off, size) => {
    const s = Buffer.alloc(64);
    s.writeUInt32LE(nameOff[nameIdx], 0); s.writeUInt32LE(type, 4);
    s.writeBigUInt64LE(3n, 8); s.writeBigUInt64LE(0n, 16);
    s.writeBigUInt64LE(BigInt(off), 24); s.writeBigUInt64LE(BigInt(size), 32);
    push(s, shoff + i * 64);
  };
  sh(0, 0, 0, 0, 0);
  sh(1, 1, 3, strOff, strtab.length);
  push(strtab, strOff);
  extra.forEach((s, k) => {
    sh(2 + k, 2 + k, s.type ?? 1, s.off, s.data.length);
    push(s.data, s.off);
  });
  const size = Math.max(...parts.map((p) => p.off + p.b.length));
  const out = Buffer.alloc(size);
  for (const p of parts) p.b.copy(out, p.off);
  return out;
}

// ---------- fuse record builders ----------
const SENT = Buffer.from("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX", "latin1"); // 32B
// decoy record: wire[6]=0x39 DECOY, wire[7] in {0x39,0x72}
const decoy = (i) => Buffer.concat([
  SENT,
  Buffer.from([0x01, 0x08, 0x30, 0x31, 0x30, 0x30, 0x31, 0x31, 0x39, i % 2 ? 0x72 : 0x39]),
]);
const decoys = (n) => Buffer.concat(Array.from({ length: n }, (_, i) => decoy(i)));
// real V1 fuse block: first-6 wire bytes = BLA's hardened plan, last two are
// ordinary states (0x30) — no decoy signature.
const REAL_FUSE = Buffer.concat([SENT, Buffer.from([0x01, 0x08, 0x30, 0x31, 0x30, 0x30, 0x31, 0x31, 0x30, 0x30])]);
// canonical Electron release config on Linux ELF (recoverFuseDefaults):
// RunAsNode off, CookieEncryption on, NodeOptions off, NodeCliInspect off,
// AsarIntegrity OFF (darwin-only canonical → 'assumed' confidence here),
// OnlyLoadFromAsar on, V8Snapshot off, GrantFileProtocolExtraPrivileges off.
const RESTORED_FUSE = Buffer.concat([SENT, Buffer.from([0x01, 0x08, 0x30, 0x31, 0x30, 0x30, 0x30, 0x31, 0x30, 0x30])]);
// a real fuse block NOT matching BLA's plan (Electron-ish defaults)
const STOCK_FUSE = Buffer.concat([SENT, Buffer.from([0x01, 0x08, 0x31, 0x30, 0x31, 0x31, 0x30, 0x30, 0x30, 0x30])]);

const TRAILER = () =>
  Buffer.concat([
    Buffer.from(`\0[BLA-NATIVE-SHIELD-V1]\0.dep-v0\0`, "utf8"),
    Buffer.from("/rustc/" + "0".repeat(40) + "/library/core/src/enclave_guard.rs\0", "latin1"),
    Buffer.from("PROTECTED_CANARY_CREDENTIAL=decoy\0", "utf8"),
    Buffer.alloc(64, 0xcc),
  ]);

const elf = elf64({ extra: [{ name: ".text", off: 0x800, data: Buffer.from("REALCODE".repeat(16), "latin1") }] });
const elfFuse = elf64({ extra: [{ name: ".rodata", off: 0x800, data: Buffer.concat([Buffer.from("fuse-section\0", "latin1"), REAL_FUSE]) }] });
const elfStock = elf64({ extra: [{ name: ".rodata", off: 0x800, data: Buffer.concat([Buffer.from("fuse-section\0", "latin1"), STOCK_FUSE]) }] });
const elfFuseRestored = elf64({ extra: [{ name: ".rodata", off: 0x800, data: Buffer.concat([Buffer.from("fuse-section\0", "latin1"), RESTORED_FUSE]) }] });

const decoyEntry = (r) => (r.report.decoys ?? []).find((d) => d.kind === "fuse-decoy-sentinels");

let pass = 0, fail = 0;
const check = (name, fn) => {
  try { fn(); pass++; console.log(`  ok  ${name}`); }
  catch (e) { fail++; console.log(`FAIL  ${name}: ${e.message}`); }
};

check("decoys before trailer marker: cut + peel restores pristine elf", () => {
  const r = scrubNative(Buffer.concat([elf, decoys(34), TRAILER()]));
  assert.deepEqual(r.buffer, elf);
  assert.ok(r.report.trailerDropped > 0, "trailer cut");
  assert.deepEqual(decoyEntry(r), { kind: "fuse-decoy-sentinels", records: 34, bytesDropped: 34 * 42 });
  assert.equal(r.report.fuseDecoySentinelsDropped, 34);
  assert.equal(r.report.hardened, true);
});

check("bare 34-decoy append (no marker): peeled, pristine elf restored", () => {
  const r = scrubNative(Buffer.concat([elf, decoys(34)]));
  assert.deepEqual(r.buffer, elf);
  assert.equal(r.report.trailerDropped, undefined);
  assert.deepEqual(decoyEntry(r), { kind: "fuse-decoy-sentinels", records: 34, bytesDropped: 34 * 42 });
});

check("2-record run (minimum): peeled", () => {
  const r = scrubNative(Buffer.concat([elf, decoys(2)]));
  assert.deepEqual(r.buffer, elf);
  assert.equal(decoyEntry(r)?.records, 2);
});

check("lone record: KEPT byte-exact (conservative — could be a real fuse)", () => {
  const input = Buffer.concat([elf, decoys(1)]);
  const r = scrubNative(input);
  assert.deepEqual(r.buffer, input);
  assert.equal(decoyEntry(r), undefined);
  // a decoy-flagged record (wire[6]=0x39) is residue, not a mutated real fuse
  assert.equal(r.report.suspiciousFuseRecord, true);
  assert.equal(r.report.fuseWireSuspect, undefined);
});

check("clean elf: untouched, no decoys, not hardened", () => {
  const r = scrubNative(Buffer.from(elf));
  assert.deepEqual(r.buffer, elf);
  assert.deepEqual(r.report.decoys, []);
  assert.equal(r.report.hardened, false);
  assert.equal(r.report.fuseWireSuspect, undefined);
});

check("real fuse in .rodata + bare decoy run: peeled, wire restored to canonical, suspect flagged", () => {
  const r = scrubNative(Buffer.concat([elfFuse, decoys(34)]));
  assert.deepEqual(r.buffer, elfFuseRestored);
  assert.equal(decoyEntry(r)?.records, 34);
  assert.equal(r.report.fuseWireSuspect, true);
  assert.equal(r.report.fuseRecovery?.status, "restored");
  assert.ok(r.report.fuseRecovery.restored.some((x) => x.startsWith("EnableEmbeddedAsarIntegrityValidation: enabled -> disabled")));
});

check("real fuse in .rodata + decoys + trailer: full restore, suspect flagged", () => {
  const r = scrubNative(Buffer.concat([elfFuse, decoys(34), TRAILER()]));
  assert.deepEqual(r.buffer, elfFuseRestored);
  assert.ok(r.report.trailerDropped > 0);
  assert.equal(decoyEntry(r)?.records, 34);
  assert.equal(r.report.fuseWireSuspect, true);
  assert.equal(r.report.fuseRecovery?.status, "restored");
});

check("lone real fuse matching hardened plan: wire restored to canonical, suspect flagged", () => {
  const r = scrubNative(Buffer.from(elfFuse));
  assert.deepEqual(r.buffer, elfFuseRestored);
  assert.equal(r.report.fuseWireSuspect, true);
  assert.equal(r.report.fuseRecovery?.status, "restored");
});

check("lone real fuse NOT matching plan: untouched, not suspect", () => {
  const r = scrubNative(Buffer.from(elfStock));
  assert.deepEqual(r.buffer, elfStock);
  assert.equal(r.report.fuseWireSuspect, undefined);
});

check("two real-looking fuse blocks: no suspect (ambiguous, conservative)", () => {
  const twoFuse = elf64({ extra: [{ name: ".rodata", off: 0x800, data: Buffer.concat([REAL_FUSE, Buffer.alloc(16, 0), STOCK_FUSE]) }] });
  const r = scrubNative(twoFuse);
  assert.deepEqual(r.buffer, twoFuse);
  assert.equal(r.report.fuseWireSuspect, undefined);
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
