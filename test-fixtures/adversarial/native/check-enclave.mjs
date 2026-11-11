// Focused checks for scrubNative's BLA 3.2.4 `.enclave` mapped-section removal.
//   real 3.2.4 fixture (slack-plant + appended section + V1 trailer)
//     -> section stripped, slack re-zeroed, byte-exact restore
//   slack-only plant (no section)                          -> re-zeroed slack
//   non-signature bytes in slack                           -> KEPT (real data)
//   legit .enclave section without decoy payload           -> KEPT (SGX guard)
//   decoy section followed by real overlay                 -> header stripped,
//     payload bytes retained + flagged (never cut real bytes)
//   decoy .enclave mid-table                               -> header zeroed,
//     nsec unchanged, neighbouring sections intact
// Usage: node test-fixtures/adversarial/native/check-enclave.mjs
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");
const { scrubNative } = await import(pathToFileURL(join(root, "src", "trailer.mjs")).href);

const HARDENED = readFileSync(join(here, "in", "pe-enclave-324.exe"));
const PRISTINE = readFileSync(join(here, "expected", "pe-enclave-324.exe")); // 1536B, 1x .text

// ---------- PE fixture helpers (built on the pristine PE32+) ----------
const pe = (b) => b.readUInt32LE(0x3c);
const nsecOf = (b) => b.readUInt16LE(pe(b) + 6);
const soiOf = (b) => b.readUInt32LE(pe(b) + 4 + 20 + 56);
const align = (v, a) => Math.ceil(v / a) * a;
// Append one IMAGE_SECTION_HEADER + raw payload, bumping nsec/SizeOfImage —
// same mutation shape BLA's injectMappedWindowsPeDecoySection performs.
function addSection(base, { name, payload, vsize, chars = 0x40000060 }) {
  const p = pe(base), coff = p + 4, opt = coff + 20;
  const nsec = base.readUInt16LE(coff + 2), optSize = base.readUInt16LE(coff + 16);
  const secTbl = opt + optSize;
  const SA = base.readUInt32LE(opt + 32), FA = base.readUInt32LE(opt + 36);
  let maxVA = 0, maxRaw = 0;
  for (let i = 0; i < nsec; i++) {
    const s = secTbl + i * 40;
    maxVA = Math.max(maxVA, base.readUInt32LE(s + 12) + Math.max(base.readUInt32LE(s + 8), base.readUInt32LE(s + 16)));
    maxRaw = Math.max(maxRaw, base.readUInt32LE(s + 20) + base.readUInt32LE(s + 16));
  }
  const vs = vsize ?? payload.length;
  const rawSize = align(payload.length, FA), rawPtr = align(maxRaw, FA), va = align(maxVA, SA);
  const hdr = Buffer.alloc(40);
  Buffer.from(name, "latin1").copy(hdr, 0, 0, 8);
  hdr.writeUInt32LE(vs, 8); hdr.writeUInt32LE(va, 12);
  hdr.writeUInt32LE(rawSize, 16); hdr.writeUInt32LE(rawPtr, 20);
  hdr.writeUInt32LE(chars, 36);
  const out = Buffer.concat([base, Buffer.alloc(Math.max(0, rawPtr - base.length)), payload, Buffer.alloc(rawSize - payload.length)]);
  hdr.copy(out, secTbl + nsec * 40);
  out.writeUInt16LE(nsec + 1, coff + 2);
  out.writeUInt32LE(align(va + Math.max(vs, rawSize), SA), opt + 56);
  return out;
}
// Signature-bearing decoy payload fragment (islands + RSDS + RTTI + tag).
const DECOY_PAYLOAD = Buffer.concat([
  Buffer.from([0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5]), Buffer.alloc(40, 0xcc),
  Buffer.from("RSDS\x01\x02\x03\x04C:\\build\\agent\\work\\enclave-ring0-runtime\\x.pdb\0.enclave\0.?AVFoo@bar@@\0", "latin1"),
]);
const nulEnclave = Buffer.from("\0.enclave\0", "latin1");

let pass = 0, fail = 0;
const check = (name, fn) => {
  try { fn(); pass++; console.log(`  ok  ${name}`); }
  catch (e) { fail++; console.log(`FAIL  ${name}: ${e.message}`); }
};

check("real BLA 3.2.4 fixture: section stripped + slack cleansed + trailer cut = byte-exact", () => {
  const r = scrubNative(HARDENED);
  assert.deepEqual(r.buffer, PRISTINE);
  assert.equal(r.report.peEnclaveSectionRemoved, true);
  assert.equal(r.report.peSlackCleansed, 224);
  assert.equal(r.report.hardened, true);
  assert.ok(r.report.trailerDropped > 0);
  const sec = r.report.decoys.find((d) => d.kind === "pe-enclave-section");
  assert.equal(sec.virtualSize, 0x83f);
  assert.equal(sec.rawBytesDropped, 0xa00);
  // no decoy surface survives
  assert.equal(r.buffer.includes(Buffer.from(".?AV", "latin1")), false);
  assert.equal(r.buffer.includes(nulEnclave), false);
  assert.equal(nsecOf(r.buffer), 1);
  assert.equal(soiOf(r.buffer), 0x2000);
});

check("slack-only plant (no appended section): slack re-zeroed, rest untouched", () => {
  const t = Buffer.from(PRISTINE);
  DECOY_PAYLOAD.copy(t, 0x520); // 224B slack region of .text
  const r = scrubNative(t);
  assert.deepEqual(r.buffer, PRISTINE);
  assert.equal(r.report.peSlackCleansed, 224);
  assert.equal(r.report.peEnclaveSectionRemoved, undefined);
  assert.equal(r.report.hardened, true);
});

check("non-signature bytes in slack: KEPT (could be real overlay data)", () => {
  const t = Buffer.from(PRISTINE);
  Buffer.from("legit compiler padding / overlay-ish data").copy(t, 0x520);
  const r = scrubNative(t);
  assert.deepEqual(r.buffer, t);
  assert.equal(r.report.peSlackCleansed, undefined);
  assert.equal(r.report.hardened, false);
});

check("legit .enclave section without decoy payload: KEPT byte-exact (SGX guard)", () => {
  const t = addSection(PRISTINE, { name: ".enclave", payload: Buffer.alloc(0x100, 0x41) });
  const r = scrubNative(t);
  assert.deepEqual(r.buffer, t);
  assert.equal(r.report.peEnclaveSectionRemoved, undefined);
  assert.equal(r.report.hardened, false);
});

check("decoy .enclave at EOF (bare, no trailer): removed, bytes dropped", () => {
  const t = addSection(PRISTINE, { name: ".enclave", payload: DECOY_PAYLOAD, vsize: DECOY_PAYLOAD.length });
  const r = scrubNative(t);
  assert.deepEqual(r.buffer, PRISTINE);
  assert.equal(r.report.peEnclaveSectionRemoved, true);
  assert.equal(r.report.peEnclaveRawRetained, undefined);
});

check("decoy .enclave + real overlay after it: header stripped, bytes retained + flagged", () => {
  const t = Buffer.concat([addSection(PRISTINE, { name: ".enclave", payload: DECOY_PAYLOAD, vsize: DECOY_PAYLOAD.length }), Buffer.from("REAL-OVERLAY-DATA!")]);
  const r = scrubNative(t);
  assert.equal(r.buffer.length, t.length);
  assert.equal(r.report.peEnclaveSectionRemoved, true);
  assert.equal(r.report.peEnclaveRawRetained, true);
  assert.equal(nsecOf(r.buffer), 1);                       // forged header hidden
  assert.equal(r.buffer.subarray(r.buffer.length - 18).toString("latin1"), "REAL-OVERLAY-DATA!");
});

check("decoy .enclave mid-table: header zeroed, nsec unchanged, neighbours intact", () => {
  let t = addSection(PRISTINE, { name: ".enclave", payload: DECOY_PAYLOAD, vsize: DECOY_PAYLOAD.length });
  t = addSection(t, { name: ".rdata", payload: Buffer.from("real section data".repeat(8)) });
  const r = scrubNative(t);
  assert.equal(r.buffer.length, t.length);                 // no truncation
  assert.equal(r.report.peEnclaveSectionRemoved, true);
  assert.equal(nsecOf(r.buffer), 3);                       // mid-table slot stays counted
  // the .enclave header (index 1) is zeroed; .rdata (index 2) untouched
  const p = pe(r.buffer), secTbl = p + 4 + 20 + r.buffer.readUInt16LE(p + 4 + 16);
  assert.ok(r.buffer.subarray(secTbl + 40, secTbl + 80).equals(Buffer.alloc(40)));
  assert.equal(r.buffer.subarray(secTbl + 80, secTbl + 86).toString("latin1"), ".rdata");
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
