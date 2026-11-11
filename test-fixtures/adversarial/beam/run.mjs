// Adversarial test-harness for BLADE's scrubBeam (src/trailer.mjs — scrubBeam).
// Builds hostile BEAM files into this directory, runs scrubBeam on each, and
// re-parses the output to detect: FALSE-DROP (real chunk/atom lost),
// STALE-REF (atom-index references left dangling), SIZE-FIELD-WRONG (FOR1
// form length or chunk size fields wrong), PASS, and EVASION (decoy survives).
//
//   node test-fixtures/adversarial/beam/run.mjs
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scrubBeam } from "../../../src/trailer.mjs";

const DIR = dirname(fileURLToPath(import.meta.url));
const hex = (n) => "0x" + n.toString(16).padStart(4, "0");
const pad4 = (n) => (4 - (n % 4)) % 4;

// ---------------- builders ----------------
function chunkBuf(name, payload, { declaredSize, padLen } = {}) {
  const size = declaredSize ?? payload.length;
  const h = Buffer.alloc(8);
  h.write(name, 0, "latin1");
  h.writeUInt32BE(size >>> 0, 4);
  return Buffer.concat([h, payload, Buffer.alloc(padLen ?? pad4(payload.length))]);
}
// chunks: [{name, payload, declaredSize?, padLen?}] — offsets tracked per the
// DECLARED layout (what scrubBeam's walk sees).
function beam(chunks, { formSizeOverride, tail } = {}) {
  const parts = [Buffer.from("BEAM", "latin1")];
  const layout = [];
  let off = 12;
  for (const c of chunks) {
    const size = c.declaredSize ?? c.payload.length;
    const pad = c.padLen ?? pad4(c.payload.length);
    layout.push({ name: c.name, off, size, payloadOff: off + 8, wire: 8 + c.payload.length + pad });
    parts.push(chunkBuf(c.name, c.payload, c));
    off += 8 + size + pad4(size);
  }
  const body = Buffer.concat(parts);
  const hdr = Buffer.alloc(8);
  hdr.write("FOR1", 0, "latin1");
  hdr.writeUInt32BE(formSizeOverride ?? body.length, 4);
  return { buf: Buffer.concat([hdr, body, ...(tail ? [tail] : [])]), layout };
}
function atu8(atoms) { // classic non-compact utf8 table
  const parts = [Buffer.alloc(4)];
  parts[0].writeInt32BE(atoms.length);
  for (const a of atoms) {
    const b = Buffer.from(a, "utf8");
    parts.push(Buffer.from([b.length & 0xff]), b);
  }
  return Buffer.concat(parts);
}
function atu8Compact(atoms) { // OTP28+ compact-u table (negative count)
  const encU = (v) => v < 16
    ? Buffer.from([(v << 4) & 0xff])
    : v < 0x800
      ? Buffer.from([0x08 | (((v >> 8) & 0x07) << 5), v & 0xff])
      : Buffer.from([0x38, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]);
  const parts = [Buffer.alloc(4)];
  parts[0].writeInt32BE(-atoms.length);
  for (const a of atoms) {
    const b = Buffer.from(a, "utf8");
    parts.push(encU(b.length), b);
  }
  return Buffer.concat(parts);
}
function atomLatin1(atomByteArrays) { // classic latin1 Atom chunk
  const parts = [Buffer.alloc(4)];
  parts[0].writeInt32BE(atomByteArrays.length);
  for (const b of atomByteArrays) parts.push(Buffer.from([b.length & 0xff]), b);
  return Buffer.concat(parts);
}
const L = (s) => Buffer.from(s, "latin1");
// compact-term operand encoder for the tiny Code streams we emit
const opU = (v) => Buffer.from([(v << 4) | 0]); // tag 0 = literal/u
const opA = (v) => Buffer.from([(v << 4) | 2]); // tag 2 = atom index
const opI = (v) => Buffer.from([(v << 4) | 1]); // tag 1 = integer
const opF = (v) => Buffer.from([(v << 4) | 5]); // tag 5 = label
// code chunk: 20-byte header + op stream we control byte-for-byte.
function codeChunk(ops /* [{op, operandAtoms:[{byteOffInPayload, atomIdx}]}], raw */) {
  const head = Buffer.alloc(20);
  head.writeUInt32BE(16, 0);    // sub_size
  head.writeUInt32BE(0, 4);     // instruction set
  head.writeUInt32BE(172, 8);   // opcode max
  head.writeUInt32BE(4, 12);    // label count
  head.writeUInt32BE(1, 16);    // function count
  return Buffer.concat([head, ops]);
}
function expT(entries) { // {atomIdx, arity, label}
  const parts = [Buffer.alloc(4)];
  parts[0].writeUInt32BE(entries.length);
  for (const e of entries) {
    const t = Buffer.alloc(12);
    t.writeUInt32BE(e.atomIdx, 0); t.writeUInt32BE(e.arity, 4); t.writeUInt32BE(e.label, 8);
    parts.push(t);
  }
  return Buffer.concat(parts);
}
function impT(entries) { // {modAtom, funAtom, arity}
  const parts = [Buffer.alloc(4)];
  parts[0].writeUInt32BE(entries.length);
  for (const e of entries) {
    const t = Buffer.alloc(12);
    t.writeUInt32BE(e.modAtom, 0); t.writeUInt32BE(e.funAtom, 4); t.writeUInt32BE(e.arity, 8);
    parts.push(t);
  }
  return Buffer.concat(parts);
}
function lineT(fnameAtomIdx) { // minimal Line chunk; item[1] = atom ref to fname
  const head = Buffer.alloc(20);
  head.writeUInt32BE(0, 0);   // version
  head.writeUInt32BE(0, 4);   // flags
  head.writeUInt32BE(1, 8);   // num line instructions
  head.writeUInt32BE(2, 12);  // num line items
  head.writeUInt32BE(1, 16);  // num filenames
  return Buffer.concat([head, opU(0), opA(fnameAtomIdx)]); // line 0, fname = atom idx
}
// Real BLA decoy payload (vendor/bla erlang-beam.ts:310-335): the head record
// `[BLA-BEAM-SHIELD]\0`, optional extra NUL-terminated records, the canary
// record (canary value = exactly 16 lowercase hex chars), then the per-chunk
// suffix `\nchunk=<idx>\n` — where <idx> matches the decoy index encoded in
// the chunk's name (Bla0-9 → 0-9, Bl0a-z → 10-35, B<base36 pad-3> → ≥36).
const blaDecoy = (idx, extra = Buffer.alloc(0)) => Buffer.concat([
  Buffer.from("[BLA-BEAM-SHIELD]\x00", "utf8"),
  extra,
  Buffer.from(`BLA_BEAM_CANARY=0123456789abcdef\x00\nchunk=${idx}\n`, "utf8"),
]);

// ---------------- verifier ----------------
function parseOut(buf) {
  const r = { ok: false, chunks: [], errors: [] };
  if (buf.length < 12 || buf.subarray(0, 4).toString("latin1") !== "FOR1" || buf.subarray(8, 12).toString("latin1") !== "BEAM") {
    r.errors.push("bad magic"); return r;
  }
  r.ok = true;
  r.formSize = buf.readUInt32BE(4);
  r.formEnd = 8 + r.formSize;
  r.sizeFieldOK = r.formEnd === buf.length;
  let at = 12;
  while (at + 8 <= Math.min(buf.length, r.formEnd)) {
    const name = buf.subarray(at, at + 4).toString("latin1");
    const size = buf.readUInt32BE(at + 4);
    const entry = { name, size, off: at, payloadOff: at + 8 };
    r.chunks.push(entry);
    if (at + 8 + size > r.formEnd) { entry.truncated = true; break; }
    at += 8 + size + pad4(size);
  }
  r.endAfterWalk = at;
  return r;
}
function readAtoms(payload) { // returns {names, compact, ok}
  if (payload.length < 4) return { names: [], ok: false };
  const declared = payload.readInt32BE(0);
  const compact = declared < 0;
  const count = Math.abs(declared);
  const names = [];
  let p = 4;
  for (let i = 0; i < count; i++) {
    let len;
    if (compact) {
      const f = payload[p];
      if (f === undefined) return { names, compact, ok: false };
      if ((f & 0x08) === 0) { len = f >> 4; p += 1; }
      else if ((f & 0x10) === 0) { len = ((f >> 5) << 8) | payload[p + 1]; p += 2; }
      else { const nb = (f >> 5) + 2; len = 0; for (let k = 0; k < nb; k++) len = (len << 8) | payload[p + 1 + k]; p += 1 + nb; }
    } else { len = payload[p]; p += 1; }
    if (len === undefined || p + len > payload.length) return { names, compact, ok: false };
    names.push({ name: payload.subarray(p, p + len).toString("utf8"), raw: Buffer.from(payload.subarray(p, p + len)), off: p });
    p += len;
  }
  return { names, compact, ok: true };
}
// scan Code chunk payload for `a`-tag operands; return [{byteOff, atomIdx}]
function codeAtomRefs(payload) {
  const refs = [];
  let p = 20;
  while (p < payload.length) {
    const op = payload[p++];
    const arity = ({ 1: 1, 2: 3, 51: 2 })[op] ?? 0;
    for (let i = 0; i < arity; i++) {
      const b = payload[p];
      const tag = b & 7, val = b >> 4;
      if (tag === 2) refs.push({ byteOff: p, atomIdx: val, op });
      p += 1;
    }
    if (arity === 0) { p += 0; } // ops we don't model consume just the opcode
  }
  return refs;
}

// ---------------- cases ----------------
const cases = [];
const add = (file, desc, built, expect) => {
  writeFileSync(join(DIR, file), built.buf);
  cases.push({ file, desc, built, expect });
};

// --- Case group 1: legit chunk names that match the drop patterns ---
// scrubBeam drops a chunk only when its payload is byte-shape-exact —
// `[BLA-BEAM-SHIELD]\0` head + `\nchunk=<idx>\n` tail matching the index
// encoded in a decoy-family name — and it sits in a decoy tail position
// (after the last standard chunk, or inside a decoy-named group). Name-only
// or marker-quoting chunks survive; surviving marker text is neutralized in
// place so nothing quotable remains.
{
  const atoms = ["demo", "run", "stop"];
  add("fp-B0xy.beam", "legit app chunk 'B0xy' (B[0-9a-z]{3}) — no BLA marker", beam([
    { name: "AtU8", payload: atu8(atoms) },
    { name: "Code", payload: codeChunk(Buffer.concat([Buffer.from([2]), opA(1), opA(2), opI(0)])) },
    { name: "B0xy", payload: Buffer.from("app telemetry v1 real data") },
    { name: "ExpT", payload: expT([{ atomIdx: 2, arity: 0, label: 1 }]) },
    { name: "StrT", payload: Buffer.alloc(4) },
  ]), "PASS");
}
{
  add("fp-boundary-names.beam", "many legit B* names, no markers — boundary sweep", beam([
    { name: "AtU8", payload: atu8(["m", "f"]) },
    { name: "B0xy", payload: Buffer.from("sig A") },
    { name: "Bzzz", payload: Buffer.from("sig B") },
    { name: "Bl00", payload: Buffer.from("sig C") },
    { name: "Bla9", payload: Buffer.from("sig D") },
    { name: "Blx0", payload: Buffer.from("sig E") },
    { name: "B1A2", payload: Buffer.from("uppercase A — control") },
    { name: "BLA9", payload: Buffer.from("uppercase LA — control") },
    { name: "B_xy", payload: Buffer.from("underscore — control") },
    { name: "b0xy", payload: Buffer.from("lowercase b — control") },
    { name: "Code", payload: codeChunk(Buffer.from([1])) },
  ]), "PASS");
}
{
  add("fp-Blah-decoyless.beam", "legit 'Blah' chunk (Bl+ah) — reads like English", beam([
    { name: "AtU8", payload: atu8(["m"]) },
    { name: "Blah", payload: Buffer.from("mysterious but real app data") },
    { name: "Code", payload: codeChunk(Buffer.from([1])) },
  ]), "PASS");
}
{
  // legit-named chunks that merely QUOTE the marker (env-dump capturing the
  // canary env var, docs describing the signature): payload lacks the
  // `[BLA-BEAM-SHIELD]\0` head record and `\nchunk=N\n` suffix, so both
  // chunks survive — the quoted marker text is neutralized in place.
  add("fp-B0xy-marker.beam", "legit 'B0xy'/'Bdoc' chunks whose payloads quote BLA markers", beam([
    { name: "AtU8", payload: atu8(["m", "f"]) },
    { name: "B0xy", payload: Buffer.from("env-dump: BLA_BEAM_CANARY=user_defined_thing\nPATH=/bin") },
    { name: "Bdoc", payload: Buffer.from("docs: strips [BLA-BEAM-SHIELD] markers from release") },
    { name: "Code", payload: codeChunk(Buffer.from([1])) },
    { name: "ExpT", payload: expT([{ atomIdx: 2, arity: 0, label: 1 }]) },
  ]), "PASS");
}
{
  // decoy payloads under names OUTSIDE the decoy families: no encoded index
  // to match, but the payload is still byte-shape-exact and the chunks sit
  // in tail position → drop.
  add("evasion-marker-wrong-name.beam", "shape-exact payloads in non-matching names 'Dcoy'/'Xyz9' at tail", beam([
    { name: "AtU8", payload: atu8(["m", "f"]) },
    { name: "Code", payload: codeChunk(Buffer.from([1])) },
    { name: "Dcoy", payload: blaDecoy(0) },
    { name: "Xyz9", payload: blaDecoy(1, Buffer.from("decoy payload renamed\x00")) },
  ]), "PASS");
}
{
  // mid-form decoy-named GROUP (BLA appends at tail, but a reordered form
  // still drops a contiguous run of decoy-named chunks)
  add("pass-decoy-real.beam", "true BLA decoy chunks (correct drops — control)", beam([
    { name: "AtU8", payload: atu8(["m", "f"]) },
    { name: "Code", payload: codeChunk(Buffer.concat([Buffer.from([2]), opA(1), opA(2), opI(0)])) },
    { name: "Bla0", payload: blaDecoy(0) },
    { name: "Bla1", payload: blaDecoy(1) },
    { name: "Bl0a", payload: blaDecoy(10) },
    { name: "B100", payload: blaDecoy(1296) }, // parseInt("100",36) = 1296
    { name: "ExpT", payload: expT([{ atomIdx: 2, arity: 0, label: 1 }]) },
  ]), "PASS");
}

// --- Case group 2: atoms with enclave/canary/BLA substrings ---
{
  add("enclave-atoms.beam", "app about enclaves: enclave_attest, enclave.unseal, BLA_session_key, canary_probe", beam([
    { name: "AtU8", payload: atu8(["enclave_attest", "enclave.unseal", "BLA_session_key", "canary_probe", "enclave_mod", "run"]) },
    { name: "Code", payload: codeChunk(Buffer.concat([Buffer.from([2]), opA(5), opA(6), opI(0)])) },
    { name: "ExpT", payload: expT([{ atomIdx: 6, arity: 0, label: 1 }, { atomIdx: 1, arity: 1, label: 2 }]) },
  ]), "PASS");
}
{
  // legit app happens to use the exact canary atom name mid-table
  const code = Buffer.concat([
    Buffer.from([2]), opA(1), opA(4), opI(0),     // func_info atom(1) atom(4) int(0)
    Buffer.from([1]), opF(1),                    // label 1
    Buffer.from([51]), opA(5), opU(1),           // (op 51-ish) atom(5) u(1)
  ]);
  add("stale-mid-canary.beam", "legit atom 'bla_beam_canary' at index 3 of 5; refs to 4,5", beam([
    { name: "AtU8", payload: atu8(["mymod", "init", "bla_beam_canary", "handle_req", "stop"]) },
    { name: "Code", payload: codeChunk(code) },
    { name: "ExpT", payload: expT([{ atomIdx: 4, arity: 0, label: 2 }, { atomIdx: 5, arity: 1, label: 3 }]) },
    { name: "LocT", payload: expT([{ atomIdx: 5, arity: 1, label: 9 }]) },
    { name: "ImpT", payload: impT([{ modAtom: 1, funAtom: 4, arity: 0 }]) },
    { name: "Line", payload: lineT(5) },
  ]), "PASS");
}
{
  add("stale-tarpit-prefix.beam", "legit atom 'bla_tarpit_atom_stats' at index 3 of 5", beam([
    { name: "AtU8", payload: atu8(["mymod", "init", "bla_tarpit_atom_stats", "handle_req", "stop"]) },
    { name: "Code", payload: codeChunk(Buffer.concat([Buffer.from([2]), opA(1), opA(4), opI(0)])) },
    { name: "ExpT", payload: expT([{ atomIdx: 4, arity: 0, label: 2 }, { atomIdx: 5, arity: 1, label: 3 }]) },
  ]), "PASS");
}
{
  add("tail-after-canary.beam", "hardened tail + ONE legit atom after canary (tool merge)", beam([
    { name: "AtU8", payload: atu8(["m", "f", "bla_beam_canary", "[BLA-BEAM-SHIELD]", "late_real_atom"]) },
    { name: "Code", payload: codeChunk(Buffer.concat([Buffer.from([2]), opA(1), opA(2), opI(0), Buffer.from([51]), opA(5), opU(0)])) },
    { name: "ExpT", payload: expT([{ atomIdx: 5, arity: 0, label: 7 }]) },
    { name: "Bla2", payload: blaDecoy(2) },
  ]), "PASS");
}
{
  add("pass-append-only.beam", "BLA-intended layout: canaries appended at END — control", beam([
    { name: "AtU8", payload: atu8(["mymod", "init", "stop", "bla_beam_canary", "[BLA-BEAM-SHIELD]", "bla_tarpit_atom_0_ab12"]) },
    { name: "Code", payload: codeChunk(Buffer.concat([Buffer.from([2]), opA(1), opA(2), opI(0), Buffer.from([51]), opA(3), opU(0)])) },
    { name: "ExpT", payload: expT([{ atomIdx: 2, arity: 0, label: 2 }, { atomIdx: 3, arity: 1, label: 3 }]) },
    { name: "Bla0", payload: blaDecoy(0) },
  ]), "PASS");
}
{
  add("stale-second-atu8.beam", "two AtU8 tables; canary mid-table in SECOND", beam([
    { name: "AtU8", payload: atu8(["m", "f"]) },
    { name: "Code", payload: codeChunk(Buffer.from([1])) },
    { name: "AtU8", payload: atu8(["x", "bla_beam_canary", "y", "z"]) },
    { name: "LocT", payload: expT([{ atomIdx: 3, arity: 0, label: 4 }]) },
  ]), "PASS");
}
{
  add("stale-index0.beam", "canary atom at index 1 — whole table nuked", beam([
    { name: "AtU8", payload: atu8(["bla_beam_canary", "real1", "real2"]) },
    { name: "Code", payload: codeChunk(Buffer.concat([Buffer.from([2]), opA(2), opA(3), opI(0)])) },
    { name: "ExpT", payload: expT([{ atomIdx: 2, arity: 0, label: 1 }]) },
  ]), "PASS");
}
{
  // both atom tables trimmed — atomsDropped overwrites instead of accumulating
  add("two-atu8-both-trim.beam", "two AtU8 tables BOTH containing canary tails", beam([
    { name: "AtU8", payload: atu8(["m", "f", "bla_beam_canary"]) },
    { name: "Code", payload: codeChunk(Buffer.from([1])) },
    { name: "AtU8", payload: atu8(["x", "y", "bla_beam_canary", "bla_tarpit_atom_0_a", "bla_tarpit_atom_1_b"]) },
    { name: "LocT", payload: expT([{ atomIdx: 2, arity: 0, label: 4 }]) },
  ]), "PASS");
}

// --- Case group 3: padding / alignment ---
{
  const sizes = [1, 2, 3, 4, 5, 6, 7];
  const chunks = [
    { name: "AtU8", payload: atu8(["m", "f"]) },
    ...sizes.map((n, i) => ({ name: `Pd${i}a`, payload: Buffer.alloc(n, 0x41 + i) })),
    { name: "Code", payload: codeChunk(Buffer.from([1])) },
    { name: "Bla3", payload: blaDecoy(3, Buffer.alloc(3, 0xcc)) }, // 62B — non-4-aligned
  ];
  add("pad-sizes.beam", "payload sizes 1..7 mod-4 sweep, decoy with non-4-aligned payload", beam(chunks), "PASS");
}
{
  // last chunk's declared size extends past formEnd (truncated tail chunk)
  add("oversize-tail.beam", "last chunk declares size beyond FOR1 end; decoy dropped earlier", {
    buf: (() => {
      const body = Buffer.concat([
        Buffer.from("BEAM", "latin1"),
        chunkBuf("AtU8", atu8(["m", "f"])),
        chunkBuf("Bla0", blaDecoy(0)),
        chunkBuf("Tail", Buffer.alloc(16, 0x51), { declaredSize: 64, padLen: 0 }), // lies: only 16b present
      ]);
      const hdr = Buffer.alloc(8);
      hdr.write("FOR1", 0, "latin1");
      hdr.writeUInt32BE(body.length, 4);
      return Buffer.concat([hdr, body]);
    })(),
    layout: [],
  }, "PASS");
}
{
  // chunk written WITHOUT required 4-byte pad — desyncs the chunk walk
  const body = Buffer.concat([
    Buffer.from("BEAM", "latin1"),
    chunkBuf("AtU8", atu8(["m", "f"])),
    chunkBuf("Xyz1", Buffer.alloc(5, 0x55), { padLen: 0 }),  // 5-byte payload, NO pad
    chunkBuf("Bla7", blaDecoy(7)),
    chunkBuf("StrT", Buffer.alloc(4, 0x53)),
  ]);
  const hdr = Buffer.alloc(8);
  hdr.write("FOR1", 0, "latin1");
  hdr.writeUInt32BE(body.length, 4);
  add("evasion-misaligned.beam", "chunk with missing pad desyncs walk — Bla7 decoy hidden behind it", {
    buf: Buffer.concat([hdr, body]), layout: [],
  }, "PASS");
}

// --- Case group 4: Atom(latin1) vs AtU8, compact tables ---
{
  add("atom-classic-tail.beam", "classic Atom chunk, ASCII atoms, canary tail — control", beam([
    { name: "Atom", payload: atomLatin1([L("m"), L("f"), L("bla_beam_canary"), L("bla_tarpit_atom_0_zz")]) },
    { name: "Code", payload: codeChunk(Buffer.concat([Buffer.from([2]), opA(1), opA(2), opI(0)])) },
  ]), "PASS");
}
{
  add("atom-latin1-nonascii.beam", "latin1 Atom chunk w/ café(0xE9) résumé before canary", beam([
    { name: "Atom", payload: atomLatin1([L("m"), Buffer.from([0x63, 0x61, 0x66, 0xe9]), Buffer.from([0x72, 0xe9, 0x73, 0x75, 0x6d, 0xe9]), L("bla_beam_canary"), L("tail")]) },
    { name: "Code", payload: codeChunk(Buffer.concat([Buffer.from([2]), opA(1), opA(2), opI(0)])) },
    { name: "ExpT", payload: expT([{ atomIdx: 3, arity: 0, label: 1 }]) },
  ]), "PASS");
}
{
  add("atom-latin1-overlong.beam", "latin1 atom 200×0xE9 → utf8 400B → length byte wraps", beam([
    { name: "Atom", payload: atomLatin1([L("m"), Buffer.alloc(200, 0xe9), L("bla_beam_canary")]) },
    { name: "Code", payload: codeChunk(Buffer.from([1])) },
  ]), "PASS");
}
{
  add("atu8-compact-mid.beam", "OTP28 compact AtU8, tarpit-named legit atom mid-table", beam([
    { name: "AtU8", payload: atu8Compact(["m", "f1", "bla_tarpit_atom_9_zz", "f2", "f3"]) },
    { name: "Code", payload: codeChunk(Buffer.concat([Buffer.from([2]), opA(1), opA(4), opI(0)])) },
    { name: "ExpT", payload: expT([{ atomIdx: 4, arity: 0, label: 1 }, { atomIdx: 5, arity: 2, label: 2 }]) },
  ]), "PASS");
}
{
  add("atu8-compact-tail.beam", "OTP28 compact AtU8, canaries at END — control", beam([
    { name: "AtU8", payload: atu8Compact(["m", "f1", "f2", "bla_beam_canary", "bla_tarpit_atom_0_q"]) },
    { name: "Code", payload: codeChunk(Buffer.concat([Buffer.from([2]), opA(1), opA(2), opI(0)])) },
    { name: "ExpT", payload: expT([{ atomIdx: 2, arity: 0, label: 1 }, { atomIdx: 3, arity: 2, label: 2 }]) },
    { name: "Bla4", payload: blaDecoy(4) },
  ]), "PASS");
}

// --- Case group 5: FOR1 form-length handling ---
{
  // realistic hardened file: many decoy chunks + canary atoms
  const decoys = Array.from({ length: 70 }, (_, i) => ({
    name: i < 10 ? `Bla${i}` : i < 36 ? `Bl${i.toString(36).padStart(2, "0")}` : `B${i.toString(36).padStart(3, "0")}`.slice(0, 4),
    payload: blaDecoy(i),
  }));
  add("for1-recompute.beam", "fully hardened file (70 decoy chunks + canary atoms)", beam([
    { name: "AtU8", payload: atu8(["m", "f", "bla_beam_canary", "[BLA-BEAM-SHIELD]", "bla_tarpit_atom_0_1", "bla_tarpit_atom_1_2"]) },
    { name: "Code", payload: codeChunk(Buffer.concat([Buffer.from([2]), opA(1), opA(2), opI(0)])) },
    { name: "ExpT", payload: expT([{ atomIdx: 2, arity: 0, label: 1 }]) },
    ...decoys,
  ]), "PASS");
}
{
  add("for1-tail-garbage.beam", "real appended trailer AFTER IFF form; decoy inside form", (() => {
    const b = beam([
      { name: "AtU8", payload: atu8(["m", "f"]) },
      { name: "Code", payload: codeChunk(Buffer.from([1])) },
      { name: "Bla0", payload: blaDecoy(0) },
    ], { tail: Buffer.from("SIGNATURE-BLOCK-v9-real-appended-trailer-bytes!!..END") });
    return b;
  })(), "PASS");
}
{
  add("for1-declared-long.beam", "declared formSize exceeds file end — clipped parse", (() => {
    const b = beam([
      { name: "AtU8", payload: atu8(["m", "f"]) },
      { name: "Code", payload: codeChunk(Buffer.from([1])) },
      { name: "Bla0", payload: blaDecoy(0) },
    ], { formSizeOverride: 0x00ffffff });
    return b;
  })(), "PASS");
}
{
  // atom table declares more atoms than it contains — parse fails → canary survives
  const badTable = (() => {
    const parts = [Buffer.alloc(4)];
    parts[0].writeInt32BE(8); // claims 8, has 4
    for (const a of ["m", "f", "bla_beam_canary", "x"]) {
      const b = Buffer.from(a, "utf8");
      parts.push(Buffer.from([b.length]), b);
    }
    return Buffer.concat(parts);
  })();
  add("evasion-trunc-table.beam", "atom table truncated (count>actual) — canary survives, hardened:false", beam([
    { name: "AtU8", payload: badTable },
    { name: "Code", payload: codeChunk(Buffer.from([1])) },
  ]), "PASS");
}

// ---------------- run ----------------
const out = [];
const emit = (s = "") => { console.log(s); out.push(s); };
const results = [];
for (const c of cases) {
  const { buf, layout } = c.built;
  const r = scrubBeam(buf);
  const p = parseOut(r.buffer);
  const lines = [];
  const log = (s) => lines.push(s);
  log(`## ${c.file}`);
  log(`  in=${buf.length}B out=${r.buffer.length}B hardened=${r.report.hardened} dropped(chunks=${r.report.decoyChunksDropped ?? 0} atoms=${r.report.canaryAtomsDropped ?? 0}) expect=${c.expect}`);

  // input layout
  for (const l of layout) log(`  in  ${hex(l.off)} chunk "${l.name}" size=${l.size}`);

  // output checks
  if (!p.ok) { log(`  OUT: not a BEAM (${p.errors.join(";")})`); }
  else {
    if (!p.sizeFieldOK) log(`  SIZE-FIELD-WRONG: FOR1 size=${p.formSize} but file is ${r.buffer.length} (end ${hex(p.formEnd)} vs ${hex(r.buffer.length)})`);
    for (const ch of p.chunks) log(`  out ${hex(ch.off)} chunk "${ch.name}" size=${ch.size}${ch.truncated ? " TRUNCATED" : ""}`);
    // atom table state
    const atomChunks = p.chunks.filter((x) => x.name === "AtU8" || x.name === "Atom");
    let atomNames = null;
    for (const ac of atomChunks) {
      const t = readAtoms(r.buffer.subarray(ac.payloadOff, ac.payloadOff + ac.size));
      log(`  out ${hex(ac.payloadOff)} ${ac.name}: count=${t.names.length} compact=${!!t.compact} parse=${t.ok ? "ok" : "FAIL"}`);
      t.names.forEach((n, i) => log(`      atom[${i + 1}] @${hex(ac.payloadOff + n.off)} "${n.name}"`));
      atomNames = t.names.map((n) => n.name); // BEAM override semantics: last atom table wins
    }
    // dangling ref scan
    if (atomNames !== null) {
      for (const ch of p.chunks) {
        if (["ExpT", "LocT", "FunT"].includes(ch.name)) {
          const body = r.buffer.subarray(ch.payloadOff, ch.payloadOff + ch.size);
          const n = body.length >= 4 ? body.readUInt32BE(0) : 0;
          for (let i = 0; i < n; i++) {
            const ai = body.readUInt32BE(4 + i * 12);
            if (ai > atomNames.length || ai === 0) log(`  STALE-REF: ${ch.name} entry[${i}] @${hex(ch.payloadOff + 4 + i * 12)} atom-index ${ai} > table size ${atomNames.length}`);
            else log(`  ref-ok : ${ch.name} entry[${i}] @${hex(ch.payloadOff + 4 + i * 12)} atom-index ${ai} -> "${atomNames[ai - 1]}"`);
          }
        }
        if (ch.name === "ImpT") {
          const body = r.buffer.subarray(ch.payloadOff, ch.payloadOff + ch.size);
          const n = body.length >= 4 ? body.readUInt32BE(0) : 0;
          for (let i = 0; i < n; i++) {
            const mi = body.readUInt32BE(4 + i * 12), fi = body.readUInt32BE(8 + i * 12);
            if (mi > atomNames.length) log(`  STALE-REF: ImpT entry[${i}] mod-atom ${mi} @${hex(ch.payloadOff + 4 + i * 12)} > ${atomNames.length}`);
            if (fi > atomNames.length) log(`  STALE-REF: ImpT entry[${i}] fun-atom ${fi} @${hex(ch.payloadOff + 8 + i * 12)} > ${atomNames.length}`);
          }
        }
        if (ch.name === "Line") {
          const body = r.buffer.subarray(ch.payloadOff, ch.payloadOff + ch.size);
          const nItems = body.length >= 16 ? body.readUInt32BE(12) : 0;
          for (let i = 0, q = 20; i < nItems && q < body.length; i++, q++) {
            const b = body[q];
            if ((b & 7) === 2 && (b >> 4) > atomNames.length) log(`  STALE-REF: Line item[${i}] @${hex(ch.payloadOff + q)} fname atom-index ${b >> 4} > ${atomNames.length}`);
          }
        }
        if (ch.name === "Code") {
          const body = r.buffer.subarray(ch.payloadOff, ch.payloadOff + ch.size);
          for (const ref of codeAtomRefs(body)) {
            if (ref.atomIdx > atomNames.length) log(`  STALE-REF: Code operand @${hex(ch.payloadOff + ref.byteOff)} op=${ref.op} atom-index ${ref.atomIdx} > ${atomNames.length}`);
            else log(`  ref-ok : Code operand @${hex(ch.payloadOff + ref.byteOff)} atom-index ${ref.atomIdx} -> "${atomNames[ref.atomIdx - 1]}"`);
          }
        }
      }
    }
  }
  // residue check — any canary text surviving in the OUTPUT means a partial miss
  const residue = r.buffer.includes(L("[BLA-BEAM-SHIELD]")) || r.buffer.includes(L("bla_beam_canary")) || /bla_tarpit_atom_/.test(r.buffer.toString("latin1"));
  if (residue) log(`  RESIDUE: BLA canary text still present in output`);
  const verdict = /STALE-REF/.test(lines.join("\n")) ? "STALE-REF"
    : /SIZE-FIELD-WRONG/.test(lines.join("\n")) ? "SIZE-FIELD-WRONG"
    : residue ? "EVASION"
    : c.expect;
  log(`  VERDICT: ${verdict}`);
  results.push({ file: c.file, expect: c.expect, verdict });
  emit(lines.join("\n"));
}
emit("\n=== SUMMARY ===");
for (const r of results) emit(`${r.verdict.padEnd(16)} ${r.file}  (expect ${r.expect})`);
writeFileSync(join(DIR, "full-log.txt"), out.join("\n") + "\n");
