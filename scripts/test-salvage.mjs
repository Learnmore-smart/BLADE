#!/usr/bin/env node
// Unit checks for recovery/salvage.mjs — the keep+flag helpers that
// rescue real data from truncated/marker-poisoned containers.
import { triagePcapTail, detectEvmPad, salvageZipMember, repairDex, preserveApkMeta } from "../src/recovery/salvage.mjs";
import zlib from "node:zlib";

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) pass++; else { fail++; console.log("FAIL:", name); } };

// --- triagePcapTail --------------------------------------------------------------
{
  const r = triagePcapTail(Buffer.alloc(0));
  ok(r.kept.length === 0 && r.reason === "empty", "empty tail");
}
{
  // marker bytes alone are pure armor — always dropped; the envelope
  // requirement governs the *surrounding* bytes.
  const tail = Buffer.from("[BLA-PCAP-SHIELD]");
  const r = triagePcapTail(tail);
  ok(r.kept.length === 0 && r.dropped.length === tail.length && r.reason === "marker-bytes",
     "bare marker bytes dropped");
}
{
  // marker text with surrounding bytes but NO plausible envelope -> the
  // non-marker bytes are kept (can't attribute them to a record)
  const tail = Buffer.from("real-tail-bytes-[BLA-PCAP-SHIELD]-more-real");
  const r = triagePcapTail(tail);
  ok(r.kept.length > 0 && r.kept.toString().includes("real-tail-bytes"), "non-marker surroundings kept");
}
{
  const r = triagePcapTail(Buffer.from("normal packet bytes, no markers"));
  ok(r.reason === "no-markers" && r.kept.length === 31, "no markers -> keep all");
}
{
  // a marker inside a well-formed classic-LE record envelope -> dropped
  const hdr = Buffer.alloc(16);
  hdr.writeUInt32LE(1_700_000_000, 0);  // sane epoch
  hdr.writeUInt32LE(123_456, 4);        // sane frac-secs (<1e9)
  const payload = Buffer.from("AAAA[BLA-PCAP-SHIELD]BBBB");
  hdr.writeUInt32LE(payload.length, 8); // incl_len == orig_len
  hdr.writeUInt32LE(payload.length, 12);
  const r = triagePcapTail(Buffer.concat([hdr, payload]));
  ok(r.dropped.length === 16 + payload.length && r.kept.length === 0,
     `enveloped marker dropped (kept=${r.kept.length}, dropped=${r.dropped.length}, reason=${r.reason})`);
}

// --- detectEvmPad ------------------------------------------------------------------
{
  // null must not crash (default-param bug fixed)
  const r = detectEvmPad(null);
  ok(r && r.padStart === null, "detectEvmPad(null) safe");
  ok(detectEvmPad(Buffer.alloc(0)).padStart === null, "empty safe");
}
{
  // all-zero tail: 0x00 is a valid STOP instruction — NOT junk pad
  const code = Buffer.concat([Buffer.from([0x60, 0x80, 0x60, 0x40]), Buffer.alloc(64)]);
  const r = detectEvmPad(code);
  ok(r.padStart === null, "zero tail is valid STOPs, not pad");
}
{
  // BLA's real EVM decoy shape: a JUMPDEST (0x5b) run -> detected
  const code = Buffer.concat([Buffer.from([0x60, 0x80, 0x60, 0x40]), Buffer.alloc(64).fill(0x5b)]);
  const r = detectEvmPad(code);
  ok(r.padStart === 4 && r.confidence !== "low", "JUMPDEST run detected as pad");
}
{
  // plausible code — no pad
  const code = Buffer.from([0x60, 0x80, 0x60, 0x40, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);
  const r = detectEvmPad(code);
  ok(r.padStart === null, "real bytecode -> no pad");
}

// --- salvageZipMember --------------------------------------------------------------
{
  const raw = zlib.deflateRawSync(Buffer.from("hello zip member content"));
  const r = salvageZipMember(raw, 8);
  ok(r.data && r.data.toString().includes("hello zip member"), "deflate member decoded");
}
{
  const raw = Buffer.from("stored member bytes");
  const r = salvageZipMember(raw, 0);
  ok(r.data && r.data.toString() === "stored member bytes", "stored member passthrough");
}
{
  // marker text spliced into the middle of a deflate stream
  const good = zlib.deflateRawSync(Buffer.from("A".repeat(500)));
  const mid = Math.floor(good.length / 2);
  const poisoned = Buffer.concat([good.subarray(0, mid), Buffer.from("[BLA-PCAP-SHIELD]"), good.subarray(mid)]);
  const r = salvageZipMember(poisoned, 8);
  ok(r.data !== null, "spliced stream yields output");
}
{
  const r = salvageZipMember(Buffer.alloc(0), 8);
  ok(r.data === null && r.salvagedBytes === 0, "empty member -> none");
}
{
  const r = salvageZipMember(Buffer.from("not compressed at all"), 8);
  ok(r.data !== undefined && typeof r.note === "string", "garbage member -> shaped");
}

// --- repairDex ------------------------------------------------------------------
{
  // valid dex header with a corrupted file_size gets repaired back to the
  // real length; checksum fields recomputed.
  const dex = Buffer.alloc(0x200);
  dex.write("dex\n035", 0, "latin1");
  dex.writeUInt32LE(0x300, 0x20);         // file_size LIES: says 0x300, real 0x200
  dex.writeUInt32LE(0x70, 0x38);          // header_size (standard)
  dex.writeUInt32LE(0x12345678, 0x34);    // endian_tag
  const r = repairDex(Buffer.from(dex));
  ok(r.buf.length === 0x200 && Array.isArray(r.repairs) && typeof r.status === "string",
     `dex repaired shape (${r.status})`);
}
{
  // non-dex input -> honest status, buf returned unchanged-ish
  const r = repairDex(Buffer.from("not a dex file at all"));
  ok(typeof r.status === "string" && r.buf !== undefined, "non-dex -> shaped result");
}
{
  const r = repairDex(Buffer.alloc(0));
  ok(typeof r.status === "string", "empty dex safe");
}

// --- preserveApkMeta -------------------------------------------------------------
// Build minimal local + central headers with alignment-padding extras.
{
  const mkLocal = (extra) => {
    const h = Buffer.alloc(30 + 4 + extra.length);
    h.writeUInt32LE(0x04034b50, 0);
    h.writeUInt32LE(0xdead1234, 10);           // DOS timestamp
    h.writeUInt16LE(4, 26);                    // name len
    h.writeUInt16LE(extra.length, 28);         // extra len
    h.write("x.apk", 30, "latin1");
    extra.copy(h, 34);
    return h;
  };
  const mkCentral = (extra) => {
    const h = Buffer.alloc(46 + 4 + extra.length);
    h.writeUInt32LE(0x02014b50, 0);
    h.writeUInt32LE(0xbeef5678, 12);           // DOS timestamp (central wins)
    h.writeUInt16LE(4, 28);
    h.writeUInt16LE(extra.length, 30);
    h.write("x.apk", 46, "latin1");
    extra.copy(h, 50);
    return h;
  };
  const a11e = Buffer.concat([Buffer.from([0x1e, 0xa1, 0x10, 0x00]), Buffer.alloc(16)]);
  { // alignment pad in local extra -> recovered verbatim
    const r = preserveApkMeta(mkLocal(a11e), mkCentral(Buffer.alloc(0)));
    ok(r && r.extraPad && r.extraPad.length === 20 && r.extraPad.readUInt16LE(0) === 0xa11e,
       "0xa11e pad recovered from local extra");
    ok(r.timestamp === 0xbeef5678, "central timestamp preferred");
  }
  { // central-only pad -> fallback path
    const r = preserveApkMeta(mkLocal(Buffer.alloc(0)), mkCentral(a11e));
    ok(r && r.extraPad && r.extraPad.readUInt16LE(0) === 0xa11e, "0xa11e pad from central fallback");
  }
  { // all-zero extra region -> whole region is pad
    const r = preserveApkMeta(mkLocal(Buffer.alloc(24)), mkCentral(Buffer.alloc(0)));
    ok(r && r.extraPad && r.extraPad.length === 24, "all-zero extra -> whole region pad");
    ok(r.timestamp === 0xbeef5678, "timestamp from central");
  }
  { // local timestamp used when central is zero
    const central = mkCentral(Buffer.alloc(0));
    central.writeUInt32LE(0, 12);
    const r = preserveApkMeta(mkLocal(Buffer.alloc(0)), central);
    ok(r.timestamp === 0xdead1234, "local timestamp fallback");
  }
  { // no extras, no timestamps -> nulls, no throw
    const local = mkLocal(Buffer.alloc(0));
    local.writeUInt32LE(0, 10);
    const central = mkCentral(Buffer.alloc(0));
    central.writeUInt32LE(0, 12);
    const r = preserveApkMeta(local, central);
    ok(r && r.extraPad === null && r.timestamp === null, "clean headers -> nulls");
  }
  { // garbage buffers -> nulls, no throw
    const r = preserveApkMeta(Buffer.from("junk"), null);
    ok(r && r.extraPad === null && r.timestamp === null, "garbage -> nulls, no throw");
  }
  { // filler-field 0xffff with zero payload counts as pad
    const filler = Buffer.concat([Buffer.from([0xff, 0xff, 0x08, 0x00]), Buffer.alloc(8)]);
    const r = preserveApkMeta(mkLocal(filler), null);
    ok(r && r.extraPad && r.extraPad.readUInt16LE(0) === 0xffff, "0xffff filler pad recovered");
  }
  { // non-pad extra (e.g. real field id) -> not recovered
    const real = Buffer.concat([Buffer.from([0x01, 0x00, 0x04, 0x00]), Buffer.from([1, 2, 3, 4])]);
    const r = preserveApkMeta(mkLocal(real), null);
    ok(r && r.extraPad === null, "non-pad extra not recovered");
  }
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
