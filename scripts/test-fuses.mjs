#!/usr/bin/env node
// Unit checks for recoverFuseDefaults — the Electron fuse-wire recovery
// that must restore real V1 records to canonical release defaults while
// refusing decoy sentinels, ambiguous multi-records, and truncated wires.
import { readFileSync } from "node:fs";
import { recoverFuseDefaults } from "../src/recovery/canonical.mjs";

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) pass++; else { fail++; console.log("FAIL:", name); } };

const SENTINEL = Buffer.from("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX", "latin1");
// V1 record: sentinel ‖ ver(1) ‖ len ‖ wire bytes (0x30/0x31/0x72/0x39 states)
const mkRec = (wire, { version = 1, padFront = "PAD", padBack = "TAIL" } = {}) => {
  const w = Buffer.from(wire);
  const rec = Buffer.concat([SENTINEL, Buffer.from([version, w.length]), w]);
  return Buffer.concat([Buffer.from(padFront), rec, Buffer.from(padBack)]);
};
// canonical release wire for a non-darwin container:
// RunAsNode=0 CookieEnc=1 NodeOptions=0 CliInspect=0 AsarInteg=0
// OnlyLoadFromAsar=1 V8Snapshot=0 FileProtoPriv=0
const canonical = () => Buffer.from([0x30, 0x31, 0x30, 0x30, 0x30, 0x31, 0x30, 0x30]);

// --- absent / decoy / ambiguous -------------------------------------------
{
  const r = recoverFuseDefaults(Buffer.from("no fuses here"));
  ok(r.status === "absent" && r.sentinelCount === 0 && r.buf.equals(Buffer.from("no fuses here")), "no sentinel -> absent");
}
{
  // decoy-only: wire containing a '9' byte is never treated as real
  const decoyWire = canonical(); decoyWire[3] = 0x39;
  const buf = mkRec(decoyWire);
  const r = recoverFuseDefaults(buf);
  ok(r.status === "unsupported" && r.sentinelCount === 1 && r.buf.equals(buf), "decoy record -> unsupported, bytes untouched");
}
{
  // two real records -> ambiguous, refuse
  const buf = Buffer.concat([mkRec(canonical(), { padBack: "" }), mkRec(canonical(), { padFront: "" })]);
  const r = recoverFuseDefaults(buf);
  ok(r.status === "ambiguous" && /refusing/i.test(r.note), "two real records -> ambiguous");
}
{
  // truncated wire (len claims more than buffer has)
  const rec = Buffer.concat([SENTINEL, Buffer.from([1, 20]), canonical()]);
  const r = recoverFuseDefaults(rec);
  ok(r.status === "unsupported", "truncated wire -> unsupported");
}
{
  // version != 1 -> rejected record, still unsupported
  const r = recoverFuseDefaults(mkRec(canonical(), { version: 2 }));
  ok(r.status === "unsupported", "v2 record -> unsupported");
}

// --- restoration ----------------------------------------------------------
{
  // real record with drifted bytes -> restored to canonical
  const drifted = canonical(); drifted[0] = 0x31; drifted[2] = 0x72;
  const buf = mkRec(drifted);
  const r = recoverFuseDefaults(buf);
  ok(r.status === "restored" && r.restored.length === 2, "drifted wire -> restored");
  ok(r.restored[0].is === "disabled" && r.restored[0].was === "enabled", "state names populated");
  ok(!r.buf.equals(buf), "output bytes changed");
  ok(r.buf.indexOf(SENTINEL) >= 0, "sentinel preserved");
  // input buffer must stay pristine
  ok(buf.indexOf(0x72) >= 0, "input untouched (copy-on-write)");
}
{
  // already-canonical wire -> unchanged
  const r = recoverFuseDefaults(mkRec(canonical()));
  ok(r.status === "unchanged" && r.restored.length === 0, "canonical -> unchanged");
}
{
  // real + decoy: decoy is ignored, real restored
  const decoyWire = canonical(); decoyWire[5] = 0x39;
  const drifted = canonical(); drifted[1] = 0x30; // flip cookie-enc off
  const buf = Buffer.concat([mkRec(decoyWire, { padBack: "" }), mkRec(drifted, { padFront: "" })]);
  const r = recoverFuseDefaults(buf);
  ok(r.status === "restored" && r.sentinelCount === 2, "real+decoy -> decoy ignored, real restored");
}
{
  // report side-channel is populated
  const report = {};
  const drifted = canonical(); drifted[4] = 0x31; // flip asar-integ on
  recoverFuseDefaults(mkRec(drifted), report);
  ok(report.fuseRecovery && report.fuseRecovery.restoredCount === 1, "report.fuseRecovery populated");
}

// --- real adversarial fixtures ---------------------------------------------
for (const [name, want] of [
  ["case7-elf-fuse-single-decoy.elf", "unsupported"],
  ["case7-elf-fuse-decoys-bare.elf", "unsupported"],
  ["case7-elf-fuse-decoys-then-trailer.elf", "unsupported"],
]) {
  const r = recoverFuseDefaults(readFileSync(`test-fixtures/adversarial/native/in/${name}`));
  ok(r.status === want, `${name} -> ${want} (got ${r.status})`);
}
{
  const r = recoverFuseDefaults(readFileSync("test-fixtures/adversarial/native/in/case7-elf-fuse-real-plus-decoys.elf"));
  ok(r.status === "restored" || r.status === "unchanged", `real-plus-decoys -> restored/unchanged (got ${r.status})`);
  ok(r.sentinelCount > 1, "real-plus-decoys saw multiple sentinels");
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
