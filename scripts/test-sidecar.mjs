#!/usr/bin/env node
// Unit checks for the bunfs-snapshot / bla-sidecar note inspectors —
// pure-decoy artifacts that must be flagged and tombstoned, never salvaged.
import { readFileSync, readdirSync } from "node:fs";
import { inspectBunfsSnapshot, bunfsTombstone, inspectSidecarNote, sidecarNoteTombstone } from "../src/trailer.mjs";

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) pass++; else { fail++; console.log("FAIL:", name); } };

const BUNFS_TRAILER = Buffer.from("\n---- Bun! ----\n");
// synthetic bunfs graph: data ‖ Offsets(32B) ‖ sentinel
const mkBunfs = ({ sized = false, moduleCount = 3, entryPointId = 0 } = {}) => {
  const off = Buffer.alloc(32);
  off.writeUInt32LE(moduleCount * 52, 12);
  off.writeUInt32LE(entryPointId, 16);
  const data = Buffer.from("opaque decoy module data BLA bunfs");
  const tail = Buffer.concat([data, off, BUNFS_TRAILER]);
  if (!sized) return tail;
  const footer = Buffer.alloc(8); footer.writeBigUInt64LE(BigInt(tail.length), 0);
  return Buffer.concat([tail, footer]);
};

// --- inspectBunfsSnapshot -------------------------------------------------
{
  const r = inspectBunfsSnapshot(mkBunfs({ moduleCount: 3, entryPointId: 7 }));
  ok(r.format === "bunfs-snapshot" && r.hardened === true && r.decoy === true, "snapshot shaped");
  ok(r.variant === "appended-trailer", "plain trailer variant");
  ok(r.moduleCount === 3 && r.entryPointId === 7, "offsets block parsed");
  ok(/honeypot|decoy/i.test(r.note), "decoy note");
}
{
  const r = inspectBunfsSnapshot(mkBunfs({ sized: true, moduleCount: 2 }));
  ok(r.variant === "appended-trailer-sized", "sized trailer variant");
  ok(r.moduleCount === 2, "sized variant offsets parsed");
}
{
  // empty buffer: end===0===length must NOT read as appended-trailer
  const r = inspectBunfsSnapshot(Buffer.alloc(0));
  ok(r.variant === "malformed", "empty -> malformed (regression)");
  ok(r.decoy === true, "empty still flagged decoy");
}
{
  const r = inspectBunfsSnapshot(Buffer.from("no sentinel here"));
  ok(r.variant === "malformed" && r.moduleCount === undefined, "no sentinel -> malformed");
}
{ ok(bunfsTombstone().includes("[BLADE]"), "bunfs tombstone text"); }

// --- inspectSidecarNote ---------------------------------------------------
{
  const note = { schema: "bla-sidecar-entangle/v1", kind: "strip-fail-binding", entryPath: "app.js", sidecarPaths: ["a.so", "b.node"], sha256: "00".repeat(32) };
  const r = inspectSidecarNote(Buffer.from(JSON.stringify(note)));
  ok(r.format === "sidecar-note" && r.hardened === true && r.decoy === true, "sidecar shaped");
  ok(r.kind === "strip-fail-binding" && r.entryPath === "app.js", "note fields parsed");
  ok(r.sidecarPaths.length === 2, "sidecar paths parsed");
  ok(/binding record|excluded/i.test(r.note), "sidecar note text");
}
{
  // malformed JSON still flags decoy, fields default
  const r = inspectSidecarNote(Buffer.from("{broken"));
  ok(r.decoy === true && r.kind === undefined && r.sidecarPaths.length === 0, "malformed note safe");
  ok(inspectSidecarNote(Buffer.alloc(0)).decoy === true, "empty note safe");
}
{
  const t = sidecarNoteTombstone();
  const doc = JSON.parse(t);
  ok(doc.schema === "blade-tombstone/v1" && /sidecar-entangle/.test(doc.removed), "sidecar tombstone is parseable tombstone/v1");
}

// --- real fixtures if present ---------------------------------------------
try {
  const dir = "test-fixtures/hardened";
  const snap = readdirSync(dir).find((f) => f.endsWith(".bunfs-snapshot"));
  if (snap) {
    const r = inspectBunfsSnapshot(readFileSync(`${dir}/${snap}`));
    ok(r.decoy === true && r.variant.startsWith("appended-trailer"), `real snapshot ${snap}`);
  }
  const sc = readdirSync(dir).find((f) => f.endsWith(".bla-sidecar.v1.json"));
  if (sc) {
    const r = inspectSidecarNote(readFileSync(`${dir}/${sc}`));
    ok(r.decoy === true && r.kind !== undefined, `real sidecar ${sc}`);
  }
} catch {}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
