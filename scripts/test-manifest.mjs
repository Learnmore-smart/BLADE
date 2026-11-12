#!/usr/bin/env node
// Unit checks for BLA provenance-artifact inspectors + tombstone emitters.
// inspectBlaManifest classifies every bla-*/vN schema; tombstones are the
// exclusion artifacts written in place of pure-decoy files.
import { inspectBlaManifest, blaManifestTombstone, headerTombstone, bunfsTombstone,
         sidecarNoteTombstone } from "../src/trailer.mjs";

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) pass++; else { fail++; console.log("FAIL:", name); } };
const J = (o) => Buffer.from(JSON.stringify(o));

// --- inspectBlaManifest: schema classification -----------------------------------
{
  const r = inspectBlaManifest(J({ schema: "defense-manifest-v1", signature: "ed25519:abc" }));
  ok(r.format === "bla-manifest" && r.hardened === true && r.decoy === true, "defend manifest -> decoy");
  ok(r.signed === true, "ed25519 signature detected");
  ok(r.note.includes("attestation"), "attestation note");
}
{
  const r = inspectBlaManifest(J({ schema: "defense-manifest-v1" }));
  ok(r.signed === false, "unsigned manifest -> signed:false");
}
{
  const r = inspectBlaManifest(J({ schema: "bla-harden-summary/v1", runId: "rs-1", artifacts: ["a.js", "b.wasm", "c.py"] }));
  ok(r.runId === "rs-1" && r.artifactsRecorded === 3, "summary runId+artifacts surfaced");
  ok(r.note.includes("harden-run summary"), "summary note");
}
{
  const r = inspectBlaManifest(J({ schema: "bla-harden-summary/v2", runId: "rs-2" }));
  ok(r.runId === "rs-2" && r.artifactsRecorded === undefined, "summary without artifacts array");
}
{
  const r = inspectBlaManifest(J({ schema: "bla-integrity-coverage/v1", nodes: [1, 2] }));
  ok(r.nodesRecorded === 2, "coverage nodes surfaced");
  ok(r.note.includes("integrity-coverage matrix"), "coverage note");
}
{
  const r = inspectBlaManifest(J({ schema: "bla-bind-scope/v1", domains: ["a.com", "b.com"] }));
  ok(r.domains === 2, "bind-scope domains surfaced");
  ok(r.note.includes("bind-scope contract"), "bind-scope note");
}
{
  const r = inspectBlaManifest(J({ schema: "bla-weave-plan/v1", targets: [{ f: "a.py" }, { f: "b.py" }], overallStatus: "planned" }));
  ok(r.weaveTargets === 2 && r.overallStatus === "planned", "weave-plan targets+status");
  ok(r.note.includes("weave workorder"), "weave-plan note");
}
{
  // malformed json -> still shaped, never throws
  const r = inspectBlaManifest(Buffer.from("{broken"));
  ok(r.format === "bla-manifest" && r.decoy === true, "malformed json -> decoy report");
  ok(inspectBlaManifest(Buffer.alloc(0)).format === "bla-manifest", "empty safe");
}
{
  // unknown schema -> still a manifest-class decoy report (generic note)
  const r = inspectBlaManifest(J({ schema: "something-else/v1" }));
  ok(r.note.includes("attestation"), "unknown schema -> generic attestation note");
}

// --- tombstones ----------------------------------------------------------------------
{
  const t = JSON.parse(blaManifestTombstone("bla-harden-summary/v2"));
  ok(t.schema === "blade-tombstone/v1" && t.removed.includes("bla-harden-summary/v2"), "manifest tombstone is valid JSON");
  const d = JSON.parse(blaManifestTombstone());
  ok(d.removed.includes("defense-manifest-v1"), "default tombstone schema");
}
{
  // text tombstones are comments, NOT json — emitters for decoy source artifacts
  const h = headerTombstone(), b = bunfsTombstone();
  ok(h.startsWith("/*") || h.startsWith("//"), "header tombstone is a comment");
  ok(b.startsWith("//"), "bunfs tombstone is a comment");
  ok(h.includes("BLADE") && b.includes("BLADE"), "text tombstones carry BLADE marker");
  let notJson = false;
  try { JSON.parse(h); } catch { notJson = true; }
  ok(notJson, "header tombstone not JSON");
}
{
  const t = JSON.parse(sidecarNoteTombstone());
  ok(t.schema === "blade-tombstone/v1" && t.removed.includes("sidecar-entangle"), "sidecar tombstone JSON");
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
