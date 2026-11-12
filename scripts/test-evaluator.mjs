#!/usr/bin/env node
// Unit checks for evaluator.mjs — the containment-corpus digest math BLA
// embeds as a tamper oracle, and BLADE's single-char inversion repair.
import { computeContainmentCorpusDigest, repairCorpusDigest } from "../src/evaluator.mjs";

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) pass++; else { fail++; console.log("FAIL:", name); } };

const corpus = () => [
  { coupledAnchorSymbol: "scc_9f", triggerPayload: "dispatch_probe" },
  { coupledAnchorSymbol: "ring0_slot", triggerPayload: "attest" },
  { coupledAnchorSymbol: "vault_edge", triggerPayload: "seal_check" },
];

// determinism — same input, same digest, across seeds.
const d0 = computeContainmentCorpusDigest(corpus(), 0);
ok(d0 === computeContainmentCorpusDigest(corpus(), 0), "digest deterministic");
ok(d0 >>> 0 === d0, "digest is u32");
ok(computeContainmentCorpusDigest(corpus(), 1) !== d0, "seed changes digest");
ok(computeContainmentCorpusDigest([], 0) !== computeContainmentCorpusDigest(corpus(), 0), "entries change digest");
// field order matters: anchor::payload string is what's hashed.
const swapped = corpus().map((e) => ({ coupledAnchorSymbol: e.triggerPayload, triggerPayload: e.coupledAnchorSymbol }));
ok(computeContainmentCorpusDigest(swapped, 0) !== d0, "field order matters");

// single-char tamper → repair inverts it back, uniquely.
for (const [ei, field, at, rep] of [
  [0, "coupledAnchorSymbol", 2, "X"],
  [1, "triggerPayload", 0, "z"],
  [2, "triggerPayload", 4, "Q"],
]) {
  const tampered = corpus();
  const orig = tampered[ei][field];
  tampered[ei] = { ...tampered[ei], [field]: orig.slice(0, at) + rep + orig.slice(at + 1) };
  ok(computeContainmentCorpusDigest(tampered, 0) !== d0, `tamper ${ei}/${field}/${at} changes digest`);
  const fix = repairCorpusDigest(tampered, d0);
  ok(fix && fix.entry === ei && fix.field === field && fix.charIndex === at && fix.newChar === orig[at],
     `repair inverts ${ei}/${field}/${at} (got ${JSON.stringify(fix)})`);
  if (fix) {
    const restored = corpus();
    restored[fix.entry] = { ...restored[fix.entry], [fix.field]: fix.newText };
    ok(computeContainmentCorpusDigest(restored, 0) === d0, `restored digest matches for ${ei}/${field}/${at}`);
  }
}

// untouched corpus against its own digest → no unique tamper to find → null.
ok(repairCorpusDigest(corpus(), d0) === null, "intact corpus -> null (no phantom fix)");

// multi-char tamper → ambiguous → null (honest refusal, no guess).
const multi = corpus();
multi[0] = { ...multi[0], triggerPayload: "XXXXXXXXXXX" };
ok(repairCorpusDigest(multi, d0) === null, "multi-char tamper -> null");

// wrong expected digest → no printable unique fix → null.
ok(repairCorpusDigest(corpus(), 0xdeadbeef) === null, "wrong expected -> null");

// non-string fields coerced via String() — never throws.
ok(typeof computeContainmentCorpusDigest([{ coupledAnchorSymbol: 42, triggerPayload: null }], 0) === "number",
   "non-string fields coerced");

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
