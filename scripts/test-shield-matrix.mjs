#!/usr/bin/env node
// Hint→family matrix for emitRuntimeCounterShield — every regex anchor
// in RUNTIME_FAMILIES must resolve to its family, anchors must not
// cross-fire, and the no-hint path emits the conservative full surface.
import { emitRuntimeCounterShield } from "../src/recovery/canonical.mjs";

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) pass++; else { fail++; console.log("FAIL:", name); } };

const FAMILIES = [
  "inspector-shadow-vault", "cdp-shape-guard", "frida-capture-saturation",
  "memory-diff-churn", "self-seal", "canary-honeypot", "tee-fiction",
];

// every regex alternative, one representative hint each
const ANCHORS = {
  "inspector-shadow-vault": [
    "_shadowVault_x", "inspectorObserved", "HARDWARE_ENCLAVE_DELEGATED",
    "decorative-deception-signal", "enclave:vsock:9", "tpm2:pcr0:x",
    "execArgv", "--inspect", "remote-debugging",
  ],
  "cdp-shape-guard": [
    "cdpShapeBudgetGuard", "__playwright", "__puppeteer_evaluation_script__",
    "webdriver", "overBudgetJsonEnvelope",
  ],
  "frida-capture-saturation": [
    "fridaRealmRing", "fridaCaptureSaturator", "ENCLAVE_TEE_TRACE",
    "_frida_", "frida", "Frida-Interlock", "frida-attestation",
  ],
  "memory-diff-churn": [
    "shadowHeap", "stepShadowHeap", "readSplitShare", "splitShareA",
    "splitShareB", "state_diff_frontier", "diffEnvelope", "rollingMask",
  ],
  "self-seal": [
    "measureIntegrity", "integrityDigest", "self-seal", "selfExpected",
    "NODE_OPTIONS", "native code", "integrity check failed",
  ],
  "canary-honeypot": [
    "canaryCredentialHoneypot", "probeCanaryHoneypot",
    "ambiguousTransportEndpoints", "conflictingQueryEndpoints",
    "PROTECTED_CANARY", "TRANSPORT_ENDPOINT", "bla_canary_synthetic",
  ],
  "tee-fiction": [
    "enclave_unseal_payload", "enclave_unseal", "invokeHardwareEnclave",
    "verifyRemoteAttestationQuote", "vsockTransportStub",
    "unsealVsockCid16Frame", "verifyShamirEd25519QuorumRing",
    "TEE-ENCLAVE", "enclave_export_", "tpm2", "pkcs11",
  ],
};

// 1) every anchor resolves its own family (and only that family fires alone)
for (const [fam, hints] of Object.entries(ANCHORS)) {
  for (const h of hints) {
    const r = emitRuntimeCounterShield([h]);
    ok(r.families.includes(fam), `hint '${h}' -> ${fam} (got ${JSON.stringify(r.families)})`);
  }
}

// 2) multi-hint union
{
  const r = emitRuntimeCounterShield(["__playwright", "shadowHeap", "pkcs11"]);
  ok(r.families.includes("cdp-shape-guard") && r.families.includes("memory-diff-churn") && r.families.includes("tee-fiction"), "multi-hint union");
  ok(!r.families.includes("self-seal") && !r.families.includes("canary-honeypot"), "union excludes unhit families");
}

// 3) no hints -> conservative full surface
{
  const r = emitRuntimeCounterShield([]);
  ok(r.families.length === FAMILIES.length, "empty -> all families");
  const r2 = emitRuntimeCounterShield();
  ok(r2.families.length === FAMILIES.length, "undefined -> all families");
  const r3 = emitRuntimeCounterShield([123, {}, null]);
  ok(r3.families.length === FAMILIES.length, "non-string hints filtered -> all families");
}

// 4) emit shape — families drive real script output
{
  const r = emitRuntimeCounterShield(["__playwright"]);
  ok(typeof r.fridaScript === "string" && r.fridaScript.length > 100, "frida script emitted");
  ok(typeof r.cdpNotes === "string", "cdp notes emitted");
  ok(r.fridaScript.includes("cdp-shape-guard"), "script names the family");
}

// 5) no cross-fire: a benign hint resolves no families
{
  const r = emitRuntimeCounterShield(["ordinary_variable_name", "console.log"]);
  ok(r.families.length === 0, "benign hints -> no families");
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
