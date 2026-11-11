// BLADE adversarial harness — BLA 3.2.4 emission-shape regressions.
// Fixtures:
//   app.hardened.js          real `bla protect --intensity maximum --self-seal`
//                            output (single-entry self-digest + .every-entangled
//                            seed + 3.2.4 vault vocab)
//   full-seal.hardened.js    transformJavaScriptWithBlaShield with the new
//                            selfSeal options (2 sites, selfDigestCheck, hardFail)
//   selfseal-324.src.js      standalone generateSelfSealSnippet (interleavedSites:2)
//   encstrings-324.src.cjs   real encryptStrings output (blaS/blaT/blaK stub)
//   encstrings-new-324.src.cjs  3.2.4 stub variant (resolveBundleSlot/catalogFrameTable/
//                            sessionKeyMask hints + kb/ks derive) — byte-faithful
//                            mirror of vendor/bla/src/engine/encrypt-strings.ts
//   asar-preamble-324.src.js real generateSidecarAsarMainJsPreamble IIFE lifted
//                            verbatim from app2.hardened.asar member main.js
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { dehardenJs } from "../../../../src/js-deharden.mjs";

const DIR = dirname(fileURLToPath(import.meta.url));
const OUT = join(DIR, "out");
mkdirSync(OUT, { recursive: true });
const read = (f) => readFileSync(join(DIR, f), "utf8");

const results = [];
function record(caseId, ok, detail) {
  results.push({ caseId, verdict: ok ? "PASS" : "FAIL", detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${caseId}${detail ? "  — " + detail : ""}`);
}

// ---- 1. real maximum+selfSeal fixture -------------------------------------
{
  const src = read("app.hardened.js");
  const r = dehardenJs(src, { filename: "app.hardened.js" });
  writeFileSync(join(OUT, "app.cleaned.js"), r.code);
  const residue =
    /measureIntegrity|integrity check failed|__blaAsarSidecarDigest|0xfffffffc|\.every\(/.test(r.code);
  const realKept =
    /function checkEntitlement|const crypto = require\("node:crypto"\)|tenant:\$\{/.test(r.code);
  record(
    "v324 app.hardened.js",
    r.report.hardened && r.report.seedResolved && !residue && realKept &&
      r.report.selfSealFunctionsRemoved >= 1,
    `seed=${r.report.seed?.parity} sealFns=${r.report.selfSealFunctionsRemoved} residue=${residue} realKept=${realKept}`,
  );
}

// ---- 2. integrated selfSeal (2 sites, selfDigestCheck, hardFail) -----------
{
  const src = read("full-seal.hardened.js");
  const r = dehardenJs(src, { filename: "full-seal.hardened.js" });
  writeFileSync(join(OUT, "full-seal.cleaned.js"), r.code);
  const residue =
    /measureIntegrity|integrity check failed|selfExpected|integrityDigest/.test(r.code);
  record(
    "v324 full-seal selfSeal",
    r.report.seedResolved && r.report.selfSealFunctionsRemoved === 2 &&
      r.report.selfSealBindingsRemoved === 1 && !residue &&
      r.report.danglingRefs.length === 0,
    `sealFns=${r.report.selfSealFunctionsRemoved} binds=${r.report.selfSealBindingsRemoved} residue=${residue} dangling=${r.report.danglingRefs.length}`,
  );
}

// ---- 3. standalone self-seal snippet (not otherwise hardened) --------------
{
  const src = read("selfseal-324.src.js");
  const r = dehardenJs(src, { filename: "selfseal-324.src.js" });
  writeFileSync(join(OUT, "selfseal.cleaned.js"), r.code);
  const residue = /measureIntegrity|integrityDigest|selfExpected|integrity check failed/.test(r.code);
  record(
    "v324 selfseal standalone",
    r.report.selfSealFunctionsRemoved === 2 && r.report.selfSealBindingsRemoved === 1 && !residue,
    `sealFns=${r.report.selfSealFunctionsRemoved} binds=${r.report.selfSealBindingsRemoved} residue=${residue}`,
  );
}

// ---- 4. encryptStrings stubs decode + decl removal --------------------------
{
  for (const [f, expected, n] of [
    ["encstrings-324.src.cjs",
      ["https://billing.internal.example.com/v2/license/verify-lease",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"], 2],
    ["encstrings-new-324.src.cjs",
      ["https://billing.internal.example.com/v2/license/verify-lease",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "sk-live-4eC39HqLyjWDarjtT1zdp7dc"], 3],
  ]) {
    const src = read(f);
    const r = dehardenJs(src, { filename: f });
    writeFileSync(join(OUT, f + ".cleaned.js"), r.code);
    const stubGone = !/_blaS|_blaT|Uint8Array|resolveBundleSlot|catalogFrameTable|sessionKeyMask|blaS\w*_|blaT\w*_|blaK\w*_/.test(r.code);
    const decoded = expected.every((s) => r.code.includes(JSON.stringify(s)));
    record(
      `v324 encryptStrings ${f}`,
      r.report.decryptedStrings === n && stubGone && decoded,
      `decrypted=${r.report.decryptedStrings}/${n} stubGone=${stubGone} decoded=${decoded}`,
    );
  }
}

// ---- 5. ASAR main-JS preamble IIFE ------------------------------------------
{
  const src = read("asar-preamble-324.src.js");
  const r = dehardenJs(src, { filename: "asar-preamble-324.src.js" });
  writeFileSync(join(OUT, "asar-preamble.cleaned.js"), r.code);
  const gone = !/__blaAsarSidecarDigest|integrity binding mismatch/.test(r.code);
  const realKept = /GREETING|hello v324/.test(r.code);
  record(
    "v324 asar preamble IIFE",
    r.report.asarPreambleRemoved === 1 && gone && realKept,
    `removed=${r.report.asarPreambleRemoved} gone=${gone} realKept=${realKept}`,
  );
}

// ---- 6. real double-harden (protect output re-protected) --------------------
// `bla protect` applied twice: two corpus families, second seed-decl expected
// digest expressed as arithmetic over the FIRST seed, and both seeds
// entangled into real expressions. Cleaned code must execute identically.
{
  const src = read("double-harden-324.src.js");
  const r = dehardenJs(src, { filename: "double-harden-324.src.js" });
  writeFileSync(join(OUT, "double-harden.cleaned.js"), r.code);
  const noMachinery =
    !/_interlockSafetyCorpus_|_deriveContainmentCorpusDigest_|\.every\(_f/.test(r.code);
  const noDangling = r.report.danglingRefs.length === 0;
  const mod = { exports: {} };
  let execOk = false, parity = false;
  try {
    new Function("module", "exports", "require", r.code)(mod, mod.exports, () => ({}));
    const t = mod.exports.deriveSessionTicket("ENT-ALPHA-9", "pro");
    const v = mod.exports.validateEnterpriseLicense("ENT-ALPHA-9", "pro", t);
    const bad = mod.exports.validateEnterpriseLicense("E", "p", 1);
    execOk = true;
    parity = v.valid && v.tier === "enterprise-unlimited" && bad.valid === false;
  } catch { /* execOk stays false */ }
  record(
    "v324 double-harden exec parity",
    noMachinery && noDangling && execOk && parity,
    `machinery=${!noMachinery} dangling=${r.report.danglingRefs.length} exec=${execOk} parity=${parity}`,
  );
}

// ---- 7. double-hardened Electron bridge (IPC decoy data objects) ------------
// protect(bridge) fed through protect again at maximum: decoy payload objects
// (systemDiagnosticLog, evidenceLedger, grpcServiceMirage, canaryCredentialHoneypot)
// survive cleaning under plausible names unless content-vocab fires.
{
  const src = read("double-bridge-324.src.js");
  const r = dehardenJs(src, { filename: "double-bridge-324.src.js" });
  writeFileSync(join(OUT, "double-bridge.cleaned.js"), r.code);
  const channels =
    ["notion:clipboard:read-rich", "notion:clipboard:write-rich", "notion:clipboard:selection-sync"]
      .every((c) => r.code.includes(c)) &&
    r.code.includes("contextBridge") && r.code.includes("setupMainClipboardHandlers");
  const noDecoyData =
    !/remediationRabbitHole|protoPackage|dispatchFrame|delegatedToEnclave|enclave\.zero_trust|_interlockSafetyCorpus_/.test(r.code);
  record(
    "v324 double-harden bridge",
    channels && noDecoyData && r.report.danglingRefs.length === 0,
    `channels=${channels} decoyData=${!noDecoyData} dangling=${r.report.danglingRefs.length}`,
  );
}

// ---- 8. sidecar-entangled JS (API-only path, strip=>fail checks) ------------
// protectTarget with sidecarEntanglePaths — emits runtime createHash/sha256
// coverage checks that refuse to run without the sidecar file. Cleaned code
// must drop the entanglement preamble AND execute standalone.
{
  const src = read("sidecar-entangle-324.src.js");
  const r = dehardenJs(src, { filename: "sidecar-entangle-324.src.js" });
  writeFileSync(join(OUT, "sidecar-entangle.cleaned.js"), r.code);
  const noEntangle = !/sidecar-key|createHash|coverageMatrix|SIDECAR_ENTANGLE/.test(r.code);
  const mod = { exports: {} };
  let ok = false;
  try {
    new Function("module", "exports", "require", r.code)(mod, mod.exports, () => ({}));
    const t = mod.exports.deriveSessionTicket("ENT-ALPHA-9", "pro");
    ok = mod.exports.validateEnterpriseLicense("ENT-ALPHA-9", "pro", t).tier === "enterprise-unlimited";
  } catch { /* ok stays false */ }
  record(
    "v324 sidecar-entangle",
    noEntangle && ok && r.report.danglingRefs.length === 0,
    `entangle=${!noEntangle} exec=${ok} dangling=${r.report.danglingRefs.length}`,
  );
}

// ---- 9. BLA showcase sources (extracted from vendor/bla benchmark) ----------
// The exact artifacts `bla benchmark` protects in its own showcase — inputs
// authored by BLA, not by us. Cleaned output must execute with identical
// results to the known benchmark expectations.
{
  const run = (code) => {
    const m = { exports: {} };
    new Function("module", "exports", "require", code)(m, m.exports, (n) => {
      if (n === "electron") return { contextBridge: { exposeInMainWorld: () => {} }, ipcRenderer: { invoke: () => {}, on: () => {}, handle: () => {}, send: () => {} } };
      return {};
    });
    return m.exports;
  };
  {
    const src = read("showcase-dxball-324.src.js");
    const r = dehardenJs(src, { filename: "showcase-dxball-324.src.js" });
    writeFileSync(join(OUT, "showcase-dxball.cleaned.js"), r.code);
    let ok = false;
    try {
      const e = run(r.code);
      ok = e.calculateSoundPan(320, 480, 640) === 2880 &&
           e.calculateSoundPan(100, 50, 640) === -4915 &&
           e.clampPan(-25000) === -10000 && e.clampPan(25000) === 10000;
    } catch { /* ok stays false */ }
    const noMach = !/_interlockSafetyCorpus_|bpeSink|grpcServiceMirage|systemDiagnosticLog|EV-TEE/.test(r.code);
    record("v324 showcase dx-ball", ok && noMach && r.report.danglingRefs.length === 0,
      `exec=${ok} machinery=${!noMach} dangling=${r.report.danglingRefs.length}`);
  }
  {
    const src = read("showcase-license-324.src.js");
    const r = dehardenJs(src, { filename: "showcase-license-324.src.js" });
    writeFileSync(join(OUT, "showcase-license.cleaned.js"), r.code);
    let ok = false;
    try {
      const e = run(r.code);
      const sum = e.computeLicenseChecksum("ENT-9942-ABCD", "pro-suite");
      const good = e.validateEnterpriseLicense("ENT-9942-ABCD", "pro-suite", sum);
      const bad = e.validateEnterpriseLicense("FREE-0000", "pro-suite", sum);
      ok = good.valid === true && good.tier === "enterprise-unlimited" && bad.valid === false;
    } catch { /* ok stays false */ }
    const noMach = !/_interlockSafetyCorpus_|bpeSink|grpcServiceMirage|systemDiagnosticLog|EV-TEE/.test(r.code);
    record("v324 showcase license-validator", ok && noMach && r.report.danglingRefs.length === 0,
      `exec=${ok} machinery=${!noMach} dangling=${r.report.danglingRefs.length}`);
  }
}

// ---- summary ----------------------------------------------------------------
const fails = results.filter((r) => r.verdict !== "PASS");
console.log(`\n${results.length - fails.length} passed, ${fails.length} failed`);
process.exit(fails.length ? 1 : 0);
