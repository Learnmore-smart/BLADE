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

// ---- summary ----------------------------------------------------------------
const fails = results.filter((r) => r.verdict !== "PASS");
console.log(`\n${results.length - fails.length} passed, ${fails.length} failed`);
process.exit(fails.length ? 1 : 0);
