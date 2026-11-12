// BLADE consolidated runner: executes every verification + adversarial suite
// and prints a pass/fail matrix. Suites that need vendor/bla are skipped
// (with a note) when the vendored package is absent.
// Usage: node scripts/verify-all.mjs [--verbose]
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const VERBOSE = process.argv.includes("--verbose");
const HAS_VENDOR_BLA = existsSync(path.join(ROOT, "vendor", "bla", "dist", "cli.js"));

// [name, script, needsVendorBla]
const SUITES = [
  ["core", "scripts/verify.mjs", false],
  ["anomaly", "scripts/test-anomaly.mjs", false],
  ["detect", "scripts/test-detect.mjs", false],
  ["evaluator", "scripts/test-evaluator.mjs", false],
  ["name-recovery", "scripts/test-name-recovery.mjs", false],
  ["precision", "scripts/test-precision.mjs", false],
  ["fuzz-js", "scripts/fuzz-js.mjs", false],
  ["canonical", "scripts/test-canonical.mjs", false],
  ["manifest", "scripts/test-manifest.mjs", false],
  ["salvage", "scripts/test-salvage.mjs", false],
  ["gates", "scripts/test-gates.mjs", false],
  ["detect-corpus", "test-fixtures/adversarial/detect/run.mjs", false],
  ["robustness", "scripts/robustness.mjs", false],
  ["js", "test-fixtures/adversarial/js/run-adversarial.mjs", true],
  ["js-324", "test-fixtures/adversarial/js/v324/run.mjs", false],
  ["asar", "test-fixtures/adversarial/asar/run.mjs", true],
  ["beam", "test-fixtures/adversarial/beam/run.mjs", false],
  ["bunfs", "test-fixtures/adversarial/bunfs/run.mjs", false],
  ["dex", "test-fixtures/adversarial/dex/run-adversarial.mjs", false],
  ["dotnet", "test-fixtures/adversarial/dotnet/run-adversarial.mjs", false],
  ["evm", "test-fixtures/adversarial/evm/run.mjs", false],
  ["html", "test-fixtures/adversarial/html/run-all.mjs", false],
  ["idempotency", "scripts/idempotency.mjs", false],
  ["jvm", "test-fixtures/adversarial/jvm/adversarial-jvm.mjs", false],
  ["model", "scripts/adversarial-model.mjs", false],
  ["native", "test-fixtures/adversarial/native/check.mjs", false],
  ["native-fuses", "test-fixtures/adversarial/native/check-fuses.mjs", false],
  ["native-enclave", "test-fixtures/adversarial/native/check-enclave.mjs", false],
  ["pcap", "test-fixtures/adversarial/pcap/run-tests.mjs", false],
  ["plist", "test-fixtures/adversarial/plist/run-tests.mjs", true],
  ["py", "test-fixtures/adversarial/py/run.mjs", true],
  ["sqlite", "test-fixtures/adversarial/sqlite/adversarial-sqlite.mjs", false],
  ["uf2", "test-fixtures/adversarial/uf2/run-tests.mjs", false],
  ["wasm", "test-fixtures/adversarial/wasm/run-adversarial.mjs", false],
  ["zip", "test-fixtures/adversarial/zip/run-adversarial.mjs", false],
];

const results = [];
for (const [name, script, needsVendor] of SUITES) {
  if (needsVendor && !HAS_VENDOR_BLA) {
    results.push({ name, status: "skip", detail: "needs vendor/bla (npm i --prefix vendor bla-agents@3.2.4)" });
    continue;
  }
  const t0 = Date.now();
  try {
    const out = execFileSync(process.execPath, [path.join(ROOT, script)], {
      encoding: "utf8", stdio: VERBOSE ? "inherit" : "pipe",
    });
    const tail = out.trim().split("\n").filter((l) => l.trim()).slice(-1)[0] ?? "";
    results.push({ name, status: "pass", detail: `${tail} (${((Date.now() - t0) / 1000).toFixed(1)}s)` });
  } catch (e) {
    const tail = (e.stdout ?? "").trim().split("\n").slice(-6).join(" | ");
    results.push({ name, status: "FAIL", detail: tail || e.message });
  }
}

const W = 16;
console.log("\n=== BLADE suite matrix ===");
for (const r of results) {
  const mark = r.status === "pass" ? " ok " : r.status === "skip" ? "skip" : "FAIL";
  console.log(`  ${mark}  ${r.name.padEnd(W)} ${r.detail}`);
}
const fails = results.filter((r) => r.status === "FAIL");
const skips = results.filter((r) => r.status === "skip");
console.log(`\n${results.length - fails.length - skips.length} suites passed, ${skips.length} skipped, ${fails.length} failed`);
process.exit(fails.length ? 1 : 0);
