// Live end-to-end matrix: REAL bla-agents 3.2.4 `protect` on freshly generated
// plain artifacts → BLADE clean → verify recovery. This is the proof harness —
// stored fixtures are generated the same way, but this script re-runs the real
// tool so nothing relies on stale or hand-built evidence.
//
//   node scripts/live-matrix.mjs [--intensity stealth,balanced] [--quick]
//
// Requires vendor/bla (npm pack bla-agents@3.2.4 unpacked there).
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import Module from "node:module";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const BLA = join(root, "vendor", "bla", "dist", "cli.js");
const BLADE = join(root, "src", "cli.mjs");
const WORK = join(root, "_live");
const arg = (name) => {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
};
const INTENSITIES = (arg("--intensity") ?? "stealth,balanced,maximum,bankrupt").split(",");
const SEED = "live-matrix";

if (!existsSync(BLA)) {
  console.error(`vendor/bla not found — run: npm pack bla-agents@3.2.4 && tar xzf into vendor/bla`);
  process.exit(2);
}
rmSync(WORK, { recursive: true, force: true });
execFileSync(process.execPath, [join(root, "scripts", "make-fixtures.mjs")], { stdio: "pipe" });
const plain = join(root, "test-fixtures", "plain");

// ---------- per-format expectations ----------
const MARKER = /enclave_build_id|COGNITIVE_ARMOR|PROTECTED_CANARY|_interlockSafetyCorpus_|obligationFlood_|\[BLA-|TRANSPORT_ENDPOINT|bla_tarpit|EnclaveStateNode|shadowHeap|BlaDexXref|\[ABI-COMPAT-SHIM\]|enclave\.internal/i;
const BYTE_EXACT = new Set([".dex", ".beam", ".evm", ".pcap", ".uf2", ".elf",
  ".macho", ".exe", ".ptx", ".dll", ".class", ".bplist", ".pyc", ".dat", ".plist"]);
const ext = (f) => f.slice(f.lastIndexOf("."));

const CONTENT_IDS = {
  "license-core.js": ["validateEnterpriseLicense", "deriveSessionTicket"],
  "electron-bridge.js": ["contextBridge", "exposeInMainWorld", "notion:clipboard:read-rich"],
  "license.py": ["derive_session_ticket", "GOLDEN_SCHEDULE"],
  ".html": ["<script", "</script>"],
  ".ptx": ["license_mix", ".entry", "st.u64"],
  ".plist": ["CFBundleIdentifier", "CFBundleVersion"],
  ".safetensors": ["general.architecture", "mlp.weight"],
  ".gguf": ["general.architecture", "llama.context_length"],
};
const EXEC_CHECK = { "license-core.js": true };  // electron-bridge requires the electron runtime

let pass = 0, fail = 0, skip = 0;
const rows = [];
const check = (tag, name, ok, detail = "") => {
  if (ok) { pass++; rows.push(`PASS  ${tag}  ${name}`); }
  else { fail++; rows.push(`FAIL  ${tag}  ${name}  ${detail}`); }
};

for (const level of INTENSITIES) {
  const hardDir = join(WORK, level, "hardened");
  const cleanDir = join(WORK, level, "cleaned");
  mkdirSync(hardDir, { recursive: true });
  mkdirSync(cleanDir, { recursive: true });
  for (const f of readdirSync(plain).sort()) {
    if (f.startsWith(".")) continue;                    // .blarc etc. — BLA's own sidecars, not artifacts
    const input = join(plain, f);
    // output must keep the artifact's own extension — BLA's
    // assertSafeOutputPath rejects unknown suffixes.
    const hardened = join(hardDir, f);
    const cleaned = join(cleanDir, f);
    const rep = join(cleanDir, f + ".report.json");
    const tag = `${level}/${f}`;

    // ---- 1. BLA protect (real tool, real output) ----
    let blaOut;
    try {
      blaOut = execFileSync(process.execPath,
        [BLA, "protect", input, "-o", hardened, "--intensity", level, "--seed", SEED],
        { stdio: "pipe", timeout: 180000 });
    } catch (e) {
      const msg = String(e.stderr ?? e.stdout ?? "").split("\n").filter(Boolean).pop() ?? "";
      skip++; rows.push(`SKIP  ${tag}  bla protect exit ${e.status}: ${msg.slice(0, 120)}`);
      continue;
    }
    if (!existsSync(hardened)) {
      // protect may write to a different path or refuse silently — inspect stdout
      const tail = String(blaOut).split("\n").filter((l) => /output|wrote|refus|error|skip/i.test(l)).pop() ?? "";
      skip++; rows.push(`SKIP  ${tag}  no output (${tail.slice(0, 100)})`);
      continue;
    }

    // ---- 2. BLADE clean ----
    try {
      execFileSync(process.execPath,
        [BLADE, hardened, "-o", cleaned, "--report", rep, "--quiet"],
        { stdio: "pipe", timeout: 120000 });
      check(tag, "blade", true);
    } catch (e) {
      check(tag, "blade", false, `exit ${e.status}: ${String(e.stderr ?? "").split("\n")[0].slice(0, 120)}`);
      continue;
    }
    const out = readFileSync(cleaned);
    const orig = readFileSync(input);
    const e = ext(f);

    // ---- 3. recovery assertions ----
    if (BYTE_EXACT.has(e)) {
      check(tag, "byte-exact", out.equals(orig),
        `len ${out.length} vs ${orig.length}`);
    }
    const ids = CONTENT_IDS[f] ?? CONTENT_IDS[e];
    if (ids) {
      const text = out.toString("utf8");
      for (const id of ids) {
        check(tag, `content:${id}`, text.includes(id), "missing");
      }
      check(tag, "marker-free", !MARKER.test(text),
        "residual BLA decoy vocabulary");
    }
    if (e === ".wasm") {
      check(tag, "wasm-magic", out.readUInt32LE(0) === 0x6d736100);
      const s = out.toString("latin1");
      if (s.includes("license_seal")) {
        check(tag, "exports", true);                       // real names survived
      } else {
        // maximum/bankrupt BLA renames exports to ops_* — original names are
        // destroyed. Contract: all real exports still exported + a recovered
        // `name` section gives readable fallbacks.
        const exportsKept = (s.match(/ops_[0-9a-f]{4}_/g) ?? []).length;
        check(tag, "exports", exportsKept >= 3,
          `expected 3 real exports, found ${exportsKept} name-suggests`);
        check(tag, "name-recovery",
          s.slice(-64).includes("name") && /add|hash|memory|export_\d/.test(s.slice(-64)),
          "no recovered name-section suggestions");
      }
      check(tag, "marker-free", !MARKER.test(s));
    }
    if (e === ".sqlite") {
      const db = new DatabaseSync(cleaned, { readOnly: true });
      const names = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all().map((r) => r.name);
      const rows0 = db.prepare("SELECT COUNT(*) n FROM license_cache").get().n;
      db.close();
      check(tag, "tables", names.includes("license_cache") && names.includes("usage_counters"), JSON.stringify(names));
      check(tag, "rows", rows0 === 2, `license_cache rows=${rows0}`);
    }
    if (e === ".asar") {
      const s = out.toString("latin1");
      check(tag, "members", s.includes("electron-bridge.js"), "member missing");
      check(tag, "marker-free", !MARKER.test(s));
    }
    if (e === ".zip" || e === ".apk") {
      check(tag, "eocd", out.readUInt32LE(out.length - 22) === 0x06054b50, "EOCD missing");
      check(tag, "marker-free", !MARKER.test(out.toString("latin1")));
    }
    if (e === ".map") {
      // BLA replaces sourcemaps wholesale — recovery is a reconstructed
      // canonical map: valid JSON, versioned, never the decoy blob.
      let map = null;
      try { map = JSON.parse(out.toString("utf8")); } catch { }
      check(tag, "map-json", map && map.version === 3 && "mappings" in map,
        "not a reconstructed v3 sourcemap");
      check(tag, "marker-free", !MARKER.test(out.toString("utf8")));
    }
    if (EXEC_CHECK[f]) {
      // the strongest check: cleaned business logic still EXECUTES identically
      try {
        const m = new Module("live");
        m._compile(out.toString("utf8"), cleaned);
        const fns = m.exports;
        if (fns && typeof fns.deriveSessionTicket === "function") {
          const t = fns.deriveSessionTicket("ENT-001", "prod");
          const v = fns.validateEnterpriseLicense("ENT-001", "prod", t);
          check(tag, "exec", v.valid === true && v.tier === "enterprise-unlimited", JSON.stringify(v));
        }
      } catch (err) {
        check(tag, "exec", false, String(err).split("\n")[0].slice(0, 100));
      }
    }
  }
}

for (const r of rows) console.log(r);
console.log(`\n${pass} passed, ${fail} failed, ${skip} skipped (bla refused/unsupported)`);
process.exit(fail ? 1 : 0);
