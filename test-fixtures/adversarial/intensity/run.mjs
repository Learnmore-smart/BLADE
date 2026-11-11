// Intensity-matrix runner: every BLA intensity level × every format must
// scrub without crashing; trailer formats must restore byte-exact to the
// sibling plain original; text formats must come back marker-free.
// Layout per level dir: <file> = plain original, hardened/<file> = BLA output.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

const DIR = dirname(fileURLToPath(import.meta.url));
const CLI = join(DIR, "..", "..", "..", "src", "cli.mjs");
const OUT = join(DIR, "_out");
mkdirSync(OUT, { recursive: true });

// formats whose BLA surface is append-only → byte-exact restore is the
// contract (same list as scripts/verify.mjs BYTE_EXACT, minus formats the
// intensity corpus doesn't carry).
const BYTE_EXACT = new Set([
  ".dex", ".beam", ".evm", ".pyc", ".uf2", ".ptx", ".bplist", ".plist",
  ".class", ".elf", ".macho", ".exe", ".dll", ".pcap", ".py",
]);
const MARKER = /\[BLA[-\]]|enclave_build_id|COGNITIVE_ARMOR|PROTECTED_CANARY|_interlockSafetyCorpus_|obligationFlood_|enclave\.internal/i;

let pass = 0, fail = 0;
const check = (name, ok, detail = "") => {
  if (ok) pass++;
  else { fail++; console.log(`FAIL  ${name} ${detail}`); }
};

const isDir = (p) => { try { return statSync(p).isDirectory(); } catch { return false; } };

for (const level of readdirSync(DIR).filter((d) =>
  isDir(join(DIR, d)) && existsSync(join(DIR, d, "hardened")))) {
  const hardenedDir = join(DIR, level, "hardened");
  const plainDir = join(DIR, level);
  const outDir = join(OUT, level);
  mkdirSync(outDir, { recursive: true });

  for (const f of readdirSync(hardenedDir)) {
    const input = join(hardenedDir, f);
    const outFile = join(outDir, f);
    const repFile = join(outDir, f + ".report.json");
    const tag = `${level}/${f}`;
    // 1) scrubs without crashing
    try {
      execFileSync(process.execPath, [CLI, input, "-o", outFile, "--report", repFile, "--quiet"], { stdio: "pipe" });
      check(`${tag} cli`, true);
    } catch (e) {
      check(`${tag} cli`, false, `exit ${e.status}: ${String(e.stderr ?? "").split("\n")[0]}`);
      continue;
    }
    const cleaned = readFileSync(outFile);
    const ext = f.slice(f.lastIndexOf("."));
    const plainPath = join(plainDir, f);

    // 2) byte-exact for trailer formats; marker-free for everything
    if (BYTE_EXACT.has(ext) && existsSync(plainPath)) {
      check(`${tag} byte-exact`, cleaned.equals(readFileSync(plainPath)),
        `(len ${cleaned.length} vs ${readFileSync(plainPath).length})`);
    }
    if ([".js", ".html", ".py", ".ptx"].includes(ext)) {
      check(`${tag} marker-free`, !MARKER.test(cleaned.toString("utf8")),
        `residual marker in cleaned output`);
    }
    // 3) sqlite: business tables survive
    if (ext === ".sqlite") {
      const db = new DatabaseSync(outFile, { readOnly: true });
      const names = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all().map((r) => r.name).sort();
      db.close();
      check(`${tag} tables`, names.includes("license_cache") && names.includes("usage_counters"),
        JSON.stringify(names));
    }
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
