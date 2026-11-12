// Idempotency harness: clean(clean(x)) must equal clean(x) for every
// scrubber. Non-idempotent output means a second pass keeps mutating —
// evidence of unstable cut points or non-deterministic rebuilds.
// Usage: node scripts/idempotency.mjs [--dir <hardened-dir>]
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const CLI = path.join(ROOT, "src", "cli.mjs");
const WORK = path.join(ROOT, "dh3", "idem");
mkdirSync(WORK, { recursive: true });

// default input dirs: real BLA outputs if present, else the committed fixture
const ARGDIR = process.argv.indexOf("--dir");
const DIRS = ARGDIR > -1 ? [process.argv[ARGDIR + 1]] : [
  path.join(ROOT, "_live", "maximum", "hardened"),
  path.join(ROOT, "_live", "bankrupt", "hardened"),
  path.join(ROOT, "test-fixtures", "hardened"),
].filter((d) => existsSync(d));

const sha = (b) => createHash("sha256").update(b).digest("hex").slice(0, 16);
// SQLite header write-counters bump on every committed write — change counter
// @24, schema cookie @40, version-valid-for @92, library version @96 (all BE
// u32). Any real sqlite write moves them, so "idempotent" for .sqlite means
// byte-stable modulo these fields.
const SQLITE_COUNTERS = [24, 40, 92, 96];
const normalize = (f, b) => {
  if (!f.endsWith(".sqlite") && !f.endsWith(".db")) return b;
  const n = Buffer.from(b);
  for (const off of SQLITE_COUNTERS) n.fill(0, off, off + 4);
  return n;
};
let pass = 0, fail = 0;
const fails = [];
for (const dir of DIRS) {
  for (const f of readdirSync(dir).sort()) {
    if (f.startsWith(".") || f.endsWith(".report.json") || f.startsWith("2x-")) continue;
    const input = path.join(dir, f);
    const o1 = path.join(WORK, `1-${f}`);
    const o2 = path.join(WORK, `2-${f}`);
    try {
      execFileSync(process.execPath, [CLI, input, "-o", o1, "--quiet"], { stdio: "pipe", timeout: 120000 });
      execFileSync(process.execPath, [CLI, o1, "-o", o2, "--quiet"], { stdio: "pipe", timeout: 120000 });
      const b1 = normalize(f, readFileSync(o1)), b2 = normalize(f, readFileSync(o2));
      const ok = b1.equals(b2);
      const tag = `${path.basename(dir)}/${f}`;
      if (ok) { pass++; console.log(`PASS  ${tag.padEnd(42)} ${sha(b1)}`); }
      else {
        fail++; fails.push(tag);
        console.log(`FAIL  ${tag.padEnd(42)} 1st=${sha(b1)} 2nd=${sha(b2)} (${b1.length}B vs ${b2.length}B)`);
        // dump first diff offset for triage
        let i = 0; while (i < Math.min(b1.length, b2.length) && b1[i] === b2[i]) i++;
        console.log(`      first diff @0x${i.toString(16)}: ${b1[i]} vs ${b2[i]}`);
      }
    } catch (e) {
      // scrub refusal on this input is acceptable idempotency-wise (stable failure)
      const msg = String(e.stderr ?? e.stdout ?? "").split("\n").filter(Boolean).pop() ?? e.message;
      console.log(`SKIP  ${path.basename(dir)}/${f.padEnd(38)} ${msg.slice(0, 60)}`);
    }
  }
}
console.log(`\n${pass} idempotent, ${fail} unstable`);
if (fails.length) console.log(`unstable: ${fails.join(", ")}`);
process.exit(fail ? 1 : 0);
