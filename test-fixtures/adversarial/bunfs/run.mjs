// Runs `node src/cli.mjs` on each bun-standalone fixture and asserts the
// route + output:
//   decoy.bunfs-snapshot        -> "bunfs-snapshot", decoy tombstone output
//   decoy-sized.bunfs-snapshot  -> "bunfs-snapshot" (appended-trailer-sized)
//   real-bun                    -> "native", byte-exact passthrough
//   app.bla-sidecar.v1.json     -> "sidecar-note", decoy tombstone output
//   notes.txt                   -> CLI exit 1 (unrecognized format)
//
//   node test-fixtures/adversarial/bunfs/gen.mjs   # (re)build inputs
//   node test-fixtures/adversarial/bunfs/run.mjs
import { mkdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
import { bunfsTombstone, sidecarNoteTombstone } from "../../../src/trailer.mjs";

const DIR = dirname(fileURLToPath(import.meta.url));
const ROOT = join(DIR, "..", "..", "..");
const OUT = join(DIR, "out");
mkdirSync(OUT, { recursive: true });

let pass = 0, fail = 0;
const check = (name, fn) => {
  try { fn(); pass++; console.log(`  ok  ${name}`); }
  catch (e) { fail++; console.log(`FAIL  ${name}: ${e.message}`); }
};
// returns { report, output, err } — err is the stderr tail on non-zero exit
const run = (file) => {
  const inp = join(DIR, file), outp = join(OUT, file), rep = join(OUT, file + ".json");
  let err = null;
  try {
    execFileSync(process.execPath, [join(ROOT, "src", "cli.mjs"), inp, "-o", outp, "--report", rep], { stdio: "pipe" });
  } catch (e) { err = String(e.stderr || e.message).trim().split("\n").pop(); }
  const read = (p) => { try { return readFileSync(p); } catch { return null; } };
  return { report: (() => { try { return JSON.parse(read(rep).toString()); } catch { return null; } })(), output: read(outp), err };
};

console.log("bun-standalone decoy fixtures");
console.log("=".repeat(60));

check("decoy.bunfs-snapshot -> bunfs-snapshot tombstone", () => {
  const { report, output, err } = run("decoy.bunfs-snapshot");
  assert.equal(err, null);
  assert.equal(report.format, "bunfs-snapshot");
  assert.equal(report.hardened, true);
  assert.equal(report.decoy, true);
  assert.equal(report.variant, "appended-trailer");
  assert.ok(report.moduleCount > 0, "expected module records");
  assert.ok(report.markersHit.includes("/$bunfs/"), "expected /$bunfs/ marker");
  assert.equal(output.toString("utf8"), bunfsTombstone());
});

check("decoy-sized.bunfs-snapshot -> bunfs-snapshot tombstone (sized variant)", () => {
  const { report, output, err } = run("decoy-sized.bunfs-snapshot");
  assert.equal(err, null);
  assert.equal(report.format, "bunfs-snapshot");
  assert.equal(report.decoy, true);
  assert.equal(report.variant, "appended-trailer-sized");
  assert.equal(output.toString("utf8"), bunfsTombstone());
});

check("real-bun -> native byte-exact passthrough (sentinel at EOF, exec magic wins)", () => {
  const { report, output, err } = run("real-bun");
  assert.equal(err, null);
  assert.equal(report.format, "native");
  assert.equal(report.hardened, false);
  assert.deepEqual(output, readFileSync(join(DIR, "real-bun")));
});

check("app.bla-sidecar.v1.json -> sidecar-note tombstone", () => {
  const { report, output, err } = run("app.bla-sidecar.v1.json");
  assert.equal(err, null);
  assert.equal(report.format, "sidecar-note");
  assert.equal(report.hardened, true);
  assert.equal(report.decoy, true);
  assert.equal(report.kind, "bun-companion-note");
  assert.deepEqual(report.sidecarPaths, ["real-bun.bunfs-snapshot"]);
  assert.equal(output.toString("utf8"), sidecarNoteTombstone());
  JSON.parse(output.toString("utf8")); // tombstone stays valid JSON
});

check("notes.txt -> unrecognized format, exit 1", () => {
  const { report, err } = run("notes.txt");
  assert.equal(report, null);
  assert.match(err, /unrecognized format/);
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
