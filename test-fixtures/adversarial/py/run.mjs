// Adversarial runner for scrubPySource (src/trailer.mjs).
// Usage: node test-fixtures/adversarial/py/run.mjs
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scrubPySource } from "../../../src/trailer.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", "..");
const PLAIN = join(HERE, "plain");
const HARD = join(HERE, "hardened");
const CLEAN = join(HERE, "cleaned");
const BLA = join(ROOT, "vendor", "bla", "dist", "cli.js");
mkdirSync(HARD, { recursive: true });
mkdirSync(CLEAN, { recursive: true });

function protect(input, output, extra = []) {
  try {
    const out = execFileSync("node", [BLA, "protect", input, "-o", output, "--seed", "adv-seed-1", ...extra], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { ok: true, out: out.slice(-300) };
  } catch (e) {
    return { ok: false, err: String(e.stderr || e.message).slice(-500) };
  }
}

// Resolve a python interpreter that can ast.parse — the Windows `python`
// Store stub exits non-zero, so probe before use.
const PY = (() => {
  for (const cand of [process.env.BLADE_PYTHON, "py", "python3", "python"]) {
    if (!cand) continue;
    const r = spawnSync(cand, ["-c", "import ast"], { stdio: "ignore" });
    if (!r.error && r.status === 0) return cand;
  }
  return null;
})();

function pyCompile(file) {
  if (!PY) return "SKIP: no python interpreter found — set BLADE_PYTHON";
  try {
    execFileSync(PY, ["-c", "import ast,sys; ast.parse(open(sys.argv[1],encoding='utf-8-sig').read())", file], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return "OK";
  } catch (e) {
    return "FAIL: " + String(e.stderr || e.message).trim().split("\n").pop();
  }
}

function lineDiff(a, b) {
  const al = a.split("\n"), bl = b.split("\n");
  const diffs = [];
  const n = Math.max(al.length, bl.length);
  for (let i = 0; i < n; i++) {
    if (al[i] !== bl[i]) diffs.push(`line ${i + 1}: orig=${JSON.stringify(al[i])} cleaned=${JSON.stringify(bl[i])}`);
  }
  return diffs;
}

function scrubFile(inputPath, outName) {
  const text = readFileSync(inputPath, "utf8");
  const r = scrubPySource(text);
  const out = join(CLEAN, outName);
  writeFileSync(out, r.code);
  return { r, out };
}

const cases = [];
function rec(name, data) { cases.push({ name, ...data }); }

// ---------- A. unprotected adversarial inputs, scrubbed directly ----------
for (const f of ["a1_marker_lines_in_code", "a2_marker_in_docstring", "a3_boundary_no_probe",
  "a4_deception_only", "a5_weave_touch_legit", "a6_opaque_if_legit",
  "a7_weave_touch_in_string", "a9_indented_marker", "e3_crlf_plain"]) {
  const src = join(PLAIN, f + ".py");
  const orig = readFileSync(src, "utf8");
  const { r, out } = scrubFile(src, f + ".cleaned.py");
  rec(f, {
    report: r.report,
    syntax: pyCompile(out),
    origCRLF: orig.includes("\r\n"), outCRLF: r.code.includes("\r\n"),
    diff: lineDiff(orig, r.code),
  });
}

// ---------- B/E/C. protect then scrub ----------
const protectCases = [
  ["b1_user_marker_in_head", []],
  ["b2_user_marker_in_tail", []],
  ["c1_weave_funcs", ["--weave-decoys"]],
  ["c3_crlf_weave", ["--weave-decoys"]],
  ["e1_shebang_future", []],
  ["e2_crlf", []],
  ["e4_trailing_comment", []],
  ["e5a_empty", []],
  ["e5b_tiny", []],
  ["e6_bom", []],
];
for (const [f, extra] of protectCases) {
  const src = join(PLAIN, f + ".py");
  const hard = join(HARD, f + ".hardened.py");
  const p = protect(src, hard, extra);
  if (!p.ok) { rec(f, { protect: "FAILED", err: p.err }); continue; }
  const hardText = readFileSync(hard, "utf8");
  const { r, out } = scrubFile(hard, f + ".cleaned.py");
  const orig = readFileSync(src, "utf8");
  rec(f, {
    protect: "ok",
    hardCRLF: hardText.includes("\r\n"),
    report: r.report,
    syntax: pyCompile(out),
    origCRLF: orig.includes("\r\n"), outCRLF: r.code.includes("\r\n"),
    diffVsOrig: lineDiff(orig.replace(/\r\n/g, "\n"), r.code),
  });
}

// ---------- D. double protect ----------
{
  const src = join(PLAIN, "d1_double.py");
  const h1 = join(HARD, "d1_double.h1.py");
  const h2 = join(HARD, "d1_double.h2.py");
  const p1 = protect(src, h1);
  const p2 = p1.ok ? protect(h1, h2) : p1;
  if (!p2.ok) { rec("d1_double", { protect: "FAILED", err: p2.err || p1.err }); }
  else {
    // pass 1 on double-hardened
    const t2 = readFileSync(h2, "utf8");
    const r1 = scrubPySource(t2);
    const out1 = join(CLEAN, "d1_double.pass1.py");
    writeFileSync(out1, r1.code);
    // pass 2 on the pass-1 residue
    const r2 = scrubPySource(r1.code);
    const out2 = join(CLEAN, "d1_double.pass2.py");
    writeFileSync(out2, r2.code);
    const orig = readFileSync(src, "utf8");
    rec("d1_double", {
      report1: r1.report,
      report2: r2.report,
      syntax1: pyCompile(out1), syntax2: pyCompile(out2),
      diffPass1VsOrig: lineDiff(orig.replace(/\r\n/g, "\n"), r1.code),
      diffPass2VsOrig: lineDiff(orig.replace(/\r\n/g, "\n"), r2.code),
    });
  }
}

for (const c of cases) {
  console.log("=== " + c.name + " ===");
  console.log(JSON.stringify(c, null, 1));
}
writeFileSync(join(HERE, "reports", "results.json"), JSON.stringify(cases, null, 2));
