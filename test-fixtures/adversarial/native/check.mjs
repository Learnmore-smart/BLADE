// Runs node src/cli.mjs on every in/* fixture, diffs output vs expected/*,
// and classifies PASS / OVERCUT / UNDER-CLEAN with exact byte offsets.
import { readdirSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");
const IN = join(here, "in"), EXP = join(here, "expected"), OUT = join(here, "out");
mkdirSync(OUT, { recursive: true });

const MARKERS = [
  "[BLA-NATIVE-SHIELD", "[BLA-GO-MAPPED]", "[BLA-FLUTTER-MAPPED]",
  "[BLA-GO-BUILDINFO]", "[BLA-FLUTTER-POOL-EXHAUST]", "PROTECTED_CANARY",
  "COGNITIVE_ARMOR", "bla-jvm-enclave-v1",
];
const firstDiff = (a, b) => {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return i;
  return a.length === b.length ? -1 : n;
};
const markersIn = (buf) => MARKERS.filter((m) => buf.includes(Buffer.from(m, "latin1")));

const files = readdirSync(IN).sort();
const rows = [];
for (const f of files) {
  const inp = join(IN, f), outp = join(OUT, f), rep = join(OUT, f + ".json");
  let cliErr = null;
  try {
    execFileSync(process.execPath, [join(root, "src", "cli.mjs"), inp, "-o", outp, "--report", rep], { stdio: "pipe" });
  } catch (e) { cliErr = (e.stderr || e.message).toString().trim().split("\n").pop(); }
  const input = readFileSync(inp);
  const output = cliErr && !readFileSync(outp, { flag: "r" }).length ? null : (() => { try { return readFileSync(outp); } catch { return null; } })();
  const exp = (() => { try { return readFileSync(join(EXP, f)); } catch { return null; } })();
  const report = (() => { try { return JSON.parse(readFileSync(rep, "utf8")); } catch { return null; } })();

  let verdict = "?", note = "";
  if (!output) {
    verdict = "CLI-FAIL"; note = cliErr;
  } else if (exp && output.equals(exp)) {
    verdict = "PASS"; note = "byte-exact restore";
  } else if (exp && output.length < exp.length && exp.subarray(0, output.length).equals(output)) {
    verdict = "OVERCUT"; note = `clean prefix cut — lost real bytes [0x${output.length.toString(16)}, 0x${exp.length.toString(16)})`;
  } else if (exp && exp.length < output.length && output.subarray(0, exp.length).equals(exp)) {
    const extra = output.subarray(exp.length);
    verdict = "UNDER-CLEAN"; note = `${output.length - exp.length} trailing bytes survive at 0x${exp.length.toString(16)}+ ${JSON.stringify(extra.subarray(0, 48).toString("latin1"))}`;
  } else if (exp) {
    const d = firstDiff(exp, output);
    const sameLen = exp.length === output.length;
    if (output.length > exp.length) {
      verdict = "UNDER-CLEAN";
      note = `first diff @0x${d.toString(16)}; output ${output.length - exp.length}B longer than expected`;
    } else if (output.length < exp.length) {
      verdict = "OVERCUT";
      note = `first diff @0x${d.toString(16)} (exp 0x${exp[d].toString(16)} got 0x${output[d]?.toString(16)}); out len 0x${output.length.toString(16)} vs exp 0x${exp.length.toString(16)}`;
    } else {
      verdict = "MUTATED"; note = `same length, first diff @0x${d.toString(16)} (exp 0x${exp[d].toString(16)} got 0x${output[d]?.toString(16)})`;
    }
  } else {
    verdict = output.equals(input) ? "PASSTHROUGH" : "CHANGED";
  }
  const surv = output ? markersIn(output) : [];
  if (surv.length) note += ` | markers survive: ${surv.join(", ")}`;
  const inIdx = input.indexOf(Buffer.from("[BLA-NATIVE-SHIELD-V1]", "latin1"));
  rows.push({
    file: f,
    fmt: report?.format ?? "?",
    verdict,
    inLen: input.length,
    outLen: output?.length ?? -1,
    firstMarkerAt: inIdx < 0 ? "-" : "0x" + inIdx.toString(16),
    trailerDropped: report?.trailerDropped,
    hardened: report?.hardened,
    decoys: report?.decoys ? JSON.stringify(report.decoys) : report?.note ?? "",
    note,
  });
}
for (const r of rows) console.log(`${r.verdict.padEnd(11)} ${r.fmt.padEnd(7)} in=0x${r.inLen.toString(16).padStart(6)} out=0x${(r.outLen < 0 ? -1 : r.outLen).toString(16).padStart(6)} marker@=${r.firstMarkerAt.padStart(8)} ${r.file}\n             ${r.note}${r.decoys ? " | " + r.decoys : ""}`);
writeFileSync(join(OUT, "results.json"), JSON.stringify(rows, null, 2));
