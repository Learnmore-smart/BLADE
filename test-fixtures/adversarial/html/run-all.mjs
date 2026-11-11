// Run every case-*.html through BLADE's cli and summarize the outcome.
import { readdirSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const dir = dirname(fileURLToPath(import.meta.url));
const outDir = join(dir, "out");
mkdirSync(outDir, { recursive: true });
const cli = join(dir, "..", "..", "..", "src", "cli.mjs");

const cases = readdirSync(dir).filter((f) => /^case.*\.html$/.test(f)).sort();
for (const c of cases) {
  const input = join(dir, c);
  const output = join(outDir, c.replace(".html", ".cleaned.html"));
  const reportPath = join(outDir, c.replace(".html", ".report.json"));
  let stdout = "", status = 0, stderr = "";
  try {
    stdout = execFileSync("node", [cli, input, "-o", output, "--report", reportPath], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    status = e.status ?? -1;
    stdout = e.stdout?.toString() ?? "";
    stderr = e.stderr?.toString() ?? "";
  }
  let report = null;
  try { report = JSON.parse(readFileSync(reportPath, "utf8")); } catch {}
  let outSnippet = "";
  try {
    const t = readFileSync(output, "utf8");
    const markerLeft = /_interlockSafetyCorpus_|obligationFlood_|scc_\w+_c\d+n\d+|labyrinthDispatch_/.test(t);
    outSnippet = JSON.stringify({ outLen: t.length, markerResidue: markerLeft });
  } catch { outSnippet = "(no output written)"; }
  console.log(`\n### ${c}  [exit ${status}]`);
  console.log("report:", report ? JSON.stringify({ hardened: report.hardened, scriptsDehardened: report.scriptsDehardened, decoyScriptsDropped: report.decoyScriptsDropped, note: report.note }) : "(none)");
  console.log("output:", outSnippet);
  if (status !== 0) console.log("stderr:", stderr.split("\n").slice(0, 8).join("\n"));
}
