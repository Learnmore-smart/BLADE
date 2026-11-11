// Runs each fixture through BLADE's CLI (detect -> scrub) and inspects the
// cleaned output buffer to classify the result.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { scrubPcap } from "../../../src/trailer.mjs";

const DIR = dirname(fileURLToPath(import.meta.url));
const CLI = join(DIR, "..", "..", "..", "src", "cli.mjs");
const OUT = join(DIR, "out");
mkdirSync(OUT, { recursive: true });

const files = readdirSync(DIR).filter((f) => f.endsWith(".pcap") || f.endsWith(".pcapng")).sort();

for (const f of files) {
  const input = join(DIR, f);
  const outFile = join(OUT, f.replace(/\.(pcap|pcapng)$/, ".cleaned.$1"));
  const repFile = join(OUT, f + ".report.json");
  console.log(`\n=== ${f} ===`);

  // 1) end-to-end via CLI (tests detect() routing too)
  let cliOk = true, cliErr = "";
  try {
    const stdout = execFileSync(process.execPath, [CLI, input, "-o", outFile, "--report", repFile],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    const first = stdout.trim().split("\n")[0];
    console.log("cli:", first);
  } catch (e) {
    cliOk = false;
    cliErr = (e.stderr || e.message || "").toString().trim().split("\n")[0];
    console.log("cli: EXIT", e.status, "-", cliErr);
  }

  // 2) direct scrubPcap inspection
  const buf = readFileSync(input);
  const r = scrubPcap(buf);
  console.log("scrub report:", JSON.stringify(r.report));
  const out = r.buffer;
  const outTxt = out.toString("latin1");
  console.log(
    `sizes: in=${buf.length} out=${out.length} | markerInOut=${outTxt.includes("[BLA-PCAP-SHIELD]")} | ` +
    `enclave.internal=${outTxt.includes("enclave.internal")} | example.com=${outTxt.includes("example.com")} | ` +
    `github.com=${outTxt.includes("github.com")}`,
  );
}
