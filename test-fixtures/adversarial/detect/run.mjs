// Detect-suite runner: every file in this directory must route to the
// expected scrubber kind AND survive a full CLI scrub without crashing.
// The table encodes verified-correct routing — including the deliberate
// "unknown" answers (fake pyc text, 4-byte wasm stub, magic-less evm).
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { detect } from "../../../src/detect.mjs";

const DIR = dirname(fileURLToPath(import.meta.url));
const CLI = join(DIR, "..", "..", "..", "src", "cli.mjs");
const OUT = join(DIR, "_out");
const REPS = join(DIR, "_reports");
mkdirSync(OUT, { recursive: true });
mkdirSync(REPS, { recursive: true });

const EXPECT = {
  "addon.node": "native", "app.aab": "zip", "app.apk": "zip", "app.ipa": "zip",
  "app.js.map": "sourcemap", "app.xapk": "zip", "asar-named.bin": "asar",
  "bad.asar": "asar", "bad.beam": "beam", "bad.class": "jvm", "bad.dex": "dex",
  "bad.pyc": "pyc", "bad.uf2": "uf2", "bad.wasm": "wasm",
  "blob-elf.bin": "native", "broken-marker.js": "js",
  "bsjb-deep.exe": "dotnet", "bsjb-early.exe": "dotnet",
  "bytecode-noext": "unknown", "cafebabe-random.bin": "native",
  "bind-scope.json": "bla-manifest", "bla-harden-summary.json": "bla-manifest",
  "weave-plan.json": "bla-manifest", "weave-renamed.txt": "bla-manifest",
  "coverage-renamed.dat": "bla-manifest", "bind-renamed.cfg": "bla-manifest",
  "schema-trap.json": "unknown", "bla.config.json": "unknown", ".blarc": "unknown",
  "capture-renamed.cap": "pcap", "capture.pcapng": "pcap",
  "cast-hardened.ts": "js", "class-renamed.bin": "jvm",
  "classic-be.pcap": "pcap", "classic-le.pcap": "pcap", "code.evm": "evm",
  "config.yaml": "unknown", "corrupt-magic.pcap": "pcap",
  "corrupt.sqlite": "sqlite", "crlf-trap.bin": "unknown",
  "data.bplist": "plist", "data.json": "unknown",
  "defend-manifest.json": "bla-manifest",
  "decorated-hardened.ts": "js", "dex-trap.dex": "dex", "empty": "unknown",
  "empty.bin": "unknown", "empty.js": "js", "fake-st.bin": "safetensors",
  "fat-macho-as-class.class": "native", "fat-macho-hardened.dylib": "native",
  "fat-macho-noext": "native", "fat-macho.dylib": "native",
  "five.bin": "unknown", "hardened.ts": "js", "hardened.tsx": "js",
  "header.h": "header", "il2cpp-trap.dat": "il2cpp", "info.plist": "plist",
  "integrity-coverage.json": "bla-manifest",
  "jvm-class-hardened.class": "jvm", "jvm-class-plain.class": "jvm",
  "kernel.ptx": "ptx", "lenprefix.bin": "safetensors", "level.db": "sqlite",
  "lib.jar": "zip", "libalpha.so": "native", "libbeta.dylib": "native",
  "mod.py": "py", "nano-le.pcap": "pcap", "notes.txt": "unknown",
  "one.bin": "unknown", "page.html": "html", "pe-plain.exe": "native",
  "plain.cts": "js", "plain.jsx": "js", "plain.mts": "js", "plain.ts": "js",
  "polyglot-zip.js": "js", "polyglot-elf.js": "js", "polyglot-wasm.js": "js",
  "real.db": "sqlite", "real.safetensors": "safetensors",
  "sqlite-magic-garbage.db": "sqlite", "sqlite-magic-nonul.db": "sqlite",
  "tiny.dex": "dex", "tiny.gguf": "gguf", "tiny.safetensors": "safetensors",
  "trap.dex": "dex", "valid.beam": "beam", "valid.gguf": "gguf",
  "valid.pyc": "pyc", "valid.uf2": "uf2", "valid.wasm": "wasm",
  "wasm4-noext": "unknown",
};

let pass = 0, fail = 0;
const files = readdirSync(DIR).filter((f) =>
  !f.startsWith("_") && f !== "run.log" && f !== "run.mjs" && statSync(join(DIR, f)).isFile());

// every fixture must have an expectation — a new file without one is a fail
for (const f of files) {
  const buf = readFileSync(join(DIR, f));
  const got = detect(buf, extname(f).toLowerCase());
  if (!(f in EXPECT)) { fail++; console.log(`FAIL  ${f}: no expectation registered (detected '${got}')`); continue; }
  if (got === EXPECT[f]) { pass++; }
  else { fail++; console.log(`FAIL  ${f}: routed '${got}', expected '${EXPECT[f]}'`); }
}

// and every file must survive the CLI end-to-end (writes into _out/_reports)
for (const f of files) {
  const input = join(DIR, f);
  const outFile = join(OUT, f);
  const repFile = join(REPS, f + ".json");
  try {
    execFileSync(process.execPath, [CLI, input, "-o", outFile, "--report", repFile, "--quiet"],
      { stdio: "pipe" });
    pass++;
  } catch (e) {
    // exit 1 (unrecognized format) is the expected answer for "unknown"
    if (EXPECT[f] === "unknown" && e.status === 1) { pass++; continue; }
    fail++;
    console.log(`FAIL  ${f}: cli exit ${e.status} — ${String(e.stderr ?? e.message).split("\n")[0]}`);
  }
}

console.log(`\n${pass} passed, ${fail} failed (${files.length} fixtures × route+cli)`);
process.exit(fail ? 1 : 0);
