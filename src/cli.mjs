#!/usr/bin/env node
// BLADE — Bypass LLM Agent Defense Engine.
// Adaptive de-hardening of BLA (bla-agents) protected artifacts so downstream
// analyzers (REA / humans) see real logic instead of decoys.
//
//   node src/cli.mjs <input> [-o output] [--report out.json]
//
// All processing is local; nothing is uploaded.
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { dehardenJs, looksBlaHardened } from "./js-deharden.mjs";
import { scrubAsar, scrubWasm, scrubSqlite, scrubSafetensors, scrubGguf } from "./formats.mjs";
import {
  scrubNative, scrubDex, scrubIl2cpp, scrubDotnet, scrubEvm, scrubPtx,
  scrubJvm, scrubPlistXml, scrubBplist, scrubPcap, scrubUf2, scrubBeam,
  scrubPyc, scrubZip, scrubPySource, scrubHtml, inspectSourcemap,
  inspectShieldHeader, headerTombstone,
  inspectBunfsSnapshot, bunfsTombstone,
  inspectSidecarNote, sidecarNoteTombstone, inspectBlaManifest, blaManifestTombstone,
} from "./trailer.mjs";
import { detect } from "./detect.mjs";
import {
  emitRuntimeCounterShield, reconstructSourceMap, scoreStructuralAnomaly,
} from "./recovery/canonical.mjs";
import { createRequire } from "node:module";
import { createHash } from "node:crypto";

const VERSION = createRequire(import.meta.url)("../package.json").version;

const USAGE = `blade — de-harden a BLA-protected artifact

usage: node src/cli.mjs <input> [-o output] [--report out.json] [--quiet] [--verbose]

options:
  -o <path>          output path (default: <input>.cleaned<ext>)
  --format <kind>    force a scrubber route instead of detect()
  --report <path>    write the full JSON report to <path> ("-" = stdout)
  --quiet            suppress the report dump on stdout
  --verbose          never truncate the report on stdout
  --dry-run          analyze only — write no artifact or sidecar files
  --help, -h         show this text
  --version          print the blade version

input "-" reads the artifact from stdin (requires -o).

exit codes: 0 success · 1 unrecognized format · 2 usage/IO error

All processing is local; nothing is uploaded.`;

function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) { console.log(USAGE); process.exit(0); }
  if (args.includes("--version")) { console.log(VERSION); process.exit(0); }
  const oIdx = args.indexOf("-o");
  const rIdx = args.indexOf("--report");
  const fIdx = args.indexOf("--format");
  const quiet = args.includes("--quiet");
  const verbose = args.includes("--verbose");
  const dryRun = args.includes("--dry-run");
  const writeOut = dryRun ? () => {} : (p, c) => {
    try {
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, c);
    } catch (e) {
      console.error(`blade: cannot write ${p}: ${e.code ?? e.message}`);
      process.exit(2);
    }
  };
  const VALUE_FLAGS = new Set(["-o", "--report", "--format"]);
  const FLAG_SET = new Set(["-o", "--report", "--format", "--quiet", "--verbose", "--dry-run", "--help", "-h", "--version", "-"]);
  if (args.includes("--quiet") && args.includes("--verbose")) {
    console.error("blade: --quiet and --verbose are mutually exclusive");
    process.exit(2);
  }
  for (const f of ["-o", "--report", "--format"]) {
    if (args.indexOf(f) !== args.lastIndexOf(f)) {
      console.error(`blade: ${f} given twice — ambiguous`);
      process.exit(2);
    }
  }
  for (const a of args) {
    if (a.startsWith("-") && a !== "-" && !FLAG_SET.has(a)) {
      console.error(`blade: unknown flag ${a}\n\n${USAGE}`);
      process.exit(2);
    }
  }
  for (const f of VALUE_FLAGS) {
    const i = args.indexOf(f);
    // `-` is a legal value for --report (stdout) — only other flags reject.
    if (i !== -1 && (i + 1 >= args.length || (args[i + 1].startsWith("-") && !(f === "--report" && args[i + 1] === "-")))) {
      console.error(`blade: ${f} requires a value\n\n${USAGE}`);
      process.exit(2);
    }
  }
  const positionals = args.filter((a, i) => (a === "-" || !a.startsWith("-")) && !VALUE_FLAGS.has(args[i - 1]));
  if (positionals.length > 1) {
    console.error(`blade: unexpected extra input '${positionals[1]}' — one artifact per run`);
    process.exit(2);
  }
  const input = positionals[0];
  if (!input) {
    console.error(USAGE);
    process.exit(2);
  }
  const stdin = input === "-";
  if (stdin && oIdx === -1) {
    console.error("blade: stdin input requires -o <output>");
    process.exit(2);
  }
  let buf;
  try {
    buf = stdin ? readFileSync(0) : readFileSync(input);
  } catch (e) {
    console.error(`blade: cannot read ${input}: ${e.code ?? e.message}`);
    process.exit(2);
  }
  // Hash the pristine input NOW — some scrubbers (native trailers) mutate the
  // buffer in place, so hashing after dispatch would report corrupted bytes.
  const inputSha256 = createHash("sha256").update(buf).digest("hex");
  const ext = stdin ? "" : extname(input).toLowerCase();
  const KNOWN_KINDS = new Set(["js", "asar", "wasm", "sqlite", "safetensors", "gguf", "native", "dex", "il2cpp", "dotnet", "evm", "ptx", "jvm", "plist", "pcap", "pcapng", "uf2", "beam", "pyc", "zip", "py", "html", "sourcemap", "header", "bunfs-snapshot", "sidecar-note", "bla-manifest"]);
  const KIND_ALIASES = { pcapng: "pcap" }; // same scrubber handles both magics
  let kind;
  if (fIdx !== -1) {
    kind = args[fIdx + 1];
    if (!KNOWN_KINDS.has(kind)) {
      console.error(`blade: unknown --format '${kind}' (known: ${[...KNOWN_KINDS].join(", ")})`);
      process.exit(2);
    }
    kind = KIND_ALIASES[kind] ?? kind;
  } else {
    kind = detect(buf, ext);
  }
  // BLA's own config sidecar (bla.config.json/.blarc/.blarc.json) is direct
  // provenance that the artifact set was BLA-processed — keep verbatim and
  // surface it rather than erroring "unrecognized format".
  if (kind === "unknown" && /^(bla\.config\.json|\.blarc(?:\.json)?)$/i.test(basename(input))) {
    kind = "bla-config";
  }
  if (stdin && kind === "sqlite") {
    console.error("blade: sqlite scrubbing needs a real input path (WAL sidecars are merged) — stdin unsupported");
    process.exit(2);
  }
  const output = oIdx !== -1 ? args[oIdx + 1] : input.replace(/(\.[^.]*)?$/, ".cleaned$1");
  // --report must not clobber the artifact or the input being analyzed.
  if (rIdx !== -1 && args[rIdx + 1] !== "-") {
    const rp = resolve(args[rIdx + 1]);
    if (rp === resolve(input) || rp === resolve(output)) {
      console.error(`blade: --report path '${args[rIdx + 1]}' collides with input/output — choose a separate report path`);
      process.exit(2);
    }
  }
  // Windows reserved device names: `-o nul`/`NUL.txt`/`con` creates an
  // undeletable file or writes to the console device. Reject stem matches.
  {
    const stem = basename(output).split(".")[0];
    if (/^(nul|con|prn|aux|com[1-9]|lpt[1-9])$/i.test(stem)) {
      console.error(`blade: '${output}' is a Windows reserved device name — choose another output path`);
      process.exit(2);
    }
  }

  // kind → { scrub } — the buf-based formats share one dispatch shape:
  // run the scrubber, keep its report, write `buffer` (binary) or `code` (text).
  const BUFFER_KINDS = {
    wasm: scrubWasm, safetensors: scrubSafetensors, gguf: scrubGguf,
    native: scrubNative, dex: scrubDex, il2cpp: scrubIl2cpp, dotnet: scrubDotnet,
    evm: scrubEvm, jvm: scrubJvm, pcap: scrubPcap, uf2: scrubUf2,
    beam: scrubBeam, pyc: scrubPyc, zip: scrubZip,
  };
  const CODE_KINDS = { ptx: scrubPtx, py: scrubPySource, html: scrubHtml };

  let report;
  if (kind === "js") {
    const src = buf.toString("utf8");
    const r = dehardenJs(src, { filename: basename(input) });
    report = { format: "js", ...r.report };
    // passthrough must be byte-exact — re-encoding the utf8 string would
    // silently damage non-UTF8 payloads (latin-1 bytes, UTF-16 blobs).
    writeOut(output, r.code === src ? buf : r.code);
    if (!r.report.hardened) report.note = "no BLA markers found — passthrough";
  } else if (kind === "asar") {
    // `unpacked` entries live in the sibling <input>.unpacked/ dir — feed them
    // in for integrity checks and re-emit whatever survives to
    // <output>.unpacked/.
    const extRoot = `${input}.unpacked`;
    // archive member paths are attacker-controlled — `../`, absolute and
    // drive-letter forms must never escape <input>.unpacked/ or the output dir.
    const safeMemberPath = (p) => {
      if (typeof p !== "string" || p.length === 0) return null;
      if (p.startsWith("/") || /^[a-zA-Z]:[\\/]/.test(p) || p.startsWith("\\\\")) return null;
      const parts = p.split(/[\\/]+/);
      if (parts.some((s) => s === ".." || s === "")) return null;
      return parts.join("/");
    };
    const r = scrubAsar(buf, {
      getExternal: (p) => {
        const sp = safeMemberPath(p);
        if (!sp) return null;
        const fp = join(extRoot, sp);
        try { return existsSync(fp) ? readFileSync(fp) : null; } catch { return null; }
      },
    });
    report = r.report;
    writeOut(output, r.buffer);
    if (r.unpackedExternals?.length) {
      for (const u of r.unpackedExternals) {
        const sp = safeMemberPath(u.path);
        if (!sp) { report.unpackedPathBlocked = (report.unpackedPathBlocked ?? 0) + 1; continue; }
        const fp = join(`${output}.unpacked`, sp);
        if (!dryRun) mkdirSync(dirname(fp), { recursive: true });
        writeOut(fp, u.content);
      }
    }
  } else if (kind === "sqlite") {
    // scrubSqlite is path-based (WAL checkpoint needs a real output file);
    // under --dry-run, scrub to a throwaway temp path and delete it.
    if (dryRun) {
      const tmp = join(tmpdir(), `blade-dry-${process.pid}-${Date.now()}.sqlite`);
      const r = scrubSqlite(input, tmp); report = r.report;
      for (const s of ["", "-wal", "-shm", "-journal"]) { try { rmSync(tmp + s); } catch {} }
      report.note = (report.note ? report.note + "; " : "") + "dry-run — no artifact written";
    } else {
      const r = scrubSqlite(input, output); report = r.report;
    }
  } else if (kind === "plist") {
    const isBin = buf.length >= 6 && buf.subarray(0, 6).toString("latin1") === "bplist";
    if (isBin) { const r = scrubBplist(buf); report = r.report; writeOut(output, r.buffer); }
    else { const r = scrubPlistXml(buf.toString("utf8")); report = r.report; writeOut(output, r.code); }
  } else if (BUFFER_KINDS[kind]) {
    const r = BUFFER_KINDS[kind](buf); report = r.report; writeOut(output, r.buffer);
  } else if (CODE_KINDS[kind]) {
    const r = CODE_KINDS[kind](buf.toString("utf8")); report = r.report; writeOut(output, r.code);
  } else if (kind === "sourcemap") {
    const r = inspectSourcemap(buf.toString("utf8")); report = r;
    if (!r.honeyMap) {
      // Genuine map — copy verbatim. Reconstructing it would destroy real
      // mappings for zero benefit (non-idempotent, too).
      writeOut(output, buf);
      report.action = "passthrough";
    } else {
      // Honey map: original mappings are destroyed and the passthrough bytes
      // are poison. Recover to the best degree available: locate the sibling
      // JS, deharden it, and emit a spec-valid identity map over the
      // dehardened code (positions an analyst actually sees). No sibling → a
      // clean skeleton; either way the output is never the honey map.
      let parsed = null;
      try { parsed = JSON.parse(buf.toString("utf8")); } catch {}
      let dehardenedJs = null;
      const jsPath = parsed?.file ? join(dirname(input), parsed.file)
        : input.endsWith(".map") ? input.slice(0, -4) : null;
      if (jsPath && existsSync(jsPath)) {
        try {
          const src = readFileSync(jsPath, "utf8");
          dehardenedJs = looksBlaHardened(src) ? dehardenJs(src, { filename: basename(jsPath) }).code : src;
        } catch {}
      }
      const rec = reconstructSourceMap(parsed, dehardenedJs, dehardenedJs ? Buffer.byteLength(dehardenedJs) : buf.length);
      writeOut(output, JSON.stringify(rec.map));
      report.action = dehardenedJs ? "reconstructed-identity-map" : "skeleton-map";
      report.sourceMapRecovery = rec.status;
    }
  } else if (kind === "header") {
    const r = inspectShieldHeader(buf.toString("utf8")); report = r;
    if (r.decoyHeader) { writeOut(output, headerTombstone()); report.action = "excluded-decoy-header"; }
    else writeOut(output, buf);
  } else if (kind === "bunfs-snapshot") {
    // standalone decoy module graph — 100% honeypot surface, tombstone it
    const r = inspectBunfsSnapshot(buf); report = r;
    writeOut(output, bunfsTombstone()); report.action = "excluded-decoy-graph";
  } else if (kind === "sidecar-note") {
    // strip=>fail binding record only — tombstone it
    const r = inspectSidecarNote(buf); report = r;
    writeOut(output, sidecarNoteTombstone()); report.action = "excluded-decoy-note";
  } else if (kind === "bla-manifest") {
    // defend-mode attestation manifest / harden-run summary — pure BLA
    // provenance, tombstone it
    const r = inspectBlaManifest(buf); report = r;
    writeOut(output, blaManifestTombstone(r.schema)); report.action = "excluded-attestation";
  } else if (kind === "bla-config") {
    // BLA's own config sidecar — provenance evidence, keep verbatim + flag
    report = { blaConfig: true, note: "BLA protection config — sibling artifacts were likely BLA-processed" };
    writeOut(output, buf); report.action = "kept-provenance";
  } else {
    console.error(`unrecognized format: ${input}${stdin ? " (stdin carries no filename — use --format <kind>)" : ""}`);
    process.exit(1);
  }

  report.input = input;
  report.output = output;
  report.format = kind;
  report.inputSha256 = inputSha256;
  report.inputSize = buf.length;

  // Signature-free anomaly scoring — surfaces structures typical of BLA even
  // when no known signature matches (future/renamed variants).
  report.structuralAnomaly = scoreStructuralAnomaly(buf, kind);

  // Runtime defenses can't be cleaned statically — emit countermeasures
  // alongside the artifact when their marker surface is present.
  const RUNTIME_HINTS = [
    "state_diff_frontier_", "rollingMask", "splitShareA", "splitShareB",
    "stepShadowHeap_", "cdpShapeBudgetGuard_", "fridaCaptureSaturator_",
    "probeCanaryHoneypot_", "measureIntegrity", "enclave_unseal",
    "_shadowVault_", "fridaRealmRing_", "obligationFlood", "labyrinthDispatch",
    "diffFrontier", "readSplitShare", "inspectorObserved",
  ];
  const hints = RUNTIME_HINTS.filter((m) => buf.includes(m));
  // Evidence gate: a genuine file that merely *mentions* a hint string in
  // text/comments must not sprout counter-shield sidecars.
  const removalEvidence =
    ["removedTopLevel", "injectedFunctionsRemoved", "selfSealFunctionsRemoved",
     "bindScopeCheckRemoved", "weaveStatementsRemoved", "prologueCallsRemoved",
     "membersRemoved", "keysDropped", "entriesRemoved", "mapMembersReconstructed"]
      .some((k) => (report[k] ?? 0) > 0);
  if (hints.length > 0 && (report.hardened === true || removalEvidence)) {
    // Feed the harvested evidence too — machinery names the scrubbers removed
    // map to families the raw substring hints miss (and vice versa).
    const harvested = [...hints,
      ...(report.removedNameSamples ?? []),
      ...(report.recoveredStrings ?? []),
      ...(report.renamedBindings ?? []).flat(),
    ];
    const cs = emitRuntimeCounterShield(harvested);
    const a = output + ".blade-counter.js", n = output + ".blade-cdp-notes.md", s = output + ".blade-tee-stub.js";
    writeOut(a, cs.fridaScript); writeOut(n, cs.cdpNotes); writeOut(s, cs.teeStubSurface);
    report.runtimeCounterShield = { fridaScript: a, cdpNotes: n, teeStubSurface: s, hints, families: cs.families };
  }

  const json = JSON.stringify(report, null, 2);
  const reportToStdout = rIdx !== -1 && args[rIdx + 1] === "-";
  if (rIdx !== -1 && !reportToStdout) {
    mkdirSync(dirname(args[rIdx + 1]), { recursive: true });
    writeFileSync(args[rIdx + 1], json);
  }
  if (reportToStdout) {
    // `--report -` means machine-readable stdout: full JSON, nothing else.
    process.stdout.write(json + "\n");
  } else if (!quiet) {
    console.log(`[BLADE] ${kind} ${input} -> ${output}`);
    console.log(!verbose && json.length > 1200 ? json.slice(0, 1200) + "\n ... (truncated; see --report)" : json);
  }
}
// Only run when invoked directly (`blade <input>` / `node src/cli.mjs ...`);
// importing this module for its exports must not execute main().
import { pathToFileURL } from "node:url";
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();

export { main, USAGE, VERSION };
