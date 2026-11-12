# Changelog

All notable changes to BLADE are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `scripts/fuzz-js.mjs` — 400-round seeded AST-level mutation fuzzer for
  the JS de-hardener (statement splice/dup, vocabulary injection, fake
  bind-scope IIFEs, opaque-guard wraps, mid-token truncation). Contract:
  never throw, shaped result, output parses when input parses.
- `scripts/test-anomaly.mjs`, `test-evaluator.mjs`,
  `test-name-recovery.mjs`, `test-precision.mjs`, `test-canonical.mjs` —
  91 module-level unit checks over the scoring/repair/recovery helpers.
- `report.mixedStatementsKept` (+ `mixedStatementsKeptTruncated`) —
  conservative mixed injected+real statement keeps are now listed with
  previews (capped at 200).
- `bla-weave-plan/v1` workorder detection → bla-manifest tombstone with
  `weaveTargets`/`overallStatus`.
- Robustness crash-regression probes for the duplicate block-scoped
  declaration traverse crash (top-level/nested/destructured shapes).
- CI: 5 → 10 gated steps (detect corpus, unit suites, fuzzer, asar,
  idempotency).

### Fixed

- `dehardenJs` no longer throws `TypeError: Duplicate declaration` on
  parse-tolerated conflicting block-scoped decls (pre-detected via a
  manual lexical walk; legal `var` redecls still pass through).
- Both `generate` emission sites fall back to pristine-source passthrough
  on adversarial node shapes instead of throwing.
- `recoverWasmExports(null)` no longer throws (the last exported helper
  that could crash on degenerate input).
- `index.d.mts`: six drifted declaration shapes corrected
  (`scoreSqliteObjects`, `beamLoneDecoyScore`, `neutralizePyLiteralMarkers`,
  `detectOpaqueSeedVariants`, `RuntimeCounterShield`, `makeEvaluator`,
  `inspectBlaManifest`, `DetectedKind`).

### Security

- Self-hardening pass over every parser and the CLI (hostile artifacts are
  attacker-controlled input): ASAR `.unpacked` member paths sanitized in
  both directions (traversal/absolute/drive-letter rejected); ELF extended
  section numbering, PE optional-header magic, PYC `marshalSkip`/`weaveScan`
  counts all bounds-checked — malformed inputs now yield controlled reports
  instead of `RangeError` crashes; ASAR `integrity.blockSize` validated
  against runaway loops; `inputSha256` hashed on pristine bytes before any
  in-place mutation; unhardened `.js` passthrough is byte-exact (no UTF-8
  re-encode); `--report` cannot clobber input/output; extra positional
  args rejected; `-o` writes create dirs and report errors; Windows
  reserved device names rejected as output paths; plist nested-key removal
  backreference fixed (`\2`→`\1`); malformed WASM section lengths surfaced
  as notes instead of silent desync.

### Added

- CI workflow running the core verification plus the JS and BLA 3.2.4
  adversarial suites, with `bla-agents@3.2.4` vendored from npm at job time.
- `CONTRIBUTING.md` documenting the evidence-driven recovery contract.
- `src/index.mjs` library entry point — the full scrubber/recovery API is
  importable as `import { detect, scrubNative } from "blade"`.
- `src/detect.mjs` — format routing extracted from the CLI.
- `scripts/robustness.mjs` — degenerate/truncated/bit-flipped inputs through
  all 21 scrubbers; format-rejection throws are legal, anything else is a bug.
- `scripts/test-detect.mjs` — 37 synthetic-buffer routing unit tests.
- `scripts/verify-all.mjs` — consolidated suite matrix (`npm run test:all`),
  with vendor-dependent suites gated on `vendor/bla` presence.
- CLI flags: `--help`, `--version`, `--quiet`, `--verbose`, `--dry-run`
  (analyze + report without writing artifacts).
- `report.suspiciousKeys` on plist scrubbing — BLA-prefixed keys outside the
  known emission set are surfaced instead of silently kept.
- PCAP: pcapng block walk — decoy EPB/SPB/PB blocks are dropped; markers
  inside structural blocks (SHB/IDB/options) are flagged but kept.
- `report.inputSha256` + `report.inputSize` — provenance on every report.
- JSDoc across the full public API surface (all 50 exports).
- `.gitattributes` (LF for source, verbatim `-text` for `test-fixtures/`),
  `.editorconfig`, `CHANGELOG.md`.
- npm script per adversarial suite (`npm run test:<format>`).
- `scripts/live-matrix.mjs` — end-to-end harness running the real vendored
  `bla-agents@3.2.4` CLI: `protect` → BLADE clean → verify at all four
  intensities plus the opt-in decoy-flag pass, `protect` output re-protected
  (double-harden) on JS/WASM, `bla audit` exposure scoring on cleaned JS,
  and WASM compile assertions. 370/370 checks.
- Multi-layer recovery: every resolved BLA seed is bound into the evaluator
  environment and folded into opaque predicates (double/triple-harden);
  corpus discovery runs in source order so later corpora can reference
  earlier seeds; still-referenced seeds rebind as folded constants.
- BLA decoy-data removal behind the generic-suffix name gate: tagged
  `evidenceLedger_*`/`grpcServiceMirage_*`/`systemDiagnosticLog_*`/
  `canaryCredentialHoneypot_*`, `bpeSink_*` token-amplifier tables, EV-TEE
  diagnostic records, frida shadow-ring `{epoch, slots}` objects, and
  tarpit pid-seed declarations.
- v324 suite: real BLA 3.2.4 showcase fixtures extracted from
  `vendor/bla/dist/engine/benchmark.js` (dx-ball, license-validator).

### Fixed

- `scrubNative` whole-section `fill(0)` destroyed real bytes when BLA
  appended its marker after legitimate `.go.buildinfo`/`.isolate` content
  (BLA's own ELF fixture) — now zeroes only from the first marker and also
  covers BLA's planted `\xff Go buildinf:` magic prefix.
- `scrubGguf` left BLA's trailing NUL filler after stripped decoy KVs — now
  trimmed when `tensorCount=0` and decoys were dropped.
- `scrubSafetensors` re-emitted an empty `__metadata__` after dropping all
  its decoy keys — the block is omitted entirely now.
- `scrubJvm` returned after cutting the trailer without processing a
  stuffed constant pool (double-harden both appends and stuffs) — the
  trimmed buffer now feeds CP decoy-drop/neutralize; degenerate all-decoy
  classes process before the validity gate.
- `scrubDex` `ERR_OUT_OF_RANGE` on double-hardened inputs (marker searched
  in the uncut buffer but filled into the cut one).
- `scrubWasm` double-harden export floods — decoys aliasing the same
  `(kind,idx)` as real exports dedup when the module is proven hardened.

- `scrubAsar` crashed with a raw `JSON.parse` error on truncated/corrupt
  archives — now keep+flags like every other scrubber.
- `scrubWasm`/`scrubGguf` threw on bad magic — now keep+flag passthrough.
- `scrubPlistXml` required a strict `</key>\n<value>` layout — odd layouts
  (same-line, blank-line, comment-separated, `<date>`/`<array>` values,
  lone-CR line endings) left decoys behind. All covered now.
- `scrubPlistXml` missed `[]` subsets on single-quoted DOCTYPE ids.
- CLI `-o out.js in.js` misread the output path as the input.
- Importing the package executed the CLI (`main` pointed at `cli.mjs`);
  `cli.mjs` now self-gates on direct invocation.
- plist/py harnesses hardcoded machine-specific python paths — both now
  probe `BLADE_PYTHON`/`py`/`python3`/`python` and skip gracefully.
- `scrubPcap` rejected big-endian *nanosecond* pcaps (0xa1b23c4d BE) —
  they now parse and decoy packets are dropped correctly.
- `scrubSqlite` copied only the main DB file — committed-but-uncheckpointed
  rows in a `-wal` sidecar were silently lost. The WAL is now copied,
  checkpointed into the output, and journal mode restored to DELETE so the
  artifact is one self-contained file.
- `.gitattributes` initially normalized `test-fixtures/` `.py` files,
  destroying the CRLF-preservation property under test; the fixture tree is
  now stored verbatim.

### Changed

- `.gitignore` now excludes BaiduYun (and generic cloud-sync) sidecar
  artifacts.

## [1.0.0] — initial public release

### Added

- Format-detecting de-hardening CLI covering JS, ASAR, WASM, SQLite,
  safetensors, GGUF, ELF/Mach-O/PE, DEX, il2cpp, .NET, EVM, PTX, JVM class,
  plist (XML+binary), PCAP/PCAPNG, UF2, BEAM, PYC, ZIP/APK, Python source,
  HTML, sourcemaps, C/C++/Rust/Go shield headers, Bun standalone snapshots,
  and sidecar-entangle notes.
- JavaScript AST de-hardening: containment-corpus digest resolution, opaque
  seed parity (all three BLA test shapes incl. 3.2.4 `.every(...)`
  entanglement), injected-machinery removal, `encryptStrings` stub decoding
  for the ≤3.2.2 and 3.2.4 keystreams, template-literal reconstruction,
  self-seal `measureIntegrity` stripping, ASAR/plain-JS sidecar preamble
  removal.
- `src/recovery/` layer: canonical fuse/source-map restoration, runtime
  counter-shield emission (Frida/CDP/TEE), evidence-based name recovery for
  JS locals and WASM exports, Python literal+comment marker neutralization,
  guarded orphan-machinery sweep, SQLite/BEAM suspicion scoring, PCAP tail
  salvage, EVM reachable-prefix pad split, ZIP member salvage, bounded DEX
  repair, APK metadata preservation, signature-free structural-anomaly
  scoring.
- PE `.enclave` mapped-section strip with SGX guard + zero-slack cleanse
  (BLA 3.2.4), byte-exact on real fixtures.
- Python sidecar preamble splice (`__bla_hashlib` block) — byte-exact.
- Adversarial fixture corpus across 20+ formats, all generated by real
  `bla-agents` releases (3.2.2 + 3.2.4), with per-suite runners.
- Honest recovery grading in every report: exact / canonical / inferred /
  salvage / keep+flag / unrecoverable.
