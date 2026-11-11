# BLADE — Bypass LLM Agent Defense Engine

Adaptive de-hardening of **BLA** (`bla-agents@3.2.4`, `qybaihe/bla`) protected
artifacts so downstream analyzers (**REA** `rea-agents@6.3.0`, `morluto/rea`)
see real logic instead of decoys. All processing is local; nothing is uploaded.
(3.2.2 and earlier outputs remain fully supported — 3.2.4 additions are
listed in "BLA 3.2.4 coverage" below.)

## Usage

```bash
node scripts/make-fixtures.mjs          # generate plain fixtures
node vendor/bla/dist/cli.js protect <file> --intensity bankrupt --output test-fixtures/hardened
node src/cli.mjs <input> [-o output] [--report report.json]
node scripts/verify.mjs                 # full scrub + equivalence checks (37 checks)
```

## How it works (adaptive, not "more tools")

BLA is a counter-analysis toolkit: it does not encrypt logic, it surrounds it
with structures sized to break REA's resource budgets and evidence contracts.
BLADE's strategy is to recognize BLA-generated structure by its own signatures
and remove it *before* analysis, rather than raising limits:

1. **Seed resolution** — BLA bakes a runtime seed as
   `seed = base | (digest(corpus,0) === expected ? 1 : 0)`. BLADE recomputes
   the containment-corpus digest (FNV-style, `0x85ebca6b`/`0x26b5c67b`) to
   resolve the parity bit that every opaque predicate depends on.
   (`src/evaluator.mjs`, `src/js-deharden.mjs`)
2. **Bounded partial evaluation to a fixpoint** — folds the four
   seed-dependent opaque-predicate families and combinatorial string/int
   ternaries, unwraps `if(opaqueTrue){...}` and deletes `if(opaqueFalse){...}`.
   The evaluator is depth-capped because BLA deliberately emits deep
   expressions to exhaust evaluators.
3. **Authoritative injected-name harvest** — the `void [f1, f2, ...]` trailer
   BLA emits enumerates its own injected functions; BLADE uses it as ground
   truth, plus the STRONG/GENERIC name families (`obligationFlood_*`,
   `scc_*_cNnN`, `labyrinthDispatch_*`, `_interlockSafetyCorpus_*`, …).
4. **Boundary classification** — the injected payload is a contiguous suffix
   plus a small prologue region; legitimate statements in between are kept.
   Reference analysis skips nested function bodies so a real
   `ipcMain.handle(ch, async () => { stepper(3); realWork() })` is not
   discarded for carrying a swept prologue.
5. **Residual sweep + canonical-name restore** — injected calls inside
   retained functions are removed; destructured `require()` bindings are
   renamed back to their property names (`contextBridge`, `ipcMain`, …) and
   `module.exports` keys restore original export names — the identifiers
   downstream detectors key on.
6. **Format scrubbers** (`src/formats.mjs`):
   - **ASAR**: parse Chromium Pickle framing, drop `enclave/`+`.bla/` decoy
     namespaces, de-harden surviving `.js` entries, repack, and **recompute
     per-file `integrity` SHA-256 blocks** (stale integrity trips REA's
     fail-closed `artifact_integrity_mismatch` gate).
   - **WASM**: drop `bla.*`/`enclave.*`/honey `name` custom sections, filter
     `enclave_export_*` decoys from the export table, rebuild the module.
   - **SQLite**: drop honey tables/views (`enclave_*`, `tpm2_*`,
     `zero_trust_*`, `canary_*`, `system_diagnostic_log`,
     `GENERATED ALWAYS AS enclave_unseal_payload(...)` virtual columns),
     then `VACUUM`.
   - **safetensors/GGUF**: drop `enclave.*`/`bla.*`/`canary*` metadata keys
     (including the 35-deep `enclave.nesting.breaker`), strip
     `enclave_topology_seal` tensor fields, and drop **legitimate-looking
     keys whose values contain BLA armor markers** (e.g. a poisoned
     `general.description`).
7. **Trailer/structural scrubbers** (`src/trailer.mjs`) — the remaining 20
   formats. BLA overwhelmingly uses append-only trailers; each scrubber cuts
   at BLA's *own* separator bytes/markers rather than generic NUL runs:
   - native ELF/Mach-O/PE, .NET, IL2CPP, bplist, EVM, PTX: exact-marker cut;
   - DEX: cut + recompute file_size/SHA-1/Adler32;
   - JVM `.class`: parse CP, drop the appended Utf8 decoy run, restore
     `constant_pool_count`, cut trailing JSON;
   - BEAM: drop `B*`-named decoy chunks, trim canary atoms from `AtU8`;
   - PCAP/UF2: keep original packets/blocks, drop marker-flagged decoys;
   - PYC: version-dispatched marshal walker (py37/py38–310/py311+) locates
     the root object's exact end;
   - Python source: boundary-marker splice that absorbs BLA's join newlines;
   - plist XML: drop `BLA*` key/value pairs + empty internal subset;
   - ZIP/APK: rebuild archive minus decoy members, recurse into inner
     `.dex`/`.js`; HTML: deharden each inline script;
   - `.map`: BLA overwrites it wholesale → flagged `unrecoverable`.

## Minimal reproducible result

Fixtures: `scripts/make-fixtures.mjs` → `test-fixtures/plain`, hardened with
`bla protect --intensity bankrupt` → `test-fixtures/hardened`.

| artifact | plain | hardened | BLADE output |
|---|---:|---:|---:|
| license-core.js | 1,296 B | 138,231 B | 2,146 B |
| electron-bridge.js | 1,293 B | 219,737 B | 1,254 B |
| app.asar | 446 B | 18,041,111 B | 920 B (header 17.4 MB → 532 B, 4,003 → 2 entries) |
| seal.wasm | 95 B | 6,880,194 B | 166 B (250 decoy exports dropped, 3 kept) |
| licenses.sqlite | 20,480 B | 65,536 B | 20,480 B (6 honey objects dropped) |
| mlp.safetensors | 176 B | 10,152 B | 176 B (all decoy metadata dropped) |
| model.gguf | 150 B | 7,744 B | 179 B (26 of 30 KV records dropped) |

### Broader format corpus (20 formats, `--intensity bankrupt [--weave-decoys]`)

BLA's remaining shields are almost all **append-only trailers** or
**decoy-entry insertions**; `src/trailer.mjs` strips them marker-aware and
rebuilds only the mutated structures. All 16 trailer formats recover
**byte-exact** against the plain originals:

| artifact | plain | hardened | result |
|---|---:|---:|---|
| daemon.elf | 96 B | 1.16 MB | byte-exact (trailer dropped at `BLA-NATIVE-SHIELD` marker) |
| tool.macho | 32 B | 1.16 MB | byte-exact |
| service.exe | 512 B | 1.16 MB | byte-exact |
| Lib.dll (.NET) | 512 B | 8.1 KB | byte-exact (`BLA_DOTNET_CLR_SHIELD_V1` section cut) |
| classes.dex | 112 B | 17.0 KB | byte-exact (string-table decoys + trailer cut; SHA-1/Adler32 recomputed) |
| global-metadata.dat (IL2CPP) | 256 B | 122.8 KB | byte-exact |
| Info.plist | 317 B | 2.9 KB | byte-exact (19 `BLA*` keys + empty internal subset removed) |
| data.bplist | 256 B | 8.0 KB | byte-exact (binary trailer cut) |
| Main.class | 24 B | 11.9 KB | byte-exact (30 appended Utf8 CP entries + JSON tail removed, cp_count restored) |
| core.beam | 80 B | 256.1 KB | byte-exact (258 `B*` decoy chunks dropped, 4,157 canary atoms trimmed from AtU8) |
| token.evm | 31 B | 4.19 MB | byte-exact (CBOR metadata tail + `JUMPDEST` padding cut) |
| kernel.ptx | 306 B | 26.6 KB | byte-exact (`// [BLA-PTX-SHIELD]` comment tail cut) |
| capture.pcap | 24+44 B | 26.6 KB | byte-exact (160 injected HTTP/DNS packets dropped by `pcapPayload` marker) |
| fw.uf2 | 1,024 B | 140.5 KB | byte-exact (272 non-main-flash decoy blocks dropped) |
| app.pyc | 1,024 B | 8.8 KB | byte-exact (48 appended marshal records removed by version-dispatched marshal walker) |
| license.py | 718 B | 40.3 KB | byte-exact (324 injected lines + 4 woven decoy statements removed) |

Rebuilt containers (byte layout differs, verified content-equivalent):

| artifact | result |
|---|---|
| bundle.zip | member set + per-member bytes identical (11 decoy entries dropped) |
| app.apk | member set + per-member bytes identical; inner `classes.dex` recursively dehardened (16 decoy assets/libs/manifests dropped) |
| app.html | markup byte-identical; both inline scripts dehardened (semantics preserved, BLA-renamed locals unrecoverable) |
| app.js.map | **unrecoverable** — BLA replaced the map wholesale; passthrough flagged `untrusted` |

### REA baseline vs BLADE (measured, rea@6.3.0 CLI)

| input | REA direct | REA on BLADE output |
|---|---|---|
| `hardened-app/` (2 JS files) | **OOM kill** — `Ineffective mark-compacts near heap limit`, exit 134, ~65–74 s, 4 GB heap | — |
| `cleaned-app/` | — | success in 3.5 s; full graph: 3 literal `ipc-channel`s, 2 `ipc-handler`s, `context-bridge-api`, `/api/v1/clipboard/blocks` endpoint — same kinds as the *plain* graph |
| `hardened/app.asar` | **OOM kill** while projecting entry 1/4003 (inner JS), exit 134, ~74 s | — |
| `cleaned/app.asar` | — | success in 2.5 s, ~34k output tokens; graph identical in kind to plain (`electron-main`, literal channels, `notionClipboard` bridge) |

The MCP surface fails identically: `analyze_javascript_application` on the
hardened directory drops the REA server connection (same OOM), while plain and
cleaned inputs return complete evidence.

For standalone `.wasm`/`.sqlite`/`.safetensors`/`.gguf` REA 6.3.0 exposes **no
analysis surface** on this host (`inspect-artifact`: "unsupported binary
format"; `inspect-binary-layout`: Linux x64 ELF only) — there is no direct
baseline to beat; BLADE's value there is producing a decoy-free artifact with
business data verified intact.

## Defenses BLADE currently bypasses

- **AST exhaustion injection** (decoy corpora, obligation floods, SCC
  labyrinth, token sinks): 138–220 KB → ~1.3–2.2 KB per file; REA goes from
  fatal OOM to a complete graph.
- **Opaque predicates / tarpit**: all four seed-parity families folded and
  removed.
- **Runtime-seed split-share deception**: seed bit resolved, `runtimeSeed*`,
  `shadowHeap*`, `readSplitShare_*` eliminated.
- **IPC de-literalization**: channel literals recovered; canonical binding
  names restored so REA emits `ipc-channel`/`context-bridge-api` nodes.
- **Deception suffix** (mirage/honeypot/decoy IPC/crash decoys + `void […]`
  index): removed wholesale.
- **Honey source maps / armor comments**: trailers and marker comments
  stripped.
- **ASAR header amplification + entry flood**: 17.4 MB header → 532 B;
  4,001 `enclave/…` entries dropped; inner JS de-hardened; per-entry
  integrity recomputed.
- **WASM custom-section + export flood**: 6.9 MB → 166 B; 250 decoy exports
  dropped.
- **SQLite honey schema**: 6 decoy objects (incl. generated-column trap
  views) dropped; all business rows intact.
- **Model metadata nesting breakers**: `enclave.nesting.breaker` (35-deep),
  `enclave_topology_seal`, armor-valued `general.description` removed.
- **Native trailer payloads** (ELF/Mach-O/PE): ~1.16 MB appended decoy text
  cut at the exact `BLA-NATIVE-SHIELD` separator; original bytes untouched.
- **.NET CLR shield section**, **IL2CPP metadata trailer**: cut at marker,
  byte-exact.
- **DEX string-table pollution**: appended `enclave_*`/canary string entries
  and trailer removed; file_size + SHA-1 signature + Adler32 recomputed.
- **Plist traps**: XML `BLA*` key/value pairs + empty internal subset
  removed; binary plist trailer cut.
- **JVM constant-pool injection**: appended Utf8 decoy run located and
  dropped, `constant_pool_count` restored, trailing JSON payload cut.
- **BEAM chunk/atom flood**: `Bla0`/`Bl0x`/`B0xx` decoy chunks dropped;
  canary atoms trimmed from `AtU8`, count field restored.
- **EVM CBOR + JUMPDEST padding**: terminal metadata tail and up to ~4.2 MB
  of `5b` padding cut at the `BLA-EVM-SHIELD` boundary; merged-pad runs are
  split at the last reachable jump target (dead tail dropped, provably-
  owned prefix kept — semantic fidelity preserved).
- **PCAP decoy packets**, **UF2 decoy blocks**: dropped by BLA's own
  payload markers (`[BLA-PCAP-SHIELD]`, non-main-flash flag + marker).
- **PYC marshal trailer**: version-dispatched marshal walker finds the exact
  root end; 48 appended records removed.
- **Python source injection**: prologue/deception block plus
  `--weave-decoys` statements removed; byte-exact.
- **ZIP/APK decoy members**: archive rebuilt without `enclave/`, `.bla/`,
  fake JNI libs, manifests, multidex xref entries; inner `.dex`/`.js`
  recursively cleaned.
- **HTML inline-script hardening**: scripts dehardened in place, markup
  untouched.

## Not bypassed — and why (updated post-recovery round)

True information-theoretic losses only — everything below has a best-degree
recovery or approximation (see *Round 6*); what remains impossible is the
exact original bytes/names where BLA destroyed them:

- **Renamed local identifiers** (params/locals like `observeSharedTree_014`):
  the exact original names are destroyed, but `recoverJsNames`
  (`src/recovery/name-recovery.mjs`) now infers semantically accurate
  replacements — embedded original-name fragments BLA leaves in its own
  rename vocabulary (`serialKey`, `productCode`, `expectedTicket`,
  `PLAN_MATRIX` recovered verbatim), init-expression shapes, call-site and
  property-read evidence, structural roles. Import bindings, exported
  names, eval-visible and `.name`-observed bindings are never touched;
  surviving decoy-machinery names are never renamed (renaming a kept decoy
  would hide its identity). Uninferable bindings are reported under
  `unrenamable`, never given fabricated provenance.
- **WASM original export names**: `recoverWasmExports` parses the export
  table and emits a valid, append-ready `name` custom section reconstructing
  names from surviving name-section fragments, embedded `ops_*` hints and
  signature/position heuristics; provably-decoy exports are marked rather
  than given fabricated names.
- **`enclave_unseal_payload` / external-runtime semantics**: fictional by
  design — `emitRuntimeCounterShield` now emits a loadable no-op TEE stub +
  Frida/CDP counter-instrumentation artifacts so analysis environments can
  satisfy the claimed surfaces instead of failing on them.
- **Source maps**: original mappings are unrecoverable (BLA replaced the
  map wholesale), but `reconstructSourceMap` now emits a *valid* v3
  identity-ish map over the dehardened output — honey sources/markers
  stripped, surviving `sourcesContent` reused, and `x_blade_note` records
  that mappings are reconstructed and untrusted. Consumers get a parseable
  map instead of a poisoned or missing one.
- **Real Electron fuse wires** (mutated in place): `recoverFuseDefaults`
  restores a *single verified* real sentinel to canonical release-build
  defaults per platform (e.g. AsarIntegrity `enabled→disabled` on ELF,
  `enabled` on PE/Mach-O) — canonical values are documented Electron
  invariants, not the (unrecoverable) pre-harden values. Ambiguous,
  absent, or decoy-only records are refused.
- **PYC byte-exactness after `--weave-decoys`**: surgical excise +
  in-place count patch stays the strategy; `pycSurgicalSpans` now
  *validates* the splice against the original and reports
  `bytePreservedPct` — exact preservation metrics instead of blind trust.
  FLAG_REF/interning identity remains destroyed information.
- **Runtime-only defenses** (CDP/Frida/inspector deception, memory-diff
  churn): outside static scope — but `emitRuntimeCounterShield` emits the
  instrumentation artifacts (Frida capture-saturation guard script, CDP
  shape-guard notes, TEE stub) that a dynamic-analysis pass needs.
- **Unknown future BLA variants**: `scoreStructuralAnomaly` adds
  signature-free detection — overlays past declared ends, entropy spikes,
  text-on-binary overlays, repeated fixed-stride EOF records, NUL-prefixed
  vocab records, JS identifier-shape density — so shape-shifted variants
  still get flagged when the keyed signatures miss.

## Adversarial hardening (subagent audit, this round)

40 subagents (10 inventory + 30 per-defense) audited every shield family
against crafted hostile inputs. Fixes landed this session:

- **PE/dotnet routing**: marker-driven dispatch (BLA sniffs `BSJB` only in
  first 4 KiB — late-`BSJB` files get native trailers; BLADE now routes by
  actual marker, not header).
- **`cutAtMarker` false-cut class**: sibling-window check fixed (was
  vacuous), EOF-proximity heuristic removed — marker text in `.rodata`/
  signatures/data no longer truncates real content (shared fix across
  native/dotnet/DEX/IL2CPP/JVM/BEAM/bplist).
- **UF2**: decoy drop now requires BOTH the marker AND a `NOT_MAIN_FLASH`/
  `FILE_CONTAINER` flag (flags at block offset 8).
- **EVM**: trailing `0x5b` JUMPDEST runs only stripped when ≥4096 bytes AND
  a BLA CBOR trailer was removed — short legit tails survive.
- **JVM**: decoy-anchor requires BLA's fixed head entries; tags 5/6
  (Long/Double, 9 B / 2 slots) handled; `slice(0,-1)` desync fixed.
- **BEAM**: chunk drops now require payload markers, not just names.
- **DEX**: min-length guard before checksum writes; xref-decoy deletion
  requires marker + `Lcom/enclave/xref/` prefix; only real `dex\n` members
  get scrubbed inside ZIP (nested jars/renamed dex protected).
- **ZIP/APK**: decoy-member regex tightened to BLA's actual emitted names
  (`assets/bla-shield/*`, `assets/enclave/bla-*`, `enclave/shadow_module_*`);
  unreadable members preserve raw spans instead of emitting 0-byte files;
  `dehardenJs` wrapped (bad member can't kill the archive); `.class`
  members scrubbed recursively; IL2CPP member check requires magic or
  canonical name.
- **ASAR**: decoy paths narrowed to BLA's real shapes
  (`enclave/shards/ring0-slot-*`, `hardware-tee-bridge.js`) + content-marker
  check for non-JS payloads; `unpacked` entries passthrough (were reading
  other entries' bytes); `__proto__`/`constructor` path segments can't walk
  the prototype chain; `files` non-object / string `size` guarded.
- **PYC**: full `--weave-decoys` support (see limitations); magic `3394`
  (CPython 3.7) dispatch added; forward-scan picks earliest valid suffix.
- **SQLite**: identifier quoting (injection via crafted schema names),
  narrowed honey detection, surgical generated-column removal.
- **JS dehardener**: `constValues` restricted to primitives (stale container
  fold bug), write-position guards (`x++` → `1++` crash), `looksBlaHardened`
  now requires ≥2 injected-name families or corpus+seed evidence (lone
  marker strings can't flip the gate).
- **Python source**: boundary markers must sit at column 0 outside
  triple-quoted strings; CRLF preserved; fallback splice for truncated
  blocks.
- **Safetensors**: descriptor drop removed — BLA never injects tensor
  descriptors (only `__metadata__` + `enclave_topology_seal`); real
  `enclave_*`-named tensors survive.
- **Detection**: `pcapng` magic, magic-only `.pyc` (renamed files), ext
  fallbacks for `.asar/.wasm/.sqlite/.gguf/.dex/.class/.beam/.uf2/.pcap`.
- **Native ELF**: extended section numbering (`e_shnum=0`/`e_shstrndx=
  0xffff`) guard; V2 trailer variant recognized.

Newly confirmed unreachable/not-applicable vectors (documented, no action):
Electron fuses shield is dormant in shipped CLI; pcapng is rejected by
BLA's own protector (can't produce hardened pcapng); `emit-headers` output
is decoy-only generated source (tombstone, don't analyze).

### Round 2 — audit follow-ups

- **Detection**: fat Mach-O disambiguation via arch `cputype` (an
  `nfat_arch` in 45–90 previously misrouted to JVM); directory/unreadable
  input fails with a clean error instead of a stack trace.
- **ZIP**: ZIP64 sentinel detection → passthrough (BLA never emits zip64);
  central-directory bounds + local-header magic check + try/catch →
  malformed/fake-EOCD archives passthrough instead of crashing;
  tiny-member read guard.
- **PCAP**: decoy classification now requires the explicit
  `[BLA-PCAP-SHIELD]` tag OR ≥2 distinct ambient markers — a captured
  packet merely mentioning `enclave.internal` survives.
- **UF2**: non-512-aligned trailing bytes preserved (was whole-file bail).
- **Plist**: XML key removal narrowed to BLA's six exact emitted key names
  (was `BLA*` — user `BLAConfig`-style keys were collateral); nested-dict
  values handled.
- **GGUF**: removed the inter-KV padding writer — it inserted bogus bytes
  that parse as a phantom `tensor_info` (self-corruption); tensor offsets
  are relative so no repadding is needed; KV loop is now fail-soft on
  malformed lengths/types/zero-advance.
- **Safetensors**: truncated/unparseable headers passthrough with note.
- **HTML**: `<script>` inside `<!-- -->` comments is inert — skipped
  (comment-span check on match offset).
- **JS dehardener — rescue pass**: declarations dropped only on the
  generic `_hex{3,4}` suffix heuristic are restored at original position
  when kept code still references them (real `sku_lookup_a1b2` functions
  survived in the audit case: 200+ → 0 lost). `void <ident>` harvest now
  requires injected-family name shape — plain `void pendingTick` no longer
  marks real names for deletion.

### Round 3 — ASAR/BEAM/DEX adversarial integration

- **ASAR — 29/29 adversarial cases green**
  (`test-fixtures/adversarial/asar/run.mjs`):
  - Pickle tolerance: `firstU32=8` header variant accepted; `jsonLen`
    overruns into NUL padding/next-record bytes retry at the last `}` —
    malformed headers still fail closed.
  - `unpacked` entries: external bytes are embedded contiguously in the
    data section AND re-emitted to `<output>.unpacked/` (CLI passes a
    `getExternal` resolver over `<input>.unpacked/`); nodes keep
    `unpacked:true` + `size` + recomputed SHA-256 `integrity`/`blocks` —
    output stays self-contained for analysis while the external layout
    is preserved verbatim.
  - `.mts`/`.cts` members dehardened (harness JS-path coverage fixed);
    proto-pollution paths (`__proto__`/`constructor`/`toString`) safe.
- **BEAM — at documented-conservative ceiling**: classic `Atom` tables
  re-encode names as latin1 (UTF-8 mojibake doubled chunk size 223 B →
  607 B before the fix). Contiguous-decoy-tail atom trimming only —
  mid-table canary names stay (index-preserving; reported as residue).
  Decoy chunks require BLA's byte-exact emission shape — payload opens
  with `[BLA-BEAM-SHIELD]\x00` and ends with `\nchunk=<idx>\n` matching
  the index encoded in the decoy-family name (`Bla0-9`, `Bl0a-z`,
  `B<base36>`) — and must sit in a tail position (after the last
  standard chunk, or inside a decoy-named group). A legit-named chunk
  that merely quotes marker text (`fp-B0xy-marker`) survives; the
  quoted marker bytes are neutralized in place instead. Shape-exact
  decoys under names outside the family (`Dcoy`/`Xyz9` at tail) still
  drop; a lone marker-bearing chunk between real chunks is kept —
  dropping it would require heuristic guesses against real
  `Code`/`ExpT`/`ImpT`/`Line` index references.
- **DEX**: BLA's planted xref vocabulary (`BLA-DEX-XREF-V1`,
  `BlaDexXref.java`) overwritten in place alongside the trailer marker;
  unmarked trailing garbage past declared `file_size` is trimmed +
  checksums resealed when the declared region is self-consistent
  (sub-header/corrupt inputs keep passthrough); ZIP members carrying
  any dex-marker family route to `scrubDex` (xref-only members were
  neutralized without checksum reseal → INVALID; now valid).
- **ZIP/APK — 29/29 adversarial cases green**
  (`test-fixtures/adversarial/zip/run-adversarial.mjs`, verdict logic
  de-staled where fixtures predated the fixes): strongest-candidate
  EOCD selection (real CD beats fake CDs hidden in archive comments),
  ZIP64 locator/record walk, SFX MZ-stub routing (MZ+EOCD shape → zip
  not native), signing-block preservation in both layouts
  (`signingInvalidated` reported), data-descriptor/comment/extra-field/
  EFS/original-method preservation, nested-archive recursion (bounded
  depth 3), CRC-guided nlen-lie repair, post-EOCD garbage dropped on
  rebuild (no zip semantics; re-emitting re-poisons strict readers).
  Kept-and-flagged residue: corrupt/un-inflatable members preserve raw
  bytes with marker residue (reported); 16 MiB member inflation has no
  hard cap (bounded by input size — DoS note).

### Round 4 — SQLite closeout

`test-fixtures/adversarial/sqlite` — **12/13 PASS**, up from 9/13:

- **Row-bait density rule**: a table whose sampled rows (≤64) are ≥80%
  `[BLA-`/`enclave_unseal_payload` marker strings is a payload-decoy even
  under a plausible name — catches `audit_log` / `orders_enclave_backup`
  (`03-name-collisions`) while real tables (all-real rows) are untouched.
- **Dangling-reference pass**: after decoy drops, views/triggers whose DDL
  references a dropped object are downstream decoy machinery and are
  dropped in a fixpoint — `v_audit → enclave_key_hierarchy` falls while
  the real `v_recent_errors → system_diagnostic_log` survives
  (`12-dangling-refs`).
- **Trap-column surgery now actually runs**: `kept` objects previously
  lost their `sql`, disabling generated-column removal entirely; with the
  field restored, `enclave_unseal_payload(sku)` VIRTUAL columns are
  surgically dropped and real rows compare equal on the remaining
  columns (harness now diffs real columns only — an injected generated
  column referencing BLA's runtime-only UDF makes the raw input dump
  unreadable, so `SELECT *` equality was never achievable).
- **Case 04 ceiling (keep+flag)**: `trg_users_mirror`,
  `v_enclave_user_dump`, `user_export_view`, `enclave_idx_users_email`,
  `idx_users_lower` are fixture-invented stealth objects — BLA emits no
  triggers/indexes/views bound to user tables, and their DDL is fully
  benign, bound to a *real* table. Dropping them would delete
  indistinguishable real user objects; the two vocab-named ones are
  reported under `suspiciousObjects`.

### Round 5 — trailer discrimination + Python/ELF closeout

`cutAtMarker` (shared by native/DEX/IL2CPP/.NET/BEAM/bplist/JVM/PCAP)
gained two continuation rules that closed six previously documented
native failures:

- **Embedded-in-identifier**: a marker closed by `]` and immediately
  followed by a word char (`prefix_[BLA-NATIVE-SHIELD-V1]_suffix`) is
  content — real BLA records are NUL/structure-terminated. Fixes
  over-cuts in `case1` (.rodata marker) and `case2` (marker inside
  WIN_CERTIFICATE bytes) while still cutting the real trailer behind them.
- **Short-tail sibling**: a marker ≤512 B from EOF needs only one vocab
  sibling reaching near-EOF (was ≥2 unconditionally) — catches
  `[BLA-NATIVE-SHIELD-V2]` and other sparse short trailers; `case5`
  near-EOF markers now keep their real bytes.

ELF extended numbering (`e_shnum=0`/`e_shstrndx=SHN_XINDEX`) no longer
skips the in-place `.go.buildinfo`/`.isolate` decoy scan — when the
resolved index can't decode sane names, the SHT_STRTAB section that
resolves every `nameOff` is used instead.

Python source: opaque-predicate `if` lines are only removed when the
entire body is weave calls — a body with real statements means the shape
is guarding legit code (was: orphaned body → IndentationError). The
injected-region splice now runs to a fixpoint (bounded 3 passes) for
double-hardened input, and the deception-block comment match tolerates
BLA's `(inert)` suffix variants. Second+ regions require the probe-call
terminator so a lone user-written boundary comment is never spliced.

New coverage landed this round (subagent implementations, both spec- and
quality-reviewed):

- **Electron-fuses decoy sentinels** — BLA appends up to 34 contiguous
  42-byte decoy records (`dL7pKGdn…` sentinel + `01 08` + wire bytes with
  wire[6]=0x39 DECOY) *before* the native trailer marker, so they survived
  the trailer cut. `scrubNative` now peels the contiguous ≥2-record run
  from the post-cut EOF (a lone record stays — could be a real fuse
  block); a surviving decoy-flagged record is reported
  `suspiciousFuseRecord`, a single plan-matching fuse is reported
  `fuseWireSuspect` (BLA mutates real fuse wires in place — originals
  destroyed, detect-and-report only). 10/10 fuse fixtures pass, byte-exact
  restores.
- **bun-standalone sidecars** — BLA emits sibling `.bunfs-snapshot`
  (decoy module graph, `payloadOffset==0` ⇔ whole file is the graph) and
  `.bla-sidecar.v1.json` companion notes; previously unrouted → CLI exit
  1. Both now detected by content (after all exec-magic routes, so real
  `bun build --compile` output is untouched) and tombstoned —
  `bunfs-snapshot`/`sidecar-note` formats, 5/5 fixtures pass.
- **BEAM polyglot dead** — `fp-B0xy-marker` was a true distinguisher
  waiting to be used: BLA decoy names cap at ~`B077` (`B0xy`=idx 1222 is
  unreachable), payloads start `[BLA-BEAM-SHIELD]\0`, end
  `\nchunk=<nameIdx>\n`, sit only in the decoy tail run, and come in ≥8.
  The tightened shape predicate keeps `B0xy`/`Bdoc` (markers neutralized
  in place) → BEAM **26/26**.
- **CAFEBABE polyglot dead** — `jvmClassLooksValid` requires
  `this_class`/`super_class` to resolve to tag-7 `CONSTANT_Class`
  entries (JVMS §4.1 — the forged class has `this_class=0`), plus a
  BLA-signature override (`[BLA-NATIVE-SHIELD`→native,
  `BLA_JVM_SHIELD_V1`/`bla-jvm-enclave-v1`→jvm) and a major∈[46,90]
  floor → native **25/25**.

Final adversarial standings: core **29/29**, ASAR **29/29**, ZIP **29/29**,
native **25/25** (incl. fuses 10/10), bunfs **5/5**, BEAM **26/26**,
SQLite **12/13** (1 keep+flag ceiling — BLA provably emits no
user-table-bound objects), DEX **16/19** (3 malformed-input preserved),
JS **13/13**, .NET **12/12**, JVM at documented ceiling, WASM **11/11**,
Python all-syntax-OK (residue only in docstring/indented/user markers —
kept by design), EVM at documented merged-pad ceiling.

### Residual documented limitations

- **APK rebuild normalizes metadata**: original compression method,
  local/central extra fields, comments, EFS flags and the v2 signing
  block are preserved; inter-record alignment gap padding and
  timestamps are regenerated — member *content* is byte-exact,
  container padding is not. Re-signing is a packaging step, not
  analysis (`signingInvalidated` is reported).
- **Seed-matcher fragility**: opaque-seed detection keys on BLA's current
  `X | (typeof D === "function" && D(0) === N ? 1 : 0)` shape. A shape
  change degrades gracefully (predicates stay, no wrong folds).
- **EVM JUMPDEST pad**: `detectEvmPad` runs real reachable-control-flow
  analysis on every post-trailer candidate (the old ≥4 KiB blind fast path
  was deleting *reachable* JUMPDESTs). Unreachable pads are cut at any
  size; a pad containing reachable jump targets gets a **reachable-prefix
  split** — every byte through the last reachable target is provably owned
  and kept, the dead tail after it is dropped (`reachablePrefixKept` /
  `deadTailDropped` / `partialCut` reported). Dynamic-destination jumps
  veto entirely. Residual: owned dead bytes past the last reachable
  target are information-destroyed (fixture loses ≤6B); a dangling dest
  pointing into BLA pad keeps ≤its-prefix of dead bytes (`4h`: 4B).
- **PCAP residue**: `triagePcapTail` replaces the wholesale drop —
  marker-free bytes and complete record envelopes inside an unwalkable
  tail are now salvaged; only marker bytes and their containing record
  envelopes are dropped.
- **SQLite stealth objects**: kept and flagged as before, now scored —
  `scoreSqliteObjects` assigns per-object suspicion (canonical names,
  marker DDL, row bait, random suffixes, dangling refs, zero-purpose DDL)
  and caps recommendations on user-bound objects.
- **BEAM lone mid-form decoy**: kept (index-safety), now scored —
  `beamLoneDecoyScore` reports `drop|flag|keep` from exact payload shape,
  index consistency, position and group membership.
- **ZIP corrupt members**: `salvageZipMember` attempts stored/raw-deflate/
  zlib/brotli/prefix-capable decode, marker splicing and
  prefix-to-first-error — a member that can only be partially decoded now
  yields its recovered prefix instead of raw poisoned bytes.
- **DEX malformed inputs**: `repairDex` repairs file_size/SHA-1/Adler32 and
  dangling map offsets *when structural validation passes* — never
  fabricates missing structures.
- **Opaque-seed variants**: `detectOpaqueSeedVariants` AST-scans for
  changed predicate shapes (different `|(...?1:0)` forms, tampered corpus
  decls) so a drifted BLA emits `opaqueSeedVariantCandidates` instead of
  silently passing hardened code through.
- **Python residue**: `neutralizePyLiteralMarkers` now covers comments as
  well as literals/docstrings/f-string holes — same-length `_` replacement
  kills marker text in any kept position. Double-hardened input also gets
  a guarded orphan-machinery sweep: a second injected region whose
  boundary was consumed by the outer splice leaves snake+hex defs and
  `SCREAMING` consts behind — swept only when the body/docstring carries
  BLA armor vocabulary (`QUORUM_PROTOCOL_DESCRIPTOR`, `enclave_build_id`,
  `SGX_SEALED`, …), never user code on name shape alone.
- **JS machinery-name collisions**: `recoverJsNames` never renames
  `machinery`-style names (`scc_*`, `obligationFlood_*`, …) — a decl that
  survived dehardening under one is real code, and renaming a kept decoy
  would hide its identity. Fixes the two FALSE-STRIP fixtures
  (`obligationFlood_threshold`, `scc_realHelper_c1n1`) → JS **14/14**.

### Round 6 — best-degree recovery for every remaining ceiling

Four recovery modules (`src/recovery/`) were built by parallel implementer
subagents and wired into the pipeline; each targets a previously
partial/impossible item:

| module | recovery | wired at |
|---|---|---|
| `canonical.mjs` | `recoverFuseDefaults` (canonical fuse restore), `reconstructSourceMap` (valid v3 map + `x_blade_note`), `emitRuntimeCounterShield` (Frida/CDP/TEE artifacts), `scoreStructuralAnomaly` (signature-free anomaly detection) | `scrubNative`, CLI map+report paths |
| `name-recovery.mjs` | `recoverJsNames` (hint/init/usage/role evidence renames), `recoverWasmExports` (emits valid `name` section) | `dehardenJs` (all JS callers), `scrubWasm` |
| `precision.mjs` | `pycSurgicalSpans` (preserved-byte %), `neutralizePyLiteralMarkers` (literals+comments), `scoreSqliteObjects`, `beamLoneDecoyScore`, `detectOpaqueSeedVariants` | `scrubPyc`, `scrubPySource`, `scrubSqlite`, `scrubBeam`, `dehardenJs` |
| `salvage.mjs` | `triagePcapTail`, `detectEvmPad` (reachability-vetoed), `salvageZipMember`, `repairDex`, `preserveApkMeta` | `scrubPcap`, `scrubEvm`, ZIP/DEX/APK paths |

Distinguisher discipline kept throughout: exact byte recovery, inferred
reconstruction, canonical restoration, salvage/prefix recovery, keep+flag
and unrecoverable are reported as *different* report fields — nothing
claims byte-provenance it doesn't have.

Python double-hardening closeout: `d1_double` (two nested injected
regions, 647→8 lines) now recovers to a clean `main()` — region splice to
fixpoint + guarded orphan sweep + literal/comment neutralization.

Standings after Round 6: core **29/29**, ASAR **29/29**, ZIP **29/29**,
native **25/25** + fuses **10/10**, bunfs **5/5**, BEAM **26/26**
(in-place atom neutralization closed `fp-B0xy-marker`), SQLite **12/13**
(case 04 scored keep+flag — proven ceiling), DEX **19/19** (16 PASS +
3 malformed-in preserved), **JS 14/14** (was 13/13 + 2 FALSE-STRIP —
machinery-name rename gate), WASM **11/11**, .NET **12/12**, Python all
syntax-OK incl. `d1_double`, EVM reachable-prefix recovery on all merged
pads (4d/4f/4g/4h — reachable code preserved, dead tails dropped),
JVM at documented stale-label/predicted ceilings.

### Round 7 — BLA 3.2.4 coverage (upstream `qybaihe/bla@3.2.2 → 3.2.4` sync)

The vendored BLA was synced to upstream `3.2.4` (14 changed files, 0 new
defense files) and every artifact-affecting change was countered against
**real 3.2.4 outputs generated by the released npm package**:

| 3.2.4 change | counter | result |
|---|---|---|
| PE `.enclave` mapped-section injection (decoy x86-64 islands + MSVC RTTI + RSDS/PDB + Win32 strings; section-add **and** zero-slack plant, both can co-occur) | `peParse` + signature-verified section strip (`nsec`-1, `SizeOfImage` restore, EOF truncate) + signature-gated slack re-zero (`src/trailer.mjs`) | **byte-exact restore** on real fixture (1,166,058 → 1,536 B); legit `.enclave` without decoy payload kept byte-exact (SGX guard); `check-enclave.mjs` 7/7 |
| ASAR main-JS sidecar preamble `(function(){ var __expected="…"; var __blaAsarSidecarDigest=0; … "integrity binding mismatch" })()` | `isAsarSidecarPreamble` — IIFE marker (`__bla\w*SidecarDigest`) or `"integrity binding mismatch"` + `createHash` + `readFileSync` shape → statement strip (`src/js-deharden.mjs`) | cleaned `main.js` byte-identical to 61 B original; `.bla/`+`enclave/` dir residue also dropped from repacked archives |
| Plain-JS + Python sidecar preambles (`__blaSidecarDigest` / `import hashlib as __bla_hashlib … RuntimeError("integrity binding mismatch")`) | same JS IIFE strip (JS variant) + col-0 `__bla_` import/try-block splice gated on marker+literal (`scrubPySource`) | py cleaned byte-identical to original |
| Self-seal single-entry self-digest (`selfSeal:true` w/o siblings → 2 interleaved `measureIntegrity*_<hex>` fns + `var b = (h1()^h2())>>>0`) | `isSelfSealMeasureFn` shape (node:crypto + readFileSync + `integrity check failed`/`/^[0-9a-f]{64}$/` + self-measure cue) → decl + binding removal + injectedNames (`src/js-deharden.mjs`) | `sealFns` removed, `binding` dangling=0 on real fixture |
| Opaque-seed test variants: bare `D(0)===N`, and `[fns].every(_f=>typeof _f==="function") && (D(0)===N)` decoy entanglement; `& 0xfffffffc` fold mask | `findSeedDigestCheck` — extracts the `D(0)===N` comparison from any position of `&&`/`===` trees; `_deriveContainmentCorpusDigest_` name gate unchanged | seed resolves on all three emitted shapes; 3.2.2 outputs still pass |
| `encryptStrings` per-entry keystream (MTP fix) + renamed hints (`resolveBundleSlot`/`catalogFrameTable`/`sessionKeyMask`, no `bla*` names) | shape-detected decode stub (`var e=T[i],k=K,kl,o=new Uint8Array(e.length)` loop + Buffer/TextDecoder/fromCharCode tail), both old `k[j%kl]` and new `kb^ks` derivations; `F(<lit>)` calls decoded to literals, stub decls removed | real-generated stubs decode 2/2 + 3/3 strings correctly |
| `TemplateLiteral` de-literalization (combinatorial chunks + `""+expr` coercion) | existing fold already recovers cooked chunks (verified: `` `tenant:${u.tenant}\|seat:${u.seat}` `` reconstructed) | no change needed |
| Runtime-shield honest labels removed (`decorative-deception-signal` → `attestationState:"RING0_SEALED"`, `AF_VSOCK_RING0`, `HARDWARE_ENCLAVE_DELEGATED`, `protocolVersion:"3.4.0"`) | `RUNTIME_MARKERS` extended with new literals | shadow-vault IIFE still classified injected |
| `_blaS`/`_blaT` dead-marker aliases now self-stripped by BLA | detection is shape-based, never name-based — no dependency | no change needed |
| DEX decoy-classes audit tightening (≥8 `Lcom/enclave/*` + consistent header) | artifact shape unchanged (declared-boundary trailer + reseal) — already bypassed | no change needed |

Additional fixes landed this round:
- **ASAR empty decoy-dir residue** — `enclave/`+`.bla/` dir nodes no longer
  materialize when all children were dropped.
- **HARD_FAMILY leaf decls** — `tokenSink_*`, `fridaRealmRing_*`,
  `_runtimeState*_` tail blobs now classified injected via the same
  `GENERIC_SUFFIX && HARD_FAMILY` conjunction already used for hard naming;
  the 3.2.4 maximum+selfSeal fixture now reduces 111,310 B → 24 clean lines
  (was 59 lines incl. residue).
- **`test-fixtures/adversarial/js/v324/`** — real-3.2.4 regression harness
  (generated via the released npm package): 6/6 PASS.
- `vendor/bla` synced to upstream `3.2.4` (src + npm dist) — all future
  fixture generation targets the current version.

Standings after Round 7: core **29/29**, ASAR **29/29** (+ byte-exact
3.2.4 member recovery), JS **14/14** + v324 **6/6**, native **26/26** +
fuses **10/10** + enclave **7/7**, BEAM **26/26**, ZIP **29/29**, WASM
**11/11**, SQLite **12/13** (proven keep+flag), DEX 16+3 malformed-in,
Python 21 checks incl. byte-exact sidecar-preamble restore, .NET **12/12**,
EVM reachable-prefix on merged pads, JVM at documented predicted-label
ceilings.

### Round 8 — precision + keep-and-flag closeout

Model formats (34-case suite, all PASS/PASS+flag):

- **Armor-value dominance rule**: a marker mention is no longer a death
  sentence — string values drop only when the marker heads the value or
  covers ≥50% of it. Prose like `[BLA 2024] Boundary-Layer Analysis`
  (citation) and `enclave.delegation` protocol mentions now survive in
  both safetensors `__metadata__` and GGUF KVs.
- **Metadata vocab narrowed to BLA's real emissions**
  (`enclave.<delegation|manifest|canary|diagnostic|nesting|topology>.*`
  + `bla.shield.signature`); ambiguous `enclave_*`/`bla.*`/`canary*`
  keys are kept+flagged via `suspiciousMeta`/`suspiciousKeys`.
- **`__metadata__` type confusion**: non-object metadata no longer
  iterated per-char (was: `{"0":"n","1":"o",…}` corruption).
- **GGUF bounds**: unknown scalar/array types abort the KV walk to
  keep+flag instead of desyncing; `kvCount` under-declaration detected
  by plausible-record sniffing; `tensorRegionShort` flags truncated
  tensor_info regions; string-array elements are filtered surgically
  (bait elements rebuilt out, clean elements kept).
- **Deep-structure flagging**: metadata values or tensor-descriptor
  fields beyond REA's 32-frame budget are kept + reported.

JVM (24-case suite, all consistent):

- **In-place neutralization**: decoys that can't be tail-cut (mid-pool
  or followed by real entries) get same-length benign overwrites —
  CP indices and references stay valid; reported as
  `decoyCpEntriesNeutralized`.
- **Tail cut tightened**: requires every entry from anchor to CP end to
  match decoy vocab (fixes the all-Utf8-tail overcut).

SQLite: live `-wal` sidecars are copied, checkpointed, and folded into
the output (journal reset to `DELETE` — self-contained artifact);
verdict `KEEP+FLAG` marks the scorer-vs-survivor ceiling honestly.

Robustness contract: every scrubber is now keep-and-flag on malformed
or wrong-magic input (`270 passed, 0 failed, 0 format-rejections`) —
truncated ASAR/WASM/GGUF headers return bytes untouched with a note
instead of throwing.

### Round 9 — PCAP coverage + CLI/library ergonomics

PCAP:

- **pcapng block walk**: EPB/SPB/PB blocks whose payload hits the decoy
  signature are dropped; markers inside structural blocks (SHB/IDB/
  options) are flagged but kept — the file format requires them.
  Reported as `format:"pcapng"`, `decoyBlocksDropped`, `suspiciousBlocks`.
- **BE nanosecond pcaps** (`0xa1b23c4d` big-endian) were rejected by both
  `detect()` and the scrubber's endianness table — they now route and
  scrub correctly (decoy packets dropped, real packets kept).

CLI:

- `--report -` streams the full untruncated JSON report to stdout —
  composes with stdin input for pure-pipe usage
  (`cat artifact | blade - -o out --report -`).
- `--format <kind>` overrides detection (24 kinds accepted).
- `--dry-run` no longer writes a sqlite artifact — `scrubSqlite` is
  path-based, so dry-run scrubs to a temp file and reports normally.
- Reports now carry `inputSha256` + `inputSize` provenance.

Library/dx:

- `package.json` gains `repository`/`bugs`/`homepage` and a `files`
  whitelist (npm tarball is src+docs only, 166 kB).
- JSDoc across all 50 public exports; the keep+flag/passthrough contract
  is documented at `src/index.mjs`.
- `detect()` BE-nsec routing covered by unit tests (40/40).

## Verification

`node scripts/verify.mjs` — **37 checks, all passing**:
- JS parse + behavioral equivalence (exports, IPC handlers, channel strings,
  store effects) against the plain originals.
- Canonical API names present in cleaned output.
- SQLite business tables/rows intact, decoys gone.
- WASM magic + exact-consumption section walk, exports ≥ 1.
- safetensors header + F32 weights (`1.5`, `-2.25`) intact.
- GGUF magic + KV parseable, zero surviving armor strings.
- ASAR entries = `{package.json, electron-bridge.js}`, per-file SHA-256
  integrity consistent, inner JS marker-free.
- **Byte-exact recovery** for all 16 append-only trailer formats
  (ELF/Mach-O/PE/.NET/DEX/IL2CPP/bplist/EVM/PCAP/UF2/PYC/PTX/py/plist/class/BEAM).
- ZIP/APK member set + per-member content equality vs plain.
- HTML non-script markup identical, both scripts dehardened and
  marker-free.
- Source map passthrough correctly flagged `unrecoverable`.
- Scrubber edge paths: BE-nsec pcap decoy drop, pcapng EPB drop with
  SHB preservation, HTML `on*=`/`javascript:` handler flagging.
- Evaluator: corpus-digest single-char tamper is uniquely repairable;
  untampered input reports no repair.
- CLI edges: stdin requires `-o`, `--report -` streams full JSON,
  `--format` overrides detection.
