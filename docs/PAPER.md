# BLADE: Evidence-Driven De-Hardening of BLA-Protected Artifacts

**Author:** Noah Zixin Zhang
**Built using Devin**
**Target:** `bla-agents` 3.2.4 (`qybaihe/bla`) hardening of artifacts analyzed by REA (`morluto/rea`) and human reverse engineers.

---

## Abstract

BLA ("Bypass-LLM-Agents") hardens software artifacts against LLM-driven
reverse-engineering agents by injecting resource-exhaustion vectors
(token amplification, call-graph labyrinths, oversized ASAR headers),
deceptive payloads (architecture mirages, honey sourcemaps, decoy routes,
canary honeypots, prompt-completion poisoning), and provenance noise
(signed manifests, entangled sidecars) into real build outputs. BLADE is a
format-aware de-hardening pipeline that removes BLA's protections before
analysis, restoring artifacts to byte-exact or semantically-equivalent
form and — where BLA destroyed information — to the best honest degree of
recovery, with every intervention recorded in a per-artifact report.
Against real BLA 3.2.4 output at all four intensities, BLADE passes
370/370 live checks (378/378 with `bla audit`/`bla verify` sub-checks),
is idempotent across all scrubbers (`clean(clean(x)) === clean(x)`),
and in a live A/B through the REA MCP server converts an
18 MB hardened ASAR that crashes the analyzer into an 884 B artifact
that yields a complete `JavaScriptApplicationGraph`.

## 1. Introduction

LLM-driven reverse-engineering agents (REA and peers) analyze build
artifacts by parsing formats, extracting structure, and reasoning over
evidence under a finite budget. BLA exploits that loop: it rewrites
artifacts so the analyzer spends its budget on decoys, tarpits, and
poisoned evidence instead of real program logic.

The naive countermeasure — deleting anything that "looks like BLA" — is
itself an attack: aggressive deletion destroys real logic and produces
false confidence. BLADE instead treats de-hardening as an
**evidence-preserving restoration problem**: every transformation must be
justified by a concrete BLA emission signature, every byte of real
content must survive, every unrecoverable element must be labeled rather
than hidden, and the pipeline's own output must be a fixed point
(idempotent) so re-cleaning never drifts.

## 2. Threat model and scope

The artifacts are assumed to be in the analyst's lawful possession —
hardened by their author/CI with `bla protect`, `bla defend`, or project
`harden` runs, optionally with flags such as `--self-seal`,
`--weave-decoys`, `--llm-directives`, `--sidecar-entangle`,
`--sign-manifest`, `--wasm-preserve-exports`, and custom `--seed`s.
BLA is treated as opaque at the artifact level but inspectable at the
emission level: we catalog exactly what bytes, members, and syntax shapes
each emitter writes, and we counter precisely those.

Non-goals: defeating protections other than BLA's, bypassing code
signing/licensing for unauthorized use, or claiming recovery of
information BLA provably destroyed (names, original mappings).

## 3. BLA defense taxonomy (3.2.4)

We group BLA's protections by the analyzer resource they attack.

**Budget exhaustion.** Token amplifiers (BPE-sink dictionaries, long
decoy symbol names), call-graph labyrinths (hundreds of shadow procedures
and SCC cross-references — observed 186 procedures / 632 XRefs in one
`defend` run), ASAR header amplification (≈18 MB header on a sub-KB
payload), CDP shape budget breakers, Frida capture rings
(`{epoch, slots: Array(N).fill(0)}`), regex worker tarpits, WASM
interface exhaustion (decoy `enclave_export_*` name spam).

**Evidence deception.** Architecture mirages (planted `GO_MAGIC`
buildinfo magic), honey sourcemaps (wholesale `.map` replacement pointing
at `enclave://tee-runtime` sources with a fixed canary GUID),
decompiler illusions, crash-trace decoys, IPC de-literalization and decoy
routes (`enclave/shards/ring0-slot-*`, `hardware-tee-bridge.js`),
evidence-contract poisoning, semantic honeypots, cognitive-armor
trigger comments.

**Self-protection.** Self-seal wrappers, encrypted-string tables,
opaque predicates, IPC de-literalization indirection.

**Provenance noise.** `.bla-manifest.json` (schema
`defense-manifest-v1`, optionally Ed25519-signed), `bla-harden-summary.json`
(schema `bla-harden-summary/v2`), entangled sidecar notes, BunFS
snapshots, decoy header files (`.h`/`.rs`/`.go`), decoy archive members
under `assets/bla-shield/`.

**Format payloads.** Per-format shield emitters for ASAR, ZIP/APK,
WASM, JVM `.class`, Python (source and `.pyc`), SQLite, models
(GGUF/safetensors), native ELF/Mach-O/PE, `.NET`, mobile-game metadata
(`global-metadata.dat`), Apple plist (XML + binary), DEX, BEAM, UF2,
EVM bytecode, PTX, PCAP/PCAPNG, HTML, headers, and sourcemaps.

## 4. BLADE architecture

```
input ─► detect (magic, schema markers, provenance routes)
      ─► route: scrub | deharden | tombstone | passthrough
      ─► per-format de-hardening (signature-driven)
      ─► integrity reconstruction (hashes, framing, sealing)
      ─► report (recovered / removed / preserved / unrecoverable)
```

**Detection** (`src/detect.mjs`) dispatches on content, not extension.
Magic bytes identify binary formats; schema markers route BLA provenance
(`defense-manifest-v1`, `bla-harden-summary/vN`, sidecar notes, BunFS
snapshots); filename routes only ambiguous provenance (`.blarc`,
`bla.config.json`). Every file BLA emits is routed to a deliberate
action — nothing falls through to "unknown" silently.

**Three action classes.** *Scrub* removes injected regions and rebuilds
the container with recomputed integrity. *Tombstone* replaces pure
provenance/attestation artifacts with a labeled stub preserving
analyst-useful fields (`runId`, `artifactsRecorded`, `signed`) while
excluding them from the analysis corpus. *Passthrough* copies bytes
verbatim when content is genuine — including the subtle case of a
legitimate file in a BLA-flavored directory, where path alone is never
grounds for deletion.

**Conservatism invariants.**

1. *Signature-first, path-last.* Decoys are dropped only on exact BLA
   emission signatures or whitelisted decoy paths; a real
   `enclave/` SDK directory or `.bla/` config survives.
2. *Deharden, don't delete.* JS members containing both decoys and real
   logic are dehardened in place, not removed.
3. *Integrity is recomputed, never stale.* ASAR SHA256 blocks and block
   hashes, DEX SHA1, and similar seals are regenerated after any edit.
4. *Unknown ⇒ verbatim.* Unparseable input is copied, never corrupted.
5. *Idempotent.* `clean(clean(x)) === clean(x)` over all 81 harness
   cases (SQLite normalized over its four header write-counters, which
   any real write bumps).

## 5. Recovery ceilings — honesty as a feature

BLA sometimes destroys information rather than wrapping it. BLADE
documents these ceilings instead of fabricating:

- **Honey sourcemaps** are replaced wholesale; original mappings are
  unrecoverable. BLADE emits a spec-valid *identity* map over the
  dehardened sibling JS — real `sourcesContent`, line-accurate positions —
  and marks `unrecoverable: true`, `sourceMapRecovery` in the report.
  Genuine maps pass through byte-exact (verified by regression).
- **Mangled WASM export names** and **stacked decoy names at 2×/3×
  hardening** (`ops_*` on `ops_*`) are unrecoverable; code/type/function
  sections remain byte-identical and the report says so.
- **ASAR header schema** gains SHA256 integrity blocks BLA adds; they
  cannot be "un-added" — preserved, documented, members residue-free.
- **SQLite** is rebuilt (VACUUM-class semantics): rows are fully
  preserved, file bytes differ — flagged as a layout-level diff.

## 6. Experimental methodology

Evidence hierarchy: (1) real `bla` CLI output, not synthetic fixtures —
`protect`/`defend`/project `harden` at `stealth`, `balanced`, `maximum`,
`bankrupt`, plus opt-in flags and multiple `--seed`s; (2) double- and
triple-hardening; (3) BLA's own `benchmark` showcase corpus — artifacts
we did not author; (4) BLA's own validators — `bla audit` and
`bla verify` on cleaned output (every defense invariant FAILs on cleaned
output where it passed on hardened); (5) adversarial fixture suites per
format (cut-vs-keep assertions, residue sweeps); (6) the live REA MCP
server as an end-to-end consumer.

**Suite totals:** 25 verification suites in `scripts/verify-all.mjs`
(26 with idempotency), 370/370 live-matrix checks (378/378 with
`--audit`), 270/270 robustness cases with 0 format rejections,
30/30 ASAR adversarial cases, 24 JVM cases, 39 core checks,
81/81 idempotency cases.

## 7. Live REA result

`analyze_javascript_application` (REA MCP) on the same artifact:

| Input | Size | Outcome |
|---|---|---|
| BLA `maximum` ASAR | ≈18 MB | **REA server crashed/disconnected** (budget exhaustion) |
| BLADE-cleaned ASAR | 884 B | Full `JavaScriptApplicationGraph`: `ipc-channel` `notion:clipboard:read-rich`, `context-bridge-api` `notionClipboard` (`readRichBlocks`, `writeRichBlocks`), resolved `electron-main`, `integrity_contradictions: []` |

`recover_javascript_sources` was untestable (Wakaru 1.13.0 unavailable on
the host) — recorded as an environmental limitation, not hidden.

## 8. Limitations

- Hand-woven decoys added by a human agent before hardening are
  source-indistinguishable — BLA's `--require-agent-weave` acknowledges
  the same boundary. Machine-emitted weaves (`--weave-decoys`) are
  recovered byte-exact on Python/`.pyc`.
- BLA evolution: signatures are cataloged per emitter at 3.2.4; new
  emitters need new signatures — the architecture makes each addition a
  localized, testable change.
- Recovery ceilings in §5 are inherent, not engineering debt.
- The counter-shield sidecars are analyst aids, not de-hardening: the
  TEE-stub global sweep is authoritative only for script-carrier bundles
  (module-scoped CJS machinery is invisible to it), and the emitted
  Frida/CDP notes carry documented platform assumptions (64-bit
  `timeval`, ~10 MHz QPF, `remote-debugging` command-line residue).

## 8a. Self-hardening

Because hardened artifacts are attacker-controlled bytes, BLADE treats
its own parsers as an attack surface: archive member paths are sanitized
in both directions (traversal rejected), every binary parser
bounds-checks before reading (truncated ELF/PE/PYC/ASAR produce
controlled reports rather than `RangeError` escapes), integrity
`blockSize` values are validated against runaway loops, input hashes are
computed before any in-place mutation, and unhardened passthrough is
byte-exact. A 270-check robustness suite feeds deliberately malformed
inputs to every parser and requires reports, not crashes.

## 9. Related work

BLA (`qybaihe/bla`, `bla-agents` 3.2.4) is the defense under test.
REA (`morluto/rea`) is the analyzer whose budget and evidence pipeline
BLA attacks and whose MCP server provides our end-to-end ground truth.
BLADE is the de-hardening layer that sits between them.

## 10. Conclusion

De-hardening is tractable when it is treated as restoration rather than
deletion: catalog the defense's emissions, counter them signature-first,
rebuild integrity honestly, label what cannot be recovered, and prove
the result with the defender's own validators and the target analyzer
itself. On real BLA 3.2.4 output across every shipped intensity and
flag, that discipline turns analyzer-crashing artifacts into fully
analyzable ones — byte-exact wherever BLA left the bytes intact, and
honestly labeled wherever it did not.

---

*Corresponding artifact evidence: `REPORT.md` (per-round findings and the
defense matrix), `scripts/verify-all.mjs` (reproducible runner).*
