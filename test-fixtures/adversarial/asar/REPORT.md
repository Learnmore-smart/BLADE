# Adversarial test report — `scrubAsar` (`src/formats.mjs:14-106`)

Harness: `build.mjs` (crafts fixtures + `.manifest.json` expectations into `built/`),
`run.mjs` (independent pickle reader, byte-compares real entries, recomputes
integrity, diffs JS top-level names). Output: `results.json`, `run-output.txt`.

**Environment note:** `src/formats.mjs` currently does **not parse** — duplicate
`readU32Leb`/`writeU32Leb` declarations (lines 128-143 alongside 113-127) in the
WASM section, introduced by a concurrent edit. ASAR section (lines 1-106) is
unaffected; it was tested verbatim via extraction (`.scrubAsar-under-test.mjs`).

## Verdict table

| Case | Fixture | Verdict |
|---|---|---|
| control | t0-plain.asar | PASS |
| 1. real enclave/.bla dirs | t1-real-enclave-dirs.asar | **REAL-ENTRY-DROPPED** |
| 2. links/unpacked/integrity | t2-links-unpacked-integrity.asar | **INTEGRITY-BROKEN** |
| 3a. 50KB real JS, no markers | t3a-clean-big.asar | PASS |
| 3b. markers in comment only | t3b-marker-comment.asar | **OVER-CLEAN-JS** |
| 3c. real fns w/ BLA-strong names | t3c-real-strongnames.asar | **OVER-CLEAN-JS** |
| 3d. marker comment + generic-suffix tail | t3d-generic-tail.asar | **OVER-CLEAN-JS** |
| 3e. markers in .mts/.cts/.js | t3e-ext-gap.asar | PASS (extension gap warned) |
| 4. BLA markers in entry names | t4-markers-in-names.asar | **REAL-ENTRY-DROPPED** (exact-name files) |
| 5a-j,l pickle edges | t5a..t5l | PASS except below |
| 5d. firstU32=8 | t5d-firstu32-8.asar | PARSE-FAIL (fail closed) |
| 5e2. jsonLen overrun into NUL pad | t5e2-jsonlen-nulpad.asar | PARSE-FAIL (fail closed) |
| 5k. `"size":"64"` string | t5k-size-string.asar | **INTEGRITY-BROKEN** |
| 6a. `__proto__/` dir | t6a-proto-dir.asar | **PARSE-FAIL (crash/DoS)** |
| 6b. `__proto__` file | t6b-proto-file.asar | **REAL-ENTRY-DROPPED** (+dead bytes) |
| 6c. `constructor/` dir | t6c-ctor-dir.asar | **PARSE-FAIL (crash/DoS)** |
| 6d. `toString/` dir | t6d-tostring-dir.asar | **PARSE-FAIL (crash/DoS)** |
| 7. structural oddities | t7-struct-oddities.asar | **INTEGRITY-BROKEN** (malformed node emitted) |
| baseline plain | test-fixtures/plain/app.asar | PASS |
| baseline real BLA 18MB | test-fixtures/hardened/app.asar | PASS (4001 decoys dropped, 393 ms) |

## Findings

### F1 — REAL-ENTRY-DROPPED: namespace filter hits real apps (`isDecoyAsarPath`, formats.mjs:22-25)
Filter drops every entry whose **top segment** is exactly `enclave`, `.bla`, or
`.enclave`, applied at the leaf level after dir recursion. A real app shipping
`enclave/sdk/`, `.enclave/eif-manifest.json` (Nitro-enclave configs), `.bla/` tool
dirs, or top-level **files** literally named `enclave`/`.bla`/`.enclave` loses
them silently — counted as `decoyEntriesDropped` with no distinction. Case t1: 5
real files + 2 real empty dirs lost. `.enclave` isn't even documented in the
comment (only `enclave/`+`.bla/`).

Also: **empty real dirs are never preserved** — repack materializes dirs only on
kept-file path segments (formats.mjs:46-49), so `logs/`, `cache/empty/` vanish.

Near-misses correctly survive: `enclave.md`, `enclaves/`, `Enclave/`,
`lib/enclave/`, `vendor/.bla/`, `enclave-sdk/`, all T4 marker-in-name paths.
The same strictness is an **evasion gap**: case-sensitive, top-level-only —
BLA could relocate decoys to `Enclave/` or `x/enclave/` and they would sail
through untouched.

### F2 — INTEGRITY-BROKEN: `unpacked` entries repacked with stolen bytes (formats.mjs:36-37,63-64)
`unpacked:true` entries carry no `offset`; their bytes live in the companion
`<name>.asar.unpacked/` dir. The walk reads `raw.subarray(dataOffset+offset,
+size)` anyway → every unpacked file is repacked **containing other entries'
bytes** (`adder.node` got `package.json`+blobs; `lib.node` with offset 80 stole
from `blob1`). Then `unpacked` is dropped from the output node and `integrity`
is **recomputed over the stolen bytes** — self-consistent integrity over wrong
content, the worst kind: downstream integrity checks pass on garbage.
`executable:true` is preserved (good). The scrubber has no `.asar.unpacked`
companion handling at all — correct behavior would be dropping the entry,
keeping `unpacked:true` + real integrity, or extracting from the sidecar dir.

Packed entry missing `offset` (`noof.bin`) → `offset ?? 0` → steals `data[0..size]`.

Links pass through verbatim (good) — including stale `size`/`offset` fields when
present (warn only).

Integrity shapes: old bare-hex-string and `{algorithm,hash}` (no blocks) inputs
are upgraded to the full object form (fine); `SHA512` is forcibly rewritten to
`SHA256` while keeping its `blockSize` (consistent but lossy); `integrity:null`
→ none emitted. Zero-size files kept.

### F3 — OVER-CLEAN-JS: `dehardenJs` strips real code once any marker substring appears
`looksBlaHardened` (js-deharden.mjs:61-63) is a substring regex — a doc-comment
mentioning `_interlockSafetyCorpus_` triggers the whole pipeline on real code.
Observed on a 51 KB real-ish bundle:

- **Pass 0** (`js-deharden.mjs:169-181`): any top-level `void <ident>` statement
  harvests `<ident>` into `injectedNames` — real `void pendingTick;` → the real
  `const pendingTick = setInterval(...)` decl is then removed as injected
  (its setInterval side effect dies).
- **Strong names**: real functions `obligationFlood_payments` (batch job),
  `scc_tarjan_c1n3` (Tarjan SCC), `labyrinthDispatch_router`, `tokenSink_oauth`
  match `STRONG_NAME` and are deleted.
- **`refsOnlyInjected`** (js-deharden.mjs:324-334): a real statement that only
  *calls* an injected name is removed — `if (env) obligationFlood_payments(...)`
  wiring deleted even though `env`/`process` are unbound globals.
- **Suffix region + `GENERIC_SUFFIX_NAME`** (`_hex{3,4}`, js-deharden.mjs:58,364-385):
  after the boundary, every top-level decl whose names all end `_XXXX` dies —
  200+ real `sku_lookup_XXXX` helpers and the tail fns `finalizeBatch_0f3c`,
  `auditTrail_99aa`, `cachePrime_2b3c`, `dedupeSkus_4d5e` removed.
- Net: 217→9 names (t3b), 216→9 (t3c), 126→9 (t3d). `module.exports` survives
  but still references removed bindings → **runtime ReferenceError at require**,
  not flagged because those names aren't in `injectedNames` (danglingRefs only
  tracks injected names).

3a control: 50 KB real bundle without markers → byte-identical passthrough. t3e:
`.js` twin cleaned correctly (only injected names removed) — but `.mts`/`.cts`
aren't in the extension regex (formats.mjs:55 `/\.(m?js|cjs|jsx|ts|tsx)$/`) so
hardened payloads under those names pass through fully armed (coverage gap).

### F4 — PARSE-FAIL / proto-pollution: `__proto__`/`constructor`/`toString` names (formats.mjs:48)
`dir.files[s] ??= {files:{}}` resolves through the prototype chain:
- `__proto__/x.js`: `dir.files.__proto__` → `Object.prototype` (truthy, `??=`
  no-op) → `dir = Object.prototype` → `dir.files` undefined →
  `dir.files["x.js"] = entry` throws `TypeError` → **crash (DoS)**.
- `constructor/`/`toString/`/`hasOwnProperty/` dirs: same class — the inherited
  member is truthy, `??=` skips init, traversal crashes on `dir.files`.
- `__proto__` top-level **file**: `dir.files["__proto__"] = entry` invokes the
  `__proto__` setter → sets `newRoot.files`'s prototype instead of an own key →
  entry silently absent from output JSON **while its data bytes are still
  emitted** (dead 31-byte gap in data region — both verdicts apply).

### F5 — INTEGRITY-BROKEN: size as string → concat slice bug (formats.mjs:37)
`raw.subarray(off, off + ent.size)` — with `size:"64"`, `off + "64"` is string
concat (`"20064"`) → `subarray(off, 20064)` clamps to EOF → the entry swallows
all subsequent files' bytes (victim.bin got 128 B instead of 64 B). Offsets are
`Number()`'d correctly, but `size` is never coerced/validated.

### F6 — malformed-node passthrough (formats.mjs:30-38)
- `{files:"x"}`: `Object.entries("x")` → ent `"x"` → `ent.link` hits
  `String.prototype.link` (truthy!) → treated as link → passthrough emits
  `"strdir/0": "x"` — a non-object node in output header (readers choke).
- `{files:null}` → becomes a 0-byte file. `{files:[{...}]}` → phantom child
  `"0"` packed with 5 B of someone else's data.
- `{files:{...}, link:"x"}`: files branch wins; the `link` is silently dropped.
- `offset:"xyz"` → `Number` NaN → `subarray(NaN,…)` → 0-byte file, silent.
  `size:-5` → empty. `size:1e9` past EOF → silently truncated to EOF.

### Pickle framing verdict (case 5+6)
Tolerant where it should be: non-zero pad bytes, extra header padding, trailing
junk, lying `inner` field, space-padded `jsonLen`, aligned jsonLen, duplicated
offsets, data gaps, NaN offsets. Correctly fail-closed on `firstU32!=4` and on
`jsonLen` overrunning into non-whitespace (PARSE-FAIL = throws, no half-output).
Output framing is canonical and verified: `u32@0=4`, `inner=aligned+4`,
`headerSize=inner+4`, contiguous data packing — an independent reader parses
every emitted archive and all `integrity` objects recompute correctly.

### Minor
- `report.headerBytesIn` calls `readAsar(buf)` a second time (formats.mjs:96) —
  redundant re-parse of the input.
- `entriesIn` counts leaf entries only (dirs not counted) — fine, but
  `decoyEntriesDropped` also counts *real* entries caught in the namespaces
  (F1), so reports can't distinguish decoys from collateral.
