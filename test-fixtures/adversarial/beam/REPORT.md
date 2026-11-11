# Adversarial report — `scrubBeam` (`src/trailer.mjs:325-442`)

Harness: `run.mjs` (rebuilds every `.beam` here, runs scrubBeam in-process,
re-parses output, scans atom-index refs). Raw per-chunk dump: `full-log.txt`.

Tested against the CURRENT code, which drops a chunk only when
`nameDecoy && payloadDecoy` (trailer.mjs:341-349): name must match
`^Bla\d$|^Bl[0-9a-z]{2}$|^B[0-9a-z]{3}$` AND payload must contain
`[BLA-BEAM-SHIELD]` or `BLA_BEAM_CANARY=`. Atom trim (line 402) cuts the
table at the first `bla_beam_canary` / `[BLA-BEAM-SHIELD]` / `bla_tarpit_atom_*`
atom and **never renumbers atom-index references** in Code/ExpT/ImpT/LocT/Line.

## Case → verdict

### 1. Legit chunk names matching the patterns
| case | verdict | offsets |
|---|---|---|
| fp-B0xy (legit `B0xy`, no marker) | PASS — kept | chunk @0x48 survives |
| fp-boundary-names (`B0xy Bzzz Bl00 Bla9 Blx0` + controls `B1A2 BLA9 B_xy b0xy`) | PASS — all kept | @0x1c..0xcc; uppercase/underscore/lowercase-b controls correctly untouched |
| fp-Blah (`Blah`) | PASS — kept | @0x1c |
| **fp-B0xy-marker** (`B0xy` quoting `BLA_BEAM_CANARY=`, `Bdoc` quoting `[BLA-BEAM-SHIELD]`) | **FALSE-DROP** | `B0xy` @0x1c and `Bdoc` @0x5c dropped — name+substring coincidence still kills real chunks; `payloadDecoy` is an `includes()` scan, not a prefix/whole-payload check |
| pass-decoy-real (`Bla0 Bla1 Bl0a B100` + markers) | PASS | all 4 dropped @0x3c..0xf0 |
| **evasion-marker-wrong-name** (`Dcoy`,`Xyz9` carrying full BLA payloads) | **EVASION** | both survive @0x1c,0x58 — marker text never inspected when the name doesn't match; `hardened:false` returned with `[BLA-BEAM-SHIELD]` intact |

### 2. Canary-named atoms / atom-index references
Atoms containing `enclave`/`canary`/`BLA` as *substrings* are safe — the match
list is exact-name or `^bla_tarpit_atom_` prefix only (line 402).

| case | verdict | offsets |
|---|---|---|
| enclave-atoms (`enclave_attest, enclave.unseal, BLA_session_key, canary_probe, …`) | PASS — untouched | all 6 atoms @0x19..0x60 survive |
| **stale-mid-canary** (`bla_beam_canary` at index 3 of 5) | **STALE-REF** | table cut to 2 atoms; dangling: Code operand @0x42 (atom 4), @0x47 (atom 5); ExpT[0] @0x58→4, ExpT[1] @0x64→5; LocT[0] @0x7c→5; ImpT fun-atom @0x98→4; Line fname @0xbd→5 |
| **stale-tarpit-prefix** (legit `bla_tarpit_atom_stats` at index 3) | **STALE-REF** | Code @0x42→4; ExpT @0x50→4, @0x5c→5 |
| **tail-after-canary** (real BLA tail + one legit atom after it) | **STALE-REF** | `late_real_atom` (idx 5) dropped; Code @0x3d→5, ExpT @0x4c→5 |
| pass-append-only (BLA-intended: canaries at END) | PASS | atoms 1-3 keep indexes; refs @0x45/0x46/0x49/0x58/0x64 all resolve |
| **stale-second-atu8** (2nd AtU8, canary mid-table) | **STALE-REF** | 2nd table cut 4→1; LocT[0] @0x58→3 dangling |
| **stale-index0** (canary at index 1) | **STALE-REF** | table emptied to count=0; Code @0x35→2,@0x36→3; ExpT @0x44→2 all dangling |
| two-atu8-both-trim | PASS + report bug | `atomsDropped`=3 reported, actual 4 (1+3): `atomsDropped` is overwritten per table (line 405), not accumulated |

**Confirmed real bug:** scrubBeam never renumbers atom references. It is only
correct when BLA's appended atoms sit at the very tail (append-only trim
preserves indexes 1..cutAt). Any earlier match point — legit atom named
`bla_beam_canary`/`bla_tarpit_atom_*`, or a real atom after a canary tail —
truncates mid-table and leaves Code/ExpT/ImpT/LocT/Line pointing past the new
table size. The match should verify the tail-run is *all* canaries (or cut at
the last non-canary+1), or renumber references.

### 3. Padding / alignment
| case | verdict | offsets |
|---|---|---|
| pad-sizes (payloads 1..7 B, decoy size 54) | PASS | pads recomputed @0x1c..0x7c; FOR1 size correct |
| oversize-tail (last chunk declares 64 B, only 16 present) | FALSE-DROP (malformed input) | `Tail` @0x5c: walk breaks at `at+8+size>formEnd` (line 335); the 16 real payload bytes @0x64 vanish once `Bla0` @0x1c triggers rebuild |
| **evasion-misaligned** (5 B chunk written without pad) | **EVASION** | walk leaves `Xyz1` @0x1c stepping 8+5+pad(3)→0x2c, inside `Bla7`'s header @0x29 → reads size 861618764 → break; `Bla7` decoy @0x29 + `StrT` @0x61 never parsed → `hardened:false`, marker survives |

### 4. Atom vs AtU8 / latin1
(BLA only injects into `AtU8`; `Atom` latin1 trim is reachable only when a
classic table already holds a canary-named atom — collision or other tooling.)

| case | verdict | offsets |
|---|---|---|
| atom-classic-tail (Atom, ASCII) | PASS | tail cut in chunk @0x0c; atoms 1-2 @0x19/0x1b kept, indexes preserved |
| **atom-latin1-nonascii** (`caf\xE9`, `r\xE9sum\xE9`) | **FALSE-DROP (corruption)** | atoms re-encoded UTF-8 not latin1: `café`@0x1b → `caf U+FFFD`, `résumé`@0x22 → `r U+FFFD sum U+FFFD` — real atoms destroyed (also misleads anything matching by name) |
| **atom-latin1-overlong** (200×0xE9) | **FALSE-DROP (corruption)** | atom[2]@0x1b inflates 200→600 bytes; length byte wraps 600&0xFF=88 while 600 bytes follow → internally inconsistent table (size=607 emitted for 2 atoms) |
| **atu8-compact-mid** (OTP28 compact, tarpit atom mid-table) | **STALE-REF** | cut to 2; Code @0x3e→4; ExpT @0x4c→4, @0x58→5 |
| atu8-compact-tail | PASS | compact round-trips (re-encoded `0x18` 2-byte len vs BLA's `0x38` — both valid) |

### 5. FOR1 form length
| case | verdict | offsets |
|---|---|---|
| for1-recompute (70 decoy chunks + 4 canary atoms) | PASS | FOR1 size field == file-8 after rebuild; 70 decoys @0xa0..0x12f4 all dropped |
| for1-tail-garbage (real trailer appended after IFF form) | FALSE-DROP | 47 trailer bytes past formEnd silently discarded on rebuild (rebuild only emits parsed chunks) |
| for1-declared-long (formSize > file) | PASS | clipped at buf.length, size recomputed correctly |
| evasion-trunc-table (AtU8 declares 8, has 4; canary inside) | EVASION | table `ok=false` → kept verbatim → `bla_beam_canary` @0x1d survives; `hardened:false` |

## Intended-path control
`test-fixtures/hardened/core.beam` (real BLA output, 258 decoy chunks + 4157
canary atoms) → scrub → **byte-identical** to `test-fixtures/plain/core.beam`
(80 B). FOR1 size, pads, and append-only atom trim all correct for the
designed case; FOR1 recompute is right (no SIZE-FIELD-WRONG anywhere).

## Bugs found
1. **STALE-REF (real, high impact):** atom trim cuts at first canary-name match
   without checking the rest of the table is all-canary and without renumbering
   atom-index references in Code/ExpT/ImpT/LocT/Line. Any legit atom named
   `bla_beam_canary`, `[BLA-BEAM-SHIELD]`, or `bla_tarpit_atom_*` — or any real
   atom sitting after the canary run — mass-drops real atoms and leaves every
   reference > newCount dangling. trailer.mjs:402-421.
2. **Latin1 `Atom` corruption:** trimmed tables are always re-encoded UTF-8
   (line 410) even for the latin1 `Atom` chunk → non-ASCII atoms become U+FFFD
   bytes; >255-byte UTF-8 results wrap the 1-byte length field (line 417).
   Decode (line 396) should be latin1 for `Atom`, re-encode latin1.
3. **Name-gated payload check:** markers are only checked when the chunk name
   matches the BLA patterns → renamed/misnamed decoys (or a malformed size
   desyncing the walk) evade entirely. Conversely `includes()` over the whole
   payload still drops legit chunks that merely quote the marker.
4. **`atomsDropped` underreport:** overwritten per table (line 405), not `+=`.
5. **Silent tail loss:** bytes after `formEnd` and chunks past a failed
   size-check are dropped whenever a rebuild happens, with no report field.
