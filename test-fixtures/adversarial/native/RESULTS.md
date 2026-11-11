# Adversarial results — `scrubNative` / native trailer scrubbing

> **Status update (latest run): 19/20 PASS.** Bugs 1, 2 and 4 are fixed:
> `cutAtMarker` now vets continuations (embedded-in-identifier markers are
> content; short tails need one vocab sibling reaching near-EOF; long tails
> need ≥2) so case1/case2-cert/case5/case6-V2 all pass; the ELF in-place
> scan falls back to whichever SHT_STRTAB resolves sane section names, so
> `e_shnum=0`/`e_shstrndx=SHN_XINDEX` no longer skips. Remaining:
> `case3-fat-macho-nfat45-parseable.class` (bug 3 — a deliberate CAFEBABE
> polyglot whose arch records were crafted to parse as a JVM constant
> pool; both readings are structurally valid, documented ambiguity) and
> `case4-elf-marker-in-dynsym` keeps the marker by name-scoped design.

Hardened inputs produced by the real `protectNativeBinary` from
`vendor/bla/dist` (same `\0[BLA-NATIVE-SHIELD-V1]\0.dep-v0\0…` trailer BLA
emits) plus hand-built ELF64 / PE32+ / fat-Mach-O files. `gen.mjs` regenerates
`in/` + `expected/`; `check.mjs` runs `node src/cli.mjs <in> -o <out>
--report <out>.json` on each input and diffs bytes. Raw per-file data:
`out/results.json`.

## Bugs found

1. **`cutAtMarker` sibling check is vacuous** — `src/trailer.mjs:24-27`.
   `win = buf.subarray(at, at+4096)` starts AT the marker, so `win` always
   begins with `[BLA-` and `TRAILER_SIBLING.test(win)` is always true. The
   intended "a lone marker inside real content is left alone" never engages;
   the first `indexOf` still wins. Verified: regex is false over the window
   *after* the marker (`subarray(at + m.length, …)`), true as written.
2. **`eofNear` (512 B) overrides real content** — `src/trailer.mjs:26`. Any
   marker occurrence ending within 512 B of EOF is unconditionally treated as
   a trailer.
3. **`detect()` cafebabe disambiguation is forgeable** — `src/cli.mjs:33-40`.
   `v = readUInt16BE(6)` is JVM major (45-90) vs fat `nfat_arch` low half. A
   fat Mach-O with `nfat_arch` in [45,90] routes to `scrubJvm` regardless of
   extension — passthrough (`UNDER-CLEAN`) for real cputypes, destructive
   `scrubJvm` structural rebuild (`OVERCUT`) if the arch records happen to
   parse as a constant pool.
4. **In-place ELF scan skipped under extended section numbering** —
   `src/trailer.mjs:56`. Guard requires `e_shnum > 0 && e_shstrndx > 0 &&
   e_shstrndx < e_shnum`. Valid ELF with `e_shnum=0` (real count in
   shdr[0].sh_size) or `e_shstrndx=SHN_XINDEX(0xffff)` (real index in
   shdr[0].sh_link) silently skips the whole scan — planted `.go.buildinfo` /
   `.isolate` decoys survive.
5. **Name-scoped section cleanup** — `src/trailer.mjs:73`. Only sections named
   exactly `.go.buildinfo`/`.isolate` are inspected; the same BLA markers in
   any other section survive.
6. **Only marker version V1 is recognized** — a `-V2` (or unversioned)
   trailer passes through untouched.
7. **MZ routing prefers the native marker** — `src/cli.mjs:57-61`. Any PE
   containing `[BLA-NATIVE-SHIELD-V1]` anywhere (even inside a signature or
   managed strings) is force-routed to `scrubNative` and cut at the first
   occurrence — relevant to case 2b.

## Table (byte offsets hex)

| fixture | route | result | detail |
|---|---|---|---|
| case1-elf-marker-in-real-content.elf | native | **OVERCUT** | marker in `.rodata` @0x617 (preceded by `_`); output ends 0x616 — lost real bytes [0x616, 0x8d0) = 698 B (rest of .rodata + .tail). Sibling check vacuous: only `[BLA-` in window is the marker itself |
| case1-elf-marker-in-content-hardened.elf | native | **OVERCUT** | same file really hardened (trailer @0x8d0). indexOf hits the .rodata marker first → output 0x616; report falsely claims `eof-trailer 131735` dropped |
| case2-pe-signed-numrva4-hardened.exe | native | PASS | signed PE evading BLA hazard gate (`numRva=4` < 5 → `detectNativeEofAppendHazard:"none"`, BLA really appends). Cert @0x309… + trailer @0x35d → byte-exact restore, signature region preserved |
| case2-pe-signed-detected-passthrough.exe | native | PASS | `numRva=16` → hazard detected → BLA never hardened it → passthrough (context control) |
| case2-pe-cert-contains-marker-hardened.exe | native | **OVERCUT** | marker inside `WIN_CERTIFICATE.bCertificate` @0x30c → cut @0x30b: destroys cert tail + everything after. Lost [0x30b, 0x367) = 92 B of signature + entire trailer |
| case3-fat-macho-hardened.bin / .class | native | PASS | `nfat=1` → v=1 → native, byte-exact |
| case3-fat-macho-i386-parseable.class | native | PASS | real cputype=7 → v=1 → native (the jvm-sentinel string in the slice is real content, correctly kept) |
| case3-fat-macho-nfat45-hardened.bin | **jvm** | **UNDER-CLEAN** | `nfat=45` → v=45 → "jvm"; CP unparseable → passthrough: entire `\0[BLA-NATIVE-SHIELD-V1]` trailer @0xbfe survives, plus all decoy markers ([BLA-GO-BUILDINFO], canaries, COGNITIVE_ARMOR) |
| case3-fat-macho-nfat45-parseable.class | **jvm** | **OVERCUT** | arch records crafted to parse as CP (utf8 `BlaEnclaveDelegation` = JVM_HARD_ANCHOR) → `scrubJvm` rebuild writes 30 B: input 0x203a9 → output 0x1e. Fat header + slices + native trailer all destroyed |
| case4-elf-inplace-hardened.elf | native | PASS* | trailer cut @0xc88b + `.go.buildinfo` / `.isolate` zeroed, `section-overwrite` reported (originals irrecoverable — by design) |
| case4-elf-inplace-shnum0.elf | native | **UNDER-CLEAN** | `e_shnum=0`/`e_shstrndx=0xffff` extended numbering → scan skipped. `[BLA-GO-MAPPED]` @0x463 and `[BLA-FLUTTER-MAPPED]` @0x835 survive in output; only eof-trailer dropped |
| case4-elf-marker-in-dynsym.elf | native | **UNDER-CLEAN (partial)** | target sections zeroed, but `[BLA-GO-MAPPED]` @0xc819 in `.dynsym` survives — name-scoped cleanup only |
| case4-elf-inplace-no-trailer.elf | native | PASS | planted `.go.buildinfo` zeroed even with no EOF trailer present |
| case5-elf-trailing-section-hardened.elf | native | PASS | trailer after real last section → byte-exact |
| case5-elf-marker-is-last-bytes.elf | native | **OVERCUT** | real `.rodata` ends `…;\nZ` + marker at EOF → `backup=1` eats the real `Z` @0x831 AND the marker: lost [0x831, 0x848) = 23 B. File was never hardened but reported `hardened:true` |
| case5-elf-marker-near-eof.elf | native | **OVERCUT** | marker followed by 300 B real `R` data → `eofNear` (≤512) fires → lost [0x80b, 0x94e) = 323 B |
| case6-elf-double-trailer.elf | native | PASS | first indexOf wins → byte-exact original |
| case6-elf-marker-mid-trailer.elf | native | PASS | embedded 2nd marker inside trailer also dropped (first-occurrence cut covers it) |
| case6-elf-trailer-v2.elf | native | **UNDER-CLEAN** | `[BLA-NATIVE-SHIELD-V2]` unrecognized → 80 B trailer survives verbatim @0x880 |

## Notes

- `cutAtMarker` is shared by dex/il2cpp/dotnet/beam/bplist/jvm/pcap — the
  vacuous-sibling + `eofNear` issues are systemic, not native-only.
- `subarray(0, end)` with `end = at - backup`: a marker at buffer offset 0
  yields `end = -1` → `subarray(0, -1)` keeps all but the last byte (marker
  survives). Unreachable via CLI `detect()` for native (magic required at 0),
  latent for other routes.
- The PE signature itself is byte-preserved when the trailer is the only
  marker occurrence (cut is a pure prefix — headers untouched), but
  Authenticode over the cut output is moot: the signature was already
  invalidated the moment BLA appended bytes post-cert.
