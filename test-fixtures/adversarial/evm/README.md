# Adversarial fixtures for `scrubEvm` (src/trailer.mjs)

Regenerate inputs and re-run the harness:

```bash
node test-fixtures/adversarial/evm/run.mjs
```

BLA trailer shape (vendor/bla `evm-bytecode.ts`): contract bytes, then an
optional 0x5b JUMPDEST pad run (64 KiB at `maximum`, ~4 MiB at `bankrupt`,
none at `balanced`), then a Solidity-shaped CBOR map carrying `bla` /
`bla_evm_canary` keys plus canary records, then a u16be length suffix.

Current `scrubEvm` semantics (trailer.mjs:121-153):

- One terminal-CBOR pass: `u16be(len-2)` -> `off`; cut iff `buf[off]>>5===5`
  (CBOR map major type) AND the region contains `[BLA-EVM-SHIELD]` /
  `bla_evm_canary` / `PROTECTED_CANARY` as UTF-8 text. Region is NOT
  validated as well-formed CBOR; marker may sit anywhere inside it.
- JUMPDEST pad-strip: counts the contiguous 0x5b run at the new EOF and
  strips it **only when a marker was cut AND the run is >= 4096 bytes**
  (`padStripped = dropped > 0 && pad >= 4096`). Runs < 4096 are preserved
  and reported via `jumpdestTailPreserved`. NOTE: this threshold was added
  mid-testing; an earlier version stripped any run when `dropped > 0`.

## Cases

| Fixture | Construction | Result |
| --- | --- | --- |
| case-1a | real code + unreachable 0x5b run, no metadata, no BLA | PASS — passthrough; no marker => never cut |
| case-1b | tail parses as CBOR-map frame (0xa1 + len) but no marker | PASS — passthrough; marker text is the gate |
| case-1c | real solc auxdata only, no BLA | PASS — passthrough |
| case-2a | solc auxdata (len 0x0033) + real BLA trailer after it | PASS — byte-exact; auxdata preserved |
| case-2b | legacy auxdata len 0x005B (a3 ipfs+bzzr0+solc) + BLA trailer | PASS — the 0x5b low length byte at 0x9D is preserved by the <4KiB rule (pre-threshold code ate it: REAL-AUXDATA-LOST) |
| case-3a | marker strings inside PUSH32 immediate, real auxdata terminal | PASS — mid-file markers ignored (no indexOf scan) |
| case-3b | marker inside PUSH32 + EOF len collides with 0xa0 inside immediate | PUSH-DATA-CUT — severs PUSH32 at 0x41, cuts 42 B from 0x42 |
| case-4a | 96 B 0x5b pad, no CBOR | PASS — passthrough (stealth pad survives, legit pad never cut) |
| case-4b | 96 B 0x5b pad + well-formed markerless CBOR | LEFTOVER-PADDING — hardened:false, trailer fully survives |
| case-4c | BLA maximum pad on contract ending 0x33 | PASS — byte-exact boundary |
| case-4d | contract's own 10x 0x5b merged w/ BLA's 64 KiB pad | REAL-BYTES-CUT — merged run 65546 >= 4096 stripped incl. 10 real bytes at 0x41–0x4A |
| case-4e | contract's own 10x 0x5b + BLA balanced (zero BLA pad) | PASS — run 10 < 4096 preserved (pre-threshold code ate it) |
| case-4f | own 10x 0x5b + handcrafted BLA pad 4000 (merged 4010) | LEFTOVER-PADDING — whole run < 4096 preserved; 4000 BLA pad bytes survive |
| case-4g | own 10x 0x5b + handcrafted BLA pad 4086 (merged 4096) | REAL-BYTES-CUT — threshold cliff: run exactly 4096 stripped incl. own 10 bytes at 0x41–0x4A |
| case-4h | no own 0x5b tail + handcrafted BLA pad exactly 4096 | PASS — byte-exact |
| case-5a | two consecutive BLA CBOR trailers | LEFTOVER-TRAILER — single pass cuts only the outer one at 0x93; inner 82 B trailer (0x41–0x92) survives; a second scrubEvm run removes it |
| case-5b | BLA CBOR, then real solc auxdata at EOF | LEFTOVER-TRAILER — non-BLA terminal CBOR at 0x93–0xC7 masks BLA trailer at 0x41–0x92; hardened:false, markers survive |
| case-6a/6b | real protect() output vs plain (balanced / maximum) | PASS — byte-exact |
