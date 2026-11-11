// BLADE recovery — byte-level salvage for the cases the primary scrubbers
// must conservatively skip (see REPORT.md "Residual documented limitations"):
//   * unwalkable pcap tails dropped wholesale when any marker is present
//   * EVM JUMPDEST pads kept unless ≥4 KiB AND a marked trailer was removed
//   * corrupt/un-inflatable zip members raw-preserved WITH marker residue
//   * malformed dexes (bad file_size / stale SHA-1+Adler32 / dangling map)
//   * APK rebuild normalizing per-member alignment padding + timestamps
// Every export is a pure function over Buffers — no I/O, no dispatch.
import { createHash } from "node:crypto";
import { inflateRawSync, inflateSync, brotliDecompressSync } from "node:zlib";

const B = (s) => Buffer.from(s, "latin1");

// ============================================================================
// marker vocabulary (kept in sync with src/formats.mjs + src/trailer.mjs)
// ============================================================================
// PCAP decoy vocabulary — PCAP_DECOY_MARKERS in src/formats.mjs.
const PCAP_MARKERS = [
  "[BLA-PCAP-SHIELD]", "BLA-PCAP-Shield", "enclave.internal",
  "X-BLA-Nested-", "PROTECTED_CANARY_CREDENTIAL=", "/bla/tarpit/",
];
// Zip-member marker vocabulary — every shield marker the callers route on
// (trailer.mjs scrubDex/scrubIl2cpp/scrubJvm/scrubZip + MEMBER_MARKERS).
const MEMBER_MARKER_LITS = [
  "[BLA-DEX-SHIELD-V1]", "[BLA-IL2CPP-SHIELD]", "[BLA-EVM-SHIELD]",
  "[BLA-PCAP-SHIELD]", "[BLA-NATIVE-SHIELD-V1]", "[BLA-NATIVE-SHIELD]",
  "[BLA-JVM-ENCLAVE:", "[BLA-BEAM-SHIELD]", "[BLA-UF2-SHIELD]",
  "[BLA-PTX-SHIELD]", "[BLA-GO-MAPPED]", "[BLA-FLUTTER-MAPPED]",
  "[BLA-GO-BUILDINFO]", "[BLA-FLUTTER-POOL-EXHAUST]",
  "BLA-DEX-XREF-V1", "BlaDexXref.java", "BLA_JVM_SHIELD_V1",
  "BLA_DOTNET_CLR_SHIELD_V1", "BLA_BPLIST_DEPTH_GUARD_",
  "BLA-MODEL-SHIELD", "bla_beam_canary", "BLA_BEAM_CANARY=",
  "PROTECTED_CANARY_CREDENTIAL=", "bla_evm_canary",
];
// Parametric families — same shapes as MEMBER_MARKERS in src/trailer.mjs.
const MEMBER_MARKER_RES = [
  /\[BLA-[A-Z0-9-]*SHIELD[^\]\n]*\]?/g,
  /BLA_[A-Z0-9_]*SHIELD[A-Z0-9_]*/g,
  /BLA-DEX-XREF-V1/g,
  /PROTECTED_CANARY_CREDENTIAL=[^\s]*/g,
];

// Collect [start,end) spans of every marker hit inside `buf` (latin1 view —
// markers are ASCII so byte offsets are exact). Merges overlaps.
function markerSpans(buf, extraRes = []) {
  const s = buf.toString("latin1");
  const spans = [];
  for (const lit of MEMBER_MARKER_LITS) {
    let i = 0;
    for (;;) {
      i = s.indexOf(lit, i);
      if (i < 0) break;
      spans.push([i, i + lit.length]);
      i += lit.length;
    }
  }
  for (const rx of MEMBER_MARKER_RES.concat(extraRes)) {
    for (const m of s.matchAll(rx)) {
      // regex families are unbounded ([^\]\n]*) — a real BLA marker is a
      // short record; a >512 B match is content, never excise it.
      if (m[0].length && m[0].length <= 512) spans.push([m.index, m.index + m[0].length]);
    }
  }
  spans.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const [a, b] of spans) {
    const last = merged[merged.length - 1];
    if (last && a <= last[1]) last[1] = Math.max(last[1], b);
    else merged.push([a, b]);
  }
  return merged;
}
// Remove marker byte runs entirely (excision — markers are injected bytes,
// not content). Returns { buf, removedSpans }.
function stripMarkerRuns(buf) {
  const spans = markerSpans(buf);
  if (!spans.length) return { buf, removedSpans: [] };
  const parts = [];
  let prev = 0;
  for (const [a, b] of spans) {
    if (a > prev) parts.push(buf.subarray(prev, a));
    prev = b;
  }
  if (prev < buf.length) parts.push(buf.subarray(prev));
  return { buf: Buffer.concat(parts), removedSpans: spans };
}

// ============================================================================
// 1) triagePcapTail — byte-triage an unwalkable pcap residue
// ============================================================================
// The scrubber's record walk stops at the first corrupt record; today's
// residue rule drops the whole tail when it contains any marker. Here we
// scan the tail for marker runs and drop only the marker bytes — or their
// whole containing record envelope when a plausible 16-byte record header
// (incl_len covering the marker, orig_len >= incl_len) precedes the marker
// within 64 B. Everything else is kept verbatim.
/**
 * Byte-triage an unwalkable pcap tail: drop only marker runs — or their
 * containing 16-byte record envelope when a plausible header precedes the
 * marker — and keep everything else verbatim. Replaces wholesale tail
 * drops so one corrupt record can't hide real bytes.
 * @param {Buffer} tail
 * @returns {{ kept: Buffer, dropped: Buffer, reason: string }}
 */
export function triagePcapTail(tail) {
  const empty = { kept: tail ?? Buffer.alloc(0), dropped: Buffer.alloc(0), reason: "empty" };
  if (!tail || tail.length === 0) return empty;
  const latin = tail.toString("latin1");
  const hits = [];
  for (const m of PCAP_MARKERS) {
    let i = 0;
    for (;;) {
      i = latin.indexOf(m, i);
      if (i < 0) break;
      hits.push([i, i + m.length]);
      i += m.length;
    }
  }
  if (!hits.length) return { kept: tail, dropped: Buffer.alloc(0), reason: "no-markers" };
  hits.sort((a, b) => a[0] - b[0]);

  const MAX_INCL = 16 * 1024 * 1024; // same bound as scrubPcap
  const drops = [];
  let envelopes = 0, byteRuns = 0;
  for (const [ms, me] of hits) {
    const lastDrop = drops[drops.length - 1];
    if (lastDrop && ms < lastDrop[1]) continue; // already inside a dropped envelope
    // nearest plausible record header within 64 B preceding the marker:
    // header start h in [ms-64, ms-16], marker fully inside [h+16, h+16+incl),
    // envelope COMPLETE within the tail (a truncated record can't be
    // attributed to the marker). The fractional-second field MUST be < 1e9 —
    // a shifted read of a real header produces garbage there (it lands on
    // timestamp or payload bytes), which is the strongest rejection signal
    // short of walking the whole stream. BOTH endiannesses are then scored
    // together: BLA writes orig_len == incl_len (+4) and sane epoch stamps
    // corroborate (+1 each); ties prefer the earliest start (largest
    // envelope = genuine record start), then LE.
    let env = null, envScore = -1, envH = Infinity;
    for (const be of [false, true]) {
      for (let h = Math.max(0, ms - 64); h <= ms - 16; h++) {
        const incl = be ? tail.readUInt32BE(h + 8) : tail.readUInt32LE(h + 8);
        const orig = be ? tail.readUInt32BE(h + 12) : tail.readUInt32LE(h + 12);
        const tsSec = be ? tail.readUInt32BE(h) : tail.readUInt32LE(h);
        const tsFrac = be ? tail.readUInt32BE(h + 4) : tail.readUInt32LE(h + 4);
        if (!(incl > 0 && incl <= MAX_INCL && orig >= incl && tsFrac < 1e9 &&
              h + 16 <= ms && me <= h + 16 + incl && h + 16 + incl <= tail.length)) continue;
        const score = (orig === incl ? 4 : orig > incl ? 2 : 0) +
          (tsFrac > 0 ? 1 : 0) + (tsSec > 0 && tsSec < 0x80000000 ? 1 : 0);
        if (score >= 4 && (score > envScore || (score === envScore && h < envH))) {
          envScore = score; envH = h; env = [h, h + 16 + incl];
        }
      }
    }
    if (env) { drops.push(env); envelopes++; }
    else { drops.push([ms, me]); byteRuns++; }
  }
  // merge overlapping drops, then split kept/dropped
  const merged = [];
  for (const d of drops.sort((a, b) => a[0] - b[0])) {
    const last = merged[merged.length - 1];
    if (last && d[0] <= last[1]) last[1] = Math.max(last[1], d[1]);
    else merged.push([...d]);
  }
  const keptParts = [], droppedParts = [];
  let prev = 0;
  for (const [a, b] of merged) {
    if (a > prev) keptParts.push(tail.subarray(prev, a));
    droppedParts.push(tail.subarray(a, b));
    prev = b;
  }
  if (prev < tail.length) keptParts.push(tail.subarray(prev));
  const reason = envelopes && byteRuns ? "envelopes+marker-bytes"
    : envelopes ? "record-envelopes" : "marker-bytes";
  return { kept: Buffer.concat(keptParts), dropped: Buffer.concat(droppedParts), reason };
}

// ============================================================================
// 2) detectEvmPad — content-based JUMPDEST-pad detection
// ============================================================================
// BLA's real pad shape (vendor/bla evm-bytecode.ts): Buffer.alloc(n, 0x5b) —
// a pure JUMPDEST run between the last legit instruction and the metadata
// trailer. We additionally recognize "structured junk" tails (PUSH0 / PUSHn
// with all-0x00 or all-0x5b immediates). A pad candidate is a ≥16 B trailing
// run of junk instructions anchored at a linear-disassembly boundary.
// Safety: never flag a region containing reachable code. Entry-point
// basic-block reachability is computed by attributing each reachable
// JUMP/JUMPI destination to the PUSH/PUSH0 that produces it (bounded
// stack lookback); a dest edge landing on an in-pad JUMPDEST vetoes the
// cut, as does any reachable jump whose destination can't be resolved
// (ambiguous → confidence 'low', padStart null). A junk run reachable
// only by fallthrough executes no-ops to EOF — flaggable at 'medium'.
const EVM_TERMINATORS = new Map([
  [0x00, "stop"], [0xf3, "return"], [0xfd, "revert"],
  [0xfe, "invalid"], [0xff, "selfdestruct"], [0x56, "jump"],
]);
// EVM stack arity: [pops, pushes] per opcode. Unassigned opcodes default to
// [0,0] — harmless for the bounded producer lookback.
const EVM_ARITY = (() => {
  const t = new Array(256).fill([0, 0]);
  for (let o = 0x01; o <= 0x07; o++) t[o] = [2, 1];
  t[0x08] = t[0x09] = [3, 1];
  t[0x0a] = t[0x0b] = [2, 1];
  for (let o = 0x10; o <= 0x14; o++) t[o] = [2, 1];
  t[0x15] = [1, 1];
  t[0x16] = t[0x17] = t[0x18] = [2, 1];
  t[0x19] = [1, 1];
  t[0x1a] = t[0x1b] = t[0x1c] = t[0x1d] = [2, 1];
  t[0x20] = [2, 1];
  for (let o = 0x30; o <= 0x34; o++) t[o] = [0, 1];
  t[0x35] = [1, 1]; t[0x36] = [0, 1]; t[0x37] = [3, 0];
  t[0x38] = [0, 1]; t[0x39] = [3, 0]; t[0x3a] = [0, 1];
  t[0x3b] = [1, 1]; t[0x3c] = [4, 0]; t[0x3d] = [0, 1];
  t[0x3e] = [3, 0]; t[0x3f] = [1, 1];
  t[0x40] = [1, 1];
  for (let o = 0x41; o <= 0x48; o++) t[o] = [0, 1];
  t[0x50] = [1, 0]; t[0x51] = [1, 1]; t[0x52] = t[0x53] = [2, 0];
  t[0x54] = [1, 1]; t[0x55] = [2, 0]; t[0x56] = [1, 0]; t[0x57] = [2, 0];
  t[0x58] = t[0x59] = t[0x5a] = [0, 1];
  t[0x5f] = [0, 1];
  for (let o = 0x60; o <= 0x7f; o++) t[o] = [0, 1];
  for (let o = 0x80; o <= 0x8f; o++) { const n = o - 0x7f; t[o] = [n, n + 1]; }
  for (let o = 0x90; o <= 0x9f; o++) { const n = o - 0x8f + 1; t[o] = [n, n]; }
  for (let o = 0xa0; o <= 0xa4; o++) t[o] = [o - 0xa0 + 2, 0];
  t[0xf0] = [3, 1]; t[0xf1] = t[0xf2] = [7, 1]; t[0xf3] = [2, 0];
  t[0xf4] = [6, 1]; t[0xf5] = [4, 1]; t[0xfa] = [6, 1];
  t[0xfd] = [2, 0]; t[0xff] = [1, 0];
  return t;
})();
/**
 * Detect decoy padding appended after EVM bytecode's declared end:
 * opcode-walks the declared region, then classifies the tail (unreachable
 * JUMPDEST runs, marker text, entropy drop) before naming a padStart.
 * @param {Buffer} buf @param {number} [declaredEnd]
 * @returns {{ padStart: number|null, confidence: string, evidence: string }}
 */
export function detectEvmPad(buf, declaredEnd = buf.length) {
  const none = (confidence, evidence) => ({ padStart: null, confidence, evidence });
  if (!buf || buf.length === 0) return none("low", "empty-buffer");
  const end = Math.max(0, Math.min(declaredEnd >>> 0 || 0, buf.length));
  if (end < 16) return none("low", "declared region < 16B");

  // Linear disassembly of [0,end): instruction offsets, sizes, PUSH immediates.
  const instrs = []; // {off, op, size, imm, dataOff, dataEnd}
  const idxAt = new Map();
  {
    let i = 0;
    while (i < end) {
      const op = buf[i];
      idxAt.set(i, instrs.length);
      if (op >= 0x60 && op <= 0x7f) {
        const n = op - 0x5f;
        const dataOff = i + 1, dataEnd = Math.min(end, i + 1 + n);
        let imm = null;
        if (n <= 6 && dataEnd - dataOff === n) {
          imm = 0;
          for (let k = dataOff; k < dataEnd; k++) imm = imm * 256 + buf[k];
        }
        instrs.push({ off: i, op, size: 1 + n, imm, dataOff, dataEnd });
        i += 1 + n;
      } else {
        instrs.push({ off: i, op, size: 1, imm: null });
        i += 1;
      }
    }
  }

  // Junk instruction: JUMPDEST, PUSH0, or PUSHn whose immediate is all-0x00
  // or all-0x5b (pad-flavored structured pushes — strict so a real constant
  // is never eaten).
  const isJunk = (it) => {
    if (it.op === 0x5b || it.op === 0x5f) return true;
    if (it.op >= 0x60 && it.op <= 0x7f && it.dataEnd - it.dataOff === it.size - 1) {
      let z = true, j = true;
      for (let k = it.dataOff; k < it.dataEnd; k++) {
        if (buf[k] !== 0x00) z = false;
        if (buf[k] !== 0x5b) j = false;
      }
      return z || j;
    }
    return false;
  };

  // Longest trailing run of junk instructions ending exactly at `end`.
  let runIdx = instrs.length;
  while (runIdx > 0 && isJunk(instrs[runIdx - 1])) runIdx--;
  const runBytes = runIdx < instrs.length ? end - instrs[runIdx].off : 0;
  if (runBytes < 16) return none("low", `no junk tail >=16B (trailing run ${runBytes}B)`);
  const padStart = instrs[runIdx].off;
  if (padStart === 0) return none("low", "no legit instruction precedes the pad");

  let pure = true;
  for (let k = padStart; k < end; k++) if (buf[k] !== 0x5b) { pure = false; break; }

  // Jump-dest attribution: for each JUMP/JUMPI, walk back over pushes/pops
  // to find the instruction producing the top-of-stack destination. Only a
  // PUSH/PUSH0 producer yields a constant target; anything else is dynamic.
  const DYNAMIC = -1, HUGE = -2; // HUGE: constant but provably > any offset
  const jumpDest = (k) => {
    let need = 1; // item we track sits `need` deep from the stack top
    for (let j = k - 1; j >= 0; j--) {
      const it = instrs[j];
      const [pops, pushes] = EVM_ARITY[it.op];
      if (need <= pushes) {
        if (it.op === 0x5f) return 0;
        if (it.op >= 0x60 && it.op <= 0x7f) {
          if (it.imm !== null) return it.imm;
          // wide PUSH: value is a constant; check if it can be < end
          let v = 0, hi = false;
          for (let b = it.dataOff; b < it.dataEnd; b++) {
            const by = buf[b];
            if (b < it.dataEnd - 6) { if (by !== 0) hi = true; }
            else v = v * 256 + by;
          }
          return hi ? HUGE : v;
        }
        return DYNAMIC;
      }
      need = need - pushes + pops;
      if (need > 24) return DYNAMIC;
    }
    return DYNAMIC;
  };

  // Basic-block reachability from entry: propagate over fallthrough edges
  // and PUSH-resolved jump destinations. A jump DEST edge landing inside
  // the pad is reachable code — veto. A pad reachable only by fallthrough
  // still executes nothing but junk no-ops (halts at EOF either way) —
  // flaggable at reduced confidence. A reachable jump with a dynamic
  // destination makes reachability unprovable (ambiguous → low/null).
  const reach = new Set([0]);
  const reachDest = new Set(); // instructions reached via a jump-dest edge
  let dynamicJump = false;
  {
    const queue = [0];
    const add = (idx, viaDest) => {
      if (idx >= instrs.length) return;
      if (viaDest) reachDest.add(idx);
      if (!reach.has(idx)) { reach.add(idx); queue.push(idx); }
    };
    while (queue.length) {
      const i = queue.pop();
      const it = instrs[i];
      if (!it) continue;
      const op = it.op;
      if (op === 0x56) { // JUMP: dest-only edge, no fallthrough
        const d = jumpDest(i);
        if (d === DYNAMIC) dynamicJump = true;
        else if (d >= 0 && idxAt.has(d) && buf[d] === 0x5b) add(idxAt.get(d), true);
        continue;
      }
      if (EVM_TERMINATORS.has(op)) continue; // halting ops end the block
      if (op === 0x57) { // JUMPI: dest edge + fallthrough edge
        const d = jumpDest(i);
        if (d === DYNAMIC) dynamicJump = true;
        else if (d >= 0 && idxAt.has(d) && buf[d] === 0x5b) add(idxAt.get(d), true);
      }
      add(i + 1, false); // fallthrough
    }
  }
  let destTargetsInPad = 0, fallthroughInPad = 0, inPadTargets = [];
  for (const i of reach) {
    if (!instrs[i] || instrs[i].off < padStart) continue;
    if (reachDest.has(i)) {
      destTargetsInPad++;
      if (inPadTargets.length < 4) inPadTargets.push(instrs[i].off);
    } else fallthroughInPad++;
  }
  const prev = instrs[runIdx - 1];
  const term = EVM_TERMINATORS.get(prev.op) ?? null;
  const evidence = {
    runBytes, pureJumpdestRun: pure,
    terminatorBefore: term ?? (prev.op === 0x57 ? "jumpi-fallthrough"
      : prev.op >= 0x60 && prev.op <= 0x7f ? "push-feeds-nothing" : "fallthrough"),
    destTargetsInPad, fallthroughInstrsInPad: fallthroughInPad,
    inPadTargets,
  };
  if (destTargetsInPad > 0) {
    // Reachable jump targets land inside the candidate pad — the run merges
    // BLA padding with reachable contract code. Cutting the whole run would
    // delete reachable JUMPDESTs; keeping it leaves the flood in place.
    // Principled split: every byte through the LAST reachable target is
    // provably owned (a dest edge lands there or before it); bytes after it
    // are unreachable no-ops (fallthrough junk halts at EOF) — dead tail,
    // safe to cut. The owned prefix's own upper bound past the last target
    // is information-destroyed, so dead bytes between it and EOF are
    // dropped but reported as such.
    let keepEnd = padStart;
    for (const i of reachDest) {
      if (instrs[i] && instrs[i].off >= padStart) {
        const instrEnd = instrs[i].off + instrs[i].size;
        if (instrEnd > keepEnd) keepEnd = instrEnd;
      }
    }
    return {
      padStart: keepEnd,
      confidence: "medium",
      evidence: {
        ...evidence,
        reachablePrefixKept: keepEnd - padStart,
        deadTailDropped: end - keepEnd,
        partialCut: `jump target(s) inside pad at ${inPadTargets.map((x) => "0x" + x.toString(16)).join(",")} — kept reachable prefix through 0x${(keepEnd - 1).toString(16)}, dropped dead tail`,
      },
    };
  }
  if (dynamicJump) {
    return none("low", { ...evidence, veto: "reachable jump with dynamic destination — cannot prove pad unreachable" });
  }
  // No jump lands inside and no fallthrough reaches the pad → provably dead:
  // high. A junk run reachable only by fallthrough still executes no-ops to
  // EOF — flaggable, but less certain: medium.
  const confidence = fallthroughInPad > 0 ? "medium" : "high";
  return { padStart, confidence, evidence };
}

// ============================================================================
// 3) salvageZipMember — decode-or-prefix a corrupt member, minus markers
// ============================================================================
// Compact synchronous raw-DEFLATE decoder. node:zlib throws away all output
// on error, so recovering the decodable prefix before corrupt/marker-injected
// bytes needs an in-process decoder. Returns { out, ok, errAt }: on failure
// `out` holds everything decoded before the stream first faulted.
const LEN_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CLEN_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

function huffBuild(lens) {
  // canonical-code decode tables; null when over-subscribed
  let max = 0;
  for (const l of lens) if (l > max) max = l;
  if (max === 0) return { count: [0], offs: [0, 0], first: [0], syms: [], max: 0 };
  const count = new Array(max + 1).fill(0);
  for (const l of lens) if (l) count[l]++;
  let left = 1;
  for (let l = 1; l <= max; l++) {
    left = (left << 1) - count[l];
    if (left < 0) return null;
  }
  const offs = new Array(max + 2).fill(0);
  for (let l = 1; l <= max; l++) offs[l + 1] = offs[l] + count[l];
  const syms = new Array(lens.length);
  const cursor = offs.slice();
  for (let s = 0; s < lens.length; s++) if (lens[s]) syms[cursor[lens[s]]++] = s;
  const first = new Array(max + 1).fill(0);
  let code = 0;
  for (let l = 1; l <= max; l++) { code = (code + count[l - 1]) << 1; first[l] = code; }
  return { count, offs, first, syms, max };
}

function inflatePrefix(raw, outCap = 1 << 28) {
  const FAIL = {};
  let out = new Uint8Array(1 << 16), outLen = 0;
  const ensure = (n) => {
    while (outLen + n > out.length) {
      const next = Math.min(outCap, out.length * 2);
      if (outLen + n > next) throw FAIL;
      const o = new Uint8Array(next);
      o.set(out.subarray(0, outLen));
      out = o;
    }
  };
  const put = (b) => { ensure(1); out[outLen++] = b; };
  let pos = 0, bitbuf = 0, bitcnt = 0;
  const bit = () => {
    if (bitcnt === 0) {
      if (pos >= raw.length) throw FAIL;
      bitbuf = raw[pos++];
      bitcnt = 8;
    }
    const b = bitbuf & 1;
    bitbuf >>>= 1; bitcnt--;
    return b;
  };
  const bits = (n) => { let v = 0; for (let i = 0; i < n; i++) v |= bit() << i; return v >>> 0; };
  const decode = (t) => {
    let code = 0, len = 0;
    for (;;) {
      code = (code << 1) | bit();
      len++;
      if (len > t.max || len > 16) throw FAIL;
      const c = code - t.first[len];
      if (c >= 0 && c < t.count[len]) return t.syms[t.offs[len] + c];
    }
  };
  const fixedLit = (() => {
    const l = new Array(288);
    for (let s = 0; s < 288; s++) l[s] = s < 144 ? 8 : s < 256 ? 9 : s < 280 ? 7 : 8;
    return huffBuild(l);
  })();
  const fixedDist = huffBuild(new Array(32).fill(5));
  try {
    for (;;) {
      const bfinal = bits(1), btype = bits(2);
      if (btype === 0) {
        bitbuf = 0; bitcnt = 0; // stored blocks realign to byte boundary
        if (pos + 4 > raw.length) throw FAIL;
        const len = raw.readUInt16LE(pos), nlen = raw.readUInt16LE(pos + 2);
        pos += 4;
        if (((len ^ nlen) & 0xffff) !== 0xffff) throw FAIL;
        if (pos + len > raw.length) throw FAIL;
        ensure(len);
        out.set(raw.subarray(pos, pos + len), outLen);
        outLen += len; pos += len;
      } else {
        let litT, distT;
        if (btype === 1) { litT = fixedLit; distT = fixedDist; }
        else if (btype === 2) {
          const hlit = bits(5) + 257, hdist = bits(5) + 1, hclen = bits(4) + 4;
          if (hlit > 286 || hdist > 32) throw FAIL;
          const clens = new Array(19).fill(0);
          for (let i = 0; i < hclen; i++) clens[CLEN_ORDER[i]] = bits(3);
          const clT = huffBuild(clens);
          if (!clT) throw FAIL;
          const lens = new Array(hlit + hdist).fill(0);
          for (let i = 0; i < hlit + hdist;) {
            const s = decode(clT);
            if (s < 16) lens[i++] = s;
            else if (s === 16) {
              if (i === 0) throw FAIL;
              const rep = bits(2) + 3;
              if (i + rep > hlit + hdist) throw FAIL;
              for (let k = 0; k < rep; k++) lens[i++] = lens[i - 1];
            } else if (s === 17 || s === 18) {
              const rep = (s === 17 ? bits(3) + 3 : bits(7) + 11);
              if (i + rep > hlit + hdist) throw FAIL;
              i += rep; // zeros already present
            } else throw FAIL;
          }
          if (lens[256] === 0) throw FAIL; // stream can never terminate
          litT = huffBuild(lens.slice(0, hlit));
          distT = huffBuild(lens.slice(hlit));
          if (!litT || !distT) throw FAIL;
        } else throw FAIL; // btype 3 reserved
        for (;;) {
          const s = decode(litT);
          if (s < 256) { put(s); continue; }
          if (s === 256) break;
          if (s > 285) throw FAIL;
          const li = s - 257;
          const len = LEN_BASE[li] + bits(LEN_EXTRA[li]);
          const ds = decode(distT);
          if (ds > 29) throw FAIL;
          const dist = DIST_BASE[ds] + bits(DIST_EXTRA[ds]);
          if (dist > outLen) throw FAIL;
          ensure(len);
          for (let k = 0; k < len; k++) out[outLen] = out[outLen - dist], outLen++;
        }
      }
      if (bfinal) return { out: Buffer.from(out.subarray(0, outLen)), ok: true, errAt: pos };
    }
  } catch (e) {
    if (e !== FAIL) throw e; // a real bug must propagate
    return { out: Buffer.from(out.subarray(0, outLen)), ok: false, errAt: pos };
  }
}

// Attempt order per the recovery contract: stored → inflateRaw → inflate →
// brotli; then marker-splice retries (injected ASCII breaks the bitstream —
// excising it restores the original byte sequence exactly); then prefix
// decode to first error. Decoded/stored output is returned minus any marker
// byte runs. note: 'full' | 'prefix' | 'marker-stripped' | 'none'.
/**
 * Salvage a ZIP member's compressed data: attempt order stored →
 * inflateRaw → inflate → brotli → marker-splice retries (injected ASCII
 * breaks the bitstream; excising marker runs restores the original
 * sequence) → prefix decode to first error.
 * @param {Buffer} raw @param {number} method  ZIP compression method id
 * @returns {{ data: Buffer|null, salvagedBytes: number, note: string }}
 */
export function salvageZipMember(raw, method) {
  const done = (data, salvagedBytes, note) => ({ data, salvagedBytes, note });
  if (!raw || raw.length === 0) return done(null, 0, "none");
  const finish = (data, fullNote) => {
    const { buf, removedSpans } = stripMarkerRuns(data);
    return removedSpans.length
      ? done(buf, buf.length, "marker-stripped")
      : done(buf, buf.length, fullNote);
  };
  if (method === 0) return finish(raw, "full"); // stored: strip marker runs
  // 1) unmodified-input full decodes — a stream zlib accepts end-to-end is
  // complete by definition (it also swallows post-stream garbage). Marker
  // text embedded in the DECODED bytes is excised by finish().
  for (const fn of [inflateRawSync, inflateSync, brotliDecompressSync]) {
    try { return finish(fn(raw), "full"); } catch { /* next */ }
  }
  // 2) our own decoder: tolerates under-subscribed Huffman tables zlib
  // rejects; when it reaches a final block this is still a full decode.
  const p = inflatePrefix(raw);
  if (p.ok) return finish(p.out, "full");
  // 3) splice recovery: marker bytes INSERTED mid-stream corrupt the bit
  // sequence — excising them restores the original bytes exactly. But a
  // garbage decode of a corrupted stream can also "succeed" with a short
  // plausible output, so a splice candidate is trusted only when it clearly
  // dominates the honest recovered prefix (a real splice decodes the whole
  // member; garbage yields similar magnitude to the prefix itself).
  const rawSpans = markerSpans(raw).slice(0, 64);
  let bestSplice = null;
  const trySplice = (spans) => {
    const parts = [];
    let prev = 0;
    for (const [a, b] of spans) { if (a > prev) parts.push(raw.subarray(prev, a)); prev = b; }
    if (prev < raw.length) parts.push(raw.subarray(prev));
    try {
      const d = inflateRawSync(Buffer.concat(parts));
      if (!bestSplice || d.length > bestSplice.length) bestSplice = d;
    } catch { /* no */ }
  };
  for (const sp of rawSpans) trySplice([sp]);
  if (rawSpans.length > 1) trySplice(rawSpans);
  if (bestSplice && bestSplice.length >= Math.max(64, p.out.length * 2)) {
    return finish(bestSplice, "marker-stripped");
  }
  // 4) prefix decode to first error — guaranteed-correct output prefix.
  if (p.out.length > 0) {
    const { buf } = stripMarkerRuns(p.out);
    if (buf.length > 0) return done(buf, buf.length, "prefix");
  }
  // 5) last resort: a suspicious splice decode still beats nothing.
  if (bestSplice) return finish(bestSplice, "marker-stripped");
  return done(null, 0, "none");
}

// ============================================================================
// 4) repairDex — bounded header repair for malformed dexes
// ============================================================================
// Best-effort: file_size -> actual length, reseal SHA-1 sig (off 12, over
// [32..end]) + Adler32 (off 8, over [12..end]), map_off sanity. The emitted
// buffer must pass the same structural checks as the adversarial runner's
// verifyDex — otherwise passthrough, bytes untouched. Never fabricates a
// map_list: a dangling map_off is zeroed (legal "no map" encoding), and if
// that can't produce a consistent header the result is passthrough.
const DEX_MARKER = B("[BLA-DEX-SHIELD-V1]");
function adler32(b) {
  let a = 1, s = 0;
  for (let i = 0; i < b.length; i++) { a = (a + b[i]) % 65521; s = (s + a) % 65521; }
  return ((s << 16) | a) >>> 0;
}
// Mirrors verifyDex() in test-fixtures/adversarial/dex/run-adversarial.mjs.
function dexStructurallyValid(buf) {
  if (buf.length < 112) return false;
  if (buf.subarray(0, 4).toString("latin1") !== "dex\n") return false;
  if (buf.readUInt32LE(32) !== buf.length) return false;
  if (!buf.subarray(12, 32).equals(createHash("sha1").update(buf.subarray(32)).digest())) return false;
  if (buf.readUInt32LE(8) !== adler32(buf.subarray(12))) return false;
  const strSize = buf.readUInt32LE(56), strOff = buf.readUInt32LE(60);
  const typSize = buf.readUInt32LE(64), typOff = buf.readUInt32LE(68);
  const mapOff = buf.readUInt32LE(52);
  if (strSize && strOff + strSize * 4 > buf.length) return false;
  if (typSize && typOff + typSize * 4 > buf.length) return false;
  if (mapOff && mapOff + 4 > buf.length) return false;
  if (strSize && strOff + strSize * 4 <= buf.length) {
    for (let i = 0; i < strSize; i++) {
      if (buf.readUInt32LE(strOff + i * 4) >= buf.length) return false;
    }
  }
  return buf.indexOf(DEX_MARKER) < 0;
}
/**
 * Repair header-level DEX damage left by BLA decoy injection (bad
 * file_size/map_off/string_ids bounds); validated against a structural
 * walk before and after so a repair never invents a parseable file from
 * garbage. Passthrough when magic is absent or the file is already valid.
 * @returns {{ buf: Buffer, repairs: string[], status: string }}
 */
export function repairDex(buf) {
  const pass = () => ({ buf, repairs: [], status: "passthrough" });
  if (!buf || buf.length < 112 || buf.subarray(0, 4).toString("latin1") !== "dex\n") return pass();
  if (dexStructurallyValid(buf)) return { buf, repairs: [], status: "repaired" };
  const out = Buffer.from(buf);
  const repairs = [];
  const fileSize = out.readUInt32LE(32);
  if (fileSize !== out.length) {
    out.writeUInt32LE(out.length, 32);
    repairs.push(`file_size ${fileSize} -> ${out.length}`);
  }
  const mapOff = out.readUInt32LE(52);
  if (mapOff !== 0) {
    const mapEnd = mapOff + 4 <= out.length ? mapOff + 4 + out.readUInt32LE(mapOff) * 12 : Infinity;
    if (mapOff + 4 > out.length || mapEnd > out.length) {
      // map region destroyed (e.g. truncated dex) — zero the pointer rather
      // than fabricate entries; if the rest can't validate, we passthrough.
      out.writeUInt32LE(0, 52);
      repairs.push(`map_off ${mapOff} dangling -> 0`);
    }
  }
  createHash("sha1").update(out.subarray(32)).digest().copy(out, 12);
  out.writeUInt32LE(adler32(out.subarray(12)), 8);
  repairs.push("sha1+adler32 resealed");
  if (!dexStructurallyValid(out)) return pass();
  return { buf: out, repairs, status: "repaired" };
}

// ============================================================================
// 5) preserveApkMeta — recover container metadata the zip rebuild normalizes
// ============================================================================
// Pure parsing, no rebuild: extract the member's stored DOS timestamp
// (central record preferred — authoritative — local fallback) and any
// alignment-padding extra field so the caller can re-emit them verbatim.
// extra field shapes: id u16 + size u16 + data. Alignment padding shows up
// as id 0xa11e, a filler field (0xffff) with all-zero payload, or an extra
// region that is entirely zero bytes.
/**
 * Recover an APK member's original extra-field metadata (alignment
 * padding 0xa11e, filler 0xffff, all-zero regions) from the pre-scrub
 * local/central headers so re-emitted entries keep their byte offsets —
 * required for v2/v3 signature validity.
 * @returns {Buffer|null} preserved extra-field bytes
 */
export function preserveApkMeta(origLocal, origCentral) {
  const LOCAL_SIG = 0x04034b50, CENTRAL_SIG = 0x02014b50;
  const u16 = (b, o) => (b && o + 2 <= b.length ? b.readUInt16LE(o) : null);
  const u32 = (b, o) => (b && o + 4 <= b.length ? b.readUInt32LE(o) : null);
  const allZero = (b) => b.every((x) => x === 0);

  const extraOf = (hdr, sig, fixedLen, nlenOff, elenOff) => {
    if (!hdr || u32(hdr, 0) !== sig) return null;
    const nlen = u16(hdr, nlenOff), elen = u16(hdr, elenOff);
    if (nlen == null || elen == null || elen === 0) return null;
    const start = fixedLen + nlen;
    if (start + elen > hdr.length) return null;
    return hdr.subarray(start, start + elen);
  };

  const findPad = (extra) => {
    if (!extra) return null;
    let p = 0;
    while (p + 4 <= extra.length) {
      const id = extra.readUInt16LE(p), sz = extra.readUInt16LE(p + 2);
      if (p + 4 + sz > extra.length) break;
      if (id === 0xa11e) return extra.subarray(p, p + 4 + sz);
      if (id === 0xffff && allZero(extra.subarray(p + 4, p + 4 + sz))) {
        return extra.subarray(p, p + 4 + sz); // filler-field pad convention
      }
      p += 4 + sz;
    }
    return allZero(extra) ? extra : null; // whole region is alignment zeros
  };

  const localExtra = extraOf(origLocal, LOCAL_SIG, 30, 26, 28);
  const centralExtra = extraOf(origCentral, CENTRAL_SIG, 46, 28, 30);
  const extraPad = findPad(localExtra) ?? findPad(centralExtra);

  let timestamp = null;
  if (origCentral && u32(origCentral, 0) === CENTRAL_SIG) timestamp = u32(origCentral, 12);
  // a zero DOS timestamp is no timestamp — fall back to the local record
  if (!timestamp && origLocal && u32(origLocal, 0) === LOCAL_SIG) timestamp = u32(origLocal, 10);
  if (!timestamp) timestamp = null;

  return { extraPad, timestamp };
}
