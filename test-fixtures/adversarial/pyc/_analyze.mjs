// PYC weave-vs-scrub analyzer.
// For each fixture: locate marshal root end (plain vs hardened), parse root
// co_consts to enumerate TYPE_CODE decoys (name + marshal offset + consts idx),
// then run BLADE's scrubPyc and compare cleaned output vs the plain .pyc.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { scrubPyc } from "../../../src/trailer.mjs";

const DIR = fileURLToPath(new URL(".", import.meta.url));

// ---- BLADE dispatch (src/trailer.mjs pycLayout) — for reporting dispatch gaps ----
function pycLayoutBlade(magic) {
  if ((magic >= 3390 && magic <= 3393) || magic === 3400 || magic === 3401) return "py37";
  if (magic >= 3410 && magic <= 3439) return "py38";
  if (magic >= 3450 && magic <= 3699) return "py311";
  return null;
}
// ---- BLA dispatch (python-pyc-weave.ts MAGIC_LAYOUT) — the "true" layout ----
function pycLayoutBla(magic) {
  if ((magic >= 3390 && magic <= 3394) || magic === 3400 || magic === 3401) return "py37";
  if (magic >= 3410 && magic <= 3439) return "py38";
  if (magic >= 3450 && magic <= 3699) return "py311";
  return null;
}

// ---- offset-tracking marshal parser (single value at pos -> {end, node}) ----
// node kinds: "scalar" | "str" | "bytes" | "tuple" | "code" | "ref" | "other"
function parse(buf, pos, layout, depth = 0, refs = []) {
  if (depth > 400 || pos >= buf.length) return null;
  const raw = buf[pos];
  const type = raw & 0x7f;
  const flagged = (raw & 0x80) !== 0;
  let p = pos + 1;
  const u32 = () => { const v = buf.readUInt32LE(p); p += 4; return v; };
  const strN = (n) => { const s = buf.subarray(p, p + n).toString("utf8"); p += n; return s; };

  if (type === 0x72) { // TYPE_REF
    const idx = u32();
    return { end: p, node: { kind: "ref", idx, start: pos, target: refs[idx] } };
  }
  const early = [0x28, 0x29, 0x5b, 0x7b, 0x3c, 0x3e, 0x63].includes(type);
  let slot = -1;
  if (flagged && early) { slot = refs.length; refs.push(null); }
  const finish = (node) => {
    if (flagged) { if (slot >= 0) refs[slot] = node; else refs.push(node); }
    return { end: p, node };
  };

  switch (type) {
    case 0x30: case 0x4e: case 0x46: case 0x54: case 0x2e: case 0x53:
      return finish({ kind: "scalar", start: pos });
    case 0x69: p += 4; return finish({ kind: "scalar", start: pos });
    case 0x49: case 0x67: p += 8; return finish({ kind: "scalar", start: pos });
    case 0x78: case 0x79: p += 16; return finish({ kind: "scalar", start: pos });
    case 0x66: { const n = buf[p]; p += 1 + n; return finish({ kind: "str", start: pos }); }
    case 0x6c: { const n = Math.abs(buf.readInt32LE(p)); p += 4 + n * 2; return finish({ kind: "scalar", start: pos }); }
    case 0x73: { const n = u32(); p += n; return finish({ kind: "bytes", start: pos }); }
    case 0x61: case 0x41: case 0x75: case 0x74: case 0x52: {
      const n = u32(); const s = strN(n);
      return finish({ kind: "str", start: pos, text: s });
    }
    case 0x7a: case 0x5a: { const n = buf[p]; p += 1; const s = strN(n); return finish({ kind: "str", start: pos, text: s }); }
    case 0x29: case 0x28: case 0x5b: case 0x3c: case 0x3e: {
      const n = type === 0x29 ? buf[p++] : u32();
      const items = [];
      for (let i = 0; i < n; i++) {
        const r = parse(buf, p, layout, depth + 1, refs);
        if (!r) return null;
        items.push({ ...r.node, end: r.end });
        p = r.end;
      }
      return finish({ kind: "tuple", items, start: pos });
    }
    case 0x7b: {
      const items = [];
      for (;;) {
        const k = parse(buf, p, layout, depth + 1, refs);
        if (!k) return null;
        p = k.end;
        if ((k.node.rawType ?? 0) === 0x30 || buf[k.node.start] === 0x30) break;
        const v = parse(buf, p, layout, depth + 1, refs);
        if (!v) return null;
        p = v.end;
        items.push([k.node, v.node]);
      }
      return finish({ kind: "dict", items, start: pos });
    }
    case 0x63: { // TYPE_CODE
      const fields = {};
      p += 4; // argcount
      if (layout !== "py37") p += 4; // posonly
      p += 4; // kwonly
      if (layout !== "py311") p += 4; // nlocals
      p += 8; // stacksize+flags
      const rd = () => { const r = parse(buf, p, layout, depth + 1, refs); if (!r) throw new Error("bad code field"); p = r.end; return { ...r.node, end: r.end }; };
      fields.code = rd();
      fields.consts = rd();
      fields.names = rd();
      if (layout === "py311") { fields.localsplusnames = rd(); fields.localspluskinds = rd(); }
      else { fields.varnames = rd(); fields.freevars = rd(); fields.cellvars = rd(); }
      fields.filename = rd();
      fields.name = rd();
      if (layout === "py311") fields.qualname = rd();
      p += 4; // firstlineno
      fields.linetable = rd();
      if (layout === "py311") fields.exceptiontable = rd();
      return finish({ kind: "code", start: pos, name: fields.name?.text, consts: fields.consts?.items ?? [], fields });
    }
    default:
      return null;
  }
}

const DECOY_STEM = /^(reconcile_invoice_batch|hydrate_session_cache|flush_telemetry_buffer|normalize_locale_bundle|schedule_backoff_retry|compact_wal_segment|project_catalog_facet|bind_worker_pool_slot|materialize_report_cursor|encode_transport_frame|observe_metric_histogram|adapt_gateway_policy|reduce_pipeline_shard|capture_audit_sample|prime_connection_pool|transform_lookup_vector|verify_enclave_attestation|derive_hardware_kdf_schedule|authenticate_tpm_quote_digest|negotiate_vsock_channel_cipher|synchronize_hsm_key_slot|unseal_protected_memory_page)_\d{4}$/;

function collectCodeObjects(node, path = "root", out = []) {
  if (!node || node.kind !== "code") return out;
  out.push({ path, node });
  node.consts.forEach((c, i) => {
    if (c.kind === "code") collectCodeObjects(c, `${path}.co_consts[${i}]<${c.name}>`, out);
    else if (c.kind === "ref" && c.target?.kind === "code") {
      // ref to a code object — note it but don't double-walk
    }
  });
  return out;
}

function firstDiff(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return i;
  return a.length === b.length ? -1 : n;
}

function analyzePair(name, plainFile, hardFile) {
  const plain = readFileSync(DIR + plainFile);
  const hard = readFileSync(DIR + hardFile);
  const magic = plain.readUInt16LE(0);
  const bladeLayout = pycLayoutBlade(magic);   // what scrubPyc will walk with
  const layout = pycLayoutBla(magic) ?? bladeLayout ?? "py311"; // true layout for OUR parser
  const refs = [];
  const pRoot = parse(plain, 16, layout, 0, refs);
  const hRefs = [];
  const hRoot = parse(hard, 16, layout, 0, hRefs);

  const plainRootEnd = pRoot ? pRoot.end : -1;
  const hardRootEnd = hRoot ? hRoot.end : -1;
  const rootGrew = hardRootEnd > 0 && plainRootEnd > 0 ? hardRootEnd - plainRootEnd : null;

  // enumerate code objects + decoys in hardened root
  const codes = hRoot ? collectCodeObjects(hRoot.node) : [];
  const decoys = [];
  for (const { path, node } of codes) {
    node.consts.forEach((c, i) => {
      if (c.kind === "code" && DECOY_STEM.test(c.name ?? "")) {
        decoys.push({ where: path, constsIndex: i, marshalOffset: c.start, name: c.name });
      }
    });
  }

  // scrub + compare
  const scrub = scrubPyc(hard);
  const cleaned = scrub.buffer;
  const d = firstDiff(cleaned, plain);
  const exact = cleaned.equals(plain);

  // re-parse cleaned root for residual decoys
  let residual = [];
  if (!exact) {
    const cRefs = [];
    const cRoot = parse(cleaned, 16, layout ?? "py311", 0, cRefs);
    if (cRoot) {
      for (const { path, node } of collectCodeObjects(cRoot.node)) {
        node.consts.forEach((c, i) => {
          if (c.kind === "code" && DECOY_STEM.test(c.name ?? "")) {
            residual.push({ where: path, constsIndex: i, marshalOffset: c.start, name: c.name });
          }
        });
      }
    }
  }

  return {
    name, magic, layout, bladeLayout,
    dispatchMismatch: bladeLayout !== layout,
    plainLen: plain.length, hardLen: hard.length,
    plainRootEnd, hardRootEnd, rootDelta: rootGrew,
    codeObjectsInHardenedRoot: codes.length,
    decoys,
    scrub: { hardened: scrub.report.hardened, dropped: scrub.report.marshalTrailerDropped, records: scrub.report.trailerRecords, via: scrub.report.via, note: scrub.report.note },
    byteExact: exact,
    firstDiffOffset: d,
    cleanedLen: cleaned.length,
    residualDecoys: residual,
  };
}

const cases = [
  ["cp313 (magic 3571)", "plain-313.pyc", "woven/plain-313-woven.pyc"],
  ["cp312 (magic 3531)", "plain-312.pyc", "woven/plain-312-woven.pyc"],
  ["cp312 hash-hdr flags=3", "plain-312-hash.pyc", "woven/plain-312-hash-woven.pyc"],
  ["synth cp37 (3394)", "synth-37.pyc", "woven/synth-37-woven.pyc"],
  ["synth cp38 (3413)", "synth-38.pyc", "woven/synth-38-woven.pyc"],
  ["synth cp310 (3439)", "synth-310.pyc", "woven/synth-310-woven.pyc"],
  ["cp312 body, magic patched 3495 (3.11)", "synth-311-magic.pyc", "woven/synth-311-magic-woven.pyc"],
  ["synth py311-family magic 3650", "synth-315.pyc", "woven/synth-315-woven.pyc"],
  ["synth cp38 flags=1 (hash)", "synth-38-hashflag.pyc", "woven/synth-38-hashflag-woven.pyc"],
];
const trailerCases = [
  ["cp313 trailer-only", "plain-313.pyc", "trailer/plain-313-trailer.pyc"],
  ["cp37 trailer-only", "synth-37.pyc", "trailer/synth-37-trailer.pyc"],
];

for (const [label, pf, hf] of [...cases, ...trailerCases]) {
  let r;
  try { r = analyzePair(label, pf, hf); } catch (e) {
    console.log(`\n=== ${label} ===\n  ANALYZER ERROR: ${e.message}`);
    continue;
  }
  console.log(`\n=== ${label} ===`);
  console.log(`  magic=${r.magic} layout=${r.layout} bladeLayout=${r.bladeLayout}${r.dispatchMismatch ? " **DISPATCH MISMATCH**" : ""} plain=${r.plainLen}B hardened=${r.hardLen}B`);
  console.log(`  marshal root: plain end=${r.plainRootEnd} hardened end=${r.hardRootEnd} -> root delta=${r.rootDelta}B, trailer=${r.hardLen - r.hardRootEnd}B`);
  console.log(`  code objects inside hardened root: ${r.codeObjectsInHardenedRoot}; TYPE_CODE decoys found: ${r.decoys.length}`);
  for (const dd of r.decoys.slice(0, 25)) console.log(`    decoy "${dd.name}" at ${dd.where} consts[${dd.constsIndex}] marshalOff=${dd.marshalOffset}`);
  console.log(`  scrubPyc: hardened=${r.scrub.hardened} trailerDropped=${r.scrub.dropped} records=${r.scrub.records}${r.scrub.via ? " via=" + r.scrub.via : ""}`);
  console.log(`  cleaned: ${r.cleanedLen}B vs plain ${r.plainLen}B -> ${r.byteExact ? "BYTE-EXACT" : "DIVERGES at byte " + r.firstDiffOffset}`);
  if (r.residualDecoys.length) {
    console.log(`  RESIDUAL DECOYS in cleaned root: ${r.residualDecoys.length}`);
    for (const dd of r.residualDecoys.slice(0, 25)) console.log(`    residual "${dd.name}" at ${dd.where} consts[${dd.constsIndex}] marshalOff=${dd.marshalOffset}`);
  }
}
