// Adversarial test runner for BLADE scrubAsar.
// Usage: node test-fixtures/adversarial/asar/run.mjs
// Verdicts: PASS | REAL-ENTRY-DROPPED | INTEGRITY-BROKEN | PARSE-FAIL | OVER-CLEAN-JS
import { readFileSync, readdirSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { parse } from "@babel/parser";

const DIR = join(dirname(fileURLToPath(import.meta.url)));
const BUILT = join(DIR, "built");
const ROOT = join(DIR, "..", "..", "..");
const sha256 = (b) => createHash("sha256").update(b).digest("hex");

// src/formats.mjs currently does NOT parse (duplicate readU32Leb/writeU32Leb in
// the WASM section, lines 128-143 — a syntax error independent of ASAR). To test
// the ASAR scrubber verbatim we extract its exact code (lines 1..WASM marker)
// into a scratch module and import that. The code under test is unchanged.
const formatsSrc = readFileSync(join(ROOT, "src", "formats.mjs"), "utf8");
const wasmIdx = formatsSrc.indexOf("// ---------- WASM ----------");
if (wasmIdx === -1) throw new Error("WASM marker not found");
const asarSection = formatsSrc
  .slice(0, wasmIdx)
  .replace(/from "(\.\/[^"]+\.mjs)"/g, (_, rel) =>
    `from "${pathToFileURL(join(ROOT, "src", rel)).href}"`);
const scratchPath = join(BUILT, ".scrubAsar-under-test.mjs");
mkdirSync(BUILT, { recursive: true });
writeFileSync(scratchPath, asarSection + "\nexport { readAsar };\n");
const { scrubAsar } = await import(pathToFileURL(scratchPath).href);
const { looksBlaHardened } = await import(pathToFileURL(join(ROOT, "src", "js-deharden.mjs")).href);

// ---------- independent pickle/asar reader (paranoid) ----------
function readAsarDeep(buf) {
  if (buf.length < 16) throw new Error("short buffer");
  const firstU32 = buf.readUInt32LE(0);
  if (firstU32 !== 4) throw new Error(`first u32 = ${firstU32}, expected 4`);
  const headerSize = buf.readUInt32LE(4);
  const inner = buf.readUInt32LE(8);
  const jsonLen = buf.readUInt32LE(12);
  const dataOffset = 8 + headerSize;
  const framing = { firstU32, headerSize, inner, jsonLen, dataOffset };
  const aligned = Math.ceil(jsonLen / 4) * 4;
  framing.expectedInner = aligned + 4;
  framing.expectedHeaderSize = aligned + 8;
  framing.innerConsistent = inner === aligned + 4;
  framing.headerConsistent = headerSize === aligned + 8;
  const jsonText = buf.subarray(16, 16 + jsonLen).toString("utf8");
  const root = JSON.parse(jsonText);            // throws -> caller treats as PARSE-FAIL
  const entries = new Map();                    // path -> {kind, entry, content?}
  const dirs = new Set();
  (function walk(node, prefix) {
    for (const [name, ent] of Object.entries(node.files ?? {})) {
      const path = prefix + name;
      if (ent && typeof ent === "object" && ent.files && typeof ent.files === "object") {
        dirs.add(path); walk(ent, path + "/");
      } else if (ent && typeof ent === "object" && !Array.isArray(ent) && ent.link !== undefined) {
        entries.set(path, { kind: "link", entry: ent });
      } else if (ent === null || typeof ent !== "object") {
        entries.set(path, { kind: "malformed", entry: ent });
      } else {
        const off = dataOffset + Number(ent?.offset ?? 0);
        const size = typeof ent?.size === "number" ? ent.size : Number(ent?.size);
        entries.set(path, { kind: "file", entry: ent, content: buf.subarray(off, off + (Number.isFinite(size) ? size : 0)) });
      }
    }
  })(root, "");
  return { root, entries, dirs, framing, dataRegionEnd: dataOffset + totalDataBytes(entries) };
}
function totalDataBytes(entries) {
  let end = 0;
  for (const { kind, entry } of entries.values()) {
    if (kind !== "file") continue;
    const o = Number(entry.offset ?? 0), s = entry.size;
    if (Number.isFinite(o) && Number.isFinite(s)) end = Math.max(end, o + s);
  }
  return end;
}
// check contiguous packing: sort files by offset, expect 0-gap coverage 0..end
function packingGaps(entries) {
  const files = [...entries.values()].filter(e => e.kind === "file")
    .map(e => ({ o: Number(e.entry.offset ?? 0), s: e.entry.size }))
    .filter(f => Number.isFinite(f.o) && Number.isFinite(f.s)).sort((a, b) => a.o - b.o);
  const gaps = []; let cur = 0;
  for (const f of files) {
    if (f.o !== cur && f.s > 0) gaps.push({ expected: cur, found: f.o });
    cur = Math.max(cur, f.o + f.s);
  }
  return gaps;
}
// entries whose header node is not a well-formed object
function malformedEntries(entries) {
  return [...entries.entries()].filter(([, e]) => e.kind === "malformed" || (e.kind === "file" && (typeof e.entry.size !== "number" || typeof e.entry.offset !== "string")));
}

// ---------- JS structural comparison ----------
function topLevelNames(src) {
  try {
    const ast = parse(src, { sourceType: "unambiguous", plugins: ["typescript", "jsx"], errorRecovery: true });
    const names = new Set(); const exportsKeys = new Set(); let moduleExportsObj = null;
    const collect = (pat) => {
      if (!pat) return;
      if (pat.type === "Identifier") names.add(pat.name);
      else if (pat.type === "ObjectPattern") for (const p of pat.properties) collect(p.type === "RestElement" ? p.argument : p.value);
      else if (pat.type === "ArrayPattern") for (const el of pat.elements) collect(el);
      else if (pat.type === "AssignmentPattern") collect(pat.left);
      else if (pat.type === "RestElement") collect(pat.argument);
    };
    for (const st of ast.program.body) {
      if (st.type === "FunctionDeclaration" || st.type === "ClassDeclaration") { if (st.id) names.add(st.id.name); }
      else if (st.type === "VariableDeclaration") for (const d of st.declarations) collect(d.id);
      else if (st.type === "ExpressionStatement" && st.expression.type === "AssignmentExpression") {
        const l = st.expression.left;
        if (l.type === "MemberExpression" && l.object.type === "Identifier" && l.object.name === "module"
            && l.property.type === "Identifier" && l.property.name === "exports"
            && st.expression.right.type === "ObjectExpression") {
          moduleExportsObj = st.expression.right;
          for (const p of st.expression.right.properties) {
            if (p.type === "ObjectProperty" && !p.computed) {
              const k = p.key.type === "Identifier" ? p.key.name : p.key.value;
              exportsKeys.add(k);
              if (p.value.type === "Identifier" && p.value.name !== k) exportsKeys.add(`!renamed:${k}->${p.value.name}`);
            }
          }
        }
      }
    }
    return { names, exportsKeys, moduleExportsObj };
  } catch (e) { return { parseError: String(e) }; }
}

// ---------- per-fixture verification ----------
// Mirrors the CLI contract: `unpacked` entries resolve against the sibling
// <input>.unpacked/ directory when one exists on disk.
function verifyCase(name, inputBuf, manifest, fixturePath = null) {
  const res = { case: name, verdict: "PASS", findings: [], warnings: [], dropped: [], kept: [], js: null };
  const getExternal = fixturePath ? ((p) => {
    try { return readFileSync(join(`${fixturePath}.unpacked`, p)); } catch { return null; }
  }) : null;
  let inParsed = null;
  try { inParsed = readAsarDeep(inputBuf); } catch { /* malformed input — checks below still apply */ }
  const fail = (v, msg) => { if (res.verdict === "PASS") res.verdict = v; res.findings.push(`[${v}] ${msg}`); };
  const addFail = (v, msg) => { res.findings.push(`[${v}] ${msg}`); if (res.verdict === "PASS") res.verdict = v; };
  const note = (msg) => res.warnings.push(msg);
  const order = ["PASS", "OVER-CLEAN-JS", "INTEGRITY-BROKEN", "REAL-ENTRY-DROPPED", "PARSE-FAIL"];
  const bump = (v, msg) => { res.findings.push(`[${v}] ${msg}`); if (order.indexOf(v) > order.indexOf(res.verdict)) res.verdict = v; };

  let out;
  try { out = scrubAsar(inputBuf, getExternal ? { getExternal } : {}); }
  catch (e) { bump("PARSE-FAIL", `scrubAsar threw: ${e.message}`); return res; }
  res.scrubReport = out.report;

  let parsed;
  try { parsed = readAsarDeep(out.buffer); }
  catch (e) { bump("PARSE-FAIL", `output pickle unparseable: ${e.message}`); return res; }

  // framing invariants on the OUTPUT
  if (!parsed.framing.innerConsistent) bump("INTEGRITY-BROKEN", `output inner=${parsed.framing.inner} != aligned(jsonLen)+4 (${parsed.framing.expectedInner})`);
  if (!parsed.framing.headerConsistent) bump("INTEGRITY-BROKEN", `output headerSize=${parsed.framing.headerSize} != expected ${parsed.framing.expectedHeaderSize}`);
  const gaps = packingGaps(parsed.entries);
  if (gaps.length) bump("INTEGRITY-BROKEN", `output data section not contiguous: ${JSON.stringify(gaps.slice(0, 3))}`);
  if (parsed.dataRegionEnd > out.buffer.length) bump("INTEGRITY-BROKEN", `entries declare data past EOF (${parsed.dataRegionEnd} > ${out.buffer.length})`);
  for (const [p, e] of malformedEntries(parsed.entries)) {
    bump("INTEGRITY-BROKEN", `malformed node emitted for ${p}: ${JSON.stringify(e.entry).slice(0, 80)}`);
  }

  // per-manifest expectations
  for (const [path, m] of Object.entries(manifest.entries)) {
    const isDir = m.dir === true || (m.node && m.node.files && typeof m.node.files === "object" && !Array.isArray(m.node.files));
    const outEntry = parsed.entries.get(path);
    const outIsDir = parsed.dirs.has(path);
    if (m.expect === "dropped" || m.role === "decoy") {
      if (outEntry || outIsDir) bump("PASS-NOTE", `decoy ${path} survived (unexpected)`);
      else res.dropped.push(path);
      continue;
    }
    // role: real
    const nodeLink = m.node && typeof m.node === "object" && !Array.isArray(m.node) ? m.node.link : undefined;
    const nodeFiles = m.node && typeof m.node === "object" ? m.node.files : undefined;
    if (isDir || nodeFiles !== undefined) {
      // dir-ish nodes: children are what matter; malformed shapes noted below
      if (!outIsDir && isDir) bump("REAL-ENTRY-DROPPED", `real dir ${path}/ vanished (empty dirs not preserved)`);
      else if (isDir) res.kept.push(path + "/");
      continue;
    }
    if (m.link !== undefined || nodeLink !== undefined) {
      const want = m.link ?? nodeLink;
      if (!outEntry) bump("REAL-ENTRY-DROPPED", `real link ${path} missing`);
      else if (outEntry.kind !== "link") bump("INTEGRITY-BROKEN", `link ${path} became ${outEntry.kind}`);
      else {
        if (outEntry.entry.link !== want) bump("INTEGRITY-BROKEN", `link ${path} target rewritten ${want} -> ${outEntry.entry.link}`);
        const stale = Object.keys(outEntry.entry).filter(k => k !== "link");
        if (stale.length) note(`${path}: link node carries stale fields into output: ${stale.join(",")}`);
        res.kept.push(path);
      }
      continue;
    }
    if (!outEntry) { bump("REAL-ENTRY-DROPPED", `real entry ${path} missing from output`); continue; }
    if (m.expect === "corrupt-watch") {
      note(`${path}: malformed-input entry -> output kind=${outEntry.kind} size=${outEntry.content?.length ?? "?"}B node=${JSON.stringify(outEntry.entry).slice(0, 60)}`);
      res.kept.push(path);
      continue;
    }
    if (outEntry.kind !== "file") { bump("INTEGRITY-BROKEN", `${path} changed kind -> ${outEntry.kind}`); continue; }
    res.kept.push(path);
    const hadUnpacked = m.node && m.node.unpacked === true;
    if (hadUnpacked && outEntry.entry.unpacked !== true) {
      bump("INTEGRITY-BROKEN", `${path}: unpacked:true dropped — entry now claims packed data; bytes are stolen from other entries`);
    }
    const inputEntry = inParsed?.entries.get(path);
    const inputHadMarkers = inputEntry?.kind === "file" && /_interlockSafetyCorpus_|obligationFlood_|scc_\w+_c\d+n\d+|labyrinthDispatch_|decorative-deception-signal|_shadowVault_/.test(inputEntry.content.toString("utf8"));
    const isJsPath = /\.(m?js|cjs|mts|cts|jsx|ts|tsx)$/.test(path);
    if (m.expect === "bytes" && m.expectSha256) {
      if (sha256(outEntry.content) !== m.expectSha256) {
        if (isJsPath && inputHadMarkers) note(`${path}: JS rewritten by dehardenJs (expected — markers present in input)`);
        else bump("INTEGRITY-BROKEN", `${path}: content corrupted (got ${outEntry.content.length}B, sha ${sha256(outEntry.content).slice(0, 12)} != ${m.expectSha256.slice(0, 12)})`);
      }
    } else if (m.expect === "external" && m.expectSha256) {
      if (sha256(outEntry.content) !== m.expectSha256) {
        bump("INTEGRITY-BROKEN", `${path}: unpacked file repacked with wrong bytes (expected external content)`);
      }
    }
    // entry-level integrity recompute on output
    const it = outEntry.entry.integrity;
    if (it && typeof it === "object" && it.hash) {
      const algo = it.algorithm === "SHA512" ? "sha512" : "sha256";
      const h = createHash(algo).update(outEntry.content).digest("hex");
      if (h !== it.hash) bump("INTEGRITY-BROKEN", `${path}: integrity.hash mismatch (algo ${it.algorithm})`);
      if (it.blocks) {
        const bs = it.blockSize || 4 * 1024 * 1024;
        const blocks = [];
        for (let p = 0; p < outEntry.content.length; p += bs) blocks.push(createHash(algo).update(outEntry.content.subarray(p, p + bs)).digest("hex"));
        if (outEntry.content.length === 0) blocks.push(createHash(algo).update(Buffer.alloc(0)).digest("hex"));
        if (JSON.stringify(blocks) !== JSON.stringify(it.blocks)) bump("INTEGRITY-BROKEN", `${path}: integrity.blocks mismatch`);
      }
    } else if (typeof it === "string") {
      if (sha256(outEntry.content) !== it) bump("INTEGRITY-BROKEN", `${path}: string-integrity mismatch`);
    }
  }

  // decoy check: nothing under enclave/ .bla/ .enclave top-level should survive
  for (const p of parsed.entries.keys()) {
    const top = p.split("/")[0];
    if (top === "enclave" || top === ".bla" || top === ".enclave") {
      res.findings.push(`[note] decoy-ns entry still present: ${p}`);
    }
  }
  // .map members: BLA honey maps (enclave:// provenance) must be reconstructed,
  // not copied through; a surviving map carrying honey markers is residue
  for (const [p, e] of parsed.entries) {
    if (p.endsWith(".map") && e.kind === "file" && /enclave:\/\/|invokeHardwareEnclave/.test(e.content.toString("utf8"))) {
      bump("INTEGRITY-BROKEN", `${p}: BLA honey-map residue survived cleaning`);
    }
  }
  return res;
}

// ---------- JS-focused comparison for T3 cases ----------
const MARKER_RE = /_interlockSafetyCorpus_|obligationFlood_|scc_\w+_c\d+n\d+|labyrinthDispatch_|decorative-deception-signal|_shadowVault_/;
function jsCaseCheck(name, inputBuf, outputBuf, res, manifest) {
  const inParsed = readAsarDeep(inputBuf);
  const outParsed = readAsarDeep(outputBuf);
  res.jsFiles = [];
  for (const [p, e] of inParsed.entries) {
    if (e.kind !== "file") continue;
    const isDehardenedExt = /\.(m?js|cjs|jsx|ts|tsx)$/.test(p);
    const src = e.content.toString("utf8");
    const o = outParsed.entries.get(p);
    const allowed = manifest.entries[p]?.jsAllowedRemoved ?? [];
    if (!isDehardenedExt) {
      // extension gap probe: markers present but file can't be dehardened
      const out2 = o?.content?.toString("utf8");
      if (MARKER_RE.test(src)) {
        res.jsFiles.push({ file: p, note: "non-dehardened ext", markersSurvive: o ? MARKER_RE.test(out2) : "dropped" });
        if (o && MARKER_RE.test(out2)) res.warnings.push(`${p}: BLA markers survive — extension not covered by deharden regex`);
      }
      continue;
    }
    if (!o) { res.js = { file: p, missing: true }; continue; }
    const outSrc = o.content.toString("utf8");
    const before = topLevelNames(src), after = topLevelNames(outSrc);
    if (before.parseError) { res.jsFiles.push({ file: p, note: "input unparsed" }); continue; }
    const triggered = looksBlaHardened(src);
    const removed = [...before.names].filter(n => !after.names?.has(n));
    const badRemoved = removed.filter(n => !allowed.includes(n));
    const danglingExports = after.exportsKeys ? [...after.exportsKeys].filter(k => !k.startsWith("!") && !after.names.has(k) && !allowed.includes(k)) : [];
    const rec = {
      file: p, triggered, bytesChanged: outSrc !== src,
      topLevelBefore: before.names.size, topLevelAfter: after.names?.size ?? 0,
      removedNames: removed, removedCount: removed.length, badRemoved,
      danglingExports,
      inputMarkers: MARKER_RE.exec(src)?.[0] ?? null,
      outputMarkers: MARKER_RE.exec(outSrc)?.[0] ?? null,
    };
    res.jsFiles.push(rec);
    res.js = rec; // last one for the summary line
    if (triggered) {
      if (badRemoved.length) res.findings.push(`[OVER-CLEAN-JS] ${p}: real top-level names stripped: ${badRemoved.slice(0, 8).join(", ")}${badRemoved.length > 8 ? ` (+${badRemoved.length - 8} more)` : ""}`);
      if (danglingExports.length) res.findings.push(`[OVER-CLEAN-JS] ${p}: exports reference removed bindings -> runtime ReferenceError: ${danglingExports.join(", ")}`);
      if (!badRemoved.length && removed.length) res.warnings.push(`${p}: only expected injected names removed (${removed.join(",")})`);
    } else if (outSrc !== src) {
      res.warnings.push(`${p}: not flagged hardened but content changed`);
    }
  }
}

// ---------- main ----------
const results = [];
const files = readdirSync(BUILT).filter(f => f.endsWith(".asar")).sort();

// Baseline: real BLA-hardened fixture + plain control
const extras = [
  ["baseline-plain (test-fixtures/plain/app.asar)", join(ROOT, "test-fixtures/plain/app.asar"), {
    entries: { "package.json": { role: "real", expect: "bytes", expectSha256: null }, "electron-bridge.js": { role: "real", expect: "bytes", expectSha256: null } },
    _deriveSha: true,
  }],
  ["baseline-hardened (real BLA output, 18MB)", join(ROOT, "test-fixtures/hardened/app.asar"), {
    entries: { "package.json": { role: "real", expect: "bytes", expectSha256: null }, "electron-bridge.js": { role: "real", expect: "survive" } },
    _deriveSha: true, _decoys: "enclave/",
  }],
];

for (const f of files) {
  const manifest = JSON.parse(readFileSync(join(BUILT, f + ".manifest.json"), "utf8"));
  const buf = readFileSync(join(BUILT, f));
  const res = verifyCase(f, buf, manifest, join(BUILT, f));
  // JS checks for bundles
  if (res.verdict !== "PARSE-FAIL") {
    try {
      const out = scrubAsar(buf, { getExternal: (p) => { try { return readFileSync(join(`${join(BUILT, f)}.unpacked`, p)); } catch { return null; } } });
      jsCaseCheck(f, buf, out.buffer, res, manifest);
      const bad = (res.jsFiles ?? []).some(j => j.badRemoved?.length || j.danglingExports?.length);
      if (bad) res.verdict = "OVER-CLEAN-JS";
    } catch { /* already reported */ }
  }
  results.push(res);
}

for (const [name, path, manifest] of extras) {
  try {
    const buf = readFileSync(path);
    if (manifest._deriveSha) {
      const p = readAsarDeep(buf);
      for (const [k, m] of Object.entries(manifest.entries)) {
        if (m.expect === "bytes") m.expectSha256 = sha256(p.entries.get(k).content);
      }
    }
    const r = verifyCase(name, buf, manifest, path);
    // baseline-hardened extra: cleaned bridge must be real logic, no markers
    if (manifest._decoys) {
      try {
        const out = scrubAsar(buf);
        const p = readAsarDeep(out.buffer);
        const js = p.entries.get("electron-bridge.js")?.content.toString("utf8") ?? "";
        if (!js.includes("notionClipboard")) r.findings.push("[note] bridge lost notionClipboard API");
        if (/_interlockSafetyCorpus_|obligationFlood_|scc_\w+_c\d+n\d+|labyrinthDispatch_|_shadowVault_/.test(js)) r.findings.push("[note] markers survive in cleaned bridge");
        else r.warnings.push("electron-bridge.js fully dehardened, notionClipboard surface intact");
      } catch (e) { r.findings.push(`[note] baseline rescrub failed: ${e.message}`); }
    }
    results.push(r);
  } catch (e) { results.push({ case: name, verdict: "PARSE-FAIL", findings: [`fixture read failed: ${e.message}`], warnings: [], dropped: [], kept: [] }); }
}

// ---------- report ----------
console.log("\n=== BLADE scrubAsar adversarial results ===\n");
const order = ["PASS", "OVER-CLEAN-JS", "INTEGRITY-BROKEN", "REAL-ENTRY-DROPPED", "PARSE-FAIL"];
for (const r of results) {
  console.log(`${r.verdict.padEnd(19)} ${r.case}`);
  for (const f of (r.findings ?? []).slice(0, 12)) console.log(`    ${f.slice(0, 220)}`);
  for (const w of (r.warnings ?? []).slice(0, 6)) console.log(`    (warn) ${w.slice(0, 200)}`);
  for (const j of (r.jsFiles ?? [])) {
    if (j.note) { console.log(`    js ${j.file}: ${j.note}${j.markersSurvive !== undefined ? " markersSurvive=" + j.markersSurvive : ""}`); continue; }
    console.log(`    js ${j.file}: triggered=${j.triggered} changed=${j.bytesChanged} names ${j.topLevelBefore}->${j.topLevelAfter} removed=${j.removedCount}${j.danglingExports?.length ? " dangling=" + j.danglingExports.length : ""}`);
    if (j.inputMarkers) console.log(`      markers in: ${j.inputMarkers} | out: ${j.outputMarkers ?? "none"}`);
  }
  if (r.scrubReport) console.log(`    report: in=${r.scrubReport.entriesIn} kept=${r.scrubReport.entriesKept} dropped=${r.scrubReport.decoyEntriesDropped} jsDehardened=${r.scrubReport.innerJsDehardened}`);
}
const counts = {};
for (const r of results) counts[r.verdict] = (counts[r.verdict] ?? 0) + 1;
console.log("\n=== tally ===");
for (const v of order) if (counts[v]) console.log(`${v.padEnd(19)} ${counts[v]}`);
writeFileSync(join(DIR, "results.json"), JSON.stringify(results, (k, v) => v instanceof Set ? [...v] : v, 2));
console.log("\nfull details -> results.json");
