// Adversarial ASAR fixture builder for BLADE scrubAsar testing.
// Each fixture ships a .manifest.json describing every header entry:
//   role: "real"  -> app content, must survive (byte-identical if contentSha256 set)
//   role: "decoy" -> BLA-style injected entry, should be dropped
//   expect: "bytes" (default w/ sha) | "survive" | "corrupt-watch" | "external"
import { mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "built");
mkdirSync(OUT, { recursive: true });

const sha256 = (b) => createHash("sha256").update(b).digest("hex");

function integ(content, { algorithm = "SHA256", blockSize = 4 * 1024 * 1024 } = {}) {
  const hashFn = algorithm === "SHA512" ? "sha512" : "sha256";
  const it = { algorithm, hash: createHash(hashFn).update(content).digest("hex"), blockSize, blocks: [] };
  for (let p = 0; p < content.length; p += blockSize) {
    it.blocks.push(createHash(hashFn).update(content.subarray(p, p + blockSize)).digest("hex"));
  }
  if (it.blocks.length === 0) it.blocks.push(createHash(hashFn).update(Buffer.alloc(0)).digest("hex"));
  return it;
}

// ---------- packer ----------
// entries: { path, content?, dir?, link?, node? (explicit header node),
//            declaredSize?, declaredOffset?, padBefore?,
//            executable?, integrity? ("auto"|object), integOpts?,
//            role?, expect?, expectSha256? }
// opts:    { padByte, extraHeaderPad, firstU32, innerOverride,
//            jsonLenOverride, trailer, extraJson }
function packAsar(entries, opts = {}) {
  const root = { files: {} };
  const chunks = [];
  let cursor = 0;
  const manifest = { entries: {} };
  const note = (path, m) => { manifest.entries[path] = m; };

  for (const e of entries) {
    const segs = e.path.split("/");
    let dir = root;
    for (const s of segs.slice(0, -1)) {
      const cur = dir.files[s];
      if (!cur || typeof cur !== "object" || Array.isArray(cur) || typeof cur.files !== "object" || cur.files === null) {
        dir.files[s] = { files: {} };
      }
      dir = dir.files[s];
    }
    const leaf = segs[segs.length - 1];
    if (e.dir) {
      dir.files[leaf] = e.dirNode ?? { files: {} };
      note(e.path, { dir: true, role: e.role ?? "real", expect: e.expect ?? "survive" });
      continue;
    }
    if (e.node !== undefined) {
      dir.files[leaf] = e.node;
      note(e.path, { node: e.node, role: e.role ?? "real", expect: e.expect ?? "survive", expectSha256: e.expectSha256 });
      continue;
    }
    if (e.link !== undefined) {
      dir.files[leaf] = { link: e.link };
      note(e.path, { link: e.link, role: e.role ?? "real", expect: e.expect ?? "survive" });
      continue;
    }
    const content = e.content ?? Buffer.alloc(0);
    if (e.padBefore) { chunks.push(Buffer.alloc(e.padBefore, 0x61)); cursor += e.padBefore; }
    const node = { offset: String(e.declaredOffset ?? cursor), size: e.declaredSize ?? content.length };
    if (e.executable) node.executable = true;
    if (e.integrity === "auto") node.integrity = integ(content, e.integOpts);
    else if (e.integrity !== undefined) node.integrity = e.integrity;
    dir.files[leaf] = node;
    chunks.push(content);
    cursor += content.length;
    note(e.path, { node, role: e.role ?? "real", expect: e.expect ?? "bytes", expectSha256: e.expectSha256 ?? sha256(content), ...(e.jsAllowedRemoved ? { jsAllowedRemoved: e.jsAllowedRemoved } : {}) });
  }
  const json = opts.treeJson !== undefined
    ? Buffer.from(opts.treeJson, "utf8")
    : Buffer.from(JSON.stringify(root), "utf8");
  const aligned = Math.ceil(json.length / 4) * 4;
  const inner = opts.innerOverride ?? aligned + 4;
  const headerSize = opts.headerSizeOverride ?? inner + 4 + (opts.extraHeaderPad ?? 0);
  const hdr = Buffer.alloc(8 + headerSize, opts.padByte ?? 0);
  hdr.writeUInt32LE(opts.firstU32 ?? 4, 0);
  hdr.writeUInt32LE(headerSize, 4);
  hdr.writeUInt32LE(inner, 8);
  hdr.writeUInt32LE(opts.jsonLenOverride ?? json.length, 12);
  json.copy(hdr, 16);
  return { buf: Buffer.concat([hdr, ...chunks, opts.trailer ?? Buffer.alloc(0)]), manifest };
}

const F = (s) => Buffer.from(s, "utf8");
const write = (name, { buf, manifest }) => {
  writeFileSync(join(OUT, name), buf);
  writeFileSync(join(OUT, name + ".manifest.json"), JSON.stringify(manifest, null, 2));
};

const PKG = JSON.stringify({ name: "field-app", version: "3.1.0", main: "main.js" });
const MAIN_JS = `"use strict";
const { app, BrowserWindow } = require("electron");
function createWindow() {
  const w = new BrowserWindow({ width: 1024, height: 768 });
  w.loadFile("index.html");
}
app.whenReady().then(createWindow);
module.exports = { createWindow };
`;

// ============================================================
// T0 control: plain asar — no decoys, must pass cleanly
// ============================================================
write("t0-plain.asar", packAsar([
  { path: "package.json", content: F(PKG), integrity: "auto" },
  { path: "main.js", content: F(MAIN_JS), integrity: "auto" },
  { path: "assets/logo.png", content: Buffer.alloc(2048, 7), integrity: "auto" },
]));

// ============================================================
// T1: REAL top-level enclave/ .bla/ .enclave content mixed w/ decoys
// ============================================================
write("t1-real-enclave-dirs.asar", packAsar([
  { path: "package.json", content: F(PKG), integrity: "auto" },
  { path: "main.js", content: F(MAIN_JS), integrity: "auto" },
  // BLA-style decoys (same shape as vendor/bla output)
  { path: "enclave/hardware-tee-bridge.js", content: F("// decoy bridge\n"), role: "decoy", expect: "dropped" },
  { path: "enclave/shards/ring0-slot-aaa_0.json", content: F("{}"), role: "decoy", expect: "dropped" },
  { path: "enclave/shards/ring0-slot-aaa_1.json", content: F("{}"), role: "decoy", expect: "dropped" },
  { path: ".bla/sidecar.v1.json", content: F("{\"note\":\"x\"}"), role: "decoy", expect: "dropped" },
  // REAL content colliding with the same namespaces:
  { path: "enclave/sdk/client.js", content: F("exports.openEnclaveSession=()=>1;\n"), role: "real", integrity: "auto" },
  { path: "enclave/sdk/README.md", content: F("# Enclave SDK docs\n"), role: "real" },
  { path: "enclave/manifest.json", content: F("{\"eif\":\"sha384:real\"}\n"), role: "real" },
  { path: ".enclave/eif-manifest.json", content: F("{\"measure\":\"pcr0\"}\n"), role: "real" },
  { path: ".bla/team-notes.md", content: F("notes for the bla cli\n"), role: "real" },
  // near-miss names that MUST survive
  { path: "enclave.md", content: F("# doc about enclave\n"), role: "real" },
  { path: "enclaves/plural.md", content: F("plural dir\n"), role: "real" },
  { path: "Enclave/Upper.md", content: F("capital E dir\n"), role: "real" },
  { path: "lib/enclave/util.js", content: F("exports.nested=1;\n"), role: "real" },
  { path: "lib/enclave.js", content: F("exports.helper=2;\n"), role: "real" },
  { path: "vendor/.bla/cache.dat", content: Buffer.alloc(64, 3), role: "real" },
  { path: "enclave-sdk/README.md", content: F("sdk with enclave in name\n"), role: "real" },
  { path: "logs", dir: true, role: "real" },               // empty real dir
  { path: "cache/empty", dir: true, role: "real" },       // nested empty real dir
]));

// ============================================================
// T2: links, unpacked, size-0, integrity shape variants
// packed data layout (in order): package.json, blob0@0, blob1, runtime-real.js, old-str, no-blocks, sha512, null-int
// ============================================================
{
  const unpackedAdder = Buffer.alloc(4096, 0x51);   // real bytes live only in .asar.unpacked/
  const unpackedLib = Buffer.alloc(2000, 0x52);
  const unpackedExec = Buffer.alloc(512, 0x53);
  const oldStr = F("exports.b=2;\n");
  const noBlocks = F("exports.c=3;\n");
  const nullInt = Buffer.alloc(32, 0x46);
  const list = [
    { path: "package.json", content: F(PKG), integrity: "auto" },
    { path: "data/blob0.bin", content: Buffer.alloc(64, 0x41), integrity: "auto" }, // occupies data[0..64)
    { path: "data/blob1.bin", content: Buffer.alloc(64, 0x42) },
    { path: "bin/helper", link: "../external/helper" },                    // external link
    { path: "vendor/runtime.js", link: "vendor/runtime-real.js" },         // internal link
    { path: "vendor/runtime-real.js", content: F("exports.rt=1;\n") },
    { path: "bin/odd-link", node: { link: "bin/helper", size: 5, offset: "0" }, expect: "survive" },  // link carrying stale fields
    { path: "links/decoy-target", link: "enclave/x", expect: "survive" },  // link w/ decoy-ish target name
    { path: "native/adder.node", node: { size: 4096, unpacked: true }, expect: "external", expectSha256: sha256(unpackedAdder) },
    { path: "native/lib.node", node: { size: 2000, offset: "80", unpacked: true, integrity: integ(unpackedLib) }, expect: "external", expectSha256: sha256(unpackedLib) },
    { path: "native/exec.node", node: { size: 512, unpacked: true, executable: true, integrity: integ(unpackedExec) }, expect: "external", expectSha256: sha256(unpackedExec) },
    { path: "noof.bin", node: { size: 100 }, expect: "corrupt-watch" },    // packed file missing offset
    { path: "zero.bin", node: { offset: "0", size: 0 }, expect: "bytes", expectSha256: sha256(Buffer.alloc(0)) },
    { path: "a/new-int.js", content: F("exports.a=1;\n"), integrity: "auto" },
    { path: "a/old-str.js", content: oldStr, integrity: sha256(oldStr) },  // OLD form: bare hex string
    { path: "a/no-blocks.js", content: noBlocks, integrity: { algorithm: "SHA256", hash: sha256(noBlocks) } }, // no blockSize/blocks
    { path: "a/sha512.bin", content: Buffer.alloc(4096, 0x44), integrity: "auto", integOpts: { algorithm: "SHA512", blockSize: 1024 } },
    { path: "a/null-int.bin", content: nullInt, integrity: null },
  ];
  write("t2-links-unpacked-integrity.asar", packAsar(list));
  // companion .asar.unpacked dir a real Electron layout ships alongside
  mkdirSync(join(OUT, "t2-links-unpacked-integrity.asar.unpacked", "native"), { recursive: true });
  writeFileSync(join(OUT, "t2-links-unpacked-integrity.asar.unpacked", "native", "adder.node"), unpackedAdder);
  writeFileSync(join(OUT, "t2-links-unpacked-integrity.asar.unpacked", "native", "lib.node"), unpackedLib);
  writeFileSync(join(OUT, "t2-links-unpacked-integrity.asar.unpacked", "native", "exec.node"), unpackedExec);
}

// ============================================================
// T3: inner-JS deharden trigger probes (~50KB real-ish bundles)
// ============================================================
function bigBundle({ markerComment = false, strongNames = false, genericTail = false, size = 51200 } = {}) {
  const L = [];
  L.push(`"use strict";`);
  L.push(`/* field-app order pipeline bundle - real production code`);
  if (markerComment) {
    L.push(` * hardening notes: scanned artifacts may reference _interlockSafetyCorpus_,`);
    L.push(` * obligationFlood_, labyrinthDispatch_ or _shadowVault_ style names.`);
  }
  L.push(` */`);
  L.push(`const REGION_TAX = { us: 0.07, eu: 0.19, apac: 0.1, latam: 0.16 };`);
  L.push(`const FX_TABLE = { USD: 1, EUR: 0.92, JPY: 149.5, BRL: 5.05, GBP: 0.79 };`);
  L.push(`function moneyFmt_9f3d(cents, cur) { const f = FX_TABLE[cur] || 1; return cur + " " + (cents / 100 * f).toFixed(2); }`);
  L.push(`function qhash_ab12(s) { let h = 5381; for (let i = 0; i < s.length; i++) h = (h * 33 ^ s.charCodeAt(i)) >>> 0; return h.toString(16); }`);
  L.push(`function pad2_1a2b(n) { return n < 10 ? "0" + n : "" + n; }`);
  L.push(`class InvoiceLine { constructor(sku, qty, cents) { this.sku = sku; this.qty = qty; this.cents = cents; } total() { return this.qty * this.cents; } }`);
  L.push(`function computeOrderTotal(lines, region) {`);
  L.push(`  let sub = 0; for (const l of lines) sub += l.total();`);
  L.push(`  const tax = Math.round(sub * (REGION_TAX[region] || 0));`);
  L.push(`  return { sub, tax, grand: sub + tax };`);
  L.push(`}`);
  if (strongNames) {
    L.push(`// graph util - strongly connected components (Tarjan)`);
    L.push(`function scc_tarjan_c1n3(adj) {`);
    L.push(`  const idx = new Map(), low = new Map(), on = new Set(), st = [], out = [];`);
    L.push(`  let counter = 0;`);
    L.push(`  function strongconnect(v) {`);
    L.push(`    idx.set(v, counter); low.set(v, counter); counter++; st.push(v); on.add(v);`);
    L.push(`    for (const w of adj[v] || []) {`);
    L.push(`      if (!idx.has(w)) { strongconnect(w); low.set(v, Math.min(low.get(v), low.get(w))); }`);
    L.push(`      else if (on.has(w)) low.set(v, Math.min(low.get(v), idx.get(w)));`);
    L.push(`    }`);
    L.push(`    if (low.get(v) === idx.get(v)) { const comp = []; let w; do { w = st.pop(); on.delete(w); comp.push(w); } while (w !== v); out.push(comp); }`);
    L.push(`  }`);
    L.push(`  for (const v of Object.keys(adj)) if (!idx.has(v)) strongconnect(v);`);
    L.push(`  return out;`);
    L.push(`}`);
    L.push(`// batch obligation processor - drains the payment obligation queue`);
    L.push(`function obligationFlood_payments(queue, ledger) {`);
    L.push(`  const seen = new Set(); let applied = 0;`);
    L.push(`  while (queue.length) {`);
    L.push(`    const ob = queue.shift(); if (seen.has(ob.id)) continue; seen.add(ob.id);`);
    L.push(`    ledger.post(ob.account, ob.cents); applied++;`);
    L.push(`  }`);
    L.push(`  return applied;`);
    L.push(`}`);
    L.push(`// route dispatcher over the nested admin route tree`);
    L.push(`function labyrinthDispatch_router(routes, path) {`);
    L.push(`  let node = routes; for (const seg of path.split("/")) { node = node && node[seg]; if (!node) return null; }`);
    L.push(`  return node.handler || null;`);
    L.push(`}`);
    L.push(`// OAuth token sink - last writer wins`);
    L.push(`function tokenSink_oauth(store, tok) { store.set("access_token", tok.access); store.set("refresh_token", tok.refresh); }`);
  }
  L.push(`function renderTable_c3d4(rows) {`);
  L.push(`  let out = "<table>"; for (const r of rows) out += "<tr><td>" + r.join("</td><td>") + "</td></tr>";`);
  L.push(`  return out + "</table>";`);
  L.push(`}`);
  L.push(`const pendingTick = setInterval(() => {}, 60000);`);
  L.push(`void pendingTick; // keep interval reachable for leak-detector attach`);
  L.push(`const skuManifest = [];`);
  let i = 0;
  while (L.join("\n").length < size - 3000) {
    const tag = ((i * 4051) % 0xffff).toString(16).padStart(4, "0"); // 4-hex suffix
    L.push(`function sku_lookup_${tag}(id) { return skuManifest[${i}] ? skuManifest[${i}].byId[id] : null; }`);
    L.push(`skuManifest.push({ region: "r${i % 5}", byId: { "SKU-${1000 + i}": ${(i * 7919) % 50000}, "SKU-${2000 + i}": ${(i * 104729) % 90000} }, note: "generated catalog shard ${i} for pricebook sync" });`);
    i++;
  }
  if (genericTail) {
    L.push(`function finalizeBatch_0f3c(batch) { return batch.map((x) => ({ ...x, done: true })); }`);
    L.push(`function auditTrail_99aa(evt) { console.log("[audit]", evt); return evt; }`);
    L.push(`function cachePrime_2b3c(cache, rows) { for (const r of rows) cache.set(r.id, r); }`);
    L.push(`function dedupeSkus_4d5e(list) { return [...new Set(list.map((x) => x.sku))]; }`);
  }
  L.push(`module.exports = { InvoiceLine, computeOrderTotal, moneyFmt_9f3d, qhash_ab12, pad2_1a2b, renderTable_c3d4${strongNames ? ", scc_tarjan_c1n3, obligationFlood_payments, labyrinthDispatch_router, tokenSink_oauth" : ""}${genericTail ? ", finalizeBatch_0f3c, auditTrail_99aa, cachePrime_2b3c, dedupeSkus_4d5e" : ""} };`);
  if (strongNames) {
    L.push(`if (process.env.RUN_OBLIGATION_SWEEP === "1") obligationFlood_payments([], { post() {} });`);
  }
  return F(L.join("\n") + "\n");
}

// T3a: ~50KB real bundle, NO markers - control, expect byte-identical passthrough
write("t3a-clean-big.asar", packAsar([
  { path: "package.json", content: F(PKG) },
  { path: "app.bundle.js", content: bigBundle({ size: 51200 }), integrity: "auto" },
  { path: "enclave/shards/ring0-slot-ff_0.json", content: F("{}"), role: "decoy", expect: "dropped" },
]));

// T3b: marker strings inside a doc-comment only -> looksBlaHardened triggers on real code
write("t3b-marker-comment.asar", packAsar([
  { path: "package.json", content: F(PKG) },
  { path: "app.bundle.js", content: bigBundle({ markerComment: true, genericTail: true, size: 51200 }) },
]));

// T3c: real functions carrying BLA-strong names + callers referencing them
write("t3c-real-strongnames.asar", packAsar([
  { path: "package.json", content: F(PKG) },
  { path: "app.bundle.js", content: bigBundle({ strongNames: true, genericTail: true, size: 51200 }) },
]));

// T3d: marker comment + generic-suffix names in tail region only
write("t3d-generic-tail.asar", packAsar([
  { path: "package.json", content: F(PKG) },
  { path: "app.bundle.js", content: bigBundle({ markerComment: true, genericTail: true, size: 30000 }) },
]));

// T3e: hardened-markers under extensions the regex misses (.mts/.cts); .js twin controls
const hardenedMini = `// mini hardened-style payload
const _interlockSafetyCorpus_9ab = [1, 2, 3];
function obligationFlood_decoy() { return 0; }
function realWork() { return 42; }
void [obligationFlood_decoy];
module.exports = { realWork };
`;
write("t3e-ext-gap.asar", packAsar([
  { path: "package.json", content: F(PKG) },
  { path: "worker.mts", content: F(hardenedMini) },
  { path: "worker.cts", content: F(hardenedMini) },
  { path: "worker.js", content: F(hardenedMini), jsAllowedRemoved: ["obligationFlood_decoy", "_interlockSafetyCorpus_9ab"] },
]));

// ============================================================
// T4: BLA markers inside REAL entry names
// ============================================================
write("t4-markers-in-names.asar", packAsar([
  { path: "package.json", content: F(PKG) },
  { path: "docs/BLA-notes.md", content: F("# notes mentioning BLA\n"), role: "real" },
  { path: "docs/enclave-setup.md", content: F("# enclave setup guide\n"), role: "real" },
  { path: "BLA-top.txt", content: F("top file with BLA prefix\n"), role: "real" },
  { path: "x/.bla/inner.txt", content: F("nested .bla dir\n"), role: "real" },
  { path: "x/enclave/inner.txt", content: F("nested enclave dir\n"), role: "real" },
  { path: "x/.enclave/inner.txt", content: F("nested .enclave dir\n"), role: "real" },
  { path: "libs/bla/tool.js", content: F("exports.blaTool=1;\n"), role: "real" },
  { path: "pkg/.bla-meta.json", content: F("{}"), role: "real" },
  { path: "node_modules/.bin/enclave", content: F("#!/bin/sh\n"), role: "real", executable: true },
  { path: "enclave", content: F("top-level file literally named enclave\n"), role: "real" },
  { path: ".bla", content: F("top-level file literally named .bla\n"), role: "real" },
  { path: ".enclave", content: F("top-level file literally named .enclave\n"), role: "real" },
]));

// ============================================================
// T5: pickle framing edge cases
// ============================================================
const smallFiles = () => [
  { path: "package.json", content: F(PKG), integrity: "auto" },
  { path: "a.bin", content: Buffer.alloc(128, 0x61), integrity: "auto" },
  { path: "b.bin", content: Buffer.alloc(128, 0x62) },
];
// T5a: non-zero garbage in pickle pad region
write("t5a-nonzero-pad.asar", packAsar(smallFiles(), { padByte: 0xaa }));
// T5b: headerSize inflated +64 dead bytes between header and data
write("t5b-extra-headerpad.asar", packAsar(smallFiles(), { extraHeaderPad: 64 }));
// T5c: 4KB junk appended after last file
write("t5c-trailing-junk.asar", packAsar(smallFiles(), { trailer: Buffer.alloc(4096, 0xde) }));
// T5d: first u32 = 8 (noncanonical outer pickle size)
write("t5d-firstu32-8.asar", packAsar(smallFiles(), { firstU32: 8 }));
// T5e: jsonLen claims the aligned (padded) length instead of real json length
//   e1: pad is spaces -> JSON.parse tolerant, should still work
//   e2: pad is NULs  -> JSON.parse must fail
{
  const mk = (padByte, name) => {
    const root = { files: {} }; const chunks = []; let c = 0;
    for (const e of smallFiles()) {
      root.files[e.path] = { offset: String(c), size: e.content.length, integrity: integ(e.content) };
      chunks.push(e.content); c += e.content.length;
    }
    const json = Buffer.from(JSON.stringify(root), "utf8");
    const aligned = Math.ceil(json.length / 4) * 4;
    const hdr = Buffer.alloc(8 + aligned + 8, padByte);
    hdr.writeUInt32LE(4, 0); hdr.writeUInt32LE(aligned + 8, 4); hdr.writeUInt32LE(aligned + 4, 8);
    hdr.writeUInt32LE(aligned, 12);              // jsonLen claims padded length
    json.copy(hdr, 16);
    const manifest = { entries: {} };
    for (const e of smallFiles()) manifest.entries[e.path] = { role: "real", expect: "bytes", expectSha256: sha256(e.content) };
    write(name, { buf: Buffer.concat([hdr, ...chunks]), manifest });
  };
  mk(0x20, "t5e1-jsonlen-spaces.asar");
  mk(0x00, "t5e2-jsonlen-nulpad.asar");
}
// T5f: entry declares range beyond EOF -> silent truncation
write("t5f-entry-overrun.asar", packAsar([
  { path: "ok.bin", content: Buffer.alloc(64, 0x63) },
  { path: "huge.bin", content: Buffer.alloc(32, 0x64), declaredSize: 1e9, expect: "corrupt-watch" },
]));
// T5g: inner field lies, headerSize+jsonLen honest
{
  const root = { files: {} }; const chunks = []; let c = 0;
  for (const e of smallFiles()) {
    root.files[e.path] = { offset: String(c), size: e.content.length, integrity: integ(e.content) };
    chunks.push(e.content); c += e.content.length;
  }
  const json = Buffer.from(JSON.stringify(root), "utf8");
  const aligned = Math.ceil(json.length / 4) * 4;
  const hdr = Buffer.alloc(8 + aligned + 8);
  hdr.writeUInt32LE(4, 0); hdr.writeUInt32LE(aligned + 8, 4); hdr.writeUInt32LE(0, 8); // inner=0 (lies)
  hdr.writeUInt32LE(json.length, 12);
  json.copy(hdr, 16);
  const manifest = { entries: {} };
  for (const e of smallFiles()) manifest.entries[e.path] = { role: "real", expect: "bytes", expectSha256: sha256(e.content) };
  write("t5g-inner-lies.asar", { buf: Buffer.concat([hdr, ...chunks]), manifest });
}
// T5h: jsonLen already 4-aligned (control)
{
  const content = Buffer.alloc(5, 0x65);
  let name = "x";
  let root, json;
  do {
    name += "y";
    root = { files: { [name + ".bin"]: { offset: "0", size: 5 } } };
    json = Buffer.from(JSON.stringify(root), "utf8");
  } while (json.length % 4 !== 0);
  const hdr = Buffer.alloc(8 + json.length + 8);
  hdr.writeUInt32LE(4, 0); hdr.writeUInt32LE(json.length + 8, 4); hdr.writeUInt32LE(json.length + 4, 8); hdr.writeUInt32LE(json.length, 12);
  json.copy(hdr, 16);
  write("t5h-jsonlen-mult4.asar", { buf: Buffer.concat([hdr, content]), manifest: { entries: { [name + ".bin"]: { role: "real", expect: "bytes", expectSha256: sha256(content) } } } });
}
// T5i: two entries aliasing the same data range
{
  const shared = Buffer.alloc(64, 0x66);
  const { buf } = packAsar([
    { path: "one.bin", node: { offset: "0", size: 64 }, expectSha256: sha256(shared) },
    { path: "two.bin", node: { offset: "0", size: 64 }, expectSha256: sha256(shared) },
  ]);
  write("t5i-dup-offsets.asar", {
    buf: Buffer.concat([buf, shared]),
    manifest: { entries: { "one.bin": { role: "real", expect: "bytes", expectSha256: sha256(shared) }, "two.bin": { role: "real", expect: "bytes", expectSha256: sha256(shared) } } },
  });
}
// T5j: data section gap - b.bin at offset 100 (90 dead bytes)
{
  const a = Buffer.alloc(10, 0x67), gap = Buffer.alloc(90, 0), b = Buffer.alloc(10, 0x68);
  const { buf } = packAsar([
    { path: "a.bin", node: { offset: "0", size: 10 }, expectSha256: sha256(a) },
    { path: "b.bin", node: { offset: "100", size: 10 }, expectSha256: sha256(b) },
  ]);
  write("t5j-offset-gap.asar", {
    buf: Buffer.concat([buf, a, gap, b]),
    manifest: { entries: { "a.bin": { role: "real", expect: "bytes", expectSha256: sha256(a) }, "b.bin": { role: "real", expect: "bytes", expectSha256: sha256(b) } } },
  });
}
// T5k: entry size as STRING -> off + "64" string-concat bug.
// victim.bin is NOT the last entry, so the clamped slice swallows tail.bin too.
{
  const a = Buffer.alloc(64, 0x69), b = Buffer.alloc(64, 0x6a), c = Buffer.alloc(64, 0x70);
  const { buf } = packAsar([
    { path: "filler.bin", node: { offset: "0", size: 64 }, expectSha256: sha256(a) },
    { path: "victim.bin", node: { offset: "64", size: "64" }, expectSha256: sha256(b), expect: "bytes" },
    { path: "tail.bin", node: { offset: "128", size: 64 }, expectSha256: sha256(c) },
  ]);
  write("t5k-size-string.asar", {
    buf: Buffer.concat([buf, a, b, c]),
    manifest: { entries: { "filler.bin": { role: "real", expect: "bytes", expectSha256: sha256(a) }, "victim.bin": { role: "real", expect: "bytes", expectSha256: sha256(b) }, "tail.bin": { role: "real", expect: "bytes", expectSha256: sha256(c) } } },
  });
}
// T5l: offset NaN-ish + negative size
write("t5l-bad-offset.asar", packAsar([
  { path: "ok.bin", content: Buffer.alloc(32, 0x6b) },
  { path: "badoff.bin", node: { offset: "xyz", size: 10 }, expect: "corrupt-watch" },
  { path: "neg.bin", node: { offset: "0", size: -5 }, expect: "corrupt-watch" },
]));

// ============================================================
// T6: prototype-polluting entry names.
// NOTE: __proto__ keys must come through JSON.parse — assigning via
// obj["__proto__"]=x hits the setter and never creates an own property,
// so the packer can't be used for those trees (treeJson instead).
// ============================================================
{
  const polluted = F("exports.x=1;\n");
  const pkgLen = F(PKG).length;
  // raw JSON text: JSON.parse creates __proto__ as an OWN property
  const treeJson = `{"files":{"package.json":{"offset":"0","size":${pkgLen}},"__proto__":{"files":{"polluted.js":{"offset":"${pkgLen}","size":${polluted.length}}}}}}`;
  const { buf } = packAsar([], { treeJson });
  write("t6a-proto-dir.asar", {
    buf: Buffer.concat([buf, F(PKG), polluted]),
    manifest: { entries: { "package.json": { role: "real", expect: "bytes", expectSha256: sha256(F(PKG)) }, "__proto__/polluted.js": { role: "real", expect: "bytes", expectSha256: sha256(polluted) } } },
  });
}
{
  const protoFile = F("file literally named __proto__\n");
  const ok = Buffer.alloc(16, 0x6c);
  const pkgLen = F(PKG).length;
  const treeJson = `{"files":{"package.json":{"offset":"0","size":${pkgLen}},"__proto__":{"offset":"${pkgLen}","size":${protoFile.length}},"ok.bin":{"offset":"${pkgLen + protoFile.length}","size":${ok.length}}}}`;
  const { buf } = packAsar([], { treeJson });
  write("t6b-proto-file.asar", {
    buf: Buffer.concat([buf, F(PKG), protoFile, ok]),
    manifest: JSON.parse(`{"entries":{"package.json":${JSON.stringify({ role: "real", expect: "bytes", expectSha256: sha256(F(PKG)) })},"__proto__":${JSON.stringify({ role: "real", expect: "bytes", expectSha256: sha256(protoFile) })},"ok.bin":${JSON.stringify({ role: "real", expect: "bytes", expectSha256: sha256(ok) })}}}`),
  });
}
write("t6c-ctor-dir.asar", packAsar([
  { path: "package.json", content: F(PKG) },
  { path: "constructor/nested/x.js", content: F("exports.y=2;\n") },
]));
write("t6d-tostring-dir.asar", packAsar([
  { path: "package.json", content: F(PKG) },
  { path: "toString/f.js", content: F("exports.z=3;\n") },
  { path: "hasOwnProperty/g.js", content: F("exports.h=4;\n") },
]));

// ============================================================
// T7: structural oddities - files-as-null/array/string, dir+link hybrid.
// hybrid/inner.txt sits at data offset len(PKG) — where the trailer lands.
// ============================================================
{
  const inner = F("hello");
  const pkgLen = F(PKG).length;
  const { buf } = packAsar([
    { path: "package.json", content: F(PKG) },
    { path: "nulldir", node: { files: null }, expect: "corrupt-watch" },
    { path: "arrdir", node: { files: [{ size: 5, offset: "0" }] }, expect: "corrupt-watch" },
    { path: "strdir", node: { files: "x" }, expect: "corrupt-watch" },
    { path: "hybrid", node: { files: { "inner.txt": { offset: String(pkgLen), size: 5 } }, link: "elsewhere" }, expect: "corrupt-watch" },
  ]);
  write("t7-struct-oddities.asar", {
    buf: Buffer.concat([buf, inner]),
    manifest: {
      entries: {
        "package.json": { role: "real", expect: "bytes", expectSha256: sha256(F(PKG)) },
        "nulldir": { role: "real", expect: "corrupt-watch" },
        "arrdir/0": { role: "real", expect: "corrupt-watch" },
        "strdir/0": { role: "real", expect: "corrupt-watch" },
        "hybrid/inner.txt": { role: "real", expect: "bytes", expectSha256: sha256(inner) },
      },
    },
  });
}

console.log("fixtures written to", OUT);
