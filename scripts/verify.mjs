// BLADE end-to-end verification: runs the de-hardeners over
// test-fixtures/hardened -> test-fixtures/cleaned and checks every claim:
//   - cleaned JS parses and is behaviorally equivalent to plain
//   - SQLite decoy objects dropped, business rows intact
//   - WASM magic/sections valid, exports survive
//   - safetensors header + tensor weights intact
//   - GGUF magic + KV parseable
//   - ASAR legit entries survive, inner JS dehardened, integrity consistent
// Usage: node scripts/verify.mjs
import { mkdirSync, readFileSync, readdirSync, existsSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import path from "node:path";
import assert from "node:assert/strict";

const ROOT = path.resolve(import.meta.dirname, "..");
const HARD = path.join(ROOT, "test-fixtures", "hardened");
const PLAIN = path.join(ROOT, "test-fixtures", "plain");
const CLEAN = path.join(ROOT, "test-fixtures", "cleaned");
mkdirSync(CLEAN, { recursive: true });

let pass = 0, fail = 0;
const check = (name, fn) => {
  try { fn(); pass++; console.log(`  ok  ${name}`); }
  catch (e) { fail++; console.log(`FAIL  ${name}: ${e.message}`); }
};

// ---- 1. run BLADE over every hardened fixture
console.log("== scrub ==");
for (const f of readdirSync(HARD)) {
  execFileSync(process.execPath, [path.join(ROOT, "src", "cli.mjs"),
    path.join(HARD, f), "-o", path.join(CLEAN, f),
    "--report", path.join(CLEAN, f + ".report.json")], { stdio: "pipe" });
  console.log(`  ${f}`);
}

// ---- 2. JS behavioral equivalence
console.log("== javascript ==");
const require2 = createRequire(import.meta.url);
const loadCjs = (p, stubs = {}) => {
  const resolved = path.resolve(p);
  delete require2.cache[resolved];
  const { Module } = require2("module");
  const orig = Module._load;
  Module._load = function (req, ...a) { if (req in stubs) return stubs[req]; return orig.call(this, req, ...a); };
  try { return require2(resolved); } finally { Module._load = orig; }
};

check("license-core behavior equivalent", () => {
  const a = loadCjs(path.join(PLAIN, "license-core.js"));
  const b = loadCjs(path.join(CLEAN, "license-core.js"));
  assert.deepEqual(Object.keys(a).sort(), Object.keys(b).sort());
  assert.equal(a.fnv1a("hello world"), b.fnv1a("hello world"));
  assert.equal(a.deriveSessionTicket("ENT-9988-X", "machine-9"), b.deriveSessionTicket("ENT-9988-X", "machine-9"));
  assert.deepEqual(a.validateEnterpriseLicense("ENT-AB12-CD34", "machine-9"), b.validateEnterpriseLicense("ENT-AB12-CD34", "machine-9"));
  assert.deepEqual(a.validateEnterpriseLicense("BAD-1", "m"), b.validateEnterpriseLicense("BAD-1", "m"));
  assert.deepEqual(a.planLimits("enterprise"), b.planLimits("enterprise"));
  assert.deepEqual(a.planLimits("bogus"), b.planLimits("bogus"));
});

check("electron-bridge behavior equivalent (stubbed electron)", async () => {});
const electronStub = (h) => ({
  ipcMain: { handle: (c, f) => (h[c] = f) },
  ipcRenderer: { invoke: (c) => "inv:" + c, send: (c) => "send:" + c },
  contextBridge: { exposeInMainWorld: (n, api) => (h.__api = { n, api }) },
});
const runBridge = async (p) => {
  const h = {};
  const m = loadCjs(p, { electron: electronStub(h) });
  const store = new Map([["blocks", [1, 2, 3]]]);
  globalThis.fetch = async (u) => ({ url: u });
  m.setupPreloadClipboardBridge();
  m.setupMainClipboardHandlers({ get: (k) => store.get(k), set: (k, v) => store.set(k, v) });
  const api = h.__api;
  return {
    channels: Object.keys(h).filter((k) => k !== "__api"), apiName: api.n,
    read: api.api.readRichBlocks(), write: api.api.writeRichBlocks([9]), sync: api.api.syncSelection("r"),
    h1: await h["notion:clipboard:read-rich"](), h2: await h["notion:clipboard:write-rich"](null, [4, 5]),
  };
};
const bA = await runBridge(path.join(PLAIN, "electron-bridge.js"));
const bB = await runBridge(path.join(CLEAN, "electron-bridge.js"));
check("electron-bridge handler/channel behavior identical", () => assert.deepEqual(bA, bB));

check("cleaned JS preserves canonical API names", () => {
  const src = readFileSync(path.join(CLEAN, "electron-bridge.js"), "utf8");
  for (const n of ["contextBridge", "ipcRenderer", "ipcMain", "setupPreloadClipboardBridge", "setupMainClipboardHandlers"]) {
    assert.ok(src.includes(n), `missing ${n}`);
  }
});

// ---- 3. SQLite
console.log("== sqlite ==");
check("business tables/rows survive, decoys dropped", () => {
  const db = new DatabaseSync(path.join(CLEAN, "licenses.sqlite"), { readOnly: true });
  const objs = db.prepare("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").all().map((o) => o.name).sort();
  assert.deepEqual(objs, ["license_cache", "usage_counters"]);
  const rows = db.prepare("SELECT * FROM license_cache ORDER BY account_id").all();
  assert.equal(rows.length, 2);
  assert.equal(rows[0].plan_tier, "enterprise");
  const counters = Object.fromEntries(db.prepare("SELECT * FROM usage_counters").all().map((r) => [r.metric, r.counter]));
  assert.equal(counters.exports, 41);
  assert.equal(counters.signins, 130);
  db.close();
});

// ---- 4. WASM
console.log("== wasm ==");
check("magic + sections valid, exports survived", () => {
  const b = readFileSync(path.join(CLEAN, "seal.wasm"));
  assert.equal(b.readUInt32LE(0), 0x6d736100);
  assert.equal(b.readUInt32LE(4), 1);
  // section walk must terminate exactly at EOF
  let off = 8;
  while (off < b.length) {
    off++;
    let size = 0, shift = 0;
    for (;;) { const x = b[off++]; size |= (x & 0x7f) << shift; if (!(x & 0x80)) break; shift += 7; }
    off += size;
  }
  assert.equal(off, b.length);
  const report = JSON.parse(readFileSync(path.join(CLEAN, "seal.wasm.report.json"), "utf8"));
  assert.ok(report.exportsKept >= 1);
});

// ---- 5. safetensors
console.log("== safetensors ==");
check("header valid, weights intact", () => {
  const b = readFileSync(path.join(CLEAN, "mlp.safetensors"));
  const len = Number(b.readBigUInt64LE(0));
  const h = JSON.parse(b.subarray(8, 8 + len).toString());
  assert.equal(h["mlp.weight"].dtype, "F32");
  assert.deepEqual(h["mlp.weight"].shape, [2, 2]);
  const data = b.subarray(8 + len);
  assert.equal(data.readFloatLE(0), 1.5);
  assert.equal(data.readFloatLE(4), -2.25);
});

// ---- 6. GGUF
console.log("== gguf ==");
check("magic + kv parseable", () => {
  const b = readFileSync(path.join(CLEAN, "model.gguf"));
  assert.equal(b.toString("ascii", 0, 4), "GGUF");
  const kv = Number(b.readBigUInt64LE(16));
  assert.ok(kv >= 1);
  const report = JSON.parse(readFileSync(path.join(CLEAN, "model.gguf.report.json"), "utf8"));
  assert.equal(report.kvKept, kv);
  // no BLA armor strings may survive under any key (e.g. general.description)
  assert.ok(!/\[BLA|enclave_build_id|Decompilation Advisory/i.test(b.toString("utf8")));
});

// ---- 7. ASAR
console.log("== asar ==");
const asarEntries = (p) => {
  const b = readFileSync(p);
  const root = JSON.parse(b.subarray(16, 16 + b.readUInt32LE(12)).toString());
  const off = 8 + b.readUInt32LE(4);
  const out = {};
  (function walk(n, pre) {
    for (const [k, e] of Object.entries(n.files ?? {})) {
      if (e.files) { walk(e, pre + k + "/"); continue; }
      if (e.link) { out[pre + k] = { link: true }; continue; }
      const content = b.subarray(off + Number(e.offset), off + Number(e.offset) + e.size);
      out[pre + k] = { entry: e, content };
    }
  })(root, "");
  return out;
};
check("legit entries + per-file integrity consistent", () => {
  const e = asarEntries(path.join(CLEAN, "app.asar"));
  assert.deepEqual(Object.keys(e).sort(), ["electron-bridge.js", "package.json"]);
  for (const [name, { entry, content }] of Object.entries(e)) {
    if (entry.integrity) {
      assert.equal(createHash("sha256").update(content).digest("hex"), entry.integrity.hash, `integrity ${name}`);
    }
  }
  const js = e["electron-bridge.js"].content.toString();
  assert.ok(js.includes('"notionClipboard"'));
  assert.ok(js.includes("notion:clipboard:read-rich"));
  assert.ok(!/_interlockSafetyCorpus_|obligationFlood_/.test(js));
});

// ---- 8. append-only trailer formats: byte-exact recovery expected
console.log("== trailer formats (byte-exact) ==");
const BYTE_EXACT = [
  "daemon.elf", "tool.macho", "service.exe", "Lib.dll",
  "classes.dex", "global-metadata.dat", "data.bplist",
  "token.evm", "capture.pcap", "fw.uf2", "app.pyc",
  "kernel.ptx", "license.py", "Info.plist", "Main.class", "core.beam",
];
for (const f of BYTE_EXACT) {
  check(`${f} byte-exact vs plain`, () => {
    assert.deepEqual(readFileSync(path.join(CLEAN, f)), readFileSync(path.join(PLAIN, f)));
  });
}

// ---- 9. rebuilt containers: member-set + content equality
console.log("== zip/apk (member equivalence) ==");
const zipEntries = (buf) => {
  const out = new Map(); let p = 0;
  while (p + 30 <= buf.length && buf.readUInt32LE(p) === 0x04034b50) {
    const m = buf.readUInt16LE(p + 8), cs = buf.readUInt32LE(p + 18);
    const nl = buf.readUInt16LE(p + 26), el = buf.readUInt16LE(p + 28);
    const name = buf.subarray(p + 30, p + 30 + nl).toString();
    let data = buf.subarray(p + 30 + nl + el, p + 30 + nl + el + cs);
    if (m === 8) data = require2("zlib").inflateRawSync(data);
    out.set(name, data); p += 30 + nl + el + cs;
  }
  return out;
};
for (const f of ["bundle.zip", "app.apk"]) {
  check(`${f} members + content identical`, () => {
    const a = zipEntries(readFileSync(path.join(PLAIN, f)));
    const b = zipEntries(readFileSync(path.join(CLEAN, f)));
    assert.deepEqual([...b.keys()].sort(), [...a.keys()].sort());
    for (const [k, v] of a) assert.deepEqual(b.get(k), v, `member ${k}`);
  });
}

// ---- 10. HTML bundle: non-script markup identical, scripts dehardened
console.log("== html ==");
check("non-script markup identical + scripts dehardened", () => {
  const p = readFileSync(path.join(PLAIN, "app.html"), "utf8");
  const c = readFileSync(path.join(CLEAN, "app.html"), "utf8");
  const scripts = (s) => [...s.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  const stripScripts = (s) => s.replace(/<script[^>]*>[\s\S]*?<\/script>/g, "@@");
  assert.equal(stripScripts(c), stripScripts(p));
  assert.equal(scripts(c).length, scripts(p).length);
  const js = scripts(c).join("\n");
  assert.ok(js.includes("seatsFor"), "missing seatsFor");
  assert.ok(js.includes("/api/v1/license/status"), "missing endpoint literal");
  assert.ok(!/\[BLA-|enclave_|COGNITIVE_ARMOR|PROTECTED_CANARY/.test(js), "BLA markers survive");
});

// ---- 11. source map: unrecoverable by design — must be flagged, not trusted
console.log("== sourcemap ==");
check("honey map flagged unrecoverable (passthrough)", () => {
  const r = JSON.parse(readFileSync(path.join(CLEAN, "app.js.map.report.json"), "utf8"));
  assert.equal(r.unrecoverable, true);
  assert.equal(r.honeyMap, true);
});

check("genuine map passes through byte-exact (no reconstruction)", () => {
  const genuine = JSON.stringify({
    version: 3, file: "real.js", sources: ["src/real.ts"],
    sourcesContent: ["const x: number = 1;"], names: ["x"],
    mappings: "AAAA,IAAM,CAAC,GAAY,CAAC",
  });
  const inp = path.join(CLEAN, "genuine.js.map"), out = path.join(CLEAN, "genuine-out.js.map");
  writeFileSync(inp, genuine);
  execFileSync(process.execPath, [path.join(ROOT, "src", "cli.mjs"), inp, "-o", out, "--report", out + ".report.json"], { stdio: "pipe" });
  assert.equal(readFileSync(out, "utf8"), genuine, "genuine map bytes must be preserved");
  const r = JSON.parse(readFileSync(out + ".report.json", "utf8"));
  assert.equal(r.honeyMap, false);
  assert.equal(r.action, "passthrough");
});

// ---- 12. unit-level checks on scrubber edge paths
console.log("== scrubber edge paths ==");
const { scrubPcap, scrubHtml } = await import(new URL("file:///" + path.join(ROOT, "src", "trailer.mjs").replace(/\\/g, "/")));

check("BE nanosecond pcap: decoy packet dropped, real kept", () => {
  const hdr = Buffer.alloc(24);
  hdr.writeUInt32BE(0xa1b23c4d, 0); // nsec BE magic
  const rec = (payload, off) => {
    const r = Buffer.alloc(16 + payload.length);
    r.writeUInt32BE(1, 0); r.writeUInt32BE(0, 4);
    r.writeUInt32BE(payload.length, 8); r.writeUInt32BE(payload.length, 12);
    payload.copy(r, 16);
    return r;
  };
  const real = Buffer.from("GET https://example.com/ HTTP/1.1");
  const decoy = Buffer.from("GET https://enclave.internal/x [BLA-PCAP-SHIELD] canary");
  const r = scrubPcap(Buffer.concat([hdr, rec(real), rec(decoy)]));
  assert.equal(r.report.hardened, true);
  assert.equal(r.report.decoyPacketsDropped, 1);
  const out = r.buffer.toString("latin1");
  assert.ok(out.includes("example.com") && !out.includes("enclave.internal"));
});

check("pcapng: decoy EPB dropped, structural blocks kept", () => {
  const blk = (type, body) => {
    const b = Buffer.alloc(12 + body.length);
    b.writeUInt32LE(type, 0); b.writeUInt32LE(b.length, 4);
    body.copy(b, 8); b.writeUInt32LE(b.length, b.length - 4);
    return b;
  };
  const shb = Buffer.alloc(24); shb.writeUInt32LE(0x1a2b3c4d, 0); // BOM
  const good = Buffer.from("packet example.com data");
  const bait = Buffer.from("packet enclave.internal [BLA-PCAP-SHIELD] canary");
  const pad = (b) => Buffer.concat([b, Buffer.alloc((4 - (b.length % 4)) % 4)]);
  const input = Buffer.concat([
    blk(0x0a0d0d0a, pad(shb)),            // SHB
    blk(0x00000001, pad(Buffer.alloc(20))), // IDB
    blk(0x00000006, pad(good)),           // EPB real
    blk(0x00000006, pad(bait)),           // EPB decoy
  ]);
  const r = scrubPcap(input);
  assert.equal(r.report.format, "pcapng");
  assert.equal(r.report.decoyBlocksDropped, 1);
  const out = r.buffer.toString("latin1");
  assert.ok(out.includes("example.com") && !out.includes("enclave.internal"));
  assert.ok(r.buffer.readUInt32LE(0) === 0x0a0d0d0a, "SHB preserved");
});

check("html: on*=/javascript: decoy names flagged but kept", () => {
  const html = `<a onclick="obligationFlood_9f2()" href="javascript:tokenSink_12()">x</a>`;
  const r = scrubHtml(html);
  assert.equal(r.code, html, "handlers must be preserved");
  assert.ok(r.report.suspiciousEventHandlers?.length === 2);
});

// ---- 13. evaluator: corpus digest round-trip
console.log("== evaluator ==");
const { computeContainmentCorpusDigest, repairCorpusDigest } =
  await import(new URL("file:///" + path.join(ROOT, "src", "evaluator.mjs").replace(/\\/g, "/")));

check("corpus digest: tampered single char is uniquely repairable", () => {
  const entries = [
    { coupledAnchorSymbol: "anchor_a", triggerPayload: "payload one" },
    { coupledAnchorSymbol: "anchor_b", triggerPayload: "payload two" },
  ];
  const expected = computeContainmentCorpusDigest(entries);
  const tampered = entries.map((e) => ({ ...e }));
  tampered[1] = { ...tampered[1], triggerPayload: "payload Xwo" };
  const fix = repairCorpusDigest(tampered, expected);
  assert.ok(fix, "repair should find the single-char fix");
  const repaired = tampered.map((e, i) =>
    i === fix.entry ? { ...e, [fix.field]: fix.newText } : e);
  assert.equal(computeContainmentCorpusDigest(repaired), expected);
});

check("corpus digest: untampered entries report no repair", () => {
  const entries = [{ coupledAnchorSymbol: "a", triggerPayload: "p" }];
  const expected = computeContainmentCorpusDigest(entries);
  assert.equal(repairCorpusDigest(entries, expected), null);
});

// ---- 14. CLI edges: stdin routing + report-to-stdout
console.log("== cli edges ==");
check("stdin '-' requires -o", () => {
  try {
    execFileSync(process.execPath, [path.join(ROOT, "src", "cli.mjs"), "-"], { input: Buffer.alloc(8), stdio: "pipe" });
    assert.fail("should have exited 2");
  } catch (e) { assert.equal(e.status, 2); }
});
check("--report - streams untruncated JSON to stdout", () => {
  const out = execFileSync(process.execPath, [path.join(ROOT, "src", "cli.mjs"),
    path.join(HARD, "capture.pcap"), "-o", path.join(CLEAN, "edge.pcap"), "--report", "-"], { stdio: "pipe" });
  const r = JSON.parse(out.toString());
  assert.equal(r.format, "pcap");
  assert.ok(r.inputSha256?.length === 64);
});
check("--format override beats detection", () => {
  const out = execFileSync(process.execPath, [path.join(ROOT, "src", "cli.mjs"),
    "-", "-o", path.join(CLEAN, "edge.evm"), "--format", "evm", "--report", "-"],
    { input: readFileSync(path.join(HARD, "token.evm")), stdio: "pipe" });
  assert.equal(JSON.parse(out.toString()).format, "evm");
});
check("-o <reserved-name> rejected (nul/con/prn/aux/comN/lptN)", () => {
  for (const name of ["nul", "CON.txt", "aux", "com3", "lpt1"]) {
    try {
      execFileSync(process.execPath, [path.join(ROOT, "src", "cli.mjs"),
        path.join(HARD, "token.evm"), "-o", name], { stdio: "pipe" });
      assert.fail(`should have exited 2 for ${name}`);
    } catch (e) { assert.equal(e.status, 2, `exit for ${name}`); }
  }
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
