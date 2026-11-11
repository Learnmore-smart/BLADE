// Build plain (unprotected) test artifacts for the BLADE eval corpus.
import { mkdirSync, rmSync, writeFileSync, copyFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const plain = join(root, "test-fixtures", "plain");
mkdirSync(plain, { recursive: true });

// ---------- 1. Electron bridge JS (copy of BLA example) ----------
copyFileSync(
  join(root, "vendor", "bla", "examples", "notion-electron-bridge", "electron-bridge.js"),
  join(plain, "electron-bridge.js"),
);

// ---------- 2. License validator JS (real business logic with literals) ----------
writeFileSync(
  join(plain, "license-core.js"),
  `"use strict";
// Offline license verification core (customer business logic)
const GOLDEN_SCHEDULE = 0x9e3779b9;
const PLAN_MATRIX = {
  trial: { seats: 1, days: 14 },
  pro: { seats: 25, days: 365 },
  enterprise: { seats: 500, days: 1095 },
};

function fnv1a(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function deriveSessionTicket(serialKey, productCode) {
  const payload = serialKey + ":" + productCode + ":enterprise-v4";
  let acc = GOLDEN_SCHEDULE ^ fnv1a(payload);
  for (let r = 0; r < 8; r++) {
    acc = (Math.imul(acc ^ (acc >>> 13), 0x85ebca6b) + r) >>> 0;
  }
  return acc >>> 0;
}

function validateEnterpriseLicense(serialKey, productCode, expectedTicket) {
  if (!serialKey.startsWith("ENT-")) {
    return { valid: false, tier: "invalid", checksum: 0 };
  }
  const ticket = deriveSessionTicket(serialKey, productCode);
  const valid = ticket === (expectedTicket >>> 0);
  return {
    valid,
    tier: valid ? "enterprise-unlimited" : "invalid",
    checksum: ticket,
  };
}

function planLimits(tier) {
  return PLAN_MATRIX[tier] || PLAN_MATRIX.trial;
}

module.exports = {
  deriveSessionTicket,
  validateEnterpriseLicense,
  planLimits,
  fnv1a,
};
`,
);

// ---------- 3. Tiny WASM binary (hand-assembled, 2 exports) ----------
// \0asm version 1, type section (2 func types), func section (2 funcs),
// memory+export sections, code section with trivial bodies.
function leb(n) {
  const out = [];
  let v = n >>> 0;
  do {
    let b = v & 0x7f;
    v >>>= 7;
    if (v !== 0) b |= 0x80;
    out.push(b);
  } while (v !== 0);
  return Buffer.from(out);
}
function sect(id, payload) {
  return Buffer.concat([Buffer.from([id]), leb(payload.length), payload]);
}
function name(s) {
  const b = Buffer.from(s, "utf8");
  return Buffer.concat([leb(b.length), b]);
}
const typeSec = sect(1, Buffer.concat([
  leb(2),
  Buffer.from([0x60]), leb(2), Buffer.from([0x7f, 0x7f]), leb(1), Buffer.from([0x7f]), // (i32,i32)->i32
  Buffer.from([0x60]), leb(1), Buffer.from([0x7f]), leb(1), Buffer.from([0x7f]),      // (i32)->i32
]));
const funcSec = sect(3, Buffer.concat([leb(2), leb(0), leb(1)]));
const exportSec = sect(7, Buffer.concat([
  leb(3),
  name("license_seal"), Buffer.from([0x00]), leb(0),
  name("license_unseal"), Buffer.from([0x00]), leb(1),
  name("memory"), Buffer.from([0x02]), leb(0),
]));
const memSec = sect(5, Buffer.concat([leb(1), Buffer.from([0x00]), leb(1)])); // min 1 page
const codeSec = sect(10, Buffer.concat([
  leb(2),
  // func 0: local.get 0; local.get 1; i32.xor; end
  leb(7), leb(0), Buffer.from([0x20, 0x00, 0x20, 0x01, 0x73, 0x0b]),
  // func 1: local.get 0; i32.const 42; i32.add; end  (7 bytes: locals + 6)
  leb(7), leb(0), Buffer.from([0x20, 0x00, 0x41, 0x2a, 0x6a, 0x0b]),
]));
const wasm = Buffer.concat([Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]), typeSec, funcSec, memSec, exportSec, codeSec]);
writeFileSync(join(plain, "seal.wasm"), wasm);

// ---------- 4. SQLite DB with business data ----------
{
  rmSync(join(plain, "licenses.sqlite"), { force: true });
  const db = new DatabaseSync(join(plain, "licenses.sqlite"));
  db.exec(`
    CREATE TABLE license_cache (
      account_id TEXT PRIMARY KEY,
      plan_tier TEXT NOT NULL,
      offline_token TEXT NOT NULL
    );
    INSERT INTO license_cache VALUES
      ('acct_prod_01','enterprise','tok_live_9988776655'),
      ('acct_prod_02','pro','tok_live_1122334455');
    CREATE TABLE usage_counters (
      metric TEXT PRIMARY KEY,
      counter INTEGER NOT NULL
    );
    INSERT INTO usage_counters VALUES ('exports', 41), ('signins', 130);
  `);
  db.close();
}

// ---------- 5. Safetensors with 1 small tensor ----------
{
  const tensorData = Buffer.alloc(16, 0);
  tensorData.writeFloatLE(1.5, 0);
  tensorData.writeFloatLE(-2.25, 4);
  const header = {
    "__metadata__": { "general.architecture": "blade-test-mlp", "general.name": "fixture" },
    "mlp.weight": { dtype: "F32", shape: [2, 2], data_offsets: [0, 16] },
  };
  const rawJson = Buffer.from(JSON.stringify(header), "utf8");
  const jsonBytes = Buffer.alloc(Math.ceil(rawJson.length / 8) * 8, 0x20);
  rawJson.copy(jsonBytes);
  const lenPrefix = Buffer.alloc(8);
  lenPrefix.writeBigUInt64LE(BigInt(jsonBytes.length));
  writeFileSync(join(plain, "mlp.safetensors"), Buffer.concat([lenPrefix, jsonBytes, tensorData]));
}

// ---------- 6. GGUF v3 with a few metadata KV ----------
{
  function gstr(s) {
    const b = Buffer.from(s, "utf8");
    const l = Buffer.alloc(8);
    l.writeBigUInt64LE(BigInt(b.length));
    return Buffer.concat([l, b]);
  }
  const kvs = [];
  function kvStr(k, v) {
    const t = Buffer.alloc(4); t.writeUInt32LE(8);
    kvs.push(Buffer.concat([gstr(k), t, gstr(v)]));
  }
  function kvU32(k, v) {
    const t = Buffer.alloc(4); t.writeUInt32LE(4);
    const val = Buffer.alloc(4); val.writeUInt32LE(v);
    kvs.push(Buffer.concat([gstr(k), t, val]));
  }
  kvStr("general.architecture", "llama");
  kvStr("general.name", "blade-fixture");
  kvU32("llama.context_length", 4096);
  const hdr = Buffer.alloc(24);
  hdr.write("GGUF", 0, "ascii");
  hdr.writeUInt32LE(3, 4);
  hdr.writeBigUInt64LE(0n, 8);           // tensor count
  hdr.writeBigUInt64LE(BigInt(kvs.length), 16);
  writeFileSync(join(plain, "model.gguf"), Buffer.concat([hdr, ...kvs]));
}

// ---------- 7. Tiny ASAR containing the electron bridge ----------
{
  // Same Chromium-Pickle ASAR layout BLA/rea use.
  const files = [
    { relativePath: "package.json", content: Buffer.from(JSON.stringify({ name: "bridge-app", main: "electron-bridge.js" })) },
    { relativePath: "electron-bridge.js", content: Buffer.from(
      `const { contextBridge, ipcRenderer } = require("electron");
contextBridge.exposeInMainWorld("notionClipboard", {
  readRichBlocks: () => ipcRenderer.invoke("notion:clipboard:read-rich"),
  writeRichBlocks: (blocks) => ipcRenderer.invoke("notion:clipboard:write-rich", blocks),
});
`) },
  ];
  const root = { files: {} };
  const chunks = [];
  let off = 0;
  for (const f of files) {
    const segs = f.relativePath.split("/");
    let dir = root;
    for (const s of segs.slice(0, -1)) {
      dir.files[s] ??= { files: {} };
      dir = dir.files[s];
    }
    dir.files[segs[segs.length - 1]] = { offset: String(off), size: f.content.length };
    chunks.push(f.content);
    off += f.content.length;
  }
  const jsonBytes = Buffer.from(JSON.stringify(root), "utf8");
  const aligned = Math.ceil(jsonBytes.length / 4) * 4;
  const inner = aligned + 4;
  const headerSize = inner + 4;
  const hdr = Buffer.alloc(8 + headerSize);
  hdr.writeUInt32LE(4, 0);
  hdr.writeUInt32LE(headerSize, 4);
  hdr.writeUInt32LE(inner, 8);
  hdr.writeUInt32LE(jsonBytes.length, 12);
  jsonBytes.copy(hdr, 16);
  writeFileSync(join(plain, "app.asar"), Buffer.concat([hdr, ...chunks]));
}

// ---------- 8. Minimal ELF64 (no sections/segments — valid per BLA validator) ----------
{
  const elf = Buffer.alloc(64);
  elf.write("\x7fELF", 0, "latin1");
  elf[4] = 2; elf[5] = 1; elf[6] = 1;              // ELF64, LE, current
  elf.writeUInt16LE(2, 16);                        // ET_EXEC
  elf.writeUInt16LE(0x3e, 18);                     // x86_64
  elf.writeUInt32LE(1, 20);                        // version
  elf.writeBigUInt64LE(0x400000n, 24);             // entry
  elf.writeUInt16LE(64, 52);                       // ehsize
  const tail = Buffer.from("real license daemon build 4.2.0\0", "latin1");
  writeFileSync(join(plain, "daemon.elf"), Buffer.concat([elf, tail]));
}

// ---------- 9. Minimal Mach-O 64 (thin, no load commands) ----------
{
  const m = Buffer.alloc(32);
  m.writeUInt32BE(0xfeedfacf, 0);
  m.writeUInt32LE(0x01000007, 4);                  // CPU x86_64
  m.writeUInt32LE(3, 8);
  m.writeUInt32LE(2, 12);                          // MH_EXECUTE
  writeFileSync(join(plain, "tool.macho"), m);
}

// ---------- 10. Minimal PE (MZ + PE32+, no cert table) ----------
{
  const pe = Buffer.alloc(0x200);
  pe.write("MZ", 0, "latin1");
  pe.writeUInt32LE(0x80, 0x3c);                    // lfanew
  pe.write("PE\0\0", 0x80, "latin1");
  pe.writeUInt16LE(0x8664, 0x84);                  // machine
  pe.writeUInt16LE(2, 0x86);                       // sections
  pe.writeUInt16LE(0xf0, 0x94);                    // optional hdr size
  pe.writeUInt16LE(0x20b, 0x98);                   // PE32+ magic
  pe.writeUInt32LE(16, 0x98 + 108);                // number of rva dirs
  Buffer.from("license-svc\0", "latin1").copy(pe, 0x1c0);
  writeFileSync(join(plain, "service.exe"), pe);
}

// ---------- 11. .NET managed PE (BSJB marker) ----------
{
  const dll = Buffer.alloc(0x200);
  dll.write("MZ", 0, "latin1");
  dll.writeUInt32LE(0x80, 0x3c);
  dll.write("PE\0\0", 0x80, "latin1");
  dll.writeUInt16LE(0x14c, 0x84);
  dll.writeUInt16LE(0xe0, 0x94);
  dll.writeUInt16LE(0x10b, 0x98);
  Buffer.from("BSJB", "ascii").copy(dll, 0x120);   // CLR metadata root sig
  Buffer.from("LicenseVerifier\0", "latin1").copy(dll, 0x1c0);
  writeFileSync(join(plain, "Lib.dll"), dll);
}

// ---------- 12. classes.dex (valid header, checksums fixed) ----------
function fixDex(d) {
  d.writeUInt32LE(d.length, 32);                 // file_size first — it is signed
  const sha1 = createHash("sha1").update(d.subarray(32)).digest();
  sha1.copy(d, 12);
  let a = 1, b = 0;
  for (let i = 12; i < d.length; i++) { a = (a + d[i]) % 65521; b = (b + a) % 65521; }
  d.writeUInt32LE(((b << 16) | a) >>> 0, 8);
  return d;
}
{
  const dex = Buffer.alloc(112);
  dex.write("dex\n035\0", 0, "ascii");
  dex.writeUInt32LE(0x70, 36);
  dex.writeUInt32LE(0x12345678, 40);
  fixDex(dex);
  writeFileSync(join(plain, "classes.dex"), dex);
}

// ---------- 13. IL2CPP global-metadata.dat ----------
{
  const m = Buffer.alloc(256);
  m.writeUInt32LE(0xfab11baf, 0);
  m.writeInt32LE(29, 4);
  Buffer.from("LicenseManager\0IAPStore\0", "latin1").copy(m, 64);
  writeFileSync(join(plain, "global-metadata.dat"), m);
}

// ---------- 14. Apple XML plist ----------
writeFileSync(join(plain, "Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.example.licensetool</string>
  <key>CFBundleVersion</key>
  <string>4.2.0</string>
</dict>
</plist>
`);

// ---------- 15. Binary plist (bplist00, minimal valid trailer) ----------
{
  const body = Buffer.from("bplist00", "latin1");
  const obj = Buffer.concat([Buffer.from([0x5f, 0x10, 0x0c]), Buffer.from("LicenseRoot!", "latin1")]); // short ASCII str
  const offTable = Buffer.from([0x08]);
  const trailer = Buffer.alloc(32);
  trailer.writeUInt8(1, 6);        // offsetIntSize
  trailer.writeUInt8(1, 7);        // objectRefSize
  trailer.writeBigUInt64BE(1n, 8); // numObjects
  trailer.writeBigUInt64BE(0n, 16);
  trailer.writeBigUInt64BE(BigInt(body.length + obj.length), 24); // offset table offset
  writeFileSync(join(plain, "data.bplist"), Buffer.concat([body, obj, offTable, trailer]));
}

// ---------- 16. ZIP archive (BLA-strict subset: no extras/comments) ----------
function zipEntry(name, data) {
  const nb = Buffer.from(name, "ascii");
  const crc = crc32buf(data);
  const local = Buffer.alloc(30 + nb.length);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 8);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(nb.length, 26);
  nb.copy(local, 30);
  const central = Buffer.alloc(46 + nb.length);
  return { local: Buffer.concat([local, data]), central, name: nb, crc, size: data.length };
}
const CRC32_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) { let c = i; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[i] = c; }
  return t;
})();
function crc32buf(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC32_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function buildZip(files) {
  const parts = []; const centrals = []; let off = 0;
  for (const f of files) {
    const e = zipEntry(f.name, f.data);
    parts.push(e.local);
    e.central.writeUInt32LE(0x02014b50, 0);
    e.central.writeUInt16LE(20, 4); e.central.writeUInt16LE(20, 6);
    e.central.writeUInt16LE(0, 10);                              // method 0 stored
    e.central.writeUInt32LE(e.crc, 16);
    e.central.writeUInt32LE(e.size, 20); e.central.writeUInt32LE(e.size, 24);
    e.central.writeUInt16LE(e.name.length, 28);
    e.central.writeUInt32LE(off, 42);
    e.name.copy(e.central, 46);
    centrals.push(e.central);
    off += e.local.length;
  }
  const csize = centrals.reduce((a, b) => a + b.length, 0);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(csize, 12); eocd.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, ...centrals, eocd]);
}
{
  const dex = Buffer.alloc(112);
  dex.write("dex\n035\0", 0, "ascii");
  dex.writeUInt32LE(0x70, 36); dex.writeUInt32LE(0x12345678, 40);
  fixDex(dex);
  writeFileSync(join(plain, "bundle.zip"), buildZip([
    { name: "docs/readme.txt", data: Buffer.from("License tool v4.2 docs\n") },
    { name: "classes.dex", data: dex },
  ]));
  writeFileSync(join(plain, "app.apk"), buildZip([
    { name: "AndroidManifest.xml", data: Buffer.from("<manifest package=\"com.example.licensetool\"/>") },
    { name: "classes.dex", data: dex },
    { name: "res/values.xml", data: Buffer.from("<resources/>") },
  ]));
}

// ---------- 17. JVM .class (minimal, empty CP) ----------
{
  const cls = Buffer.alloc(24);
  cls.writeUInt32BE(0xcafebabe, 0);
  cls.writeUInt16BE(0, 4); cls.writeUInt16BE(52, 6);
  cls.writeUInt16BE(1, 8);                          // cp_count = 1 (empty)
  cls.writeUInt16BE(0x0021, 10);                    // access_flags public|super
  cls.writeUInt16BE(1, 12); cls.writeUInt16BE(0, 14);
  writeFileSync(join(plain, "Main.class"), cls);
}

// ---------- 18. Erlang BEAM (FOR1 + AtU8 + Code chunks) ----------
{
  const atoms = ["license_check", "verify", "seal"];
  const atu8 = [Buffer.alloc(4)];
  atu8[0].writeUInt32BE(atoms.length);
  for (const a of atoms) atu8.push(Buffer.from([a.length]), Buffer.from(a, "utf8"));
  const atu8Body = Buffer.concat(atu8);
  const chunk = (name, body) => {
    const pad = (4 - (body.length % 4)) % 4;
    const h = Buffer.alloc(8);
    h.write(name, 0, "latin1"); h.writeUInt32BE(body.length, 4);
    return Buffer.concat([h, body, Buffer.alloc(pad)]);
  };
  const body = Buffer.concat([
    Buffer.from("BEAM", "latin1"),
    chunk("AtU8", atu8Body),
    chunk("Code", Buffer.alloc(20, 0)),
  ]);
  const beam = Buffer.concat([Buffer.from("FOR1", "latin1"), Buffer.alloc(4), body]);
  beam.writeUInt32BE(body.length, 4);
  writeFileSync(join(plain, "core.beam"), beam);
}

// ---------- 19. EVM bytecode + Solidity CBOR trailer ----------
{
  const code = Buffer.from([0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15, 0x61, 0x00, 0x10, 0x57, 0x60, 0x00, 0x80, 0xfd, 0x5b, 0x50]);
  const meta = Buffer.from([0xa2, 0x64, 0x73, 0x6f, 0x6c, 0x63, 0x43, 0x00, 0x08, 0x1e, 0x64, 0x69, 0x70, 0x66, 0x73, 0x58, 0x22, 0x12, 0x20]);
  const metaBody = Buffer.concat([meta, Buffer.alloc(32, 0xab)]);
  const len = Buffer.alloc(2); len.writeUInt16BE(metaBody.length);
  writeFileSync(join(plain, "token.evm"), Buffer.concat([code, metaBody, len]));
}

// ---------- 20. CUDA PTX ----------
writeFileSync(join(plain, "kernel.ptx"), `// PTX ISA 7.0 — license checksum kernel
.version 7.0
.target sm_70
.address_size 64

.visible .entry license_mix(
  .param .u64 in,
  .param .u64 out
)
{
  .reg .u64 %rd<4>;
  ld.param.u64 %rd1, [in];
  ld.param.u64 %rd2, [out];
  xor.b64 %rd3, %rd1, 0x9e3779b97f4a7c15;
  st.u64 [%rd2], %rd3;
  ret;
}
`);

// ---------- 21. libpcap with 1 real packet ----------
{
  const gh = Buffer.alloc(24);
  gh.writeUInt32LE(0xa1b2c3d4, 0);
  gh.writeUInt16LE(2, 4); gh.writeUInt16LE(4, 6);
  gh.writeUInt32LE(65535, 16);
  gh.writeUInt32LE(1, 20);                          // LINKTYPE_ETHERNET
  const payload = Buffer.from("GET /license/status HTTP/1.1\r\nHost: api.example.com\r\n\r\n");
  const eth = Buffer.alloc(14, 0); eth[12] = 0x08;
  const ip = Buffer.alloc(20, 0); ip[0] = 0x45; ip[8] = 64; ip[9] = 6;
  ip.writeUInt16BE(20 + 20 + payload.length, 2);
  const tcp = Buffer.alloc(20, 0);
  tcp.writeUInt16BE(44321, 0); tcp.writeUInt16BE(443, 2); tcp[12] = 5 << 4; tcp[13] = 0x18;
  const frame = Buffer.concat([eth, ip, tcp, payload]);
  const rh = Buffer.alloc(16);
  rh.writeUInt32LE(1_700_000_000, 0);
  rh.writeUInt32LE(frame.length, 8); rh.writeUInt32LE(frame.length, 12);
  writeFileSync(join(plain, "capture.pcap"), Buffer.concat([gh, rh, frame]));
}

// ---------- 22. UF2 firmware (2 real main-flash blocks) ----------
{
  const block = (addr, no, n, fill) => {
    const b = Buffer.alloc(512);
    b.writeUInt32LE(0x0a324655, 0); b.writeUInt32LE(0x9e5d5157, 4);
    b.writeUInt32LE(0x2000, 8);                     // family-id flag
    b.writeUInt32LE(addr, 12);
    b.writeUInt32LE(256, 16);                       // payload size
    b.writeUInt32LE(no, 20); b.writeUInt32LE(n, 24);
    b.writeUInt32LE(0xe48bff56, 28);                // RP2040
    Buffer.from(fill, "latin1").copy(b, 32);
    b.writeUInt32LE(0x0ab16f30, 508);
    return b;
  };
  writeFileSync(join(plain, "fw.uf2"), Buffer.concat([
    block(0x10000000, 0, 2, "REAL_FIRMWARE_LICENSE_STAGE1"),
    block(0x10000100, 1, 2, "REAL_FIRMWARE_LICENSE_STAGE2"),
  ]));
}

// ---------- 23. CPython .pyc (16-byte hdr + marshal root tuple) ----------
{
  const hdr = Buffer.alloc(16);
  hdr.writeUInt16LE(0x9f0d, 0);                     // py3.11-ish magic
  hdr[2] = 0x0d; hdr[3] = 0x0a;
  const ascii = (s) => {
    const b = Buffer.from(s, "utf8");
    const h = Buffer.alloc(5); h[0] = 0x61; h.writeUInt32LE(b.length, 1);
    return Buffer.concat([h, b]);
  };
  const root = Buffer.concat([Buffer.from([0x29, 0x02]), ascii("license_core"), ascii("verify_seal")]); // TYPE_SMALL_TUPLE? use tuple
  writeFileSync(join(plain, "app.pyc"), Buffer.concat([hdr, root]));
}

// ---------- 24. Python source module ----------
writeFileSync(join(plain, "license.py"), `"""Offline license verification module."""
import hashlib

GOLDEN_SCHEDULE = 0x9E3779B9


def derive_session_ticket(serial_key: str, product_code: str) -> int:
    payload = f"{serial_key}:{product_code}:enterprise-v4"
    acc = GOLDEN_SCHEDULE ^ int.from_bytes(hashlib.sha256(payload.encode()).digest()[:4], "big")
    for r in range(8):
        acc = ((acc ^ (acc >> 13)) * 0x85EBCA6B + r) & 0xFFFFFFFF
    return acc


def validate_enterprise_license(serial_key: str, product_code: str, expected: int) -> bool:
    """Return True when the derived ticket matches."""
    if not serial_key.startswith("ENT-"):
        return False
    return derive_session_ticket(serial_key, product_code) == (expected & 0xFFFFFFFF)
`);

// ---------- 25. HTML bundle with inline scripts ----------
writeFileSync(join(plain, "app.html"), `<!doctype html>
<html><head><meta charset="utf-8"><title>License Tool</title>
<script type="module">
const PLAN = { pro: { seats: 25 }, enterprise: { seats: 500 } };
export function seatsFor(tier) { return (PLAN[tier] || PLAN.pro).seats; }
</script></head>
<body><div id="app"></div>
<script>
fetch("/api/v1/license/status").then(r => r.json()).then(s => console.log(s.tier));
</script>
</body></html>
`);

// ---------- 26. Source map (replaced wholesale by honey map) ----------
writeFileSync(join(plain, "app.js.map"), JSON.stringify({
  version: 3, file: "app.js",
  sources: ["src/app.ts"], sourcesContent: ["export const seats = 25;\n"],
  names: ["seats"], mappings: "AAAA",
}));

console.log("fixtures written to", plain);
for (const f of ["electron-bridge.js","license-core.js","seal.wasm","licenses.sqlite","mlp.safetensors","model.gguf","app.asar","daemon.elf","tool.macho","service.exe","Lib.dll","classes.dex","global-metadata.dat","Info.plist","data.bplist","bundle.zip","app.apk","Main.class","core.beam","token.evm","kernel.ptx","capture.pcap","fw.uf2","app.pyc","license.py","app.html","app.js.map"]) console.log(" -", f);
