// BLADE detect() adversarial audit — crafts edge-case inputs under
// test-fixtures/adversarial/detect/ and runs each through src/cli.mjs,
// recording: detected kind, exit code, crash signature, and whether the
// routing matches the scrubber BLA's format would need.
//
// Usage: node scripts/audit-detect.mjs
import { mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, dirname, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIX = join(ROOT, "test-fixtures", "adversarial", "detect");
const OUT = join(FIX, "_out");
const REP = join(FIX, "_reports");
mkdirSync(FIX, { recursive: true });
mkdirSync(OUT, { recursive: true });
mkdirSync(REP, { recursive: true });

const F = (name, buf) => writeFileSync(join(FIX, name), buf);

// ============================ fixture builders ============================
function minimalClass() {
  const cls = Buffer.alloc(24);
  cls.writeUInt32BE(0xcafebabe, 0);
  cls.writeUInt16BE(0, 4); cls.writeUInt16BE(52, 6);   // minor 0, major 52
  cls.writeUInt16BE(1, 8);                            // cp_count = 1
  cls.writeUInt16BE(0x0021, 10);                      // access flags
  cls.writeUInt16BE(1, 12); cls.writeUInt16BE(0, 14); // this/super
  return cls;
}
const CLASS = minimalClass();
const JVM_TRAILER = Buffer.from("\0BLA_JVM_SHIELD_V1{\"decoy\":\"enclave\"}", "latin1");

function fatMachO() {
  const m = Buffer.alloc(48);
  m.writeUInt32BE(0xcafebabe, 0);          // FAT_MAGIC
  m.writeUInt32BE(2, 4);                   // nfat_arch = 2
  m.writeUInt32BE(0x01000007, 8);          // cputype x86_64
  m.writeUInt32BE(3, 12);
  m.writeUInt32BE(0x1000, 16); m.writeUInt32BE(0x2000, 20); m.writeUInt32BE(12, 24);
  m.writeUInt32BE(0x0100000c, 28);         // cputype arm64
  m.writeUInt32BE(0, 32);
  m.writeUInt32BE(0x3000, 36); m.writeUInt32BE(0x2000, 40); m.writeUInt32BE(12, 44);
  return m;
}
const FATMACHO = fatMachO();
const NATIVE_TRAILER = Buffer.from("\0[BLA-NATIVE-SHIELD-V1]RUSTC-FLOOD|FUSE-BAIT|CANARY", "latin1");

function elf64() {
  const elf = Buffer.alloc(64);
  elf.write("\x7fELF", 0, "latin1");
  elf[4] = 2; elf[5] = 1; elf[6] = 1;
  elf.writeUInt16LE(2, 16); elf.writeUInt16LE(0x3e, 18);
  elf.writeBigUInt64LE(0x400000n, 24);
  elf.writeUInt16LE(64, 52);
  return Buffer.concat([elf, Buffer.from("license daemon 4.2\0", "latin1")]);
}
const ELF = elf64();

function pcapngBuf() {
  const b = Buffer.alloc(32);
  b.writeUInt32LE(0x0a0d0d0a, 0);          // SHB magic
  b.writeUInt32LE(28, 4);                  // block total length
  b.writeUInt32LE(0x1a2b3c4d, 8);          // byte-order magic
  b.writeUInt16LE(1, 12); b.writeUInt16LE(0, 14);
  b.writeUInt32LE(28, 28);                 // trailing block length
  return b;
}
function pcapLE(magicLE) {
  const gh = Buffer.alloc(24);
  gh.writeUInt32LE(magicLE, 0);
  gh.writeUInt16LE(2, 4); gh.writeUInt16LE(4, 6);
  gh.writeUInt32LE(65535, 16); gh.writeUInt32LE(1, 20);
  return gh;
}
function pcapBE() {
  const gh = Buffer.alloc(24);
  gh.writeUInt32BE(0xa1b2c3d4, 0);
  gh.writeUInt16BE(2, 4); gh.writeUInt16BE(4, 6);
  gh.writeUInt32BE(65535, 16); gh.writeUInt32BE(1, 20);
  return gh;
}

// minimal zip (stored, EOCD at EOF — same writer style as BLA/BLADE fixtures)
const CRC32_TABLE = (() => { const t = new Uint32Array(256); for (let i = 0; i < 256; i++) { let c = i; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[i] = c; } return t; })();
function crc32buf(buf) { let c = 0xffffffff; for (let i = 0; i < buf.length; i++) c = CRC32_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
function buildZip(files) {
  const parts = [], centrals = []; let off = 0;
  for (const f of files) {
    const nb = Buffer.from(f.name, "utf8");
    const crc = crc32buf(f.data);
    const local = Buffer.alloc(30 + nb.length);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 8); local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(f.data.length, 18); local.writeUInt32LE(f.data.length, 22);
    local.writeUInt16LE(nb.length, 26); nb.copy(local, 30);
    const central = Buffer.alloc(46 + nb.length);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 10); central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(f.data.length, 20); central.writeUInt32LE(f.data.length, 24);
    central.writeUInt16LE(nb.length, 28); central.writeUInt32LE(off, 42);
    nb.copy(central, 46);
    parts.push(Buffer.concat([local, f.data])); centrals.push(central);
    off += local.length + f.data.length;
  }
  const csize = centrals.reduce((a, b) => a + b.length, 0);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(csize, 12); eocd.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, ...centrals, eocd]);
}
function dexPlain() {
  const d = Buffer.alloc(112);
  d.write("dex\n035\0", 0, "ascii");
  d.writeUInt32LE(0x70, 36); d.writeUInt32LE(0x12345678, 40);
  d.writeUInt32LE(d.length, 32);
  createHash("sha1").update(d.subarray(32)).digest().copy(d, 12);
  let a = 1, b = 0;
  for (let i = 12; i < d.length; i++) { a = (a + d[i]) % 65521; b = (b + a) % 65521; }
  d.writeUInt32LE(((b << 16) | a) >>> 0, 8);
  return d;
}
const DEX_TRAILER = Buffer.from("\0[BLA-DEX-SHIELD-V1]DECOY-XREF", "latin1");

function safetensorsBuf() {
  const header = { "w": { dtype: "F32", shape: [1], data_offsets: [0, 4] } };
  const rawJson = Buffer.from(JSON.stringify(header), "utf8");
  const json = Buffer.alloc(Math.ceil(rawJson.length / 8) * 8, 0x20);
  rawJson.copy(json);
  const len = Buffer.alloc(8); len.writeBigUInt64LE(BigInt(json.length));
  return Buffer.concat([len, json, Buffer.alloc(4)]);
}
function ggufBuf() {
  const h = Buffer.alloc(24);
  h.write("GGUF", 0, "ascii"); h.writeUInt32LE(3, 4);
  h.writeBigUInt64LE(0n, 8); h.writeBigUInt64LE(0n, 16);
  return h;
}
function asarBuf() {
  const root = { files: { "a.js": { offset: "0", size: 2 } } };
  const json = Buffer.from(JSON.stringify(root), "utf8");
  const aligned = Math.ceil(json.length / 4) * 4;
  const inner = aligned + 4, headerSize = inner + 4;
  const hdr = Buffer.alloc(8 + headerSize);
  hdr.writeUInt32LE(4, 0); hdr.writeUInt32LE(headerSize, 4);
  hdr.writeUInt32LE(inner, 8); hdr.writeUInt32LE(json.length, 12);
  json.copy(hdr, 16);
  return Buffer.concat([hdr, Buffer.from("x;")]);
}
function beamBuf() {
  const atoms = ["go"];
  const atu8 = [Buffer.alloc(4)]; atu8[0].writeUInt32BE(atoms.length);
  for (const a of atoms) atu8.push(Buffer.from([a.length]), Buffer.from(a, "utf8"));
  const chunk = (n, body) => { const h = Buffer.alloc(8); h.write(n, 0, "latin1"); h.writeUInt32BE(body.length, 4); const pad = (4 - (body.length % 4)) % 4; return Buffer.concat([h, body, Buffer.alloc(pad)]); };
  const body = Buffer.concat([Buffer.from("BEAM", "latin1"), chunk("AtU8", Buffer.concat(atu8))]);
  const out = Buffer.concat([Buffer.from("FOR1", "latin1"), Buffer.alloc(4), body]);
  out.writeUInt32BE(body.length, 4);
  return out;
}
function uf2Buf() {
  const b = Buffer.alloc(512);
  b.writeUInt32LE(0x0a324655, 0); b.writeUInt32LE(0x9e5d5157, 4);
  b.writeUInt32LE(0x2000, 8); b.writeUInt32LE(0x10000000, 12); b.writeUInt32LE(256, 16);
  b.writeUInt32LE(0x0ab16f30, 508);
  return b;
}
function pycBuf() {
  const hdr = Buffer.alloc(16);
  hdr.writeUInt16LE(0x9f0d, 0); hdr[2] = 0x0d; hdr[3] = 0x0a;
  const ascii = (s) => { const b = Buffer.from(s, "utf8"); const h = Buffer.alloc(5); h[0] = 0x61; h.writeUInt32LE(b.length, 1); return Buffer.concat([h, b]); };
  return Buffer.concat([hdr, Buffer.from([0x29, 0x02]), ascii("license_core"), ascii("verify_seal")]);
}
function mzBuf(bsjbOffset) {
  const pe = Buffer.alloc(Math.max(0x200, bsjbOffset + 8));
  pe.write("MZ", 0, "latin1"); pe.writeUInt32LE(0x80, 0x3c);
  pe.write("PE\0\0", 0x80, "latin1");
  if (bsjbOffset > 0) Buffer.from("BSJB", "ascii").copy(pe, bsjbOffset);
  return pe;
}

// ============================ write fixtures ============================
// 1. JVM .class vs fat Mach-O (shared 0xCAFEBABE)
F("jvm-class-plain.class", CLASS);
F("jvm-class-hardened.class", Buffer.concat([CLASS, JVM_TRAILER]));
F("fat-macho.dylib", FATMACHO);
F("fat-macho-hardened.dylib", Buffer.concat([FATMACHO, NATIVE_TRAILER]));
F("fat-macho-noext", FATMACHO);
F("fat-macho-as-class.class", Buffer.concat([FATMACHO, NATIVE_TRAILER])); // fat macho named .class
F("class-renamed.bin", Buffer.concat([CLASS, JVM_TRAILER]));              // real hardened class, renamed .bin
F("cafebabe-random.bin", Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe]), Buffer.alloc(20, 0x41)]));

// 2. pcapng + pcap variants
F("capture.pcapng", pcapngBuf());
F("capture-renamed.cap", pcapngBuf());                                   // pcapng magic, .cap ext
F("corrupt-magic.pcap", Buffer.from("NOT-A-PCAP-FILE.................")); // ext .pcap, no magic
F("classic-be.pcap", pcapBE());
F("nano-le.pcap", pcapLE(0xa1b23c4d));
F("classic-le.pcap", pcapLE(0xa1b2c3d4));

// 3. zip-family containers (.aab/.ipa/.jar/.xapk/.apk)
const decoyMember = { name: "enclave/shadow_module_9f2.json", data: Buffer.from("{\"enclave\":1}") };
F("app.aab", buildZip([{ name: "manifest/AndroidManifest.xml", data: Buffer.from("<manifest/>") }, decoyMember, { name: "classes.dex", data: dexPlain() }]));
F("app.ipa", buildZip([{ name: "Payload/x.app/Info.plist", data: Buffer.from("<plist/>") }, { name: "assets/enclave/decoy.json", data: Buffer.from("{}") }]));
F("lib.jar", buildZip([{ name: "com/x/Main.class", data: Buffer.concat([CLASS, JVM_TRAILER]) }, decoyMember]));
F("app.xapk", buildZip([{ name: "manifest.json", data: Buffer.from("{}") }, { name: "enclave/canary.txt", data: Buffer.from("x") }]));
F("app.apk", buildZip([{ name: "AndroidManifest.xml", data: Buffer.from("<manifest/>") }, { name: "classes.dex", data: Buffer.concat([dexPlain(), DEX_TRAILER]) }]));

// 4. ELF under different names
F("libalpha.so", ELF); F("libbeta.dylib", ELF); F("addon.node", ELF); F("blob-elf.bin", ELF);

// 5. TypeScript through the js route
F("plain.ts", Buffer.from(`interface Plan { seats: number; days: number }
export function planLimits(tier: string): Plan { return { seats: 1, days: 14 }; }
`));
F("hardened.ts", Buffer.from(`interface Plan { seats: number; days: number }
type Tier = "trial" | "pro";
enum Limit { Trial = 14, Pro = 365 }
const _interlockSafetyCorpus_a1b2 = ["decoy-corpus"];
export function planLimits<T extends Tier>(tier: T): Plan {
  const m: Record<Tier, Plan> = { trial: { seats: 1, days: Limit.Trial }, pro: { seats: 25, days: Limit.Pro } };
  return (m[tier] ?? m.trial) satisfies Plan;
}
export class Verifier { private readonly tag = "v4"; check(s?: string): boolean { return !!s; } }
void [_interlockSafetyCorpus_a1b2];
`));
F("decorated-hardened.ts", Buffer.from(`declare function dec(t: object, k: string, d: PropertyDescriptor): void;
const _interlockSafetyCorpus_a1b2 = ["decoy-corpus"];
export class Svc { @dec check(): boolean { return true; } }
void [_interlockSafetyCorpus_a1b2];
`));
F("cast-hardened.ts", Buffer.from(`const _interlockSafetyCorpus_a1b2 = ["decoy-corpus"];
declare function foo(): unknown;
export const x = <string>foo();
void [_interlockSafetyCorpus_a1b2];
`));
F("plain.mts", Buffer.from(`export const a: number = 1;\n`));
F("plain.cts", Buffer.from(`const a: number = 1; export = a;\n`));
F("plain.jsx", Buffer.from(`export const el = <div id="x">{1}</div>;\n`));
F("hardened.tsx", Buffer.from(`const _interlockSafetyCorpus_a1b2 = ["decoy-corpus"];
export const el = <div id="x">{1}</div>;
void [_interlockSafetyCorpus_a1b2];
`));
F("broken-marker.js", Buffer.from(`const _interlockSafetyCorpus_a1b2 = ["x"];\nconst y = \`unterminated\n`));

// 6. Non-BLA-target text files
F("data.json", Buffer.from(`{"license":{"tier":"pro"}}\n`));
F("notes.txt", Buffer.from("release notes\n"));
F("run.log", Buffer.from("[info] boot ok\n"));
F("config.yaml", Buffer.from("tier: pro\n"));

// 7. SQLite by extension/magic variants
{
  const db = new DatabaseSync(join(FIX, "real.db"));
  db.exec("CREATE TABLE IF NOT EXISTS t(id TEXT PRIMARY KEY, v INTEGER); DELETE FROM t; INSERT INTO t VALUES('a',1);");
  db.close();
}
F("level.db", Buffer.from("leveldb-ish manifest content not sqlite\n"));
F("corrupt.sqlite", Buffer.from("not a database at all............"));
F("sqlite-magic-garbage.db", Buffer.concat([Buffer.from("SQLite format 3\0", "latin1"), Buffer.alloc(64, 0xab)]));
F("sqlite-magic-nonul.db", Buffer.concat([Buffer.from("SQLite format 3X", "latin1"), Buffer.alloc(64, 0xcd)])); // 15-char prefix + 'X' at byte 15

// wasm variants
F("valid.wasm", Buffer.concat([Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0])]));
F("bad.wasm", Buffer.from("not a wasm module........"));
F("wasm4-noext", Buffer.from([0, 0x61, 0x73, 0x6d])); // 4-byte \0asm only

// 8. safetensors heuristic + shadowing tests
F("real.safetensors", safetensorsBuf());
F("tiny.safetensors", Buffer.from("abc"));                                 // <8B -> readBigUInt64LE OOB?
F("lenprefix.bin", Buffer.concat([Buffer.from([5, 0, 0, 0, 0, 0, 0, 0, 0x7b]), Buffer.from("junk")])); // u64=5 + '{'
F("fake-st.bin", Buffer.concat([Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0x7b]), Buffer.alloc(8, 0x30)])); // u64=0 + '{'
F("il2cpp-trap.dat", (() => { const b = Buffer.alloc(256); b.writeUInt32LE(0xfab11baf, 0); b.writeInt32LE(29, 4); b[8] = 0x7b; return b; })());
F("dex-trap.dex", (() => { const d = dexPlain(); d[8] = 0x7b; return d; })()); // byte8='{' must not shadow dex

// 9. size edges
F("empty.bin", Buffer.alloc(0));
F("one.bin", Buffer.from([0x42]));
F("five.bin", Buffer.from([1, 2, 3, 4, 5]));
F("empty.js", Buffer.alloc(0));
F("empty", Buffer.alloc(0));
F("tiny.gguf", Buffer.concat([Buffer.from("GGUF"), Buffer.from([0])]));    // 5B GGUF -> scrub throws
F("valid.gguf", ggufBuf());
F("tiny.dex", Buffer.from("dex\n", "ascii"));                              // 4B -> passthrough
F("trap.dex", Buffer.concat([Buffer.from("dex\n", "ascii"), Buffer.alloc(4), Buffer.from("\0[BLA-DEX-SHIELD-V1]ZZZ")])); // cut -> 8B -> writeUInt32LE(32) OOB?

// extension-fallback parity vs BLA (magic missing/corrupt)
F("bad.asar", Buffer.from("not asar content................"));
F("bad.class", Buffer.from("not a class file.............."));
F("bad.dex", Buffer.from("not a dex file................"));
F("bad.beam", Buffer.from("not a beam file..............."));
F("bad.uf2", Buffer.from("not a uf2 file................"));
F("bad.pyc", Buffer.from("not a pyc file................"));
F("bytecode-noext", Buffer.concat([Buffer.from([0xa7, 0x0d, 0x0d, 0x0a]), Buffer.alloc(20, 0x55)])); // pyc magic, no ext
F("valid.pyc", pycBuf());
F("crlf-trap.bin", Buffer.from("AB\r\nthis is text with crlf at offset 2..3 — BLA routes this to pyc\n"));

// MZ/BSJB scan-depth divergence (BLA scans 4096B header only; BLADE scans whole buf)
F("bsjb-early.exe", mzBuf(0x120));
F("bsjb-deep.exe", mzBuf(5000));
F("pe-plain.exe", mzBuf(-1));

// remaining routes
F("header.h", Buffer.from("#pragma once\nint x;\n"));
F("app.js.map", Buffer.from(`{"version":3,"sources":["a.ts"],"mappings":""}`));
F("page.html", Buffer.from(`<html><body><script>console.log(1)</script></body></html>`));
F("mod.py", Buffer.from("def f():\n    return 1\n"));
F("code.evm", Buffer.from([0x60, 0x80, 0x60, 0x40, 0x52]));
F("kernel.ptx", Buffer.from(".version 7.0\n.target sm_70\n"));
F("info.plist", Buffer.from(`<?xml version="1.0"?><plist version="1.0"><dict/></plist>`));
F("data.bplist", Buffer.concat([Buffer.from("bplist00", "latin1"), Buffer.alloc(40)]));
F("asar-named.bin", asarBuf());       // asar magic under .bin ext
F("valid.beam", beamBuf());
F("valid.uf2", uf2Buf());
mkdirSync(join(FIX, "dir-input"), { recursive: true });

// ============================ expectations ============================
// expected: the kind BLADE should report (and the scrubber behind it) for the
// artifact to be handled correctly w.r.t. what BLA can emit.
const EXPECT = {
  "jvm-class-plain.class": "jvm", "jvm-class-hardened.class": "jvm",
  "fat-macho.dylib": "native", "fat-macho-hardened.dylib": "native",
  "fat-macho-noext": "native", "fat-macho-as-class.class": "native",
  "class-renamed.bin": "jvm", "cafebabe-random.bin": "native",
  "capture.pcapng": "pcap", "capture-renamed.cap": "pcap",
  "corrupt-magic.pcap": "pcap", "classic-be.pcap": "pcap",
  "nano-le.pcap": "pcap", "classic-le.pcap": "pcap",
  "app.aab": "zip", "app.ipa": "zip", "lib.jar": "zip", "app.xapk": "zip", "app.apk": "zip",
  "libalpha.so": "native", "libbeta.dylib": "native", "addon.node": "native", "blob-elf.bin": "native",
  "plain.ts": "js", "hardened.ts": "js", "decorated-hardened.ts": "js", "cast-hardened.ts": "js",
  "plain.mts": "js", "plain.cts": "js", "plain.jsx": "js", "hardened.tsx": "js",
  "broken-marker.js": "js",
  "data.json": "unknown|passthrough", "notes.txt": "unknown|passthrough",
  "run.log": "unknown|passthrough", "config.yaml": "unknown|passthrough",
  "real.db": "sqlite", "level.db": "unknown|passthrough",
  "corrupt.sqlite": "sqlite(ext)", "sqlite-magic-garbage.db": "sqlite", "sqlite-magic-nonul.db": "unknown",
  "valid.wasm": "wasm", "bad.wasm": "wasm(ext)", "wasm4-noext": "wasm",
  "real.safetensors": "safetensors", "tiny.safetensors": "safetensors",
  "lenprefix.bin": "NOT-safetensors", "fake-st.bin": "NOT-safetensors",
  "il2cpp-trap.dat": "il2cpp", "dex-trap.dex": "dex",
  "empty.bin": "unknown|passthrough", "one.bin": "unknown|passthrough", "five.bin": "unknown|passthrough",
  "empty.js": "js", "empty": "unknown|passthrough",
  "tiny.gguf": "gguf", "valid.gguf": "gguf",
  "tiny.dex": "dex", "trap.dex": "dex",
  "bad.asar": "asar(ext)", "bad.class": "jvm(ext)", "bad.dex": "dex(ext)",
  "bad.beam": "beam(ext)", "bad.uf2": "uf2(ext)", "bad.pyc": "pyc(ext)",
  "bytecode-noext": "pyc", "valid.pyc": "pyc",
  "crlf-trap.bin": "unknown|passthrough",
  "bsjb-early.exe": "dotnet", "bsjb-deep.exe": "native", "pe-plain.exe": "native",
  "header.h": "header", "app.js.map": "sourcemap", "page.html": "html",
  "mod.py": "py", "code.evm": "evm", "kernel.ptx": "ptx",
  "info.plist": "plist", "data.bplist": "plist",
  "asar-named.bin": "asar", "valid.beam": "beam", "valid.uf2": "uf2",
  "dir-input": "directory|passthrough",
};

// ============================ run ============================
const cli = join(ROOT, "src", "cli.mjs");
for (const d of [OUT, REP]) { rmSync(d, { recursive: true, force: true }); mkdirSync(d, { recursive: true }); }
const targets = readdirSync(FIX).filter((f) => !f.startsWith("_"));
const rows = [];
for (const name of targets) {
  const input = join(FIX, name);
  const out = join(OUT, name);
  const rep = join(REP, name + ".json");
  const r = spawnSync(process.execPath, [cli, input, "-o", out, "--report", rep], { encoding: "utf8" });
  const stderr = (r.stderr ?? "").trim();
  let kind = "?";
  if (existsSync(rep)) { try { kind = JSON.parse(readFileSync(rep, "utf8")).format ?? "?"; } catch {} }
  else if (r.stdout) { const m = r.stdout.match(/\[BLADE\] (\S+)/); if (m) kind = m[1]; }
  const crashed = r.status !== 0 && /Error|RangeError|at [a-zA-Z_$]/i.test(stderr);
  const rejected = /unrecognized format/.test(stderr);
  let hardened = null, extra = "";
  if (existsSync(rep)) {
    try {
      const j = JSON.parse(readFileSync(rep, "utf8"));
      hardened = j.hardened ?? j.honeyMap ?? j.decoyHeader ?? null;
      if (j.note) extra = String(j.note).slice(0, 60);
    } catch {}
  }
  // byte-exactness probes for the two "should-strip" fixtures
  if (name === "jvm-class-hardened.class" && existsSync(out)) extra = readFileSync(out).equals(CLASS) ? "trailer stripped: byte-exact" : "TRAILER SURVIVES / OUTPUT DIFFERS";
  if (name === "fat-macho-hardened.dylib" && existsSync(out)) extra = readFileSync(out).equals(FATMACHO) ? "trailer stripped: byte-exact" : "TRAILER SURVIVES / OUTPUT DIFFERS";
  if (name === "fat-macho-as-class.class" && existsSync(out)) extra = readFileSync(out).includes(Buffer.from("[BLA-NATIVE-SHIELD-V1]")) ? "NATIVE TRAILER SURVIVES" : "cleaned";
  if (name === "class-renamed.bin" && existsSync(out)) extra = readFileSync(out).includes(Buffer.from("BLA_JVM_SHIELD_V1")) ? "JVM TRAILER SURVIVES" : "cleaned";
  rows.push({ name, size: existsSync(input) && !input.endsWith("dir-input") ? readFileSync(input).length : "-", kind, expect: EXPECT[name] ?? "?", status: r.status, signal: r.signal, crashed, rejected, hardened, extra, err1: crashed ? stderr.split("\n").slice(0, 2).join(" | ").slice(0, 120) : "" });
}

// ============================ report ============================
const verdict = (row) => {
  if (row.crashed) return "CRASH";
  if (row.kind === "?") return row.rejected ? "REJECTED(exit1)" : "NO-REPORT";
  const exp = row.expect;
  if (exp === "unknown|passthrough") return row.kind === "unknown" || row.status === 1 ? "ok(no-target)" : row.kind;
  if (exp.endsWith("(ext)")) return row.kind === exp.slice(0, -5) ? "ok" : `route=${row.kind} (BLA: ${exp})`;
  if (exp === "NOT-safetensors") return row.kind === "safetensors" ? "MISROUTE→st" : `ok(${row.kind})`;
  return row.kind === exp ? "Y" : `MISROUTE→${row.kind} (want ${exp})`;
};

console.log("name".padEnd(32), "size".padStart(6), "→ kind".padEnd(14), "expected".padEnd(20), "exit", "verdict  notes");
console.log("-".repeat(140));
for (const r of rows.sort((a, b) => a.name.localeCompare(b.name))) {
  console.log(r.name.padEnd(32), String(r.size).padStart(6), ("→ " + r.kind).padEnd(14), r.expect.padEnd(20), String(r.status).padEnd(4),
    (verdict(r) + (r.hardened !== null ? ` hardened=${r.hardened}` : "") + (r.extra ? `  ${r.extra}` : "") + (r.err1 ? `  ${r.err1}` : "")).slice(0, 160));
}
console.log("-".repeat(140));
const crashes = rows.filter((r) => r.crashed);
const rejects = rows.filter((r) => r.rejected);
console.log(`\ncrashes: ${crashes.length ? crashes.map((r) => r.name).join(", ") : "none"}`);
console.log(`clean exit-1 rejects: ${rejects.length ? rejects.map((r) => r.name).join(", ") : "none"}`);
