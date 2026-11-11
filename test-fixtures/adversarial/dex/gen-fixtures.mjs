// Adversarial fixture generator for BLADE's scrubDex / scrubZip dex handling.
// Self-contained: builds minimal but structurally valid DEX files
// (header + string_ids + type_ids + string_data + map_list) so post-scrub
// offsets can be verified for dangling references.
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "out");
mkdirSync(outDir, { recursive: true });

const uleb = (v) => {
  const b = [];
  v >>>= 0;
  do { let x = v & 0x7f; v >>>= 7; if (v) x |= 0x80; b.push(x); } while (v);
  return Buffer.from(b);
};
const align4 = (n) => (n + 3) & ~3;

// file_size @32 FIRST (it is covered by the SHA-1 signature), then
// signature @12..32 over [32..end], then Adler32 @8..12 over [12..end].
function fixDex(d) {
  d.writeUInt32LE(d.length, 32);
  createHash("sha1").update(d.subarray(32)).digest().copy(d, 12);
  let a = 1, b = 0;
  for (let i = 12; i < d.length; i++) { a = (a + d[i]) % 65521; b = (b + a) % 65521; }
  d.writeUInt32LE(((b << 16) | a) >>> 0, 8);
  return d;
}

// Minimal valid DEX: header(0x70) + string_ids + type_ids + data(string_data*, map_list).
// strings: utf8 (ASCII) strings. typeStrIdxs: indexes into strings for type_ids.
function buildDex({ version = "035", strings = [], typeStrIdxs = [], midData = null, tailOverlay = null } = {}) {
  const headerSize = 0x70;
  const stringIdsOff = headerSize;
  const typeIdsOff = stringIdsOff + strings.length * 4;
  const dataOff = typeIdsOff + typeStrIdxs.length * 4;

  const chunks = [];
  let cursor = dataOff;
  const place = (buf, align = false) => {
    if (align) {
      const pad = align4(cursor) - cursor;
      if (pad) { chunks.push({ off: cursor, buf: Buffer.alloc(pad) }); cursor += pad; }
    }
    const off = cursor;
    chunks.push({ off, buf });
    cursor += buf.length;
    return off;
  };

  const stringDataOffs = strings.map((s) => {
    const u8 = Buffer.from(s, "utf8");
    let u16 = 0;
    for (const ch of s) u16 += (ch.codePointAt(0) > 0xffff ? 2 : 1);
    return place(Buffer.concat([uleb(u16), u8, Buffer.from([0])]));
  });

  // optional mid-file blob (to simulate decoy data injected NOT at EOF)
  if (midData) place(midData.buf, true);

  const mapOff = align4(cursor);
  if (mapOff !== cursor) place(Buffer.alloc(mapOff - cursor));

  const entries = [
    { type: 0x0000, size: 1, offset: 0 },                    // header
    { type: 0x0001, size: strings.length, offset: stringIdsOff },
    { type: 0x0002, size: typeStrIdxs.length, offset: typeIdsOff },
    { type: 0x2002, size: strings.length, offset: stringDataOffs[0] ?? dataOff },
    { type: 0x1000, size: 1, offset: mapOff },               // map_list itself
  ];
  const mapBuf = Buffer.alloc(4 + entries.length * 12);
  mapBuf.writeUInt32LE(entries.length, 0);
  entries.forEach((e, i) => {
    mapBuf.writeUInt16LE(e.type, 4 + i * 12);
    mapBuf.writeUInt32LE(e.size, 4 + i * 12 + 4);
    mapBuf.writeUInt32LE(e.offset, 4 + i * 12 + 8);
  });
  place(mapBuf);

  const fileSize = cursor;
  const out = Buffer.alloc(fileSize);
  out.write(`dex\n${version}\0`, 0, "ascii");
  out.writeUInt32LE(headerSize, 36);
  out.writeUInt32LE(0x12345678, 40);
  out.writeUInt32LE(mapOff, 52);
  out.writeUInt32LE(strings.length, 56);
  out.writeUInt32LE(stringIdsOff, 60);
  out.writeUInt32LE(typeStrIdxs.length, 64);
  out.writeUInt32LE(typeStrIdxs.length ? typeIdsOff : 0, 68);
  out.writeUInt32LE(fileSize - dataOff, 104); // data_size
  out.writeUInt32LE(dataOff, 108);            // data_off

  stringDataOffs.forEach((o, i) => out.writeUInt32LE(o, stringIdsOff + i * 4));
  typeStrIdxs.forEach((si, i) => out.writeUInt32LE(si, typeIdsOff + i * 4));
  for (const c of chunks) c.buf.copy(out, c.off);

  fixDex(out);
  return tailOverlay ? Buffer.concat([out, tailOverlay]) : out;
}

// BLA-identical trailer: "\0[BLA-DEX-SHIELD-V1]\0" + NUL-joined decoys + "\0",
// then file_size/signature/checksum recomputed over the whole buffer.
function blaProtect(dex, decoys = [
  "Lcom/enclave/sgx/TeeAttestationBridge;",
  "Lcom/enclave/tarpit/EnclaveStateNode_a1b2c3_0;",
  "Java_com_enclave_TeeBridge_nativeSeal",
  "PROTECTED_CANARY_CREDENTIAL=ck_test_123",
]) {
  const t = Buffer.from("\0[BLA-DEX-SHIELD-V1]\0" + decoys.join("\0") + "\0", "utf8");
  return fixDex(Buffer.concat([dex, t]));
}

// ---------- zip (stored, BLA-strict subset) ----------
const CRC_T = (() => { const t = new Uint32Array(256); for (let i = 0; i < 256; i++) { let c = i; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[i] = c; } return t; })();
const crc32 = (b) => { let c = 0xffffffff; for (let i = 0; i < b.length; i++) c = CRC_T[(c ^ b[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
function buildZip(files) {
  const parts = [], centrals = []; let off = 0;
  for (const f of files) {
    const nb = Buffer.from(f.name, "utf8");
    const crc = crc32(f.data);
    const l = Buffer.alloc(30 + nb.length);
    l.writeUInt32LE(0x04034b50, 0); l.writeUInt16LE(20, 4);
    l.writeUInt32LE(crc, 14); l.writeUInt32LE(f.data.length, 18); l.writeUInt32LE(f.data.length, 22);
    l.writeUInt16LE(nb.length, 26); nb.copy(l, 30);
    parts.push(Buffer.concat([l, f.data]));
    const c = Buffer.alloc(46 + nb.length);
    c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(20, 4); c.writeUInt16LE(20, 6);
    c.writeUInt32LE(crc, 16); c.writeUInt32LE(f.data.length, 20); c.writeUInt32LE(f.data.length, 24);
    c.writeUInt16LE(nb.length, 28); c.writeUInt32LE(off, 42); nb.copy(c, 46);
    centrals.push(c);
    off += 30 + nb.length + f.data.length;
  }
  const cs = centrals.reduce((a, b) => a + b.length, 0);
  const e = Buffer.alloc(22);
  e.writeUInt32LE(0x06054b50, 0); e.writeUInt16LE(files.length, 8); e.writeUInt16LE(files.length, 10);
  e.writeUInt32LE(cs, 12); e.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, ...centrals, e]);
}

const W = (name, buf) => { writeFileSync(join(outDir, name), buf); console.log("wrote", name, buf.length, "bytes"); };

// ================= CASE 1 =================
// Real string table containing the exact marker text inside a real string.
// Strings after it + map_list live past the first marker occurrence.
W("case1-marker-in-stringtable.dex", buildDex({
  strings: [
    "Ljava/lang/Object;",
    "auth.tag:v1:[BLA-DEX-SHIELD-V1]:prod",   // marker INSIDE a real string
    "real.method.name",
    "Lcom/app/RealClass;",
    "postMarkerString-still-legit",
  ],
  typeStrIdxs: [0, 3],
}));

// enclave_-like REAL strings, no marker at all — false-positive check.
W("case1-enclave-strings.dex", buildDex({
  strings: [
    "Lcom/enclave/sgx/TeeAttestationBridge;",
    "enclave_attestation_key",
    "Lcom/enclave/payments/SecureStore;",
    "enclave.ring0.channel",
  ],
  typeStrIdxs: [0, 2],
}));

// Real string whose content ENDS with the marker, preceded by ':' (not NUL)
// — tests the unconditional 1-byte backup eating a real byte even if the
// cut position were otherwise correct.
W("case1-marker-string-suffix.dex", buildDex({
  strings: [
    "Ljava/lang/Object;",
    "build fingerprint: release-keys [BLA-DEX-SHIELD-V1]",
    "tail-string",
  ],
  typeStrIdxs: [0],
}));

// ================= CASE 2 =================
// BLA-verified: trailer is ALWAYS one contiguous EOF append (mobile-game.ts
// Buffer.concat([baseDex, trailer])). Adversarial variant: marker+decoys NOT
// at EOF — real bytes follow the marker (post-trailer overlay / second dex).
const realTailBlock = Buffer.concat([
  Buffer.from("REAL-APPENDED-SIGNING-BLOCK\x00".padEnd(64, "R"), "latin1"),
]);
W("case2-marker-then-real-tail.dex", (() => {
  const base = buildDex({ strings: ["Ljava/lang/Object;", "s1"], typeStrIdxs: [0] });
  const fakeTrailer = Buffer.from("\0[BLA-DEX-SHIELD-V1]\0DECOY-A\0", "utf8");
  const secondDecoy = Buffer.from("DECOY-B-AT-EOF\0", "utf8");
  return fixDex(Buffer.concat([base, fakeTrailer, realTailBlock, secondDecoy]));
})());

// Marker-bearing blob inside the DATA section (between string_data and
// map_list) — decoys never appended at EOF at all.
W("case2-marker-inside-data.dex", buildDex({
  strings: ["Ljava/lang/Object;", "alpha", "beta", "gamma"],
  typeStrIdxs: [0],
  midData: { buf: Buffer.from("\0[BLA-DEX-SHIELD-V1]\0decoy-mid-data\0", "utf8") },
}));

// ================= CASE 3 =================
for (const v of ["035", "037", "039"]) {
  W(`case3-v${v}.dex`, blaProtect(buildDex({ version: v, strings: ["Ljava/lang/Object;", "x"], typeStrIdxs: [0] })));
}
// Bogus version — not a real dex version at all.
W("case3-vZZZ.dex", blaProtect(buildDex({ version: "ZZZ", strings: ["x"], typeStrIdxs: [] })));

// ================= CASE 4 =================
W("case4-classes2.dex", blaProtect(buildDex({ strings: ["Ljava/lang/Object;", "m2"], typeStrIdxs: [0] })));

// mimics BLA's planted classesN.dex xref decoy (BLA-DEX-XREF-V1 in strings)
const plantedXrefDex = buildDex({
  strings: ["V", "Landroid/util/Log;", "BLA-DEX-XREF-V1", "Lcom/enclave/xref/ExternalInvokeCaller_ab_0;", "d", "bait"],
  typeStrIdxs: [1, 3],
});
const cleanClasses = buildDex({ strings: ["Ljava/lang/Object;", "Lcom/app/Main;", "onCreate"], typeStrIdxs: [0, 1] });
const hardenedClasses2 = blaProtect(buildDex({ strings: ["Ljava/lang/Object;", "Lcom/app/Secondary;", "run"], typeStrIdxs: [0, 1] }));

W("case4-multidex.zip", buildZip([
  { name: "classes.dex", data: cleanClasses },
  { name: "classes2.dex", data: hardenedClasses2 },
  { name: "classes3.dex", data: plantedXrefDex },
  { name: "assets/enclave/bait.txt", data: Buffer.from("enclave.cid=16\n") },
  { name: "res/values.xml", data: Buffer.from("<resources/>") },
]));

// EVIL: the REAL classes.dex legitimately contains "BLA-DEX-XREF-V1" as a
// string_data constant (e.g. embedded config tag). scrubZip drops the WHOLE
// member. Also: classes2.dex has BOTH xref string and trailer — dropped
// instead of scrubbed.
const evilClasses = buildDex({
  strings: ["Ljava/lang/Object;", "Lcom/app/Main;", "cfg:BLA-DEX-XREF-V1:enabled", "realMethod"],
  typeStrIdxs: [0, 1],
});
const bothMarkers = blaProtect(buildDex({
  strings: ["Ljava/lang/Object;", "BLA-DEX-XREF-V1", "Lcom/app/Two;"],
  typeStrIdxs: [0, 2],
}));
W("case4-evil-multidex.zip", buildZip([
  { name: "classes.dex", data: evilClasses },
  { name: "classes2.dex", data: bothMarkers },
  { name: "res/values.xml", data: Buffer.from("<resources/>") },
]));

// Marker-carrying dex hidden under a non-.dex member name.
W("case4-hidden-dex.zip", buildZip([
  { name: "classes.dex", data: cleanClasses },
  { name: "assets/payload.bin", data: hardenedClasses2 },
]));

// ================= CASE 5 =================
// Truncated dex (cut mid-map_list) + trailer.
W("case5-truncated.dex", (() => {
  const full = buildDex({ strings: ["a", "b", "c", "d"], typeStrIdxs: [0] });
  const trunc = full.subarray(0, Math.floor(full.length * 0.6));
  return fixDex(Buffer.concat([Buffer.from(trunc), Buffer.from("\0[BLA-DEX-SHIELD-V1]\0x\0")]));
})());

// Tiny file: marker at offset 9 -> cut leaves 8 bytes -> writeUInt32LE @32 throws.
W("case5-tiny.dex", Buffer.concat([Buffer.from("dex\n035\0"), Buffer.from("\0[BLA-DEX-SHIELD-V1]\0pad")]));

// Short: marker lands so post-cut length ~40 (>=36, <112) — no crash, garbage output.
W("case5-short.dex", (() => {
  const head = Buffer.concat([Buffer.from("dex\n035\0"), Buffer.alloc(33)]); // 41 bytes
  head.writeUInt32LE(0x70, 36);
  return Buffer.concat([head, Buffer.from("\0[BLA-DEX-SHIELD-V1]\0pad")]);
})());

// Garbage after map_list, NO marker — passthrough baseline.
W("case5-garbage-tail.dex", Buffer.concat([
  buildDex({ strings: ["x", "y"], typeStrIdxs: [0] }),
  Buffer.from("GARBAGE-OVERLAY-DATA-NOT-A-DEX-SECTION".padEnd(80, "G"), "latin1"),
]));

// ================= CASE 6 =================
// Byte-exactness baseline: valid dex -> BLA-identical trailer -> scrub must
// reproduce the exact original bytes.
const origDex = buildDex({
  strings: ["Ljava/lang/Object;", "Lcom/app/Real;", "realName", "V"],
  typeStrIdxs: [0, 1, 3],
});
writeFileSync(join(outDir, "case6-original.dex.expected"), origDex); // reference copy
W("case6-byteexact.dex", blaProtect(origDex));

// Overlay variant: original dex whose file_size < actual length (overlay
// bytes covered by sig/adler but not file_size). Scrub rewrites file_size to
// out.length -> NOT byte-exact at @32 vs original.
const overlayCore = buildDex({ strings: ["Ljava/lang/Object;", "ov"], typeStrIdxs: [0] });
const overlayOrig = (() => {
  const o = Buffer.concat([overlayCore, Buffer.alloc(64, 0xab)]);
  // keep header file_size = real dex size (overlay excluded), but sign the
  // whole buffer like a real signed-dex-with-overlay would.
  const sha = createHash("sha1").update(o.subarray(32)).digest(); sha.copy(o, 12);
  let a = 1, b = 0;
  for (let i = 12; i < o.length; i++) { a = (a + o[i]) % 65521; b = (b + a) % 65521; }
  o.writeUInt32LE(((b << 16) | a) >>> 0, 8);
  return o;
})();
writeFileSync(join(outDir, "case6-overlay.dex.expected"), overlayOrig);
W("case6-overlay.dex", blaProtect(overlayOrig));

console.log("\nfixtures ->", outDir);
