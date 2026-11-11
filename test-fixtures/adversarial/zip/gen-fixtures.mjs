// Adversarial fixture generator for BLADE's scrubZip (src/trailer.mjs).
// Byte-level ZIP writer: data descriptors, extra fields (4K .so alignment),
// archive/entry comments, APK signing block, ZIP64, fake-EOCD-in-comment,
// local/central name mismatches, foreign compression methods, SFX stubs.
//
// Baselines use the REAL vendored BLA (protectZipOrApkBuffer + ast-shield).
// Emits out/ fixtures + manifest.json consumed by run-adversarial.mjs.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import { writeZipArchive, protectZipOrApkBuffer } from "../../../vendor/bla/dist/shields/formats/archive.js";
import { transformJavaScriptWithBlaShield } from "../../../vendor/bla/dist/shields/javascript/ast-shield.js";
import { protectAndroidDexBuffer } from "../../../vendor/bla/dist/shields/formats/mobile-game.js";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "out");
mkdirSync(outDir, { recursive: true });
const manifest = {};
const W = (name, buf, meta) => { writeFileSync(join(outDir, name), buf); manifest[name] = meta ?? {}; console.log("wrote", name, buf.length, "bytes"); };

const CRC_T = (() => { const t = new Uint32Array(256); for (let i = 0; i < 256; i++) { let c = i; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[i] = c; } return t; })();
const crc32 = (b) => { let c = 0xffffffff; for (let i = 0; i < b.length; i++) c = CRC_T[(c ^ b[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };

// ---------- raw zip writer ----------
// member: {name, data, method=0|8|other, comp?, flags?, descriptor?, descriptorSig?,
//          localExtra?, centralExtra?, localName?, fileComment?, dosTime?, dosDate?,
//          extAttr?, versionMade?, versionNeeded?, centralCrc?, centralCsize?,
//          centralUsize?, lho?, localNlenLie?}
// opts: {prepend?, signingBlock?, sigBlockBeforeCD? (EOCD cdStart points at CD
//        start, block before it — real apksigner/v2 layout), comment?(Buffer|
//        string), trailing?, zip64?,
//        eocd?: {diskNo?, cdDisk?, countDisk?, count?, cdSize?, cdStart?}}
function zbuild(members, opts = {}) {
  const prepend = opts.prepend ?? Buffer.alloc(0);
  const parts = [], centrals = [];
  let off = prepend.length;
  for (const m of members) {
    const nameB = Buffer.from(m.name, "utf8");
    const localNameB = Buffer.from(m.localName ?? m.name, "utf8");
    const data = m.data ?? Buffer.alloc(0);
    const crc = m.centralCrc ?? crc32(data);
    let comp;
    if (m.comp !== undefined) comp = m.comp;
    else if (m.method === 8) comp = deflateRawSync(data);
    else comp = Buffer.from(data);
    const csize = m.centralCsize ?? comp.length;
    const usize = m.centralUsize ?? data.length;
    const flags = m.flags ?? (m.descriptor ? 0x08 : 0);
    const localExtra = m.localExtra ?? Buffer.alloc(0);
    const centralExtra = m.centralExtra ?? Buffer.alloc(0);
    const fileComment = Buffer.from(m.fileComment ?? "", "utf8");
    const lho = m.lho ?? off;
    // `localNlenLie`: header declares a DIFFERENT name length than the bytes
    // actually written (real name occupies localNameB.length). Data is still
    // placed after the written name — readers trusting declared nlen mis-locate.
    const declaredLocalNlen = m.localNlenLie ?? localNameB.length;
    const local = Buffer.alloc(30 + localNameB.length + localExtra.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(m.versionNeeded ?? 20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(m.method, 8);
    local.writeUInt16LE(m.dosTime ?? 0, 10);
    local.writeUInt16LE(m.dosDate ?? 0, 12);
    if (!(m.descriptor || m.localSizesZero)) {
      local.writeUInt32LE(crc, 14); local.writeUInt32LE(comp.length, 18); local.writeUInt32LE(data.length, 22);
    }
    local.writeUInt16LE(declaredLocalNlen, 26);
    local.writeUInt16LE(localExtra.length, 28);
    localNameB.copy(local, 30);
    localExtra.copy(local, 30 + localNameB.length);
    parts.push(local, comp);
    let consumed = local.length + comp.length;
    if (m.descriptor) {
      const dd = Buffer.alloc(m.descriptorSig === false ? 12 : 16);
      let o = 0;
      if (m.descriptorSig !== false) { dd.writeUInt32LE(0x08074b50, 0); o = 4; }
      dd.writeUInt32LE(crc, o); dd.writeUInt32LE(comp.length, o + 4); dd.writeUInt32LE(data.length, o + 8);
      parts.push(dd); consumed += dd.length;
    }
    const c = Buffer.alloc(46 + nameB.length + centralExtra.length + fileComment.length);
    c.writeUInt32LE(0x02014b50, 0);
    c.writeUInt16LE(m.versionMade ?? 20, 4);
    c.writeUInt16LE(m.versionNeeded ?? 20, 6);
    c.writeUInt16LE(flags, 8);
    c.writeUInt16LE(m.method, 10);
    c.writeUInt16LE(m.dosTime ?? 0, 12);
    c.writeUInt16LE(m.dosDate ?? 0, 14);
    c.writeUInt32LE(crc, 16);
    c.writeUInt32LE(csize, 20);
    c.writeUInt32LE(usize, 24);
    c.writeUInt16LE(nameB.length, 28);
    c.writeUInt16LE(centralExtra.length, 30);
    c.writeUInt16LE(fileComment.length, 32);
    c.writeUInt16LE(m.diskStart ?? 0, 34);
    c.writeUInt16LE(m.intAttr ?? 0, 36);
    c.writeUInt32LE(m.extAttr ?? 0, 38);
    c.writeUInt32LE(lho, 42);
    nameB.copy(c, 46);
    centralExtra.copy(c, 46 + nameB.length);
    fileComment.copy(c, 46 + nameB.length + centralExtra.length);
    centrals.push(c);
    off += consumed;
  }
  // Layouts: default signingBlock makes EOCD cdStart point AT the block
  // (block counted as CD region); sigBlockBeforeCD points cdStart past it.
  const cdStart = off + (opts.signingBlock && opts.sigBlockBeforeCD ? opts.signingBlock.length : 0);
  const cdSize = centrals.reduce((a, b) => a + b.length, 0);
  const tail = [];
  if (opts.signingBlock) tail.push(opts.signingBlock); // sits between last local and CD
  tail.push(...centrals);
  let eocd64off = 0;
  if (opts.zip64) {
    eocd64off = cdStart + cdSize;
    const z64 = Buffer.alloc(56);
    z64.writeUInt32LE(0x06064b50, 0);
    z64.writeBigUInt64LE(44n, 4);
    z64.writeUInt16LE(45, 12); z64.writeUInt16LE(45, 14);
    z64.writeBigUInt64LE(BigInt(members.length), 24);
    z64.writeBigUInt64LE(BigInt(members.length), 32);
    z64.writeBigUInt64LE(BigInt(cdSize), 40);
    z64.writeBigUInt64LE(BigInt(cdStart), 48);
    const loc = Buffer.alloc(20);
    loc.writeUInt32LE(0x07064b50, 0);
    loc.writeBigUInt64LE(BigInt(eocd64off), 8);
    loc.writeUInt32LE(1, 16);
    tail.push(z64, loc);
  }
  const comment = Buffer.isBuffer(opts.comment) ? opts.comment : Buffer.from(opts.comment ?? "", "utf8");
  const e = Buffer.alloc(22);
  const eo = opts.eocd ?? {};
  e.writeUInt32LE(0x06054b50, 0);
  e.writeUInt16LE(eo.diskNo ?? 0, 4);
  e.writeUInt16LE(eo.cdDisk ?? 0, 6);
  e.writeUInt16LE(eo.countDisk ?? (opts.zip64 ? 0xffff : members.length), 8);
  e.writeUInt16LE(eo.count ?? (opts.zip64 ? 0xffff : members.length), 10);
  e.writeUInt32LE(eo.cdSize ?? (opts.zip64 ? 0xffffffff : cdSize), 12);
  e.writeUInt32LE(eo.cdStart ?? (opts.zip64 ? 0xffffffff : cdStart), 16);
  e.writeUInt16LE(comment.length, 20);
  tail.push(e, comment);
  if (opts.trailing) tail.push(opts.trailing);
  return Buffer.concat([prepend, ...parts, ...tail]);
}

// ---------- helpers ----------
const fixDex = (d) => {
  d.writeUInt32LE(d.length, 32);
  createHash("sha1").update(d.subarray(32)).digest().copy(d, 12);
  let a = 1, b = 0;
  for (let i = 12; i < d.length; i++) { a = (a + d[i]) % 65521; b = (b + a) % 65521; }
  d.writeUInt32LE(((b << 16) | a) >>> 0, 8);
  return d;
};
function fakeDex(label, extraStrings = []) {
  const d = Buffer.alloc(112 + extraStrings.join("").length + 16);
  d.write("dex\n035\0", 0, "ascii");
  d.writeUInt32LE(0x70, 36); d.writeUInt32LE(0x12345678, 40);
  Buffer.from([label, ...extraStrings].join("|"), "utf8").copy(d, 112);
  return fixDex(d);
}
const blaTrailerDex = (dex) => fixDex(Buffer.concat([dex, Buffer.from("\0[BLA-DEX-SHIELD-V1]\0Lcom/enclave/tarpit/EnclaveStateNode_a1b2c3_0;\0PROTECTED_CANARY_CREDENTIAL=ck_x\0", "utf8")]));
const plantedXrefDex = (() => {
  const d = fakeDex("xref", ["BLA-DEX-XREF-V1", "Lcom/enclave/xref/ExternalInvokeCaller_ab_0;", "Landroid/util/Log;"]);
  return d;
})();
const AXML = (() => { // minimal binary AndroidManifest.xml (RES_XML_TYPE)
  const b = Buffer.alloc(64);
  b.writeUInt32LE(0x00080003, 0); b.writeUInt16LE(8, 4); b.writeUInt32LE(64, 8);
  b.writeUInt32LE(0x001c0001, 12); b.writeUInt16LE(0x1c, 16); b.writeUInt32LE(28, 20);
  b.writeUInt32LE(1, 28); // stringCount=1
  return b;
})();
const fakeElf = (tag) => {
  const b = Buffer.alloc(256);
  b[0] = 0x7f; b.write("ELF", 1, "latin1"); b[4] = 2; b[5] = 1;
  Buffer.from(`real ${tag} build-id ${createHash("sha1").update(tag).digest("hex")}`).copy(b, 64);
  return b;
};
const decoyManifestJson = JSON.stringify({ schema: "bla-archive-enclave-shield/v1", protected: true, enclave_delegation: "hardware_tee_ring0" }, null, 2);

// ============================================================
// BASELINES — real vendored BLA output
// ============================================================
const baseApk = writeZipArchive([
  { name: "AndroidManifest.xml", data: AXML, storeOnly: true },
  { name: "classes.dex", data: fakeDex("primary"), storeOnly: true },
  { name: "classes2.dex", data: fakeDex("secondary"), storeOnly: true },
  { name: "resources.arsc", data: Buffer.alloc(512, 0xab), storeOnly: true },
  { name: "META-INF/MANIFEST.MF", data: Buffer.from("Manifest-Version: 1.0\r\n\r\n") },
  { name: "assets/app.js", data: Buffer.from("console.log('hello');".repeat(8)) },
  { name: "lib/arm64-v8a/libreal.so", data: fakeElf("libreal"), storeOnly: true },
]);
W("base-clean.apk", baseApk, { expectPassthrough: true });
const hardened = protectZipOrApkBuffer(baseApk, { intensity: "balanced", seed: "adv-zip", isApk: true });
W("base-bla-hardened.apk", hardened.buffer, { realBla: true, decoysInjected: hardened.decoyEntriesInjected, membersHardened: hardened.membersHardened });

// non-apk zip hardened by real BLA (decoys under assets/enclave + enclave)
const baseZip = writeZipArchive([
  { name: "src/main.js", data: Buffer.from("console.log(1);".repeat(10)) },
  { name: "docs/readme.md", data: Buffer.from("# hi\n".repeat(30)) },
]);
W("base-bla-hardened.zip", protectZipOrApkBuffer(baseZip, { intensity: "stealth", seed: "adv-zip2" }).buffer, { realBla: true });

// ============================================================
// CASE 1 — legit member names colliding with decoy patterns
// ============================================================
// 1a: 100% CLEAN apk — no decoys, no markers — but ships legit enclave/
// content. scrubZip drops name-matched members and rebuilds anyway.
W("case1a-clean-legit-enclave.apk", zbuild([
  { name: "AndroidManifest.xml", data: AXML },
  { name: "classes.dex", data: fakeDex("primary") },
  { name: "classes2.dex", data: fakeDex("multidex-2") },   // real multidex
  { name: "classes3.dex", data: fakeDex("multidex-3") },
  { name: "enclave/", data: Buffer.alloc(0) },              // real dir entry
  { name: "enclave/enclave_config.json", data: Buffer.from('{"tee":"sgx","cid":7}') },   // LEGIT
  { name: "enclave/attestation.pem", data: Buffer.from("-----BEGIN CERT-----") },
  { name: "assets/enclave/tee_policy.json", data: Buffer.from('{"policy":1}') },          // LEGIT
  { name: "Enclave/CaseDir.txt", data: Buffer.from("case-variant dir") },
  { name: "lib/arm64-v8a/libenclave.so", data: fakeElf("libenclave") },                    // LEGIT .so
  { name: "res/raw/device.bla", data: Buffer.from("real .bla extension file") },           // LEGIT .bla
  { name: "config.bla", data: Buffer.from("another real .bla file") },
  { name: "assets/enclave-backup/notes.txt", data: Buffer.from("near-miss dirname") },
  { name: "xenclave/file.txt", data: Buffer.from("near-miss prefix") },
  { name: "enclave", data: Buffer.from("file literally named enclave") },                  // no trailing slash
  { name: "resources.arsc", data: Buffer.alloc(256, 0x11) },
]), { note: "clean archive, legit names under decoy patterns" });

// 1b: mixed — real BLA decoys + planted xref dex + hardened multidex +
// legit enclave/ + legit-named .so + near-miss decoy names + nested evasion.
W("case1b-mixed.apk", zbuild([
  { name: "AndroidManifest.xml", data: AXML },
  { name: "classes.dex", data: blaTrailerDex(fakeDex("primary")) },
  { name: "classes2.dex", data: blaTrailerDex(fakeDex("multidex-2")) },   // hardened REAL multidex
  { name: "classes3.dex", data: fakeDex("multidex-3") },                  // clean REAL multidex
  { name: "classes4.dex", data: plantedXrefDex },                          // planted BLA xref decoy
  { name: "assets/bla-shield/bla-attestation-manifest.json", data: Buffer.from(decoyManifestJson) },
  { name: "assets/bla-shield/tee_bridge_stub_a1b2c3.properties", data: Buffer.from("enclave.cid=16\nenclave.sealed=true\n") },
  { name: "assets/bla-shield/AndroidManifest.xml", data: Buffer.from("<manifest decoy/>") },
  { name: "assets/bla-shield/mapping.txt", data: Buffer.from("com.a -> a.a:\n") },
  { name: "lib/arm64-v8a/libbla_enclave_jni.so", data: fakeElf("DECOY-named but legit content") },
  { name: "lib/armeabi-v7a/libbla_enclave_jni.so", data: fakeElf("decoy name, other ABI") }, // survives?
  { name: "lib/arm64-v8a/libenclave.so", data: fakeElf("libenclave") },
  { name: "enclave/enclave_config.json", data: Buffer.from('{"tee":"sgx"}') },             // LEGIT, dies
  { name: "assets/enclave/policy.json", data: Buffer.from('{"p":1}') },                    // LEGIT, dies
  { name: "payload/enclave/nested_decoy.txt", data: Buffer.from("PROTECTED_CANARY_CREDENTIAL=x") }, // nested -> survives?
  { name: "res/raw/device.bla", data: Buffer.from("real .bla file") },
  { name: "resources.arsc", data: Buffer.alloc(256, 0x22) },
]));

// ============================================================
// CASE 2 — data descriptors (flag bit 3)
// ============================================================
W("case2-descriptor.apk", zbuild([
  { name: "classes.dex", data: blaTrailerDex(fakeDex("dd-primary")), method: 8, descriptor: true },
  { name: "enclave/decoy.txt", data: Buffer.from("enclave decoy via descriptor\n"), method: 8, descriptor: true },
  { name: "note-nosig.txt", data: Buffer.from("descriptor without signature ".repeat(6)), method: 8, descriptor: true, descriptorSig: false },
  { name: "stored-dd.bin", data: Buffer.from("stored with descriptor".repeat(4)), method: 0, descriptor: true },
  { name: "plain.txt", data: Buffer.from("normal member ".repeat(8)), method: 8 },
]));

// ============================================================
// CASE 3 — ZIP64, comments, dir-first, fake EOCD, trailing garbage
// ============================================================
W("case3-zip64.apk", zbuild([
  { name: "enclave/decoy.txt", data: Buffer.from("zip64 decoy") },
  { name: "classes.dex", data: blaTrailerDex(fakeDex("z64")) },
], { zip64: true }), { expectThrow: true });

W("case3b-comments.zip", zbuild([
  { name: "enclave/decoy.txt", data: Buffer.from("decoy"), fileComment: "entry comment on decoy" },
  { name: "real.txt", data: Buffer.from("real ".repeat(20)), method: 8, fileComment: "keep me comment" },
], { comment: "archive-level EOCD comment — zip comments are legal" }));

W("case3c-dir-first.zip", zbuild([
  { name: "assets/", data: Buffer.alloc(0) },             // first entry is a directory
  { name: "assets/real.txt", data: Buffer.from("real ".repeat(10)), method: 8 },
  { name: "enclave/decoy.txt", data: Buffer.from("decoy") },
]));

// 3d: fake EOCD embedded in the comment — higher-offset EOCD wins the
// scrubber's backward scan. Fake says count=1 cdStart=0 -> 0 parsed entries
// -> hardened:false -> ORIGINAL bytes (decoys and all) pass through.
{
  const tail = Buffer.alloc(32, 0); // fake EOCD's own "comment"
  const fake = Buffer.alloc(22);
  fake.writeUInt32LE(0x06054b50, 0);
  fake.writeUInt16LE(1, 8); fake.writeUInt16LE(1, 10);
  fake.writeUInt32LE(0, 12); fake.writeUInt32LE(0, 16);   // cdSize=0 cdStart=0
  fake.writeUInt16LE(tail.length, 20);                     // check: q+22+tail==len
  W("case3d-fake-eocd-passthrough.zip", zbuild([
    { name: "enclave/decoy.txt", data: Buffer.from("decoy survives") },
    { name: "real.txt", data: Buffer.from("real ".repeat(10)) },
  ], { comment: Buffer.concat([fake, tail]) }), { evasion: true });
}

// 3e: fake EOCD pointing at fake centrals inside the comment — scrubber
// rebuilds an attacker-chosen one-member zip, silently discarding all real
// members.
{
  const keptData = Buffer.from("REAL MEMBER ZERO DATA");
  // build once to learn member0's lho, then rebuild with poison comment
  const probe = zbuild([{ name: "loot-src.txt", data: keptData }, { name: "enclave/decoy.txt", data: Buffer.from("d") }]);
  const lho0 = 0; // first member is always at 0
  const centName = (n) => Buffer.from(n, "utf8");
  const mkCentral = (name, lho, csize, usize, crc) => {
    const nb = centName(name); const c = Buffer.alloc(46 + nb.length);
    c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(20, 4); c.writeUInt16LE(20, 6);
    c.writeUInt16LE(0, 10); c.writeUInt32LE(crc, 16); c.writeUInt32LE(csize, 20); c.writeUInt32LE(usize, 24);
    c.writeUInt16LE(nb.length, 28); c.writeUInt32LE(lho, 42); nb.copy(c, 46);
    return c;
  };
  const fakeCentrals = Buffer.concat([
    mkCentral("enclave/decoy.txt", 0, 4, 4, crc32(Buffer.from("REAL"))),          // dropped by name
    mkCentral("loot.txt", lho0, keptData.length, keptData.length, crc32(keptData)), // steals member0 data
  ]);
  const fake = Buffer.alloc(22);
  fake.writeUInt32LE(0x06054b50, 0);
  fake.writeUInt16LE(2, 8); fake.writeUInt16LE(2, 10);
  fake.writeUInt32LE(fakeCentrals.length, 12);
  fake.writeUInt32LE(0, 16); // patched below — cdStart must be abs offset of fakeCentrals
  // comment = fake(22) + centrals + tail; cdStart = eocdReal+22+22 — depends on
  // real eocd offset which we don't know until assembled. Two-pass build:
  const build = (cdStartAbs) => {
    fake.writeUInt32LE(cdStartAbs, 16);
    fake.writeUInt16LE(fakeCentrals.length, 20); // no trailing after centrals
    return zbuild([
      { name: "loot-src.txt", data: keptData },
      { name: "enclave/decoy.txt", data: Buffer.from("real decoy") },
      { name: "real2.txt", data: Buffer.from("second real member ".repeat(5)), method: 8 },
    ], { comment: Buffer.concat([fake, fakeCentrals]) });
  };
  let buf = build(0);
  const eocdReal = buf.length - 22 - (22 + fakeCentrals.length);
  buf = build(eocdReal + 22 + 22);
  W("case3e-fake-eocd-poison.zip", buf, { evasion: true, poison: true });
}

// 3f: trailing garbage after EOCD — "no EOCD" -> passthrough (decoys survive)
W("case3f-trailing-garbage.zip", zbuild([
  { name: "enclave/decoy.txt", data: Buffer.from("decoy survives") },
  { name: "real.txt", data: Buffer.from("real ".repeat(10)) },
], { trailing: Buffer.from("JUNK") }), { evasion: true });

// ============================================================
// CASE 4 — binary AXML root manifest vs BLA's decoy manifest member
// ============================================================
W("case4-axml.apk", zbuild([
  { name: "AndroidManifest.xml", data: AXML, method: 0 },       // real binary AXML
  { name: "assets/bla-shield/AndroidManifest.xml", data: Buffer.from("<manifest decoy=\"true\"/>") },
  { name: "assets/bla-shield/AndroidManifest-decoy.xml", data: Buffer.from("<manifest decoy=\"true\"/>") },
  { name: "classes.dex", data: blaTrailerDex(fakeDex("axml-case")) },
  { name: "resources.arsc", data: Buffer.alloc(128, 7) },
]));

// ============================================================
// CASE 5 — nested hardened containers (jar/aar/zip members)
// ============================================================
const innerJar = zbuild([
  { name: "enclave/inner_decoy.txt", data: Buffer.from("inner enclave decoy") },
  { name: "classes.dex", data: blaTrailerDex(fakeDex("inner-jar-dex")) },
  { name: "inner/real.txt", data: Buffer.from("inner real") },
]);
const innerAar = zbuild([
  { name: "assets/bla-shield/aar_decoy.json", data: Buffer.from("{}") },
  { name: "classes.jar", data: innerJar },  // double-nested
]);
W("case5-nested.apk", zbuild([
  { name: "classes.dex", data: blaTrailerDex(fakeDex("outer-dex")) },
  { name: "libs/inner.jar", data: innerJar, method: 0 },
  { name: "libs/payload.aar", data: innerAar, method: 8 },
  { name: "assets/blob.zip", data: innerJar, method: 0 },
  { name: "enclave/outer_decoy.txt", data: Buffer.from("outer decoy") },
]));

// ============================================================
// CASE 6 — APK signing block (v2) between last entry and CD
// ============================================================
const sigBlock = (() => {
  const pair = Buffer.alloc(8 + 4 + 16);
  pair.writeBigUInt64LE(20n, 0); pair.writeUInt32LE(0x7109871a, 8); // v2 id
  Buffer.from("FAKEV2SIGBLOCK42").copy(pair, 12);
  const total = 8 + pair.length + 8 + 16;
  const b = Buffer.alloc(total);
  b.writeBigUInt64LE(BigInt(total - 8), 0);
  pair.copy(b, 8);
  b.writeBigUInt64LE(BigInt(total - 8), 8 + pair.length);
  b.write("APK Sig Block 42", 8 + pair.length + 8, "ascii");
  return b;
})();
// 6: real apksigner/v2 layout — sig block before CD, EOCD cdOffset -> CD start.
// Scrubber parses fine, rebuild silently discards the signature.
W("case6-signed.apk", zbuild([
  { name: "classes.dex", data: blaTrailerDex(fakeDex("signed-dex")) },
  { name: "enclave/decoy.txt", data: Buffer.from("decoy") },
  { name: "resources.arsc", data: Buffer.alloc(200, 9), method: 0 },
], { signingBlock: sigBlock, sigBlockBeforeCD: true }), { signingBlock: true });
// 6b: alternate layout — EOCD cdOffset -> the sig block itself (block as CD
// region). Scrubber sees non-central magic at cdStart -> 0 entries -> passthrough.
W("case6b-signed-altcd.apk", zbuild([
  { name: "classes.dex", data: blaTrailerDex(fakeDex("signed-dex-alt")) },
  { name: "enclave/decoy.txt", data: Buffer.from("decoy") },
], { signingBlock: sigBlock }), { signingBlock: true, evasion: true });

// ============================================================
// CASE 7 — stored members + 4K-alignment extra fields (.so contract)
// ============================================================
{
  // libreal.so stored; local extra field pads data to a 4096 boundary
  const nameB = Buffer.from("lib/arm64-v8a/libreal.so", "utf8");
  const probe = zbuild([{ name: "pad-probe", data: Buffer.alloc(0) }]);
  // compute padding so data start lands on 4096: header 30 + name + extra
  const headerLen = 30 + nameB.length;
  const padTotal = (4096 - (headerLen % 4096)) % 4096; // data offset = 0 -> pad extra
  const extra = Buffer.alloc(Math.max(4, padTotal));
  extra.writeUInt16LE(0xffff, 0); extra.writeUInt16LE(extra.length - 4, 2); // filler extra id
  W("case7-alignment.apk", zbuild([
    { name: "lib/arm64-v8a/libreal.so", data: fakeElf("aligned").subarray(0, 200), method: 0, localExtra: extra },
    { name: "res/drawable/big.png", data: Buffer.alloc(200, 0x89), method: 0 },          // stored >64 -> rebuilt deflated
    { name: "small.txt", data: Buffer.from("tiny stored file") },                          // stays stored
    { name: "deflated-already.txt", data: Buffer.from("was deflated ".repeat(10)), method: 8 },
    { name: "enclave/decoy.txt", data: Buffer.from("decoy") },
  ]), { alignment: true });
}

// ============================================================
// CASE 8 — foreign compression method member
// ============================================================
W("case8-bzip2-member.zip", zbuild([
  { name: "lib/x/libbzip2.so", data: Buffer.alloc(0), method: 12, comp: Buffer.from("BZh91AY&SY-fake-bzip2-stream-not-really") },
  { name: "enclave/decoy.txt", data: Buffer.from("decoy") },
  { name: "real.txt", data: Buffer.from("real ".repeat(10)), method: 8 },
]));

// ============================================================
// CASE 9 — marker collisions in legit member CONTENT
// ============================================================
W("case9-marker-collision.apk", zbuild([
  { name: "classes.dex", data: fakeDex("clean-primary") },
  { name: "classes2.dex", data: fakeDex("legit", ["cfg:BLA-DEX-XREF-V1:enabled", "Lcom/app/Real;"]) }, // legit dex w/ xref string -> DROPPED
  { name: "classes3.dex", data: (() => { const d = fakeDex("legit3", ["note:[BLA-DEX-SHIELD-V1]:tail", "Lcom/app/Real3;"]); return d; })() }, // marker mid-file -> truncated
  { name: "assets/db.dat", data: Buffer.from("REALDATA-BEFORE\0[BLA-IL2CPP-SHIELD]\0REALDATA-AFTER".repeat(4)) }, // truncated at marker
  { name: "assets/util.js", data: Buffer.from('const tag = "obligationFlood_marker_in_string";\nconst f = (x) => x * 2 + 1;\nconsole.log(tag, f(41));\n') },
  { name: "enclave/real_decoy.txt", data: Buffer.from("actual decoy") },
]));
// 9b: .js member that matches looksBlaHardened but makes dehardenJs THROW
// (duplicate top-level const) — unwrapped -> whole-archive PARSE-FAIL.
W("case9b-jsthrow.apk", zbuild([
  { name: "assets/dup.js", data: Buffer.from('const tag = "obligationFlood_x";\nconst tag = "dup";\nconsole.log(tag);\n') },
  { name: "enclave/real_decoy.txt", data: Buffer.from("actual decoy") },
  { name: "real.txt", data: Buffer.from("real ".repeat(10)) },
]), { expectThrow: true });

// ============================================================
// CASE 10 — local vs central header mismatches
// ============================================================
// 10a: central name "innocent.txt" but LOCAL name "enclave/decoy.txt" —
// scrubber decoy-matches on the central name only -> decoy survives kept.
W("case10-dualname.zip", zbuild([
  { name: "innocent.txt", localName: "enclave/decoy.txt", data: Buffer.from("PROTECTED_CANARY_CREDENTIAL=x enclave decoy content") },
  { name: "enclave/realdecoy.txt", data: Buffer.from("dropped anyway") },
]), { evasion: true });
// 10b: local nlen lies (declared 8, written 12) -> data starts 4 bytes later
// than scrubber computes -> silent content corruption.
{
  const data = Buffer.from("NOTE-CONTENTS-0123456789");
  W("case10b-nlen-lie.zip", zbuild([
    { name: "note.txt", localName: "note.txtPADX", localNlenLie: 8, data, method: 0 },
    { name: "enclave/decoy.txt", data: Buffer.from("d") },
  ]), { corruption: true, expectedData: data });
}

// ============================================================
// CASE 11 — self-extracting / prepended stub
// ============================================================
{
  const stub = Buffer.alloc(512);
  stub.write("MZ", 0, "latin1"); stub.writeUInt32LE(0x40, 0x3c);
  W("case11-sfx.apk", zbuild([
    { name: "enclave/decoy.txt", data: Buffer.from("decoy") },
    { name: "classes.dex", data: blaTrailerDex(fakeDex("sfx-dex")) },
  ], { prepend: stub }), { sfx: true });
}

// ============================================================
// CASE 12 — UTF-8 / non-ASCII member names
// ============================================================
W("case12-utf8-names.zip", zbuild([
  { name: "res/名前-ünïcodé-文件.txt", data: Buffer.from("unicode name content"), flags: 0x800 },
  { name: "enclave/decoy.txt", data: Buffer.from("d") },
]));

// ============================================================
// CASE 13 — decompression surface: big member, no size cap
// ============================================================
W("case13-zipbomb-member.zip", zbuild([
  { name: "assets/zeros.bin", data: Buffer.alloc(16 * 1024 * 1024, 0), method: 8 },
  { name: "enclave/decoy.txt", data: Buffer.from("d") },
]));

// ============================================================
// CASE 14 — hardened JS member inside zip (real ast-shield output)
// ============================================================
{
  const jsSrc = `"use strict";
function computePrice(items, tax) { let t = 0; for (const i of items) t += i.price * i.qty; return t * (1 + tax); }
function renderCart(c) { return c.items.map((i) => i.sku + ":" + i.qty).join(","); }
module.exports = { computePrice, renderCart };
`;
  const hardenedJs = await transformJavaScriptWithBlaShield(jsSrc, { filename: "assets/app.js", intensity: "stealth" });
  W("case14-hardened-js-member.zip", zbuild([
    { name: "assets/app.js", data: Buffer.from(hardenedJs.code, "utf8"), method: 8 },
    { name: "enclave/decoy.txt", data: Buffer.from("d") },
    { name: "real.txt", data: Buffer.from("real ".repeat(10)), method: 8 },
  ]), { jsHardened: true, jsOriginal: jsSrc });
}

// ============================================================
// CASE 16 — marker in a NON-dex member -> scrubDex on arbitrary content
// ============================================================
// Any member whose data contains "[BLA-DEX-SHIELD-V1]" is scrubDex'd
// regardless of name/type (the isDexMember check is OR-redundant with the
// marker requirement). A short post-cut remainder -> writeUInt32LE@32 throws.
W("case16-tinymarker.zip", zbuild([
  { name: "note.txt", data: Buffer.from("hi\0[BLA-DEX-SHIELD-V1]trailing") }, // cut -> 2 bytes -> scrubDex THROWS
  { name: "enclave/decoy.txt", data: Buffer.from("d") },
]), { expectThrow: true });
// variant: enough bytes before the marker -> no throw, but a text file gets
// "repaired" dex checksums (fields at 8/12/32 rewritten) -> corrupted content.
W("case16b-textmarker.zip", zbuild([
  { name: "read.txt", data: Buffer.concat([Buffer.from("README before marker ".repeat(3)), Buffer.from("\0[BLA-DEX-SHIELD-V1]"), Buffer.from("after".repeat(20))]) },
  { name: "enclave/decoy.txt", data: Buffer.from("d") },
]));

// ============================================================
// CASE 17 — decoy-bearing member that fails to inflate -> raw-preserved
// ============================================================
// method 8 member whose "compressed" bytes are garbage: inflate throws ->
// data=null -> raw-preserved verbatim -> marker bytes survive in output.
W("case17-corrupt-hardened.zip", zbuild([
  { name: "evil.dex", data: Buffer.alloc(0), method: 8, comp: Buffer.from("\0[BLA-DEX-SHIELD-V1] not a deflate stream at all, just marker bytes") },
  { name: "enclave/decoy.txt", data: Buffer.from("d") },
  { name: "real.txt", data: Buffer.from("real ".repeat(10)), method: 8 },
]), { evasion: true });

// ============================================================
// CASE 15 — clean passthrough control (exotic but legit)
// ============================================================
W("case15-clean-exotic.zip", zbuild([
  { name: "dir/", data: Buffer.alloc(0) },
  { name: "dir/dd.txt", data: Buffer.from("dd".repeat(40)), method: 8, descriptor: true },
  { name: "note.txt", data: Buffer.from("with comment"), fileComment: "entry comment" },
], { comment: "clean archive comment" }), { expectPassthrough: true });

writeFileSync(join(here, "manifest.json"), JSON.stringify(manifest, null, 2));
console.log("\nfixtures ->", outDir, "|", Object.keys(manifest).length, "cases");
