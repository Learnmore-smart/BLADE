// Adversarial fixture generator for BLADE's scrubNative.
// Real hardening via vendor/bla/dist protectNativeBinary where possible;
// synthetic trailers replicate BLA's exact "\0[BLA-NATIVE-SHIELD-V1]..." layout.
import { mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const blaNative = pathToFileURL(join(root, "vendor", "bla", "dist", "shields", "formats", "native.js")).href;
const blaGo = pathToFileURL(join(root, "vendor", "bla", "dist", "shields", "formats", "go-flutter-exhaustion.js")).href;
const { protectNativeBinary, detectNativeEofAppendHazard } = await import(blaNative);
const { buildMappedGoFlutterElfFixture } = await import(blaGo);

const here = dirname(fileURLToPath(import.meta.url));
const IN = join(here, "in");
const EXP = join(here, "expected");
mkdirSync(IN, { recursive: true });
mkdirSync(EXP, { recursive: true });

const M = "[BLA-NATIVE-SHIELD-V1]";
const TRAILER = () =>
  Buffer.concat([
    Buffer.from(`\0${M}\0.dep-v0\0`, "utf8"),
    Buffer.from("/rustc/" + "0".repeat(40) + "/library/core/src/enclave_guard.rs\0", "latin1"),
    Buffer.from("PROTECTED_CANARY_CREDENTIAL=decoy\0", "utf8"),
    Buffer.alloc(64, 0xcc),
  ]);

const w = (name, buf, dir = IN) => { writeFileSync(join(dir, name), buf); console.log("wrote", join(dir, name), buf.length); };

// ---------- minimal ELF64 LE builder ----------
// sections: [0] NULL, [1] .shstrtab, then caller-supplied {name,type,off,data}
function elf64({ extra = [], trailingData = null } = {}) {
  const names = ["", ".shstrtab", ...extra.map((s) => s.name)];
  const nameOff = [];
  let acc = 0;
  for (const n of names) { nameOff.push(acc); acc += Buffer.from(n, "utf8").length + 1; }
  const strtab = Buffer.alloc(acc);
  acc = 0;
  for (const n of names) { strtab.write(n, acc, "utf8"); acc += n.length + 1; }

  const shnum = 1 + names.length; // NULL + shstrtab + extras
  const shoff = 0x100;
  const strOff = 0x400;
  // lay out extras at caller offsets (already absolute)
  const parts = [];
  const push = (b, off) => parts.push({ b, off });
  const hdr = Buffer.alloc(64);
  hdr.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0);
  hdr.writeUInt16LE(3, 16); hdr.writeUInt16LE(0x3e, 18); hdr.writeUInt32LE(1, 20);
  hdr.writeBigUInt64LE(0x400000n, 24);
  hdr.writeBigUInt64LE(64n, 32);           // e_phoff
  hdr.writeBigUInt64LE(BigInt(shoff), 40); // e_shoff
  hdr.writeUInt16LE(64, 52); hdr.writeUInt16LE(56, 54); hdr.writeUInt16LE(1, 56);
  hdr.writeUInt16LE(64, 58); hdr.writeUInt16LE(shnum, 60); hdr.writeUInt16LE(1, 62);
  push(hdr, 0);
  const ph = Buffer.alloc(56);
  ph.writeUInt32LE(1, 0); ph.writeUInt32LE(6, 4);
  ph.writeBigUInt64LE(0n, 8); ph.writeBigUInt64LE(0x400000n, 16); ph.writeBigUInt64LE(0x400000n, 24);
  ph.writeBigUInt64LE(0n, 32); ph.writeBigUInt64LE(0n, 40); ph.writeBigUInt64LE(0x1000n, 48);
  push(ph, 64);
  // section headers
  const sh = (i, nameIdx, type, off, size, addr = 0) => {
    const s = Buffer.alloc(64);
    s.writeUInt32LE(nameOff[nameIdx], 0); s.writeUInt32LE(type, 4);
    s.writeBigUInt64LE(3n, 8); s.writeBigUInt64LE(BigInt(addr), 16);
    s.writeBigUInt64LE(BigInt(off), 24); s.writeBigUInt64LE(BigInt(size), 32);
    push(s, shoff + i * 64);
  };
  sh(0, 0, 0, 0, 0);
  sh(1, 1, 3, strOff, strtab.length);
  push(strtab, strOff);
  extra.forEach((s, k) => {
    sh(2 + k, 2 + k, s.type ?? 1, s.off, s.data.length, 0x400000n + BigInt(s.off));
    push(s.data, s.off);
  });
  if (trailingData) push(trailingData.b, trailingData.off);
  const size = Math.max(...parts.map((p) => p.off + p.b.length));
  const out = Buffer.alloc(size);
  for (const p of parts) p.b.copy(out, p.off);
  // fix PT_LOAD filesz/memsz now that size is known
  out.writeBigUInt64LE(BigInt(size), 64 + 32);
  out.writeBigUInt64LE(BigInt(size), 64 + 40);
  return out;
}

// ---------- minimal PE32+ builder ----------
// opts: { numRva, cert: Buffer|null, certOff }
function pe32plus({ numRva = 16, cert = null } = {}) {
  const dosHeader = Buffer.alloc(0x80);
  dosHeader[0] = 0x4d; dosHeader[1] = 0x5a;
  dosHeader.writeUInt32LE(0x80, 0x3c); // e_lfanew
  dosHeader.write("DOS stub: real bytes\0", 0x40, "latin1");
  const nt = Buffer.alloc(4 + 20 + 0xf0);
  nt.writeUInt32LE(0x00004550, 0);                    // PE\0\0
  nt.writeUInt16LE(0x8664, 4);                        // machine x64
  nt.writeUInt16LE(1, 4 + 2);                         // sections
  nt.writeUInt16LE(0xf0, 4 + 16);                     // sizeof optional
  nt.writeUInt16LE(0x2022, 4 + 18);                   // characteristics
  const opt = 24;
  nt.writeUInt16LE(0x20b, opt);                       // PE32+
  nt.writeUInt32LE(0x1000, opt + 16);                 // entry rva
  nt.writeBigUInt64LE(0x140000000n, opt + 24);        // imagebase
  nt.writeUInt32LE(0x1000, opt + 32);                 // sect align
  nt.writeUInt32LE(0x200, opt + 36);                  // file align
  nt.writeUInt32LE(0x3000, opt + 56);                 // sizeof image
  nt.writeUInt32LE(0x200, opt + 60);                  // sizeof headers
  nt.writeUInt16LE(3, opt + 68);                      // subsystem CUI
  nt.writeUInt32LE(numRva, opt + 108);                // NumberOfRvaAndSizes
  // section table (.text) + slack up to 0x200
  const secOff = 0x80 + nt.length;
  const fileHdr = Buffer.alloc(Math.max(0x200, secOff + 40) - 0x80 - nt.length);
  const pe = Buffer.concat([dosHeader, nt, fileHdr]);
  const sec = pe.subarray(secOff, secOff + 40);
  sec.write(".text", 0, "latin1");
  sec.writeUInt32LE(0x100, 8); sec.writeUInt32LE(0x1000, 12);
  sec.writeUInt32LE(0x100, 16); sec.writeUInt32LE(0x200, 20);
  sec.writeUInt32LE(0x60000020, 36);
  // .text content at file 0x200
  const text = Buffer.alloc(0x100, 0x90);
  text.write("real code bytes ending here\0", 0, "latin1");
  let body = Buffer.concat([pe, text]);
  if (cert) {
    const certOff = body.length;
    // IMAGE_DIRECTORY_ENTRY_SECURITY = DataDirectory[4] at lfanew+24+144 (PE32+)
    body.writeUInt32LE(certOff, 0x80 + 24 + 144);
    body.writeUInt32LE(cert.length, 0x80 + 24 + 144 + 4);
    body = Buffer.concat([body, cert]);
  }
  return body;
}
function winCert(payload) {
  const c = Buffer.alloc(8 + payload.length);
  c.writeUInt32LE(c.length, 0);   // dwLength
  c.writeUInt16LE(0x0200, 4);     // wRevision
  c.writeUInt16LE(0x0002, 6);     // wCertificateType = PKCS_SIGNED_DATA
  payload.copy(c, 8);
  return c;
}

// ---------- fat Mach-O builder ----------
function fatMachO(arches /* [{cputype,cpusubtype,sliceBuf,alignPow?}] */) {
  const nfat = arches.length;
  const headerLen = 8 + nfat * 20;
  let cursor = headerLen;
  const entries = [];
  for (const a of arches) {
    const align = 1 << (a.alignPow ?? 4);
    cursor = Math.ceil(cursor / align) * align;
    entries.push({ ...a, offset: cursor });
    cursor += a.sliceBuf.length;
  }
  const out = Buffer.alloc(cursor);
  out.writeUInt32BE(0xcafebabe, 0);
  out.writeUInt32BE(nfat, 4);
  entries.forEach((e, i) => {
    const o = 8 + i * 20;
    out.writeUInt32BE(e.cputype >>> 0, o);
    out.writeUInt32BE(e.cpusubtype >>> 0, o + 4);
    out.writeUInt32BE(e.offset, o + 8);
    out.writeUInt32BE(e.sliceBuf.length, o + 12);
    out.writeUInt32BE(e.alignPow ?? 4, o + 16);
    e.sliceBuf.copy(out, e.offset);
  });
  return out;
}
function thinMachO64(extra = Buffer.alloc(0)) {
  const h = Buffer.alloc(32);
  h.writeUInt32BE(0xcffaedfe, 0);   // MH_MAGIC_64 (BE read)
  h.writeUInt32BE(0x01000007, 4);   // CPU_TYPE_X86_64
  h.writeUInt32BE(3, 8);            // cpusubtype
  h.writeUInt32BE(2, 12);           // MH_EXECUTE
  h.writeUInt32BE(0, 16);           // ncmds
  h.writeUInt32BE(0, 20);           // sizeofcmds
  h.writeUInt32BE(0x00200085, 24);  // flags
  h.writeUInt32BE(0, 28);           // reserved
  return Buffer.concat([h, extra]);
}

// =====================================================================
// CASE 1 — marker inside REAL content (unhardened + really-hardened)
// =====================================================================
{
  const rodata = Buffer.concat([
    Buffer.from("real string one\0prefix_", "utf8"),
    Buffer.from(M, "utf8"),               // marker inside real .rodata, NOT preceded by NUL
    Buffer.from("_suffix\0real string two\0", "utf8"),
  ]);
  const tail = Buffer.from("TRAILING-SECTION-REAL-DATA".repeat(8), "latin1");
  const elf = elf64({
    extra: [
      { name: ".rodata", off: 0x600, data: rodata },
      { name: ".tail", off: 0x800, data: tail },
    ],
  });
  w("case1-elf-marker-in-real-content.elf", elf);
  w("case1-elf-marker-in-real-content.elf", elf, EXP);
  // same file, then REALLY hardened by BLA
  const r = protectNativeBinary(elf, { intensity: "balanced" });
  w("case1-elf-marker-in-content-hardened.elf", r.buffer);
  w("case1-elf-marker-in-content-hardened.elf", elf, EXP); // expected = pristine
}

// =====================================================================
// CASE 2 — signed PE (cert/overlay at EOF) then hardened
// =====================================================================
{
  // 2a: numRva=4 evades BLA's hazard gate (needs >=5) yet dd[4] is populated —
  //     BLA really does append the trailer after the cert. Scrub should restore.
  const cert = winCert(Buffer.concat([Buffer.from("PKCS7-SIGNATURE-BYTES", "latin1"), Buffer.alloc(64, 0xa5)]));
  const pe = pe32plus({ numRva: 4, cert });
  console.log("hazard(numRva=4,signed) =", detectNativeEofAppendHazard(pe));
  const r = protectNativeBinary(pe, {});
  console.log("  protect: appended?", r.buffer.length > pe.length, "preserved:", r.nativeBinaryPreserved);
  w("case2-pe-signed-numrva4-hardened.exe", r.buffer);
  w("case2-pe-signed-numrva4-hardened.exe", pe, EXP);

  // 2b: certificate blob itself contains the separator string (e.g. inside
  //     unauthenticated attributes / overlay data). First indexOf lands in cert.
  const certM = winCert(Buffer.concat([Buffer.from(`SIG-${M}-ATTR`, "latin1"), Buffer.alloc(64, 0xa5)]));
  const pe2 = pe32plus({ numRva: 4, cert: certM });
  const r2 = protectNativeBinary(pe2, {});
  w("case2-pe-cert-contains-marker-hardened.exe", r2.buffer);
  w("case2-pe-cert-contains-marker-hardened.exe", pe2, EXP);

  // 2c control: numRva=16 signed PE — BLA hazard-checks and passes it through.
  const pe3 = pe32plus({ numRva: 16, cert });
  console.log("hazard(numRva=16,signed) =", detectNativeEofAppendHazard(pe3));
  const r3 = protectNativeBinary(pe3, {});
  console.log("  protect: appended?", r3.buffer.length > pe3.length, "hazard:", r3.nativeAppendHazard);
  w("case2-pe-signed-detected-passthrough.exe", r3.buffer);
  w("case2-pe-signed-detected-passthrough.exe", pe3, EXP);
}

// =====================================================================
// CASE 3 — fat/universal Mach-O (0xcafebabe) misroute
// =====================================================================
{
  const slice = thinMachO64(Buffer.from("real slice bytes\0".repeat(8), "latin1"));
  const fat = fatMachO([{ cputype: 0x01000007, cpusubtype: 3, sliceBuf: slice }]);
  const r = protectNativeBinary(fat, {});
  console.log("fat hazard:", r.nativeAppendHazard, "appended:", r.buffer.length - fat.length);
  // 3a control: proper extension -> native -> clean cut
  w("case3-fat-macho-hardened.bin", r.buffer);
  w("case3-fat-macho-hardened.bin", fat, EXP);
  // 3b: SAME hardened bytes but .class extension -> jvm misroute
  w("case3-fat-macho-hardened.class", r.buffer);
  w("case3-fat-macho-hardened.class", fat, EXP);
  // 3c: fat with cputype=7 (CPU_TYPE_I386, real) whose post-cpEnd tail happens
  //     to carry the jvm structural-cut sentinel -> scrubJvm rebuilds the file.
  const sliceJ = thinMachO64(Buffer.from("xx{}\0bla-jvm-enclave-v1\0".repeat(4), "latin1"));
  const fatJ = fatMachO([{ cputype: 7, cpusubtype: 3, sliceBuf: sliceJ }]);
  const rJ = protectNativeBinary(fatJ, {});
  w("case3-fat-macho-i386-parseable.class", rJ.buffer);
  w("case3-fat-macho-i386-parseable.class", fatJ, EXP);

  // 3d: NEW detect() disambiguates cafebabe by bytes 6-7 (JVM major 45-90).
  //     nfat_arch low half lives there -> nfat=45 fat => v=45 => "jvm".
  //     Real cputypes -> CP unparseable -> passthrough -> trailer survives.
  const slices45 = Array.from({ length: 45 }, (_, i) => ({
    cputype: 0x01000007, cpusubtype: 3,
    sliceBuf: thinMachO64(Buffer.from(`slice-${i}-real\0`, "latin1")),
  }));
  const fat45 = fatMachO(slices45);
  const r45 = protectNativeBinary(fat45, {});
  w("case3-fat-macho-nfat45-hardened.bin", r45.buffer);
  w("case3-fat-macho-nfat45-hardened.bin", fat45, EXP);

  // 3e: nfat=45 AND arch fields crafted so scrubJvm's CP walk parses:
  //   cpCount=3 (cputype hi); entry1 utf8 "OK!"; entry2 utf8 "BlaEnclaveDelegation"
  //   (JVM_HARD_ANCHOR). scrubJvm rebuilds: buf[0..10]+buf[10..16]+buf[39..53]
  //   -> 30-byte output; the whole fat binary + native trailer destroyed.
  const hdrLen = 8 + 45 * 20;
  const fatE = Buffer.alloc(hdrLen + 64);
  fatE.writeUInt32BE(0xcafebabe, 0);
  fatE.writeUInt32BE(45, 4);                     // nfat=45 -> detect() v=45 -> "jvm"
  // arch0 bytes spell the constant pool:
  //   [00 03] cpCount | [01] tag utf8 [00 03] len3 "OK!" | [01] tag utf8
  //   [00 14] len20 "BlaEnclaveDelegation" (spans size/align/arch1 fields)
  fatE.writeUInt32BE(0x00030100, 8);             // cputype  -> cpCount=3, tag@10=1
  fatE.writeUInt32BE(0x034f4b21, 12);            // cpusubtype -> len=3, "OK!"
  fatE.writeUInt32BE(0x01001442, 16);            // offset   -> tag@16=1, len=20, 'B'
  fatE.writeUInt32BE(0x6c61456e, 20);            // size     -> "laEn"
  fatE.writeUInt32BE(0x636c6176, 24);            // align    -> "clav"
  fatE.writeUInt32BE(0x6544656c, 28);            // arch1.cputype  -> "eDel"
  fatE.writeUInt32BE(0x65676174, 32);            // arch1.cpusub   -> "egat"
  fatE.writeUInt32BE(0x696f6e00, 36);            // arch1.offset   -> "ion"+pad
  // arch1.size/align = 0, arch2..44 = 0 => jvmClassEnd sees all-zero tables
  const rE = protectNativeBinary(fatE, {});
  w("case3-fat-macho-nfat45-parseable.class", rE.buffer);
  w("case3-fat-macho-nfat45-parseable.class", fatE, EXP);
}

// =====================================================================
// CASE 4 — in-place ELF section planting (.go.buildinfo / .isolate)
// =====================================================================
{
  const elf = buildMappedGoFlutterElfFixture();
  const r = protectNativeBinary(elf, { intensity: "balanced" });
  console.log("in-place plants:", r.mappedGoBuildInfoPlanted, r.mappedFlutterPoolPlanted,
    "appended:", r.buffer.length - elf.length);
  w("case4-elf-inplace-hardened.elf", r.buffer);
  // expected: original restored BUT planted sections zeroed (irrecoverable by
  // design — scrubber reports this). .go.buildinfo @1024+512, .isolate @2048+48KiB
  const elfZeroed = Buffer.from(elf);
  elfZeroed.fill(0, 1024, 1024 + 512);
  elfZeroed.fill(0, 2048, 2048 + 48 * 1024);
  w("case4-elf-inplace-hardened.elf", elfZeroed, EXP);

  // 4b: same hardened file but ELF extended section numbering
  //     (e_shnum=0 -> real count in shdr[0].sh_size; e_shstrndx=0xffff ->
  //     real index in shdr[0].sh_link). Valid ELF; scrubber's guard skips scan.
  const ext = Buffer.from(r.buffer);
  const shoff = Number(ext.readBigUInt64LE(40));
  const shnum = ext.readUInt16LE(60);
  const shstrndx = ext.readUInt16LE(62);
  ext.writeBigUInt64LE(BigInt(shnum), shoff + 32);   // section[0].sh_size = real count
  ext.writeUInt32LE(shstrndx, shoff + 44);           // section[0].sh_link = real strndx
  ext.writeUInt16LE(0, 60);                          // e_shnum = 0
  ext.writeUInt16LE(0xffff, 62);                     // e_shstrndx = SHN_XINDEX
  w("case4-elf-inplace-shnum0.elf", ext);
  // ideal-scrub reference: shnum0 header + trailer stripped + whole target
  // sections zeroed (what the scrubber does when its guard doesn't skip).
  const ideal = Buffer.from(ext.subarray(0, ext.indexOf(Buffer.from(`\0${M}`, "latin1"))));
  const gOff = 1024, isoOff = 2048, ISO = 48 * 1024, GO = 512;
  ideal.fill(0, gOff, gOff + GO);
  ideal.fill(0, isoOff, isoOff + ISO);
  w("case4-elf-inplace-shnum0.elf", ideal, EXP);

  // 4c: marker planted in a NON-target section (.dynsym) — name-scoped cleanup
  const c = Buffer.from(r.buffer);
  const dynOff = 2048 + 48 * 1024; // .dynsym offset per fixture builder
  c.write("\0[BLA-GO-MAPPED]\0", dynOff + 24, "latin1"); // inside second sym
  w("case4-elf-marker-in-dynsym.elf", c);
  // ideal = idealA + marker kept in .dynsym (scrubber only scans target names)
  const idealC = Buffer.from(elfZeroed);
  idealC.write("\0[BLA-GO-MAPPED]\0", dynOff + 24, "latin1");
  w("case4-elf-marker-in-dynsym.elf", idealC, EXP);

  // 4d: ONLY a planted section, NO eof trailer at all
  const noTrailer = Buffer.from(elf);
  noTrailer.write("\0[BLA-GO-MAPPED]\0", 1024 + 8, "latin1");
  w("case4-elf-inplace-no-trailer.elf", noTrailer);
  // expected: .go.buildinfo region zeroed (correct detection even sans trailer)
  const idealD = Buffer.from(noTrailer);
  idealD.fill(0, 1024, 1024 + 512);
  w("case4-elf-inplace-no-trailer.elf", idealD, EXP);
}

// =====================================================================
// CASE 5 — real trailing section; marker at EOF / off-by-one
// =====================================================================
{
  // 5a: trailing real section then real BLA trailer -> must restore byte-exact
  const tail = Buffer.concat([Buffer.from("REAL-TAIL-SECTION\0".repeat(6), "latin1")]);
  const elf = elf64({ extra: [{ name: ".tail", off: 0x800, data: tail }] });
  const r = protectNativeBinary(elf, {});
  w("case5-elf-trailing-section-hardened.elf", r.buffer);
  w("case5-elf-trailing-section-hardened.elf", elf, EXP);

  // 5b: real trailing section whose LAST bytes literally are the marker string
  //     (file unhardened; marker is real content, preceded by 'Z' not NUL).
  const tailM = Buffer.concat([
    Buffer.from("const char *banner = \"BLA-NATIVE-SHIELD notice\";\nZ", "latin1"),
    Buffer.from(M, "latin1"),
  ]);
  const elfB = elf64({ extra: [{ name: ".rodata", off: 0x800, data: tailM }] });
  w("case5-elf-marker-is-last-bytes.elf", elfB);
  w("case5-elf-marker-is-last-bytes.elf", elfB, EXP);

  // 5c: marker inside content followed by ~300 real bytes (inside the 512-byte
  //     eofNear window) — still a trailer by the new logic -> overcut.
  const tailC = Buffer.concat([
    Buffer.from("data before\0", "latin1"),
    Buffer.from(M, "latin1"),
    Buffer.alloc(300, 0x52), // 300 bytes of real 'R' data AFTER the marker
  ]);
  const elfC = elf64({ extra: [{ name: ".rodata", off: 0x800, data: tailC }] });
  w("case5-elf-marker-near-eof.elf", elfC);
  w("case5-elf-marker-near-eof.elf", elfC, EXP);
}

// =====================================================================
// CASE 6 — multiple separator occurrences in the trailer
// =====================================================================
{
  const elf = elf64({ extra: [{ name: ".text", off: 0x800, data: Buffer.from("REALCODE".repeat(16), "latin1") }] });
  const r = protectNativeBinary(elf, {});
  // 6a: double-hardened (BLA trailer twice)
  const dbl = Buffer.concat([r.buffer, TRAILER()]);
  w("case6-elf-double-trailer.elf", dbl);
  w("case6-elf-double-trailer.elf", elf, EXP);
  // 6b: trailer region contains an extra embedded marker mid-trailer
  const mid = Buffer.concat([
    elf,
    Buffer.from(`\0${M}\0.dep-v0\0`, "utf8"),
    Buffer.from(`junk${M}more-junk`, "latin1"),
    Buffer.alloc(32, 0x41),
  ]);
  w("case6-elf-marker-mid-trailer.elf", mid);
  w("case6-elf-marker-mid-trailer.elf", elf, EXP);
  // 6c: version-drift trailer V2 — scrubber only knows V1
  const v2 = Buffer.concat([elf, Buffer.from(`\0[BLA-NATIVE-SHIELD-V2]\0.dep-v0\0`, "utf8"), Buffer.alloc(48, 0x42)]);
  w("case6-elf-trailer-v2.elf", v2);
  w("case6-elf-trailer-v2.elf", elf, EXP);
}

// =====================================================================
// CASE 7 — decoy Electron-fuse sentinel records at EOF
// =====================================================================
{
  // 42-byte record: 32B sentinel + 01 08 + 8 wire bytes; wire[6]=0x39 DECOY,
  // wire[7] in {0x39,0x72} — replicates buildDecoyElectronFuseSentinels.
  const SENT = Buffer.from("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX", "latin1");
  const decoy = (i) => Buffer.concat([
    SENT,
    Buffer.from([0x01, 0x08, 0x30, 0x31, 0x30, 0x30, 0x31, 0x31, 0x39, i % 2 ? 0x72 : 0x39]),
  ]);
  const decoys = (n) => Buffer.concat(Array.from({ length: n }, (_, i) => decoy(i)));
  // REAL V1 fuse block for .rodata: same hardened first-6 plan, but the last
  // two wire bytes are ordinary states (0x30) — not the decoy signature.
  const realFuse = Buffer.concat([SENT, Buffer.from([0x01, 0x08, 0x30, 0x31, 0x30, 0x30, 0x31, 0x31, 0x30, 0x30])]);
  const elf = elf64({ extra: [{ name: ".text", off: 0x800, data: Buffer.from("REALCODE".repeat(16), "latin1") }] });
  const elfFuse = elf64({ extra: [{ name: ".rodata", off: 0x800, data: Buffer.concat([Buffer.from("fuse-section\0", "latin1"), realFuse]) }] });

  // 7a: decoys BEFORE the trailer marker — cutAtMarker leaves them at EOF.
  const a = Buffer.concat([elf, decoys(34), TRAILER()]);
  w("case7-elf-fuse-decoys-then-trailer.elf", a);
  w("case7-elf-fuse-decoys-then-trailer.elf", elf, EXP);

  // 7b: bare append, no marker at all.
  const b = Buffer.concat([elf, decoys(34)]);
  w("case7-elf-fuse-decoys-bare.elf", b);
  w("case7-elf-fuse-decoys-bare.elf", elf, EXP);

  // 7c: a lone record could be a real trailing fuse block — must be KEPT.
  const c = Buffer.concat([elf, decoys(1)]);
  w("case7-elf-fuse-single-decoy.elf", c);
  w("case7-elf-fuse-single-decoy.elf", c, EXP);

  // 7d: real fuse in .rodata + bare decoy run — decoys peeled, fuse survives
  //     (report flags fuseWireSuspect; byte output is the pristine elf).
  const d = Buffer.concat([elfFuse, decoys(34)]);
  w("case7-elf-fuse-real-plus-decoys.elf", d);
  w("case7-elf-fuse-real-plus-decoys.elf", elfFuse, EXP);

  // 7e: clean binary — untouched.
  w("case7-elf-clean.elf", elf);
  w("case7-elf-clean.elf", elf, EXP);
}

console.log("done.");
