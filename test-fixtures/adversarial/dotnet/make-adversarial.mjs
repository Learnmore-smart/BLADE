// Generates adversarial .NET / IL2CPP fixtures for BLADE trailer scrubbers.
// Every fixture keeps a copy of its pristine "real" bytes in `expected/`
// so the harness can verify byte-exact restoration (or measure damage).
import { mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const dir = dirname(fileURLToPath(import.meta.url));
const exp = join(dir, "expected");
mkdirSync(exp, { recursive: true });

const DOTNET_MARKER = "BLA_DOTNET_CLR_SHIELD_V1";
const IL2CPP_MARKER = "[BLA-IL2CPP-SHIELD]";
const NATIVE_MARKER = "[BLA-NATIVE-SHIELD-V1]";

// --- shared builders ------------------------------------------------------
function peStub({ bsjbAt = 0x120, extraSections = [] } = {}) {
  // Minimal MZ+PE that satisfies BLADE/BLA's `MZ`+`BSJB` sniff.
  const size = Math.max(0x400, ...extraSections.map((s) => s.at + s.data.length), bsjbAt + 4);
  const pe = Buffer.alloc(size);
  pe.write("MZ", 0, "latin1");
  pe.writeUInt32LE(0x80, 0x3c);
  pe.write("PE\0\0", 0x80, "latin1");
  pe.writeUInt16LE(0x14c, 0x84);
  pe.writeUInt16LE(0xe0, 0x94);
  pe.writeUInt16LE(0x10b, 0x98);
  Buffer.from("BSJB", "ascii").copy(pe, bsjbAt);
  for (const s of extraSections) Buffer.from(s.data).copy(pe, s.at);
  return pe;
}
// What vendor/bla dotnet-managed.ts actually appends.
function dotnetTrailer(records = ["enclave_pinvoke_unseal_ring0_slot_abc_0", "charge:684032", "PROTECTED_CANARY_CREDENTIAL=tok_1"]) {
  return Buffer.from(["", DOTNET_MARKER, ...records, ""].join("\0"), "utf8");
}
// What vendor/bla mobile-game.ts protectIl2cppMetadataBuffer appends.
function il2cppTrailer(literals = ["Enclave.Ring0.Tarpit_0_deadbeef:chaff", "PROTECTED_CANARY_CREDENTIAL=tok_2"]) {
  return Buffer.from(`\0${IL2CPP_MARKER}\0${literals.join("\0")}\0`, "utf8");
}
// What vendor/bla native.ts appends (abbreviated but faithful header).
function nativeTrailer() {
  return Buffer.concat([
    Buffer.from(`\0${NATIVE_MARKER}\0.dep-v0\0`, "utf8"),
    Buffer.from("/rustc/0000aaaa/library/core/src/enclave_guard.rs\0", "latin1"),
    Buffer.from("PROTECTED_CANARY_CREDENTIAL=tok_3\0", "utf8"),
  ]);
}
function il2cppHeader(realStrings) {
  const m = Buffer.alloc(4096);
  m.writeUInt32LE(0xfab11baf, 0);
  m.writeInt32LE(29, 4);
  Buffer.from(realStrings, "latin1").copy(m, 64);
  return m;
}

const made = [];
function fixture(name, real, hardened) {
  writeFileSync(join(exp, name + ".real"), real);
  writeFileSync(join(dir, name), hardened);
  made.push(name);
}

// === Case 1a: marker text inside REAL .rsrc, BLA trailer appended =========
// A dll that legitimately mentions the tool in a version/resource string,
// then got dotnet-shielded on top.
{
  const real = peStub({
    extraSections: [
      { at: 0x200, data: Buffer.from(".rsrc\0VersionInfo: protected by BLA_DOTNET_CLR_SHIELD_V1 toolkit v9\0", "latin1") },
      { at: 0x300, data: Buffer.from("REAL_USER_STRINGS_MUST_SURVIVE\0LicenseVerifier\0", "latin1") },
    ],
  });
  fixture("case1a-marker-in-rsrc.dll", real, Buffer.concat([real, dotnetTrailer()]));
}
// === Case 1a': marker in real content, NEVER hardened =====================
{
  const real = peStub({
    extraSections: [
      { at: 0x200, data: Buffer.from("doc string: see BLA_DOTNET_CLR_SHIELD_V1 spec\0", "latin1") },
      { at: 0x280, data: Buffer.from("TAIL_DATA_AFTER_MENTION\0", "latin1") },
    ],
  });
  fixture("case1a2-marker-no-trailer.dll", real, Buffer.from(real));
}
// === Case 1b: marker bytes inside the trailer's own records ===============
{
  const real = peStub();
  fixture(
    "case1b-marker-in-records.dll",
    real,
    Buffer.concat([real, dotnetTrailer([`record mentions ${DOTNET_MARKER} again`, "PROTECTED_CANARY_CREDENTIAL=tok_9"])]),
  );
}
// === Case 2a: dotnet section, then NATIVE trailer appended after ==========
// protect ran dotnet-managed first (BSJB in first 4K), then a second pass
// (or a pipeline) appended the native EOF trailer on top.
{
  const real = peStub();
  fixture("case2a-dotnet-then-native.dll", real, Buffer.concat([real, dotnetTrailer(), nativeTrailer()]));
}
// === Case 2b: native trailer FIRST, dotnet section after ==================
// Reverse stacking (not producible by current BLA, but adversarial input).
{
  const real = peStub();
  fixture("case2b-native-then-dotnet.dll", real, Buffer.concat([real, nativeTrailer(), dotnetTrailer()]));
}
// === Case 2c: managed dll with BSJB *beyond* BLA's 4096-byte header sniff ==
// vendor/bla detector only reads 4096 header bytes -> routes "native-pe" ->
// native trailer appended. BLADE's detect() scans the WHOLE buffer for BSJB
// -> routes "dotnet" -> scrubDotnet finds no marker -> MISROUTE.
{
  const real = peStub({ bsjbAt: 0x1400 }); // >4096
  fixture("case2c-late-bsjb-native-trailer.dll", real, Buffer.concat([real, nativeTrailer()]));
}
// === Case 3: [BLA-IL2CPP-SHIELD] in real string table + trailer ===========
{
  const real = il2cppHeader(
    "LicenseManager\0IAPStore\0[BLA-IL2CPP-SHIELD]\0RealStringAfterBoundary\0MoreReal\0",
  );
  fixture("case3-marker-in-strings.dat", real, Buffer.concat([real, il2cppTrailer()]));
}
// variant: marker in real strings, no trailer at all
{
  const real = il2cppHeader("GameString\0[BLA-IL2CPP-SHIELD]\0TrailingRealStrings\0");
  fixture("case3b-marker-no-trailer.dat", real, Buffer.from(real));
}
// === Case 4: dll where a manifest/resource name mentions the marker =======
// (dotnet-managed.ts is pure-append; simulate a manifest resource whose own
// name contains the marker string, sitting mid-file.)
{
  const real = peStub({
    extraSections: [
      { at: 0x180, data: Buffer.from("manifest\0BLA_DOTNET_CLR_SHIELD_V1.manifest\0", "latin1") },
      { at: 0x280, data: Buffer.from("REAL_MANIFEST_XML_<assembly/>\0", "latin1") },
    ],
  });
  fixture("case4-marker-manifest-resource.dll", real, Buffer.concat([real, dotnetTrailer()]));
}
// === Case 5a: single-file bundle (apphost + appended managed payload) =====
// Real content already ends with a managed dll payload containing BSJB,
// then the whole thing got dotnet-shielded.
{
  // build apphost WITHOUT early BSJB: MZ+PE, then bundled payload at EOF
  const host = Buffer.alloc(0x800);
  host.write("MZ", 0, "latin1");
  host.writeUInt32LE(0x80, 0x3c);
  host.write("PE\0\0", 0x80, "latin1");
  host.writeUInt16LE(0x8664, 0x84);
  const bundled = Buffer.alloc(0x600);
  bundled.write("MZ", 0, "latin1");
  Buffer.from("BSJB", "ascii").copy(bundled, 0x40); // bundled managed dll
  Buffer.from("BundledApp.dll real bytes\0", "latin1").copy(bundled, 0x100);
  const bundleTrailer = Buffer.alloc(8); // bundle manifest offset ptr
  const real = Buffer.concat([host, bundled, bundleTrailer]);
  fixture("case5a-bundle-plus-dotnet-trailer.exe", real, Buffer.concat([real, dotnetTrailer()]));
}
// === Case 5b: bundle + NATIVE trailer (BSJB is past byte 4096) ============
{
  const host = Buffer.alloc(0x2000);
  host.write("MZ", 0, "latin1");
  host.writeUInt32LE(0x80, 0x3c);
  host.write("PE\0\0", 0x80, "latin1");
  host.writeUInt16LE(0x8664, 0x84);
  const bundled = Buffer.alloc(0x600);
  bundled.write("MZ", 0, "latin1");
  Buffer.from("BSJB", "ascii").copy(bundled, 0x40);
  Buffer.from("BundledApp.dll real bytes\0", "latin1").copy(bundled, 0x100);
  const real = Buffer.concat([host, bundled]); // BSJB lands at 0x2040 > 4096
  fixture("case5b-bundle-late-bsjb-native-trailer.exe", real, Buffer.concat([real, nativeTrailer()]));
}
// === Case 5c: bundle whose embedded payload contains marker text ==========
{
  const host = Buffer.alloc(0x400);
  host.write("MZ", 0, "latin1");
  host.writeUInt32LE(0x80, 0x3c);
  host.write("PE\0\0", 0x80, "latin1");
  const bundled = Buffer.alloc(0x400);
  Buffer.from("BSJB", "ascii").copy(bundled, 0x20);
  Buffer.from("user literal: BLA_DOTNET_CLR_SHIELD_V1 was here\0", "latin1").copy(bundled, 0x80);
  Buffer.from("MORE_BUNDLE_BYTES\0", "latin1").copy(bundled, 0x200);
  const real = Buffer.concat([host, bundled]);
  fixture("case5c-bundle-marker-in-payload.exe", real, Buffer.concat([real, dotnetTrailer()]));
}

console.log("wrote", made.length, "fixtures:");
for (const m of made) console.log(" -", m);
