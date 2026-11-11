// Adversarial test harness for BLADE's scrubJvm (src/trailer.mjs).
// Builds crafted .class files (real CP structures), applies BLA-style
// structural hardening where relevant, runs scrubJvm, and reports verdicts.
// Usage: node test-fixtures/adversarial/jvm/adversarial-jvm.mjs
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { scrubJvm } from "../../../src/trailer.mjs";

const DIR = dirname(fileURLToPath(import.meta.url));
mkdirSync(DIR, { recursive: true });

// ---------- constant-pool entry constructors ----------
const u2 = (v) => { const b = Buffer.alloc(2); b.writeUInt16BE(v & 0xffff); return b; };
const u4 = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0); return b; };
const E = {
  utf8: (s) => ({ b: Buffer.concat([Buffer.from([1]), u2(Buffer.byteLength(s, "utf8")), Buffer.from(s, "utf8")]), slots: 1, desc: `Utf8 "${s}"` }),
  int: (v) => ({ b: Buffer.concat([Buffer.from([3]), u4(v)]), slots: 1, desc: `Integer ${v}` }),
  float: (v) => { const b = Buffer.alloc(5); b[0] = 4; b.writeFloatBE(v, 1); return { b, slots: 1, desc: `Float ${v}` }; },
  long: (v) => { const b = Buffer.alloc(9); b[0] = 5; b.writeBigInt64BE(BigInt(v), 1); return { b, slots: 2, desc: `Long ${v}` } },
  double: (v) => { const b = Buffer.alloc(9); b[0] = 6; b.writeDoubleBE(v, 1); return { b, slots: 2, desc: `Double ${v}` }; },
  cls: (i) => ({ b: Buffer.concat([Buffer.from([7]), u2(i)]), slots: 1, desc: `Class ->#${i}` }),
  str: (i) => ({ b: Buffer.concat([Buffer.from([8]), u2(i)]), slots: 1, desc: `String ->#${i}` }),
  ref: (t, a, c, name) => ({ b: Buffer.concat([Buffer.from([t]), u2(a), u2(c)]), slots: 1, desc: `${name} #${a}.#${c}` }),
  mh: (k, r) => ({ b: Buffer.concat([Buffer.from([15]), Buffer.from([k]), u2(r)]), slots: 1, desc: `MethodHandle k${k} #${r}` }),
  tagU2: (t, i, name) => ({ b: Buffer.concat([Buffer.from([t]), u2(i)]), slots: 1, desc: `${name} ->#${i}` }),
};
// assign CP indexes (1-based; long/double consume 2 slots)
function index(entries) {
  let idx = 1;
  for (const e of entries) { e.cpIndex = idx; idx += e.slots; }
  return entries;
}

// ---------- class assembly ----------
// body: access this super ifaces[] fields[] methods[] attrs[]
function body({ thisIdx, superIdx, ifaces = [], fields = [], methods = [], attrs = [] }) {
  const out = [u2(0x0021), u2(thisIdx), u2(superIdx), u2(ifaces.length)];
  for (const i of ifaces) out.push(u2(i));
  const member = (m) => {
    out.push(u2(m.access ?? 1), u2(m.name), u2(m.desc), u2(m.attrs?.length ?? 0));
    for (const a of m.attrs ?? []) out.push(u2(a.name), u4(a.info.length), a.info);
  };
  out.push(u2(fields.length)); for (const f of fields) member(f);
  out.push(u2(methods.length)); for (const m of methods) member(m);
  out.push(u2(attrs.length));
  for (const a of attrs) out.push(u2(a.name), u4(a.info.length), a.info);
  return Buffer.concat(out);
}
function assemble(entries, bodyBuf, { major = 52 } = {}) {
  index(entries);
  const cpCount = 1 + entries.reduce((a, e) => a + e.slots, 0);
  const head = Buffer.alloc(10);
  head.writeUInt32BE(0xcafebabe, 0);
  head.writeUInt16BE(0, 4); head.writeUInt16BE(major, 6);
  head.writeUInt16BE(cpCount, 8);
  return Buffer.concat([head, ...entries.map((e) => e.b), bodyBuf]);
}

// ---------- BLA-style structural hardening (mirrors vendor jvm-bytecode.ts) ----------
const DECOYS = [
  "BlaEnclaveDelegation",
  "com/enclave/sgx/TeeAttestationBridge",
  "verifyShamirEd25519QuorumRing:(Ljava/nio/ByteBuffer;[B)Z",
  "unsealVsockCid16Frame:(J[B)[B",
  "[BLA-JVM-ENCLAVE:ch0001] opaque attestation chaff",
  "PROTECTED_CANARY_CREDENTIAL=sk-live-decoy-9941",
  "TRANSPORT_ENDPOINT=https://tee.internal/v9",
  "com/enclave/tarpit/StateNode_00_pc_4242",
  "com/enclave/tarpit/StateNode_01_pc_1337",
];
const ATTR_JSON = Buffer.from(
  JSON.stringify({ schema: "bla-jvm-enclave-v1", enclaveBridge: "com.enclave.sgx.TeeAttestationBridge", tarpitNodes: 9, chaffCount: 1 }),
  "utf8",
);
// structural: insert decoy Utf8s at original CP end (bump count), JSON at EOF
function blaHarden(entries, bodyBuf) {
  const orig = assemble(entries, bodyBuf);                     // original bytes
  const origCpCount = orig.readUInt16BE(8);
  let off = 10;                                                // original CP end
  for (const e of entries) off += e.b.length;
  const decoyBufs = DECOYS.map((s) => E.utf8(s).b);
  const head = Buffer.from(orig.subarray(0, off));
  head.writeUInt16BE(origCpCount + decoyBufs.length, 8);       // BLA bumps count
  const hardened = Buffer.concat([head, ...decoyBufs, orig.subarray(off), ATTR_JSON]);
  return { original: orig, hardened, firstDecoyCpIndex: origCpCount };
}

// ---------- independent CP walker (correct sizes incl. 5/6, for verification) ----------
const REAL_SIZES = { 3: 5, 4: 5, 9: 5, 10: 5, 11: 5, 12: 5, 17: 5, 18: 5, 7: 3, 8: 3, 16: 3, 19: 3, 20: 3, 15: 4, 5: 9, 6: 9 };
function walkCp(buf) {
  if (buf.length < 10 || buf.readUInt32BE(0) !== 0xcafebabe) return { ok: false, reason: "no cafebabe" };
  const cpCount = buf.readUInt16BE(8);
  const entries = [];
  let off = 10, idx = 1;
  while (idx < cpCount && off < buf.length) {
    const tag = buf[off];
    const size = tag === 1 ? 3 + buf.readUInt16BE(off + 1) : REAL_SIZES[tag];
    if (!size || off + size > buf.length) return { ok: false, reason: `truncated/unknown tag ${tag} at off ${off}`, entries, idx, cpCount };
    const text = tag === 1 ? buf.subarray(off + 3, off + size).toString("utf8") : null;
    entries.push({ cpIndex: idx, tag, off, size, text });
    off += size; idx += (tag === 5 || tag === 6) ? 2 : 1;
  }
  return { ok: idx >= cpCount, entries, cpCount, cpEnd: off, idx };
}

// ---------- fixture builders ----------
const F = {}; // name -> { buffer, kind, expect, meta }

function simpleOrigCp(extra = []) {
  // a realistic minimal pool: #1 Class(App) #2 Utf8 App #3 Class(Object) #4 Utf8 java/lang/Object ...
  const entries = index([
    E.utf8("App"),                                   // #1
    E.cls(1),                                        // #2
    E.utf8("java/lang/Object"),                      // #3
    E.cls(3),                                        // #4
    E.utf8("main"),                                  // #5
    E.utf8("([Ljava/lang/String;)V"),                // #6
    E.utf8("Code"),                                  // #7
    ...extra,
  ]);
  return entries;
}
const simpleBody = (thisIdx = 2, superIdx = 4, attrs = []) => body({ thisIdx, superIdx, attrs });

// baseline: clean class + BLA structural hardening
{
  const entries = simpleOrigCp([E.utf8("App.java") /* #8 */]);
  const { original, hardened, firstDecoyCpIndex } = blaHarden(entries, simpleBody());
  F["a1-baseline-hardened.class"] = { buffer: hardened, expect: "PASS", original, meta: `decoys at CP #${firstDecoyCpIndex}+` };
  F["a0-baseline-clean.class"] = { buffer: original, expect: "PASS", meta: "unhardened clean class" };
}

// case 0: legit CP Utf8 contains the literal trailer marker mid-pool
{
  const entries = index([
    E.utf8("Detector"),                              // #1
    E.cls(1),                                        // #2
    E.utf8("java/lang/Object"),                      // #3
    E.cls(3),                                        // #4
    E.utf8("com.acme.BLA_JVM_SHIELD_V1_Scanner"),    // #5  <-- legit string w/ marker
    E.utf8("scan"),                                  // #6
    E.utf8("()V"),                                   // #7
    E.utf8("Code"),                                  // #8
    E.utf8("Detector.java"),                         // #9
  ]);
  F["c0-marker-string-in-cp.class"] = {
    buffer: assemble(entries, simpleBody()), expect: "UNCHANGED",
    meta: "legit Utf8 #5 embeds 'BLA_JVM_SHIELD_V1' mid-CP; trailer anchor requires decoy structure, not a bare byte match",
  };
}

// case 1a: legit marker-regex string mid-CP followed by non-Utf8 entries -> guard should hold
{
  const entries = index([
    E.utf8("SecConfig"),                             // #1
    E.cls(1),                                        // #2
    E.utf8("java/lang/Object"),                      // #3
    E.cls(3),                                        // #4
    E.utf8("enclaveAttestationTimeoutMs"),           // #5  <-- legit 'enclave' match
    E.utf8("I"),                                     // #6
    E.ref(12, 5, 6, "NameAndType"),                  // #7  <-- non-Utf8 after marker
    E.ref(10, 4, 7, "Methodref"),                    // #8
    E.utf8("Code"),                                  // #9
    E.utf8("SecConfig.java"),                        // #10
  ]);
  F["c1a-marker-mid-cp-nontail.class"] = {
    buffer: assemble(entries, simpleBody()), expect: "UNCHANGED",
    meta: "marker match at CP #5 (entries[4]); NameAndType #7 + Methodref #8 follow -> every(tag===1) fails, no cut",
  };
}

// case 1b: legit marker-regex string inside an all-Utf8 tail -> guard bypassed
{
  const entries = index([
    E.utf8("WebFilter"),                             // #1
    E.cls(1),                                        // #2
    E.utf8("java/lang/Object"),                      // #3
    E.cls(3),                                        // #4
    E.utf8("BLACKLIST_ENDPOINT"),                    // #5  <-- legit 'BLA' substring match (BlackList)
    E.utf8("Ljava/lang/String;"),                    // #6
    E.utf8("doFilter"),                              // #7
    E.utf8("()V"),                                   // #8
    E.utf8("Code"),                                  // #9
    E.utf8("WebFilter.java"),                        // #10
  ]);
  F["c1b-marker-utf8-tail.class"] = {
    buffer: assemble(entries, simpleBody()), expect: "UNCHANGED",
    meta: "legit 'BLACKLIST_ENDPOINT' at CP #5 (entries[4]); tail is all-Utf8 -> cut deletes legit CP #5..#10",
  };
}

// case 1c: same legit pool PLUS real BLA decoys appended -> overcut into legit CP
{
  const entries = index([
    E.utf8("WebFilter"), E.cls(1), E.utf8("java/lang/Object"), E.cls(3),
    E.utf8("canaryReleaseEndpoint"),                 // #5  <-- legit 'CANARY' match
    E.utf8("Ljava/lang/String;"), E.utf8("doFilter"), E.utf8("()V"),
    E.utf8("Code"), E.utf8("WebFilter.java"),        // #6..#10 all Utf8
  ]);
  const { original, hardened, firstDecoyCpIndex } = blaHarden(entries, simpleBody());
  F["c1c-hardened-legit-marker.class"] = {
    buffer: hardened, expect: "PASS", original,
    meta: `legit 'canaryReleaseEndpoint' at CP #5; BLA decoys at #${firstDecoyCpIndex}+; cut lands on legit #5 -> legit CP lost`,
  };
}

// case 0b: trailer marker inside a legit ATTRIBUTE payload (not CP)
{
  const entries = index([
    E.utf8("Scanner"), E.cls(1), E.utf8("java/lang/Object"), E.cls(3),
    E.utf8("MarkerList"),                            // #5 attribute name
    E.utf8("Code"), E.utf8("Scanner.java"),
  ]);
  const b = body({ thisIdx: 2, superIdx: 4, attrs: [{ name: 5, info: Buffer.from("known markers: [BLA-NATIVE-SHIELD-V1], BLA_JVM_SHIELD_V1, [BLA-DEX-SHIELD-V1]", "utf8") }] });
  F["c0b-marker-in-attribute.class"] = {
    buffer: assemble(entries, b), expect: "UNCHANGED",
    meta: "attribute payload legitimately lists marker strings; cutAtMarker truncates mid-attribute",
  };
}

// case 1d: legit 'TRANSPORT_ENDPOINT=' config string in all-Utf8 tail (still matches new anchored regex)
{
  const entries = index([
    E.utf8("NetCfg"), E.cls(1), E.utf8("java/lang/Object"), E.cls(3),
    E.utf8("TRANSPORT_ENDPOINT=wss://api.acme.com/v2"), // #5 legit config constant — matches anchored regex
    E.utf8("Ljava/lang/String;"), E.utf8("connect"), E.utf8("()V"),
    E.utf8("Code"), E.utf8("NetCfg.java"),
  ]);
  F["c1d-transport-endpoint-tail.class"] = {
    buffer: assemble(entries, simpleBody()), expect: "UNCHANGED",
    meta: "legit 'TRANSPORT_ENDPOINT=wss://...' at CP #5 still matches anchored regex; all-Utf8 tail -> legit CP #5..#10 cut",
  };
}
// case 1e: hardened class whose original CP has a regex-matching legit string in the Utf8 tail
{
  const entries = index([
    E.utf8("NetCfg"), E.cls(1), E.utf8("java/lang/Object"), E.cls(3),
    E.utf8("PROTECTED_CANARY_CREDENTIAL=realKey"),   // #5 legit-looking but matches
    E.utf8("Ljava/lang/String;"), E.utf8("connect"), E.utf8("()V"),
    E.utf8("Code"), E.utf8("NetCfg.java"),
  ]);
  const { original, hardened, firstDecoyCpIndex } = blaHarden(entries, simpleBody());
  F["c1e-hardened-legit-canary-str.class"] = {
    buffer: hardened, expect: "PASS", original,
    meta: `legit 'PROTECTED_CANARY_CREDENTIAL=realKey' at CP #5; decoys at #${firstDecoyCpIndex}+; cut lands on legit #5`,
  };
}
// case 1f: hardened class, legit matching string mid-CP BUT followed by non-Utf8 -> guard holds, decoys still cut
{
  const entries = index([
    E.utf8("NetCfg"), E.cls(1), E.utf8("java/lang/Object"), E.cls(3),
    E.utf8("TRANSPORT_ENDPOINT=wss://api.acme.com/v2"), // #5 matches
    E.utf8("I"),
    E.ref(12, 5, 6, "NameAndType"),                  // #7 non-Utf8 after marker
    E.ref(10, 4, 7, "Methodref"),                    // #8
    E.utf8("Code"), E.utf8("NetCfg.java"),           // #9 #10 tail Utf8s
  ]);
  const { original, hardened, firstDecoyCpIndex } = blaHarden(entries, simpleBody());
  F["c1f-hardened-marker-guarded.class"] = {
    buffer: hardened, expect: "PASS", original,
    meta: `legit 'TRANSPORT_ENDPOINT=' at CP #5 guarded by NameAndType #7; decoys at #${firstDecoyCpIndex}+ -> expect cut at decoys, exact restore`,
  };
}

// case 2a: decoys followed by a non-Utf8 original entry (cannot occur from real BLA)
{
  const inner = index([
    E.utf8("App"), E.cls(1), E.utf8("java/lang/Object"), E.cls(3), E.utf8("x"), E.utf8("I"),
    E.ref(12, 5, 6, "NameAndType"),                  // #7
  ]);
  // splice decoys BEFORE the final NameAndType (simulates non-append decoy placement)
  const mixed = index([
    ...inner.slice(0, 6).map(e => e),
    ...DECOYS.slice(0, 4).map((s) => E.utf8(s)),     // decoys at entries[6..9]
    inner[6],                                        // NameAndType AFTER decoys
    E.utf8("Code"), E.utf8("App.java"),
  ]);
  F["c2a-decoys-then-nonutf8.class"] = {
    buffer: assemble(mixed, simpleBody()), expect: "NEUTRALIZED",
    meta: "decoys at entries[6..9] followed by NameAndType (tag12) -> every(tag===1) fails -> nothing cut, decoys retained",
  };
}
// case 2b: decoys followed by original Utf8 entries -> indistinguishable overcut
{
  const mixed = index([
    E.utf8("App"), E.cls(1), E.utf8("java/lang/Object"), E.cls(3),
    ...DECOYS.slice(0, 4).map((s) => E.utf8(s)),     // decoys at entries[4..7]
    E.utf8("realTailName"), E.utf8("Code"), E.utf8("App.java"), // originals after decoys
  ]);
  F["c2b-decoys-then-utf8.class"] = {
    buffer: assemble(mixed, simpleBody()), expect: "NEUTRALIZED",
    meta: "decoys at entries[4..7] followed by 3 legit Utf8s -> cut removes them too (indistinguishable)",
  };
}

// case 3: Long/Double — scrubber's JVM_CP_SIZES lacks tags 5/6
{
  // 3a: legit Long mid-CP + BLA hardening -> walker dies at tag 5 -> PARSE-FAIL
  const entries = index([
    E.utf8("Ledger"), E.cls(1), E.utf8("java/lang/Object"), E.cls(3),
    E.utf8("BALANCE"), E.utf8("J"),
    E.long(0x0123456789abcdefn),                     // #7..#8 (2 slots!)
    E.ref(12, 5, 6, "NameAndType"),                  // #9
    E.utf8("Code"), E.utf8("Ledger.java"),
  ]);
  const { original, hardened } = blaHarden(entries, simpleBody());
  F["c3a-long-mid-cp-hardened.class"] = {
    buffer: hardened, expect: "PASS", original,
    meta: "Long at CP #7-8; JVM_CP_SIZES has no tag 5 -> walker breaks -> 'unparseable constant pool', decoys retained",
  };
}
{
  // 3b: Double as LAST original entry right before appended decoys (the 'inside decoy region' variant)
  const entries = index([
    E.utf8("Calc"), E.cls(1), E.utf8("java/lang/Object"), E.cls(3),
    E.utf8("PI"), E.utf8("D"),
    E.double(3.141592653589793),                     // #7..#8 — last original entry
  ]);
  const { original, hardened, firstDecoyCpIndex } = blaHarden(entries, simpleBody());
  F["c3b-double-before-decoys.class"] = {
    buffer: hardened, expect: "PASS", original,
    meta: `Double at CP #7-8 adjacent to decoy region (#${firstDecoyCpIndex}+); walker never reaches decoys -> PARSE-FAIL`,
  };
}
{
  // 3c: a 'Long' spliced INTO the decoy region itself (BLA never emits it; robustness)
  const entries = index([
    E.utf8("App"), E.cls(1), E.utf8("java/lang/Object"), E.cls(3), E.utf8("Code"), E.utf8("App.java"),
    E.utf8("BlaEnclaveDelegation"),                  // decoy-ish
    E.long(0xdeadbeefn),                             // non-Utf8 inside 'decoy' region
    E.utf8("com/enclave/tarpit/StateNode_00_pc_1"),
  ]);
  F["c3c-long-inside-decoy-region.class"] = {
    buffer: assemble(entries, simpleBody()), expect: "NEUTRALIZED",
    meta: "Long (tag5) inside marker region -> walker breaks at tag5 -> unparseable; even if walked, every(tag===1) guard would block the cut",
  };
}

// case 4: modern CP tags 15,16,17,18,19,20 — all sized in JVM_CP_SIZES
{
  const entries = index([
    E.utf8("Modern"),                                // #1
    E.cls(1),                                        // #2
    E.utf8("java/lang/Object"),                      // #3
    E.cls(3),                                        // #4
    E.utf8("run"),                                   // #5
    E.utf8("()V"),                                   // #6
    E.ref(12, 5, 6, "NameAndType"),                  // #7
    E.ref(10, 4, 7, "Methodref"),                    // #8
    E.mh(6, 8),                                      // #9  MethodHandle (tag15, size4)
    E.tagU2(16, 6, "MethodType"),                    // #10 (tag16, size3)
    E.ref(17, 0, 7, "Dynamic"),                      // #11 (tag17, size5)
    E.ref(18, 0, 7, "InvokeDynamic"),                // #12 (tag18, size5)
    E.utf8("app.mod"),                               // #13
    E.tagU2(19, 13, "Module"),                       // #14 (tag19, size3)
    E.utf8("com/acme"),                              // #15
    E.tagU2(20, 15, "Package"),                      // #16 (tag20, size3)
    E.utf8("Code"),                                  // #17
    E.utf8("Modern.java"),                           // #18
  ]);
  const { original, hardened, firstDecoyCpIndex } = blaHarden(entries, simpleBody());
  F["c4-modern-tags-hardened.class"] = {
    buffer: hardened, expect: "PASS", original,
    meta: `tags 15/16/17/18/19/20 at CP #9-#16; decoys at #${firstDecoyCpIndex}+; expect exact restore`,
  };
}

// case 5a: schema JSON INSIDE a legit class attribute (not trailing) -> must survive
{
  const cfg = Buffer.from('{"schema":"bla-jvm-enclave-v1","note":"legit app config, not a marker"}', "utf8");
  const entries = index([
    E.utf8("Cfg"), E.cls(1), E.utf8("java/lang/Object"), E.cls(3),
    E.utf8("AppConfig"),                             // #5 attribute name
    E.utf8("Code"), E.utf8("Cfg.java"),
  ]);
  const b = body({ thisIdx: 2, superIdx: 4, attrs: [{ name: 5, info: cfg }] });
  F["c5a-schema-inside-attribute.class"] = {
    buffer: assemble(entries, b), expect: "UNCHANGED",
    meta: "attribute 'AppConfig' payload contains bla-jvm-enclave-v1 INSIDE class body; jvmClassEnd must not cut it",
  };
}
// case 5b: trailing JSON present but NO decoy CP entries -> dropFrom=-1 slice bug
{
  const entries = index([
    E.utf8("Plain"), E.cls(1), E.utf8("java/lang/Object"), E.cls(3),
    E.utf8("Code"), E.utf8("Plain.java"),            // last entry Utf8 #6
  ]);
  const clean = assemble(entries, simpleBody());
  const withJson = Buffer.concat([clean, ATTR_JSON]);  // JSON appended, no CP decoys
  F["c5b-json-tail-no-decoys.class"] = {
    buffer: withJson, expect: "PASS", original: clean,
    meta: "extraCut>0 & decoyEntries=0 -> entries.slice(0,-1) drops last entry from slot sum -> cp_count written one short (desync)",
  };
}
// case 5c: clean class + benign trailing bytes (no schema) -> untouched
{
  const entries = index([E.utf8("S"), E.cls(1), E.utf8("java/lang/Object"), E.cls(3), E.utf8("S.java")]);
  const clean = assemble(entries, simpleBody());
  F["c5c-benign-trailing-bytes.class"] = {
    buffer: Buffer.concat([clean, Buffer.from("SIGNING-BLOCK-DEADBEEF", "utf8")]),
    expect: "PASS", meta: "non-marker trailing bytes must not be cut",
  };
}

// case 6: fat Mach-O (0xCAFEBABE collision) — routing via real CLI
{
  const fat = Buffer.alloc(8 + 2 * 20 + 64);
  fat.writeUInt32BE(0xcafebabe, 0);
  fat.writeUInt32BE(2, 4);                           // nfat_arch
  // arch 0: x86_64 cputype=0x01000007
  fat.writeUInt32BE(0x01000007, 8); fat.writeUInt32BE(3, 12);
  fat.writeUInt32BE(48, 16); fat.writeUInt32BE(32, 20); fat.writeUInt32BE(2, 24);
  // arch 1: arm64 cputype=0x0100000C
  fat.writeUInt32BE(0x0100000c, 28); fat.writeUInt32BE(0, 32);
  fat.writeUInt32BE(80, 36); fat.writeUInt32BE(16, 40); fat.writeUInt32BE(2, 44);
  F["c6-fat-macho.class"] = { buffer: fat, expect: "UNCHANGED-NOTE", meta: "fat Mach-O named .class -> detect() routes jvm; scrubJvm bails unparseable (fail-safe keep)" };
  F["c6-fat-macho.bin"] = { buffer: fat, expect: "UNCHANGED-NOTE", meta: "fat Mach-O non-.class -> detect() routes native (0xcafebabe in macho list)" };
  // real hardened class with non-.class extension -> routes native, decoys retained
  const entries = index([E.utf8("App"), E.cls(1), E.utf8("java/lang/Object"), E.cls(3), E.utf8("App.java")]);
  const { hardened, original } = blaHarden(entries, simpleBody());
  F["c6-hardened-class.bin"] = { buffer: hardened, expect: "PASS", original, meta: "BLA-hardened .class renamed .bin -> new detect() routes jvm by major-version heuristic -> scrubbed" };
}
{
  // evasion attempt: major version patched outside 45-90 — detect() still
  // follows the embedded bla-jvm-enclave-v1 marker -> jvm -> decoys cut.
  // Restoration target is the same file with the adversarial major byte.
  const entries = index([E.utf8("App"), E.cls(1), E.utf8("java/lang/Object"), E.cls(3), E.utf8("App.java")]);
  const { hardened, original } = blaHarden(entries, simpleBody());
  const ev = Buffer.from(hardened);
  ev.writeUInt16BE(91, 6);
  const orig91 = Buffer.from(original);
  orig91.writeUInt16BE(91, 6);
  F["c6-hardened-major91.bin"] = { buffer: ev, expect: "PASS", original: orig91, meta: "1-byte patch (major 52->91) does NOT evade: bla-jvm-enclave-v1 marker still routes jvm -> exact restore of the major=91 file" };
}
{
  // crafted fat Mach-O with nfat_arch=52 (bytes6-7) -> falls in jvm version range -> misroutes to jvm (fail-safe unparseable)
  const fat = Buffer.alloc(8 + 20 + 32);
  fat.writeUInt32BE(0xcafebabe, 0);
  fat.writeUInt32BE(52, 4);                          // nfat_arch = 52 (crafted; real fat bins have ~2-6)
  fat.writeUInt32BE(0x0100000c, 8);                  // arm64 cputype -> cpCount=256, tag@10=0 -> unparseable
  fat.writeUInt32BE(0, 12); fat.writeUInt32BE(48, 16); fat.writeUInt32BE(32, 20); fat.writeUInt32BE(2, 24);
  F["c6-fat-macho-nfat52.bin"] = { buffer: fat, expect: "UNCHANGED-NOTE", meta: "nfat_arch=52 collides with JVM major-version range -> routes jvm -> unparseable (fail-safe, unchanged)" };
}

// ---------- run ----------
const rows = [];
for (const [name, fx] of Object.entries(F)) {
  const path = join(DIR, name);
  writeFileSync(path, fx.buffer);
  const inCp = walkCp(fx.buffer);
  let r, err = null;
  try { r = scrubJvm(Buffer.from(fx.buffer)); } catch (e) { err = e; }
  const outCp = r ? walkCp(r.buffer) : null;
  const changed = r ? !r.buffer.equals(fx.buffer) : false;
  const exactRestore = fx.original && r ? r.buffer.equals(fx.original) : null;
  // legit CP loss: compare kept Utf8 originals
  let verdict = "?";
  if (err) verdict = "CRASH: " + err.message;
  else if (r.report.hardened === false && changed === false) {
    verdict = inCp.ok ? "UNCHANGED" : `UNCHANGED (${r.report.note ?? "?"})`;
    if (r.report.suspiciousCpEntries) verdict += ` flagged=${r.report.suspiciousCpEntries.join(",")}`;
  } else if (exactRestore === true) verdict = "PASS (exact restore)";
  else if (exactRestore === false) verdict = "FALSE-POSITIVE-CUT (output != original)";
  else if (r.report.mode === "neutralize") {
    verdict = `NEUTRALIZED x${r.report.decoyCpEntriesNeutralized}` +
      (r.report.suspiciousCpEntries ? ` flagged=${r.report.suspiciousCpEntries.join(",")}` : "");
  }
  else if (r.report.hardened) {
    // cut happened on a file that was NOT BLA-hardened -> false positive
    verdict = "FALSE-POSITIVE-CUT";
  }
  rows.push({
    file: name,
    expect: fx.expect,
    report: r ? { hardened: r.report.hardened, mode: r.report.mode, decoys: r.report.decoyCpEntriesDropped, json: r.report.trailingJsonDropped, trailer: r.report.trailerDropped, note: r.report.note } : null,
    inCpCount: inCp.cpCount, inParsed: inCp.entries?.length,
    outCpCount: outCp?.cpCount, outParsed: outCp?.entries?.length,
    bytesIn: fx.buffer.length, bytesOut: r?.buffer?.length,
    exactRestore,
    verdict,
    meta: fx.meta,
  });
}

for (const row of rows) {
  console.log(`\n=== ${row.file}`);
  console.log(`  expect=${row.expect}  verdict=${row.verdict}`);
  console.log(`  report=${JSON.stringify(row.report)}`);
  console.log(`  cp in: count=${row.inCpCount} parsed=${row.inParsed} | out: count=${row.outCpCount} parsed=${row.outParsed} | bytes ${row.bytesIn}->${row.bytesOut} exactRestore=${row.exactRestore}`);
  console.log(`  meta: ${row.meta}`);
}
writeFileSync(join(DIR, "results.json"), JSON.stringify(rows, null, 2));
console.log(`\nWrote ${rows.length} fixtures + results.json to ${DIR}`);
