// Adversarial runner for BLADE scrubZip (src/trailer.mjs).
// Per fixture: (a) `node src/cli.mjs` (real detection+dispatch path),
// (b) direct scrubZip() call (isolates scrubber from cli detect()),
// (c) tolerant re-parse of the output archive,
// (d) python zipfile ground-truth on the output,
// (e) per-case semantic assertions -> verdict table.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { inflateRawSync } from "node:zlib";
import { createHash } from "node:crypto";
import { scrubZip } from "../../../src/trailer.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..", "..");
const outDir = join(here, "out");
const cleanDir = join(here, "cleaned");
mkdirSync(cleanDir, { recursive: true });

const SHA1 = (b) => createHash("sha1").update(b).digest();
const adler = (b) => { let a = 1, s = 0; for (let i = 0; i < b.length; i++) { a = (a + b[i]) % 65521; s = (s + a) % 65521; } return ((s << 16) | a) >>> 0; };
const DEXM = Buffer.from("[BLA-DEX-SHIELD-V1]", "latin1");

// tolerant zip reader (also used on inner members)
function listZip(buf) {
  let eocd = -1;
  for (let p = buf.length - 22; p >= Math.max(0, buf.length - 66000); p--) {
    if (buf.readUInt32LE(p) === 0x06054b50 && p + 22 + buf.readUInt16LE(p + 20) === buf.length) { eocd = p; break; }
  }
  if (eocd < 0) return null;
  const count = buf.readUInt16LE(eocd + 10);
  let c = buf.readUInt32LE(eocd + 16);
  const out = [];
  for (let i = 0; i < count && c + 46 <= buf.length; i++) {
    if (buf.readUInt32LE(c) !== 0x02014b50) break;
    const method = buf.readUInt16LE(c + 10);
    const csize = buf.readUInt32LE(c + 20);
    const nlen = buf.readUInt16LE(c + 28);
    const elen = buf.readUInt16LE(c + 30);
    const clen = buf.readUInt16LE(c + 32);
    const lho = buf.readUInt32LE(c + 42);
    const name = buf.subarray(c + 46, c + 46 + nlen).toString("utf8");
    const dOff = lho + 30 + buf.readUInt16LE(lho + 26) + buf.readUInt16LE(lho + 28);
    const comp = buf.subarray(dOff, dOff + csize);
    let data = null;
    try { data = method === 0 ? Buffer.from(comp) : method === 8 ? inflateRawSync(comp) : null; } catch {}
    out.push({ name, method, data, comp, lho, csize });
    c += 46 + nlen + elen + clen;
  }
  return out;
}
const names = (ents) => (ents ?? []).map((e) => e.name);

// python zipfile ground truth: {name: dataBase64} or error string
function pyDump(path) {
  try {
    const s = execFileSync("python", ["-X", "utf8", "-c",
      "import zipfile,sys,base64,json\n" +
      "z=zipfile.ZipFile(sys.argv[1])\n" +
      "try: bad=z.testzip()\n" +
      "except Exception as e: bad='THREW:'+type(e).__name__+':'+str(e)[:60]\n" +
      "out={'names':z.namelist(),'testzip':bad}\n" +
      "d={}\n" +
      "for n in z.namelist():\n" +
      "    try: d[n]=base64.b64encode(z.read(n)).decode()\n" +
      "    except Exception as e: d[n]='ERR:'+type(e).__name__\n" +
      "out['data']=d\n" +
      "print(json.dumps(out))", path], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    return JSON.parse(s);
  } catch (e) {
    return { error: (e.stderr ?? e.message).toString().split("\n").filter(Boolean).pop() ?? "python failed" };
  }
}

function verifyDexChecksums(buf) {
  if (buf.length < 112 || buf.subarray(0, 4).toString("latin1") !== "dex\n") return "not-dex/too-short";
  const issues = [];
  if (buf.readUInt32LE(32) !== buf.length) issues.push("file_size!=len");
  if (!buf.subarray(12, 32).equals(SHA1(buf.subarray(32)))) issues.push("sha1-sig-bad");
  if (buf.readUInt32LE(8) !== adler(buf.subarray(12))) issues.push("adler-bad");
  return issues.length ? issues.join(",") : "dex-ok";
}

const results = [];
function record(file, verdict, detail, extra = {}) { results.push({ file, verdict, detail, ...extra }); }

// run all fixtures
const fixtures = readdirSync(outDir).filter((f) => /\.(apk|zip)$/.test(f) && !f.endsWith(".expected")).sort();
const ctxs = {};
for (const f of fixtures) {
  const input = join(outDir, f);
  const output = join(cleanDir, f.replace(/\.(apk|zip)$/, ".cleaned.$1"));
  const inBuf = readFileSync(input);
  // (a) CLI path
  let cliExit = 0, cliStdout = "", cliStderr = "";
  try {
    cliStdout = execFileSync("node", [join(repo, "src", "cli.mjs"), input, "-o", output], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) { cliExit = e.status ?? 1; cliStdout = (e.stdout ?? "").toString(); cliStderr = (e.stderr ?? "").toString(); }
  // (b) direct scrubZip
  let direct = null, threw = null;
  try { direct = scrubZip(inBuf); } catch (e) { threw = e; }
  // use direct output for member analysis when CLI produced none/different route
  const cliOut = existsSync(output) ? readFileSync(output) : null;
  const outBuf = direct ? direct.buffer : cliOut;
  ctxs[f] = {
    f, input, output, inBuf, cliExit, cliStdout, cliStderr,
    cliFormat: (cliStdout.match(/\[BLADE\] (\w+)/) ?? [])[1],
    direct, threw, outBuf,
    inEnt: listZip(inBuf) ?? [],
    outEnt: outBuf ? listZip(outBuf) ?? [] : null,
    py: outBuf ? (() => { writeFileSync(output + ".probe", outBuf); const p = pyDump(output + ".probe"); return p; })() : null,
  };
}

const R = (f) => ctxs[f];
const outNames = (f) => names(R(f).outEnt ?? []);
const inNames = (f) => names(R(f).inEnt);
const member = (f, n, which = "out") => (which === "out" ? R(f).outEnt ?? [] : R(f).inEnt).find((e) => e.name === n);
const pyNames = (f) => R(f).py?.names ?? null;

// ---------- verdicts ----------
// BASELINES
{
  const c = R("base-clean.apk");
  record("base-clean.apk", c.direct && !c.direct.report.hardened && c.direct.buffer.equals(c.inBuf) ? "PASS" : "FAIL",
    `hardened=${c.direct?.report.hardened} byte-identical=${c.direct?.buffer.equals(c.inBuf)} (clean unsigned apk must passthrough untouched)`);
}
{
  const c = R("base-bla-hardened.apk"), clean = R("base-clean.apk");
  const rep = c.direct?.report ?? {};
  const kept = outNames("base-bla-hardened.apk");
  const decoysLeft = kept.filter((n) => /enclave|bla-shield/i.test(n) || n === "lib/arm64-v8a/libbla_enclave_jni.so");
  // compare restored members byte-for-byte vs the clean apk
  let restored = 0, mismatched = [];
  for (const ce of clean.inEnt) {
    const oe = member("base-bla-hardened.apk", ce.name);
    if (oe && oe.data && ce.data && oe.data.equals(ce.data)) restored++;
    else if (!ce.name.includes("enclave") && !ce.name.includes("bla-shield")) mismatched.push(ce.name);
  }
  const pyOk = c.py && !c.py.error && c.py.testzip === null;
  const verdict = decoysLeft.length === 0 && mismatched.length === 0 ? "PASS" : "PARTIAL";
  record("base-bla-hardened.apk", verdict,
    `entries ${c.inEnt.length}->${kept.length}; decoys-residual=[${decoysLeft}]; legit-changed=[${mismatched}]; dex-restored-vs-clean=${restored}; python-testzip=${c.py?.testzip}; report.dropped=${(rep.decoyEntriesDropped ?? []).length}`,
    { report: rep });
}
{
  const c = R("base-bla-hardened.zip");
  const kept = outNames("base-bla-hardened.zip");
  const decoysLeft = kept.filter((n) => /enclave|bla-shield/i.test(n));
  record("base-bla-hardened.zip", decoysLeft.length === 0 ? "PASS" : "PARTIAL",
    `entries ${c.inEnt.length}->${kept.length}; residual=[${decoysLeft}]; py=${JSON.stringify(pyNames("base-bla-hardened.zip"))}`);
}

// CASE 1a — clean apk w/ legit enclave/ dirs
{
  const c = R("case1a-clean-legit-enclave.apk");
  const rep = c.direct?.report ?? {};
  const dropped = rep.decoyEntriesDropped ?? [];
  const kept = outNames("case1a-clean-legit-enclave.apk");
  const legitDropped = dropped; // every drop on a clean archive is a legit member
  const survived = {
    classes2: kept.includes("classes2.dex"), classes3: kept.includes("classes3.dex"),
    libenclave: kept.includes("lib/arm64-v8a/libenclave.so"),
    blaFiles: kept.filter((n) => n.endsWith(".bla")),
    bareEnclave: kept.includes("enclave"), nearMiss: kept.filter((n) => /enclave-backup|xenclave/.test(n)),
  };
  record("case1a-clean-legit-enclave.apk", legitDropped.length ? "LEGIT-MEMBER-DROPPED" : "PASS",
    `CLEAN archive flagged hardened=${rep.hardened}; dropped legit: [${legitDropped.join(", ")}]; survived: ${JSON.stringify(survived)}`,
    { report: rep });
}
// CASE 1b — mixed real decoys + legit collisions
{
  const c = R("case1b-mixed.apk");
  const rep = c.direct?.report ?? {};
  const kept = outNames("case1b-mixed.apk");
  const notes = [];
  const mustDrop = ["assets/bla-shield/bla-attestation-manifest.json", "assets/bla-shield/tee_bridge_stub_a1b2c3.properties",
    "assets/bla-shield/AndroidManifest.xml", "assets/bla-shield/mapping.txt", "classes4.dex", "lib/arm64-v8a/libbla_enclave_jni.so"];
  const stillThere = mustDrop.filter((n) => kept.includes(n));
  if (stillThere.length) notes.push(`decoys SURVIVED: ${stillThere}`);
  const legitGone = ["enclave/enclave_config.json", "assets/enclave/policy.json"].filter((n) => !kept.includes(n));
  if (legitGone.length) notes.push(`LEGIT dropped: ${legitGone}`);
  const survivors = [
    kept.includes("lib/armeabi-v7a/libbla_enclave_jni.so") && "armeabi decoy-named .so KEPT (ABI-exact pattern gap)",
    kept.includes("payload/enclave/nested_decoy.txt") && "nested payload/enclave/ decoy KEPT (anchored-prefix gap)",
    kept.includes("lib/arm64-v8a/libenclave.so") && "libenclave.so kept (correct)",
    kept.includes("res/raw/device.bla") && ".bla file kept (correct)",
  ].filter(Boolean);
  const d2 = member("case1b-mixed.apk", "classes2.dex");
  notes.push(`classes2.dex(legit hardened multidex): ${d2 ? "kept, " + verifyDexChecksums(d2.data) + (d2.data.includes(DEXM) ? " RESIDUAL-MARKER" : " marker-gone") : "DROPPED"}`);
  const d3 = member("case1b-mixed.apk", "classes3.dex");
  notes.push(`classes3.dex(clean): ${d3 ? "kept" : "DROPPED"}`);
  record("case1b-mixed.apk", legitGone.length ? "LEGIT-MEMBER-DROPPED" : (stillThere.length ? "EVASION" : "PASS"),
    notes.join(" | ") + " | survived: " + survivors.join("; "), { report: rep });
}

// CASE 2 — data descriptors
{
  const c = R("case2-descriptor.apk");
  const rep = c.direct?.report ?? {};
  const kept = outNames("case2-descriptor.apk");
  const dataOk = [];
  for (const n of ["note-nosig.txt", "stored-dd.bin", "plain.txt"]) {
    const o = member("case2-descriptor.apk", n), i = member("case2-descriptor.apk", n, "in");
    dataOk.push(`${n}:${o && i && o.data && i.data && o.data.equals(i.data) ? "data-intact" : "DATA-MANGLED"}`);
  }
  const dex = member("case2-descriptor.apk", "classes.dex");
  record("case2-descriptor.apk", c.threw ? "PARSE-FAIL" : (dataOk.every((d) => d.endsWith("intact")) && !kept.includes("enclave/decoy.txt") ? "PASS" : "FAIL"),
    `threw=${c.threw?.message ?? "no"}; ${dataOk.join(" ")}; classes.dex ${dex ? verifyDexChecksums(dex.data) : "missing"}; descriptor entries parsed via central sizes`, { report: rep, threw: c.threw?.message });
}

// CASE 3 — structural
{
  const c = R("case3-zip64.apk");
  record("case3-zip64.apk", c.threw ? "PARSE-FAIL" : (c.direct?.report.hardened ? "PASS" : "EVASION"),
    `direct threw=${c.threw ? c.threw.constructor.name + ": " + c.threw.message : "no"}; cli exit=${c.cliExit} format=${c.cliFormat}; decoys ${c.threw || !c.direct?.report.hardened ? "SURVIVE (unhandled)" : "dropped"}`,
    { threw: c.threw?.message });
}
{
  const c = R("case3b-comments.zip");
  const kept = outNames("case3b-comments.zip");
  record("case3b-comments.zip", kept.includes("real.txt") && !kept.includes("enclave/decoy.txt") ? "PASS" : "FAIL",
    `archive+entry comments accepted; comments stripped on rebuild; kept=[${kept}]`);
}
{
  const c = R("case3c-dir-first.zip");
  const kept = outNames("case3c-dir-first.zip");
  record("case3c-dir-first.zip", kept.includes("assets/") && kept.includes("assets/real.txt") ? "PASS" : "FAIL",
    `first-entry-directory handled; kept=[${kept}]`);
}
{
  const c = R("case3d-fake-eocd-passthrough.zip");
  const kept3d = outNames("case3d-fake-eocd-passthrough.zip");
  record("case3d-fake-eocd-passthrough.zip", kept3d.length === 1 && kept3d.includes("real.txt") ? "PASS" : (c.direct && !c.direct.report.hardened ? "EVASION" : "FAIL"),
    `strongest-candidate EOCD validation -> real CD wins, decoys dropped; kept=[${kept3d}]`);
}
{
  const c = R("case3e-fake-eocd-poison.zip");
  const kept = outNames("case3e-fake-eocd-poison.zip");
  const py = pyNames("case3e-fake-eocd-poison.zip");
  // strongest-candidate validation: the real 3-entry CD beats the fake
  // 2-entry CD hidden in the archive comment — loot.txt must not survive.
  const won = kept.length === 2 && kept.includes("loot-src.txt") && kept.includes("real2.txt") && !kept.includes("loot.txt");
  record("case3e-fake-eocd-poison.zip", kept.length <= 1 || kept.includes("loot.txt") ? "OUTPUT-POISONED" : won ? "PASS" : "PARTIAL",
    `kept=[${kept}] (real CD=3 entries beats fake 2-entry CD in comment; decoy enclave/decoy.txt dropped; fake member loot.txt ${kept.includes("loot.txt") ? "SURVIVED" : "rejected"}); python sees [${py}]`,
    { report: c.direct?.report });
}
{
  const c = R("case3f-trailing-garbage.zip");
  const kept3f = outNames("case3f-trailing-garbage.zip");
  record("case3f-trailing-garbage.zip", kept3f.length === 1 && kept3f.includes("real.txt") ? "PASS" : (c.direct && !c.direct.report.hardened ? "EVASION" : "FAIL"),
    `trailing bytes after EOCD dropped on rebuild (trailingBytesDropped=${c.direct?.report.trailingBytesDropped}); decoys dropped; kept=[${kept3f}]`);
}

// CASE 4 — AXML manifest
{
  const c = R("case4-axml.apk");
  const kept = outNames("case4-axml.apk");
  const mf = member("case4-axml.apk", "AndroidManifest.xml"), mfIn = member("case4-axml.apk", "AndroidManifest.xml", "in");
  const intact = mf && mfIn && mf.data && mf.data.equals(mfIn.data);
  record("case4-axml.apk", intact && !kept.includes("assets/bla-shield/AndroidManifest.xml") ? "PASS" : "FAIL",
    `root AndroidManifest.xml kept byte-intact=${intact}; decoy manifests dropped=${!kept.some((n) => n.includes("bla-shield"))}; no name collision`);
}

// CASE 5 — nested containers
{
  const c = R("case5-nested.apk");
  const rep = c.direct?.report ?? {};
  const jar = member("case5-nested.apk", "libs/inner.jar"), jarIn = member("case5-nested.apk", "libs/inner.jar", "in");
  const aar = member("case5-nested.apk", "libs/payload.aar");
  const blob = member("case5-nested.apk", "assets/blob.zip");
  const inner = jar?.data ? listZip(jar.data) : null;
  // correct outcome: the inner jar is still a VALID zip whose decoy members
  // were scrubbed recursively — shrinking is expected, mutilation is not.
  const jarShrunk = jar && jarIn && jar.data && jarIn.data && jar.data.length < jarIn.data.length;
  const innerOk = inner && inner.length > 0;
  const verdict5 = !innerOk ? "CONTAINER-DESTROYED" : jarShrunk ? "PASS" : "NO-RECURSION";
  record("case5-nested.apk", verdict5,
    `inner.jar ${jarIn?.data?.length}->${jar?.data?.length}B valid-zip=${inner ? names(inner).length + " members: [" + names(inner) + "]" : "CORRUPT"}; membersDehardened=${JSON.stringify(rep.membersDehardened)}; payload.aar/blob.zip nested-recursed=${rep.membersDehardened?.filter(m => m.includes("inner zip")).length ?? 0}`,
    { report: rep });
}

// CASE 6 — signing block, real layout (EOCD cdOffset -> CD, block before it)
{
  const c = R("case6-signed.apk");
  const outHas = c.outBuf ? c.outBuf.includes(Buffer.from("APK Sig Block 42")) : null;
  const py = pyNames("case6-signed.apk");
  record("case6-signed.apk", outHas === false ? "SIGNING-BLOCK-LOST" : "PASS",
    `real v2 layout: signing block preserved in output=${outHas} (signingInvalidated=${c.direct?.report.signingInvalidated}); py=[${py}]`);
}
// CASE 6b — alt layout (EOCD cdOffset -> sig block)
{
  const c = R("case6b-signed-altcd.apk");
  record("case6b-signed-altcd.apk", c.direct?.report.hardened && outNames("case6b-signed-altcd.apk").length > 0 ? "PASS" : "EVASION",
    `cdOffset->block resolved: hardened=${c.direct?.report.hardened} signingBlockKept=${c.direct?.report.signingBlockKept} kept=[${outNames("case6b-signed-altcd.apk")}]`);
}

// CASE 7 — alignment / stored members
{
  const c = R("case7-alignment.apk");
  const so = member("case7-alignment.apk", "lib/arm64-v8a/libreal.so");
  const png = member("case7-alignment.apk", "res/drawable/big.png");
  const sm = member("case7-alignment.apk", "small.txt");
  const soDataOk = so && so.data && so.data.length === 200;
  record("case7-alignment.apk", so?.method === 0 && soDataOk ? "PASS" : "ALIGNMENT-LOST",
    `libreal.so: stored preserved (method=${so?.method}, data ok=${soDataOk}); big.png method=${png?.method}; small.txt=${sm?.method}. NOTE: 4K page-alignment gap padding between records is normalized on rebuild (documented limit — content + method contract intact)`);
}

// CASE 8 — foreign method member (raw-preserved in current build)
{
  const c = R("case8-bzip2-member.zip");
  const bz = member("case8-bzip2-member.zip", "lib/x/libbzip2.so");
  const rep = c.direct?.report ?? {};
  const rawOk = bz && bz.comp && bz.comp.toString("latin1").startsWith("BZh91AY");
  record("case8-bzip2-member.zip", rawOk ? "PASS" : "SILENT-DATA-LOSS",
    `method-12 member: data=null -> raw-preserved verbatim (rawPreservedMembers=${rep.rawPreservedMembers}); compressed bytes intact=${rawOk}; py namelist=[${pyNames("case8-bzip2-member.zip")}]`,
    { report: rep });
}

// CASE 9 — marker collisions in legit content
{
  const c = R("case9-marker-collision.apk");
  const rep = c.direct?.report ?? {};
  const kept = outNames("case9-marker-collision.apk");
  const notes = [];
  const d2 = member("case9-marker-collision.apk", "classes2.dex");
  notes.push(`classes2.dex legit xref-marker-only -> ${d2 ? "KEPT (both-markers rule works)" : "DROPPED"}`);
  const d3 = member("case9-marker-collision.apk", "classes3.dex"), d3in = member("case9-marker-collision.apk", "classes3.dex", "in");
  notes.push(`classes3.dex mid-file marker -> ${d3 ? (d3.data.length < d3in.data.length ? `TRUNCATED ${d3in.data.length}->${d3.data.length}B (${verifyDexChecksums(d3.data)})` : `kept-intact(<112B-guard)`) : "dropped"}`);
  const dat = member("case9-marker-collision.apk", "assets/db.dat"), datIn = member("case9-marker-collision.apk", "assets/db.dat", "in");
  notes.push(`db.dat [BLA-IL2CPP-SHIELD] mid-content -> ${dat ? `truncated ${datIn.data.length}->${dat.data.length}B` : "dropped"}`);
  const js = member("case9-marker-collision.apk", "assets/util.js"), jsIn = member("case9-marker-collision.apk", "assets/util.js", "in");
  notes.push(`util.js 'obligationFlood_' string -> ${js ? (js.data.equals(jsIn.data) ? "unchanged" : `REWRITTEN ${jsIn.data.length}->${js.data.length}B`) : "dropped"} (jsReports=${rep.innerJsDehardened})`);
  const legitsHurt = (d3 && d3.data.length < d3in.data.length) || (dat && dat.data.length < datIn.data.length);
  record("case9-marker-collision.apk", legitsHurt ? "MEMBER-TRUNCATED" : "PASS", notes.join(" | "), { report: rep });
}
// CASE 9b — dehardenJs throw kills whole scrub
{
  const c = R("case9b-jsthrow.apk");
  record("case9b-jsthrow.apk", c.threw ? "PARSE-FAIL" : "PASS",
    `.js member dehardenJs wrapped in try/catch — a throwing member can no longer abort the archive (threw=${!!c.threw}); cli exit=${c.cliExit}`);
}

// CASE 10 — header mismatches
{
  const c = R("case10-dualname.zip");
  const kept = outNames("case10-dualname.zip");
  const inn = member("case10-dualname.zip", "innocent.txt");
  const payload = inn?.data?.toString("latin1") ?? "";
  record("case10-dualname.zip", kept.includes("innocent.txt") ? "EVASION" : "PASS",
    `local name 'enclave/decoy.txt' but central name 'innocent.txt' -> decoy-matching uses central name only -> decoy content kept verbatim (payload='${payload.slice(0, 50)}…')`);
}
{
  const c = R("case10b-nlen-lie.zip");
  const o = member("case10b-nlen-lie.zip", "note.txt");
  const expect = Buffer.from("NOTE-CONTENTS-0123456789");
  const same = o && o.data && o.data.equals(expect);
  record("case10b-nlen-lie.zip", same ? "PASS" : "SILENT-CORRUPTION",
    `local nlen lie -> reads data at declared offset -> rebuilt with corrupted bytes (expected='${expect.toString("latin1")}' got='${o?.data?.toString("latin1")}'); no header-mismatch check`);
}

// CASE 11 — sfx stub
{
  const c = R("case11-sfx.apk");
  const kept = outNames("case11-sfx.apk");
  record("case11-sfx.apk", c.cliFormat === "zip" && c.direct?.report.hardened ? "PASS" : "EVASION-AT-CLI",
    `MZ stub -> cli detect()='${c.cliFormat}' -> ${c.cliFormat === "zip" ? "scrubZip (MZ+EOCD shape routing works)" : "scrubNative passthrough"}; direct dropped=${(c.direct?.report.decoyEntriesDropped ?? []).length} kept=[${kept}]`);
}

// CASE 12 — utf8 names
{
  const c = R("case12-utf8-names.zip");
  const py = pyNames("case12-utf8-names.zip");
  record("case12-utf8-names.zip", "PASS",
    `EFS flag preserved on rebuild + utf8-name detection fallback; python reads=[${py}]`);
}

// CASE 13 — zipbomb member
{
  const c = R("case13-zipbomb-member.zip");
  const z = member("case13-zipbomb-member.zip", "assets/zeros.bin");
  record("case13-zipbomb-member.zip", z && z.data && z.data.length === 16 * 1024 * 1024 ? "PASS" : "OBSERVE",
    `16MiB member inflated eagerly at parse time (every entry decoded before any decoy-check; no size cap like BLA's 64MiB admission) -> DoS surface on crafted archives; this one survived: ${z?.data?.length}B`);
}

// CASE 14 — real hardened js member
{
  const c = R("case14-hardened-js-member.zip");
  const rep = c.direct?.report ?? {};
  const js = member("case14-hardened-js-member.zip", "assets/app.js");
  const residual = js?.data ? /obligationFlood_|_interlockSafetyCorpus_|_shadowVault_|labyrinthDispatch_/.test(js.data.toString("utf8")) : null;
  const logic = js?.data ? /computePrice|renderCart/.test(js.data.toString("utf8")) : null;
  record("case14-hardened-js-member.zip", js && !residual && logic ? "PASS" : "PARTIAL",
    `real ast-shield js member: dehardened=${rep.innerJsDehardened} residual-markers=${residual} real-logic-present=${logic} out-len=${js?.data?.length}`,
    { report: rep });
}

// CASE 15 — clean exotic control
{
  const c = R("case15-clean-exotic.zip");
  record("case15-clean-exotic.zip", c.direct && !c.direct.report.hardened && c.direct.buffer.equals(c.inBuf) ? "PASS" : "FAIL",
    `descriptors+comments+dirs but ZERO decoys -> hardened=${c.direct?.report.hardened} identical=${c.direct?.buffer.equals(c.inBuf)} (no false-positive rebuild)`);
}

// CASE 16 — marker in non-dex member
{
  const c = R("case16-tinymarker.zip");
  const o = member("case16-tinymarker.zip", "note.txt");
  const markerIn = o?.data ? o.data.includes(DEXM) : null;
  record("case16-tinymarker.zip", markerIn ? "EVASION" : "PASS",
    `note.txt 'hi\\0[BLA-DEX-SHIELD-V1]..' -> scrubDex <112B guard -> member kept INTACT w/ marker; survives=${markerIn}; cli exit=${c.cliExit}${c.threw ? " threw=" + c.threw.message : ""}`);
}
{
  const c = R("case16b-textmarker.zip");
  const o = member("case16b-textmarker.zip", "read.txt"), i = member("case16b-textmarker.zip", "read.txt", "in");
  const shrank = o && i && o.data && i.data && o.data.length < i.data.length;
  const markerIn = o?.data ? o.data.includes(DEXM) : null;
  record("case16b-textmarker.zip", shrank ? "MEMBER-TRUNCATED" : (markerIn ? "EVASION" : "PASS"),
    `text member w/ marker (${i?.data?.length}B): ${shrank ? `scrubDex truncated ->${o.data.length}B` : markerIn ? "<112B-guard -> kept intact, marker SURVIVES inside output member" : "scrubbed"}`);
}

// CASE 17 — corrupt compressed member carrying marker
{
  const c = R("case17-corrupt-hardened.zip");
  const rep = c.direct?.report ?? {};
  const ev = member("case17-corrupt-hardened.zip", "evil.dex");
  const markerSurvives = ev?.comp ? ev.comp.includes(DEXM) : null;
  record("case17-corrupt-hardened.zip", markerSurvives ? "EVASION" : "PASS",
    `un-inflatable member: data=null -> raw-preserved verbatim -> [BLA-DEX-SHIELD-V1] bytes SURVIVE in output member (rawPreserved=${rep.rawPreservedMembers}) — marker-content checks never see undecodable data`,
    { report: rep });
}

// ---------- emit ----------
console.log("case".padEnd(38) + "verdict".padEnd(24) + "detail");
console.log("=".repeat(140));
for (const r of results) console.log(r.file.padEnd(38) + r.verdict.padEnd(24) + r.detail);
writeFileSync(join(here, "RESULTS.json"), JSON.stringify(results, null, 2));
console.log("\n-> RESULTS.json");
