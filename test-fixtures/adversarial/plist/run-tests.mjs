// BLADE adversarial plist-scrubber tests.
// Generates fixtures (hand-crafted + REAL vendored-BLA hardened output),
// runs scrubPlistXml/scrubBplist, validates cleaned output with python
// plistlib, and prints a verdict per case.
import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import path from "node:path";

const DIR = import.meta.dirname;
const ROOT = path.resolve(DIR, "..", "..", "..");

// Locate a python with plistlib — no hardcoded machine paths. Order prefers
// the explicit override, then the Windows launcher, then PATH pythons (the
// Windows `python` Store stub exits non-zero, so the probe filters it).
function findPython() {
  for (const cand of [process.env.BLADE_PYTHON, "py", "python3", "python"]) {
    if (!cand) continue;
    const r = spawnSync(cand, ["-c", "import plistlib"], { stdio: "ignore" });
    if (!r.error && r.status === 0) return cand;
  }
  return null;
}
const PY = findPython();

const { scrubPlistXml, scrubBplist } = await import(path.join(ROOT, "src", "trailer.mjs").replace(/\\/g, "/").replace(/^/, "file:///"));
const { protectAppleXmlPlist, protectApplePlistBuffer } = await import(path.join(ROOT, "vendor", "bla", "dist", "shields", "formats", "apple-plist.js").replace(/\\/g, "/").replace(/^/, "file:///"));

const results = [];
if (!PY) {
  console.log("SKIP: no python interpreter with plistlib found — set BLADE_PYTHON");
  process.exit(0);
}
function validate(file) {
  const j = execFileSync(PY, [path.join(DIR, "validate.py"), file], { encoding: "utf8" }).trim();
  return JSON.parse(j);
}
function caseXml(name, text, note) {
  const f = path.join(DIR, name);
  writeFileSync(f, text);
  const r = scrubPlistXml(text);
  const out = path.join(DIR, name.replace(/\.plist$/, ".cleaned.plist"));
  writeFileSync(out, r.code);
  const v = validate(out);
  return { name, note, report: r.report, verdict: v, out };
}
function caseBin(name, buf, note) {
  const f = path.join(DIR, name);
  writeFileSync(f, buf);
  const r = scrubBplist(buf);
  const out = path.join(DIR, name.replace(/\.bplist$/, ".cleaned.bplist"));
  writeFileSync(out, r.buffer);
  const v = validate(out);
  return { name, note, report: r.report, verdict: v, out, buffer: r.buffer };
}

const PUB = '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">';
const PUB_SUBSET = '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd" []>';
const HDR = '<?xml version="1.0" encoding="UTF-8"?>';

/* ================= CASE 1 — real vendor keys that start with BLA =================
   Plausible vendor keys: BLAVersion, BLATeamID, BLAServerEndpoint,
   BLAHardwareRevision, BLA_REGION_US (scalar -> regex bites), BLAFeatureFlags
   (dict value -> regex can't reach it). Controls: BlacklistEnabled, NotBLA. */
const case1base = `${HDR}
${PUB}
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.blahut.licensetool</string>
  <key>BLAVersion</key>
  <string>2.1.4</string>
  <key>BLATeamID</key>
  <string>BLAHUT9XK2</string>
  <key>BLAServerEndpoint</key>
  <string>https://licenses.blahut.example/v1</string>
  <key>BLAHardwareRevision</key>
  <integer>7</integer>
  <key>BLA_REGION_US</key>
  <string>us-east-1</string>
  <key>BLAFeatureFlags</key>
  <dict>
    <key>turbo</key>
    <true/>
  </dict>
  <key>BlacklistEnabled</key>
  <true/>
  <key>NotBLA</key>
  <string>keep me</string>
</dict>
</plist>
`;
const case1hard = protectAppleXmlPlist(case1base).xmlPlist;
const c1 = caseXml("case1-real-bla-keys.plist", case1hard,
  "real vendor BLA* keys + real BLA decoys");
const c1keys = c1.verdict.top_keys ?? [];
const c1dropped = ["BLAVersion", "BLATeamID", "BLAServerEndpoint", "BLAHardwareRevision", "BLA_REGION_US"].filter(k => !c1keys.includes(k));
const c1survivor = c1keys.includes("BLAFeatureFlags");
results.push({
  case: "1. real BLA* vendor keys",
  verdict: c1dropped.length ? "REAL-KEY-DROPPED" : "PASS",
  detail: `dropped REAL keys: ${c1dropped.join(", ") || "none"}; BLAFeatureFlags (dict value) survived=${c1survivor}; ` +
    `BlacklistEnabled kept=${c1keys.includes("BlacklistEnabled")}; NotBLA kept=${c1keys.includes("NotBLA")}; ` +
    `leftover decoys=${(c1.verdict.bla_keys ?? []).join(",") || "none"}; plistlib=${c1.verdict.plistlib}`,
});

/* ================= CASE 2 — internal-subset DOCTYPE ================= */
// 2a: REAL non-empty internal subset, never touched by BLA
const case2a = `${HDR}
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd" [
  <!ENTITY vendor "Blahut Systems">
]>
<plist version="1.0">
<dict>
  <key>VendorName</key>
  <string>&vendor;</string>
</dict>
</plist>
`;
const c2a = caseXml("case2-real-subset-raw.plist", case2a, "real internal subset, no BLA");
results.push({
  case: "2a. real non-empty subset (raw)",
  verdict: c2a.out && readFileSync(c2a.out, "utf8").includes("<!ENTITY vendor") && c2a.verdict.xml_wf === "ok" ? "PASS (subset preserved)" : "SUBSET-CORRUPT",
  detail: `hardened=${c2a.report.hardened}; internalSubsetRemoved=${c2a.report.internalSubsetRemoved} (report flag misleads: real subset intact); plistlib=${c2a.verdict.plistlib}; xml_wf=${c2a.verdict.xml_wf}`,
});

// 2b: same file pushed through REAL BLA first (BLA's own /<!DOCTYPE\s+plist[^>]*>/
// truncates at the '>' INSIDE the entity decl), then scrubbed
const case2bHard = protectAppleXmlPlist(case2a).xmlPlist;
writeFileSync(path.join(DIR, "case2-real-subset.hardened.plist"), case2bHard);
const c2b = caseXml("case2-real-subset-hardened.plist", case2bHard, "real subset -> BLA -> scrub");
results.push({
  case: "2b. real subset through BLA then scrub",
  verdict: c2b.verdict.plistlib === "ok" ? "PASS" : "PARSE-FAIL",
  detail: `BLA intermediate leaves stray ']>' + undefined entity; scrub keeps it. plistlib=${c2b.verdict.plistlib}; xml_wf=${c2b.verdict.xml_wf}; internalSubsetRemoved=${c2b.report.internalSubsetRemoved}`,
});

// 2c: control — standard BLA [] subset collapses
const c2c = caseXml("case2-empty-subset-hardened.plist", protectAppleXmlPlist(`${HDR}\n${PUB}\n<plist version="1.0">\n<dict>\n  <key>A</key>\n  <string>1</string>\n</dict>\n</plist>\n`).xmlPlist, "BLA [] subset");
results.push({
  case: "2c. BLA empty [] subset (control)",
  verdict: c2c.verdict.plistlib === "ok" && !readFileSync(c2c.out, "utf8").includes("[]") ? "PASS" : "FAIL",
  detail: `doctype collapsed=${!readFileSync(c2c.out, "utf8").includes("[]")}; plistlib=${c2c.verdict.plistlib}`,
});

// 2d: whitespace-only subset [ \n ] — should still collapse via \[\s*\]
const case2d = `${HDR}
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd" [
]>
<plist version="1.0">
<dict>
  <key>A</key>
  <string>1</string>
  <key>BLACanaryCredential_0</key>
  <string>bla_canary_x</string>
</dict>
</plist>
`;
const c2d = caseXml("case2-whitespace-subset.plist", case2d, "[\\n] subset");
results.push({
  case: "2d. whitespace-only [\\n] subset",
  verdict: c2d.verdict.plistlib === "ok" && !/\[\s*\]/.test(readFileSync(c2d.out, "utf8")) ? "PASS" : "FAIL",
  detail: `collapsed=${!/\[\s*\]/.test(readFileSync(c2d.out, "utf8"))}; plistlib=${c2d.verdict.plistlib}`,
});

// 2e: single-quoted DOCTYPE ids — regex requires double quotes
const case2e = `${HDR}
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd' []>
<plist version="1.0">
<dict>
  <key>A</key>
  <string>1</string>
  <key>BLACanaryCredential_0</key>
  <string>bla_canary_x</string>
</dict>
</plist>
`;
const c2e = caseXml("case2-single-quote-doctype.plist", case2e, "single-quoted ids");
const c2eLeft = readFileSync(c2e.out, "utf8").includes("[]");
results.push({
  case: "2e. single-quoted DOCTYPE",
  verdict: c2e.verdict.plistlib === "ok" && !c2eLeft ? "PASS" : (c2eLeft ? "MISS ([] survives)" : "PARSE-FAIL"),
  detail: `[] remains=${c2eLeft}; decoysDropped=${c2e.report.decoyKeysDropped}; internalSubsetRemoved=${c2e.report.internalSubsetRemoved}; plistlib=${c2e.verdict.plistlib}`,
});

/* ================= CASE 3 — multiline / unusually-formatted values ================= */
const case3 = `${HDR}
${PUB_SUBSET}
<plist version="1.0">
<dict>
  <key>AppName</key>
  <string>RealApp</string>
  <key>BLACanaryCredential_0</key>
  <data>
    U0VDRUVUX0RBVEFfQkxBQ0s=
    QUJDREVGRw==
  </data>
  <key>BLAWrappedNote</key>
  <string>line one
line two</string>
  <key>BLASameLine</key><string>compact</string>
  <key>BLABlankLine</key>

  <string>after blank</string>
  <key>BLACommented</key>
  <!-- a comment -->
  <string>after comment</string>
  <key>BLADictVal</key>
  <dict>
    <key>inner</key>
    <string>v</string>
  </dict>
  <key>BLABool</key>
  <true/>
  <key>BLADate</key>
  <date>2024-01-01T00:00:00Z</date>
</dict>
</plist>
`;
const c3 = caseXml("case3-multiline.plist", case3, "multiline data/string, same-line, blank-line, comment, dict, date");
const c3txt = readFileSync(c3.out, "utf8");
const c3left = (c3.verdict.bla_keys ?? []);
results.push({
  case: "3. multiline/odd formatting",
  verdict: c3.verdict.plistlib === "ok" ? (c3left.length ? `PARTIAL (leftovers: ${c3left.join(",")})` : "PASS") : "PARSE-FAIL",
  detail: `decoysDropped=${c3.report.decoyKeysDropped} (multiline <data> + wrapped <string> + <true/> handled); ` +
    `leftover BLA keys=${c3left.join(",") || "none"}; dataBlockGone=${!c3txt.includes("U0VDRUVUX")}; plistlib=${c3.verdict.plistlib}`,
});

/* ================= CASE 4 — binary plist marker collisions ================= */
function pyDump(obj) {
  const j = JSON.stringify(obj);
  const b64 = Buffer.from(j).toString("base64");
  return execFileSync(PY, ["-c",
    `import plistlib,sys,json,base64;sys.stdout.buffer.write(plistlib.dumps(json.loads(base64.b64decode('${b64}')),fmt=plistlib.FMT_BINARY))`],
    { encoding: "buffer" });
}

// 4a: marker bytes inside a REAL string object
const c4a = caseBin("case4-marker-in-string.bplist",
  pyDump({ "LogTail": "x".repeat(40) + "BLA_BPLIST_DEPTH_GUARD_132:abcdef:com.apple.fake y", "Other": 1 }),
  "marker inside real string");
results.push({
  case: "4a. marker inside real bplist string",
  verdict: c4a.report.hardened ? "FALSE-CUT" : "PASS",
  detail: `hardened=${c4a.report.hardened}; trailerDropped=${c4a.report.trailerDropped ?? 0}B of real data; plistlib=${c4a.verdict.plistlib}`,
});

// 4b: marker as a real dict KEY
const c4b = caseBin("case4-marker-as-key.bplist",
  pyDump({ "BLA_BPLIST_DEPTH_GUARD_X": "real value", "Keep": "me" }),
  "marker as real key");
results.push({
  case: "4b. marker as real bplist key",
  verdict: c4b.report.hardened ? "FALSE-CUT" : "PASS",
  detail: `hardened=${c4b.report.hardened}; trailerDropped=${c4b.report.trailerDropped ?? 0}B; plistlib=${c4b.verdict.plistlib}`,
});

// 4c: REAL BLA trailer appended — control should cleanly restore
const c4cOrig = pyDump({ "CFBundleName": "RealApp", "N": 42 });
const c4c = caseBin("case4-real-trailer.bplist", Buffer.from(protectApplePlistBuffer(Buffer.from(c4cOrig)).buffer), "real BLA trailer");
results.push({
  case: "4c. real BLA trailer (control)",
  verdict: c4c.verdict.plistlib === "ok" && Buffer.compare(Buffer.from(c4c.buffer), Buffer.from(c4cOrig)) === 0 ? "PASS" : "FAIL",
  detail: `byte-identical to original=${Buffer.compare(Buffer.from(c4c.buffer), Buffer.from(c4cOrig)) === 0}; plistlib=${c4c.verdict.plistlib}`,
});

// 4d: different BLA marker ([BLA-NATIVE-SHIELD-V1]) inside a real string — must NOT cut
const c4d = caseBin("case4-native-marker.bplist",
  pyDump({ "Note": "mentions [BLA-NATIVE-SHIELD-V1] in docs", "Keep": 1 }),
  "foreign BLA marker in string");
results.push({
  case: "4d. [BLA-NATIVE] string in bplist",
  verdict: !c4d.report.hardened && c4d.verdict.plistlib === "ok" ? "PASS" : "FALSE-CUT",
  detail: `hardened=${c4d.report.hardened}; plistlib=${c4d.verdict.plistlib}`,
});

// 4e: marker in real string AND real trailer appended — first-occurrence cut
const c4e = caseBin("case4-marker-and-trailer.bplist",
  Buffer.from(protectApplePlistBuffer(Buffer.from(pyDump({ "LogTail": "data BLA_BPLIST_DEPTH_GUARD_X more", "Keep": 7 }))).buffer),
  "real marker string + real trailer");
results.push({
  case: "4e. marker string + real trailer",
  verdict: c4e.verdict.plistlib === "ok" ? "PASS" : "FALSE-CUT",
  detail: `cut lands at FIRST occurrence (the real string), not the trailer; plistlib=${c4e.verdict.plistlib}`,
});

/* ================= CASE 5 — line endings ================= */
const case5base = `${HDR}
${PUB}
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.example.app</string>
  <key>CFBundleVersion</key>
  <string>1.0</string>
</dict>
</plist>
`;
const case5hard = protectAppleXmlPlist(case5base).xmlPlist;
// 5a: CRLF hardened file
const c5a = caseXml("case5-crlf.plist", case5hard.replace(/\r?\n/g, "\r\n"), "CRLF hardened");
const c5aleft = c5a.verdict.bla_keys ?? [];
results.push({
  case: "5a. CRLF line endings",
  verdict: c5a.verdict.plistlib === "ok" && c5aleft.length === 0 ? "PASS" : `CRLF-BREAK (leftovers: ${c5aleft.join(",")})`,
  detail: `decoysDropped=${c5a.report.decoyKeysDropped}; plistlib=${c5a.verdict.plistlib}; leftover=${c5aleft.join(",") || "none"}`,
});

// 5b: lone-CR (classic Mac) endings
const c5b = caseXml("case5-cr-only.plist", case5hard.replace(/\r?\n/g, "\r"), "CR-only hardened");
const c5bleft = c5b.verdict.bla_keys ?? [];
results.push({
  case: "5b. lone-CR line endings",
  verdict: c5bleft.length === 0 ? "PASS" : `MISS (decoys survive: ${c5bleft.length} BLA keys)`,
  detail: `regex needs literal \\n; CR-only has none. decoysDropped=${c5b.report.decoyKeysDropped}; plistlib=${c5b.verdict.plistlib}; xml_wf=${c5b.verdict.xml_wf}`,
});

// 5c: realistic mixed endings — CRLF base, BLA inserts LF lines
const c5c = caseXml("case5-mixed-crlf.plist", protectAppleXmlPlist(case5base.replace(/\r?\n/g, "\r\n")).xmlPlist, "CRLF base + LF decoys");
const c5cleft = c5c.verdict.bla_keys ?? [];
results.push({
  case: "5c. mixed CRLF+LF (realistic)",
  verdict: c5c.verdict.plistlib === "ok" && c5cleft.length === 0 ? "PASS" : `CRLF-BREAK (leftovers: ${c5cleft.join(",")})`,
  detail: `decoysDropped=${c5c.report.decoyKeysDropped}; plistlib=${c5c.verdict.plistlib}; leftover=${c5cleft.join(",") || "none"}`,
});

/* ================= CASE 6 — nesting at depth ================= */
// 6a: REAL BLA on a plist whose first </dict> is nested — decoys land inside it
const case6aBase = `${HDR}
${PUB}
<plist version="1.0">
<dict>
  <key>Outer</key>
  <dict>
    <key>InnerA</key>
    <string>1</string>
  </dict>
  <key>Top</key>
  <string>2</string>
</dict>
</plist>
`;
const c6aHard = protectAppleXmlPlist(case6aBase).xmlPlist;
const c6a = caseXml("case6-nested-real.plist", c6aHard, "BLA injects at first </dict> = nested dict");
const c6aleft = c6a.verdict.bla_keys ?? [];
results.push({
  case: "6a. real BLA decoys inside nested dict",
  verdict: c6a.verdict.plistlib === "ok" && c6aleft.length === 0 ? "PASS" : `FAIL (leftovers: ${c6aleft.join(",")})`,
  detail: `BLA put decoys inside the NESTED dict (first </dict>); decoysDropped=${c6a.report.decoyKeysDropped}; plistlib=${c6a.verdict.plistlib}; leftover=${c6aleft.join(",") || "none"}`,
});

// 6b: dict > array > dict > array > dict with BLA pairs at depth 3
const case6b = `${HDR}
${PUB_SUBSET}
<plist version="1.0">
<dict>
  <key>Level1</key>
  <array>
    <dict>
      <key>L2Arr</key>
      <array>
        <dict>
          <key>Deep</key>
          <string>real</string>
          <key>BLACanaryCredential_0</key>
          <string>deep canary</string>
        </dict>
      </array>
      <key>BLATransportEndpoint_0</key>
      <string>nested transport</string>
    </dict>
  </array>
  <key>BLAEnclaveVsockDelegationCID</key>
  <integer>16</integer>
</dict>
</plist>
`;
const c6b = caseXml("case6-deep-nested.plist", case6b, "dict>array>dict>array>dict");
const c6bleft = c6b.verdict.bla_keys ?? [];
results.push({
  case: "6b. BLA keys at depth 3 (dict in arrays)",
  verdict: c6b.verdict.plistlib === "ok" && c6bleft.length === 0 ? "PASS" : `FAIL (leftovers: ${c6bleft.join(",")})`,
  detail: `decoysDropped=${c6b.report.decoyKeysDropped}; plistlib=${c6b.verdict.plistlib}; leftover=${c6bleft.join(",") || "none"}`,
});

/* ================= REPORT ================= */
console.log("\n========== ADVERSARIAL PLIST SCRUBBER RESULTS ==========\n");
for (const r of results) {
  console.log(`${r.verdict.padEnd(34)} | ${r.case}`);
  console.log(`${"".padEnd(34)} |   ${r.detail}`);
}
console.log("\n=======================================================\n");
