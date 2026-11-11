// BLADE adversarial harness for dehardenJs.
// Builds each case, runs the dehardener, executes plain vs cleaned where
// possible, and prints a verdict per case.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { dehardenJs, looksBlaHardened } from "../../../src/js-deharden.mjs";
import { transformJavaScriptWithBlaShield } from "../../../vendor/bla/dist/shields/javascript/ast-shield.js";

const DIR = dirname(fileURLToPath(import.meta.url));
const OUT = join(DIR, "out");
mkdirSync(OUT, { recursive: true });
const read = (f) => readFileSync(join(DIR, f), "utf8");
const save = (f, code) => writeFileSync(join(OUT, f), code);

const protect = (src, opts = {}) =>
  transformJavaScriptWithBlaShield(src, {
    seed: opts.seed ?? "adv-seed-1",
    intensity: opts.intensity ?? "balanced",
    filename: opts.filename ?? "case.js",
    ...opts,
  }).code;

const deharden = (src, filename) => {
  try {
    return { r: dehardenJs(src, { filename }), crash: null };
  } catch (e) {
    return { r: null, crash: `${e.name}: ${e.message}` };
  }
};

// ---------- execution harness ----------
function makeSandbox() {
  const mod = { exports: {} };
  const sandbox = {
    module: mod,
    exports: mod.exports,
    require: (id) => {
      if (id === "electron") {
        return {
          ipcMain: { handle() {}, on() {} },
          ipcRenderer: { invoke: async () => ({}), send() {} },
          contextBridge: { exposeInMainWorld() {} },
          app: { setAsDefaultProtocolClient() {} },
          protocol: { handle() {}, registerSchemesAsPrivileged() {} },
          session: { defaultSession: { protocol: { handle() {} } } },
        };
      }
      if (id === "node:fs" || id === "fs") return { readFileSync: () => "", writeFileSync() {}, existsSync: () => false };
      return {};
    },
    console,
    setTimeout,
    clearTimeout,
    setInterval: () => 0,
    clearInterval() {},
    fetch: async () => ({ ok: true }),
    process: { env: {}, argv: [], versions: { node: "24.0.0" }, hrtime: () => [0, 0] },
    globalThis: {},
  };
  sandbox.globalThis = sandbox;
  sandbox.window = sandbox;
  return { sandbox, mod };
}

function runModule(code, label) {
  const { sandbox, mod } = makeSandbox();
  try {
    vm.runInNewContext(code, sandbox, { filename: label, timeout: 10000 });
    return { ok: true, exports: mod.exports, sandbox };
  } catch (e) {
    return { ok: false, error: `${e.name}: ${e.message}` };
  }
}

async function probe(exportsObj, calls) {
  const out = {};
  for (const [name, fn] of Object.entries(calls)) {
    try {
      out[name] = await fn(exportsObj);
    } catch (e) {
      out[name] = `THREW ${e.name}: ${e.message}`;
    }
  }
  return out;
}

const results = [];
function record(caseId, verdict, detail) {
  results.push({ caseId, verdict, detail });
  console.log(`\n=== ${caseId}: ${verdict} ===`);
  console.log(detail);
}
const diff = (a, b) => JSON.stringify(a) !== JSON.stringify(b);

// ================================================================
// CASE 1a — real unhardened file containing `void [a,b,c]` + `void x`
// ================================================================
{
  const src = read("src-01a-real-void.js");
  const { r, crash } = deharden(src, "01a.js");
  const same = r && (r.code === src || r.code.trim() === src.trim());
  if (r) save("01a.cleaned.js", r.code);
  record(
    "01a real-void-no-markers",
    crash ? "CRASH" : !r.report.hardened && same ? "PASS" : "FALSE-STRIP",
    crash ?? `hardened=${r.report.hardened} codeUnchanged=${same} removedTopLevel=${r.report.removedTopLevel}`,
  );
}

// ================================================================
// CASE 1b — real file w/ ONE marker token + void[] discards
// ================================================================
{
  const src = read("src-01b-marker-trap.js");
  const { r, crash } = deharden(src, "01b.js");
  let detail, verdict;
  if (crash) {
    verdict = "CRASH"; detail = crash;
  } else {
    save("01b.cleaned.js", r.code);
    const declGone = ["alphaScore", "betaScore", "gammaScore", "obligationFlood_threshold", "PIPELINE"]
      .filter((n) => !new RegExp(`(function|const|let|var)\\s+${n}\\b`).test(r.code));
    const clean = runModule(r.code, "01b-cleaned");
    verdict = declGone.length ? "FALSE-STRIP" : "PASS";
    detail =
      `hardened=${r.report.hardened} removedTopLevel=${r.report.removedTopLevel}\n` +
      `real decls stripped: ${JSON.stringify(declGone)}\n` +
      `danglingRefs reported: ${JSON.stringify(r.report.danglingRefs)}\n` +
      `exec cleaned.ok=${clean.ok} err=${clean.error ?? "-"} (plain runAll(5)=23121)`;
  }
  record("01b marker-token-trap", verdict, detail);
}

// ================================================================
// CASE 1c — real file w/ STRONG/GENERIC-shaped names + marker string
// ================================================================
{
  const src = read("src-01c-strong-names.js");
  const { r, crash } = deharden(src, "01c.js");
  let detail, verdict;
  if (crash) { verdict = "CRASH"; detail = crash; }
  else {
    save("01c.cleaned.js", r.code);
    const declGone = [
      "verifyEnterpriseMasterLicense_prod", "scc_mixColumns_c1n2", "obligationFlood_check",
      "audit_2fa", "\\$revLog", "diffFrontier_scan_3", "REPORT_TAG",
    ].filter((n) => !new RegExp(`(function|const|let|var)\\s+${n}\\b`).test(r.code));
    const clean = runModule(r.code, "01c-cleaned");
    verdict = declGone.length ? "FALSE-STRIP" : "PASS";
    detail =
      `hardened=${r.report.hardened} removedTopLevel=${r.report.removedTopLevel}\n` +
      `decls stripped: ${JSON.stringify(declGone)}\nremovedNameSamples: ${JSON.stringify(r.report.removedNameSamples)}\n` +
      `exec cleaned.ok=${clean.ok} err=${clean.error ?? "-"}\n` +
      `useAll=${clean.ok ? JSON.stringify((() => { try { return clean.exports.useAll?.("keykeykeykey", [1, 0, 2]); } catch (e) { return "THREW " + e.message; } })()) : "n/a"}`;
  }
  record("01c strong-name-collision", verdict, detail);
}

// ================================================================
// CASE 2 — double-harden chain: protect -> deharden -> protect -> deharden
// ================================================================
{
  const src = read("src-02-double-plain.js");
  const h1 = protect(src, { intensity: "maximum", seed: "chain-seed-A" });
  save("02.hardened1.js", h1);
  const { r: d1, crash: c1e } = deharden(h1, "02-h1.js");
  let h2 = null, d2 = null, err2 = null, c2e = null;
  if (d1) {
    save("02.cleaned1.js", d1.code);
    try {
      h2 = protect(d1.code, { intensity: "maximum", seed: "chain-seed-B" });
      save("02.hardened2.js", h2);
      ({ r: d2, crash: c2e } = deharden(h2, "02-h2.js"));
      if (d2) save("02.cleaned2.js", d2.code);
    } catch (e) {
      err2 = e.message;
    }
  }
  const plain = runModule(src, "02-plain");
  const c1 = d1 ? runModule(d1.code, "02-clean1") : { ok: false, error: c1e };
  const c2 = d2 ? runModule(d2.code, "02-clean2") : { ok: false, error: c2e ?? err2 ?? "harden2 failed" };
  const calls = {
    seal: async (ex) => [["ENT-123", 7], ["PRO-9", 3]].map(([a, b]) => ex.sealToken(a, b)),
    check: async (ex) => ex.checkToken("ENT-123", 7, ex.sealToken("ENT-123", 7)),
    mix: async (ex) => ex.mixKey(12345, 678),
  };
  const rp = plain.ok ? await probe(plain.exports, calls) : { err: plain.error };
  const r1 = c1.ok ? await probe(c1.exports, calls) : { err: c1.error };
  const r2 = c2.ok ? await probe(c2.exports, calls) : { err: c2.error };
  const pass = !diff(rp, r2) && !diff(rp, r1);
  record(
    "02 double-harden-chain",
    c1e || c2e ? "CRASH" : err2 ? "CRASH(harden2)" : pass ? "PASS" : "SEMANTIC-DIFF",
    `deharden1 crash=${c1e ?? "none"} residual=${d1 ? JSON.stringify(d1.report.residualStatements.map((s) => s.preview)) : "-"}\n` +
      `harden2 err=${err2 ?? "none"} deharden2 crash=${c2e ?? "none"}\n` +
      (d2
        ? `deharden2 removedTopLevel=${d2.report.removedTopLevel} residual=${JSON.stringify(d2.report.residualStatements.map((s) => s.preview))} dangling=${JSON.stringify(d2.report.danglingRefs)}\n`
        : "") +
      `exec: plain=${JSON.stringify(rp)}\n  clean1=${JSON.stringify(r1)}\n  clean2=${JSON.stringify(r2)}`,
  );
}

// ================================================================
// CASE 3 — hardened file with the `void [...]` index manually deleted
// ================================================================
{
  const src = read("src-02-double-plain.js");
  const h = protect(src, { intensity: "balanced", seed: "noidx-seed" });
  save("03.hardened.js", h);
  const mutated = h
    .split("\n")
    .filter((l) => !/^\s*void\s+[\[\(\w$]/.test(l))
    .join("\n");
  save("03.hardened-noidx.js", mutated);
  const { r, crash } = deharden(mutated, "03.js");
  let detail, verdict;
  if (crash) { verdict = "CRASH"; detail = crash; }
  else {
    save("03.cleaned.js", r.code);
    const plain = runModule(src, "03-plain");
    const clean = runModule(r.code, "03-cleaned");
    const calls = {
      seal: async (ex) => ex.sealToken("ENT-123", 7),
      mix: async (ex) => ex.mixKey(1, 2),
    };
    const rp = plain.ok ? await probe(plain.exports, calls) : { err: plain.error };
    const rc = clean.ok ? await probe(clean.exports, calls) : { err: clean.error };
    const leftoverDecoys = (r.code.match(/function\s+([_$a-zA-Z][\w$]*)/g) ?? [])
      .filter((d) => !["mixKey", "sealToken", "checkToken"].some((real) => d.includes(real)));
    verdict = diff(rp, rc) ? "SEMANTIC-DIFF" : leftoverDecoys.length ? "DECOY-SURVIVES" : "PASS";
    detail =
      `removedTopLevel=${r.report.removedTopLevel} injectedFnsRemoved=${r.report.injectedFunctionsRemoved}\n` +
      `residual after boundary: ${JSON.stringify(r.report.residualStatements.map((s) => s.preview.slice(0, 60)))}\n` +
      `danglingRefs=${JSON.stringify(r.report.danglingRefs)}\n` +
      `suspicious surviving fns: ${JSON.stringify(leftoverDecoys.slice(0, 10))}\n` +
      `exec plain=${JSON.stringify(rp)} cleaned=${JSON.stringify(rc)}`;
  }
  record("03 void-index-deleted", verdict, detail);
}

// ================================================================
// CASE 4 — real code AFTER the injected suffix + interleaved inside it
// ================================================================
{
  const src = read("src-04-tail-base.js");
  const h = protect(src, { intensity: "balanced", seed: "tail-seed" });
  save("04.hardened.js", h);
  // 4a: real statements appended after the whole suffix (post-harden user edit)
  const tailA =
    h +
    `\nfunction tailHelper(x) { return x + 7; }\n` +
    `const audit_2db = 4242;\n` +           // GENERIC-shaped real name
    `module.exports.tailHelper = tailHelper;\n` +
    `module.exports.audit_2db = audit_2db;\n`;
  save("04a.tail.js", tailA);
  const { r: ra, crash: ca } = deharden(tailA, "04a.js");
  let tailSurvives = null, auditDeclSurvives = null, aExtra = "";
  if (ra) {
    save("04a.cleaned.js", ra.code);
    tailSurvives = /function tailHelper/.test(ra.code);
    auditDeclSurvives = /const audit_2db/.test(ra.code);
    const execA = runModule(ra.code, "04a-cleaned");
    aExtra = `exec cleaned.ok=${execA.ok} err=${execA.error ?? "-"} (audit export ref left dangling? ${/module\.exports\.audit_2db/.test(ra.code) && !auditDeclSurvives})`;
  }
  // 4b: real statements spliced at a true top-level boundary INSIDE the suffix
  //     (right before the `void [...]` index line = last top-level slot).
  const lines = h.split("\n");
  const voidIdx = lines.findIndex((l) => /^\s*void\s*\[/.test(l));
  const injected = [
    "function midReal(x) { return x * 5; }",
    "const probe_9ab = 1;",
    "function scc_realHelper_c1n1() { return 3; }",   // STRONG-shaped real fn
    "module.exports.midReal = midReal;",
  ];
  lines.splice(voidIdx, 0, ...injected);
  const interleaved = lines.join("\n");
  save("04b.interleaved.js", interleaved);
  const { r: rb, crash: cb } = deharden(interleaved, "04b.js");
  let midSurvives = null, probeSurvives = null, sccSurvives = null, bExtra = "";
  if (rb) {
    save("04b.cleaned.js", rb.code);
    midSurvives = /function midReal/.test(rb.code);
    probeSurvives = /const probe_9ab/.test(rb.code);
    sccSurvives = /scc_realHelper_c1n1/.test(rb.code);
    const execB = runModule(rb.code, "04b-cleaned");
    bExtra = `exec cleaned.ok=${execB.ok} err=${execB.error ?? "-"}`;
  }
  record(
    "04 suffix-region real code",
    ca || cb ? "CRASH" : tailSurvives === false || midSurvives === false ? "FALSE-STRIP"
      : auditDeclSurvives === false || probeSurvives === false || sccSurvives === false ? "FALSE-STRIP" : "PASS",
    `4a tail crash=${ca ?? "none"}: tailHelper survived=${tailSurvives}, audit_2db DECL survived=${auditDeclSurvives}\n  ${aExtra}\n` +
      `4b interleaved crash=${cb ?? "none"}: midReal=${midSurvives}, probe_9ab=${probeSurvives}, scc_realHelper_c1n1=${sccSurvives}\n  ${bExtra}\n` +
      (rb ? `4b residual=${JSON.stringify(rb.report.residualStatements.map((s) => s.preview.slice(0, 50)))}` : ""),
  );
}

// ================================================================
// CASE 5 — if(opaqueTrue){realA}else{decoyB} / if(opaqueFalse){realOnly}
// ================================================================
{
  const src = read("src-05-ifelse.js");
  const h = protect(src, { intensity: "balanced", seed: "ifelse-seed" });
  save("05.hardened.js", h);
  const { r: r0, crash: c0 } = deharden(h, "05-base.js");
  let verdict = "PASS", detail = "";
  if (c0) { verdict = "CRASH"; detail = c0; }
  else {
    save("05.cleaned-base.js", r0.code);
    const plain = runModule(src, "05-plain");
    const clean = runModule(r0.code, "05-clean");
    const calls = {
      fast: async (ex) => ex.entry("fast", 5),
      slow: async (ex) => ex.entry("slow", 5),
    };
    const rp = plain.ok ? await probe(plain.exports, calls) : { err: plain.error };
    const rc = clean.ok ? await probe(clean.exports, calls) : { err: clean.error };
    const keptBothBranches = /v \* 2|\* 2/.test(r0.code) && /\+ 100|100/.test(r0.code);
    verdict = diff(rp, rc) ? "SEMANTIC-DIFF" : keptBothBranches ? "PASS" : "FALSE-STRIP";
    detail = `base: exec plain=${JSON.stringify(rp)} cleaned=${JSON.stringify(rc)} branchesKept=${keptBothBranches}`;
  }
  // hand-inject if(opaqueTrue){real}else{decoy} + if(opaqueFalse){realOnly}
  // inside the (renamed) real `entry` function, referencing the (renamed)
  // `pickPath` and the file's actual seed binding name.
  const seedName = h.match(/const\s+(\w+)\s*=\s*\(?\s*\d+\s*\|\s*\(\s*typeof/)?.[1] ?? null;
  const pickName = h.match(/pickPath:\s*(\w+)/)?.[1] ?? null;
  const entryName = h.match(/entry:\s*(\w+)/)?.[1] ?? null;
  let mutated = h, applied = false;
  if (seedName && pickName && entryName) {
    const opaqueT = `(Math.imul(${seedName} ^ 8, ${seedName} ^ 8) & 7) === 1`;
    const opaqueF = `(Math.imul(${seedName} ^ 8, ${seedName} ^ 8) & 7) === 0`;
    const inject =
      `  if (${opaqueT}) { ${pickName}("fast", 1); } else { ${pickName}("slow", 1); }\n` +
      `  if (${opaqueF}) { throw new Error("realOnly-never-runs"); }\n`;
    const re = new RegExp(`function ${entryName}\\(([^)]*)\\) \\{`);
    mutated = h.replace(re, (m) => { applied = true; return m + "\n" + inject; });
    save("05.mutated.js", mutated);
  }
  const { r: r1, crash: c1 } = applied ? deharden(mutated, "05-mut.js") : { r: null, crash: `mutation not applied (seed=${seedName} pick=${pickName} entry=${entryName})` };
  if (r1) {
    save("05.cleaned-mutated.js", r1.code);
    const cleanMut = runModule(r1.code, "05-clean-mut");
    // pass 4.5 may rename pickName back to canonical `pickPath` — accept either
    const realAKept = /\(pickPath|\("fast", 1\)/.test(r1.code) || /pickPath\("fast", 1\)/.test(r1.code);
    const decoyDropped = !/\("slow", 1\)/.test(r1.code);
    detail +=
      `\nmutated seed=${seedName} applied=${applied} crash=${c1 ?? "none"}: exec cleaned.ok=${cleanMut.ok} err=${cleanMut.error ?? "-"}` +
      `\n  mutated entry("fast",5)=${cleanMut.ok ? JSON.stringify((() => { try { return cleanMut.exports.entry?.("fast", 5); } catch (e) { return "THREW " + e.message; } })()) : "n/a"}` +
      ` realA kept=${realAKept} decoyElse dropped=${decoyDropped}` +
      ` opaqueFalse-throw removed=${!/realOnly-never-runs/.test(r1.code)}`;
    if (c1) verdict = "CRASH";
    else if (!realAKept || !decoyDropped) verdict = "FALSE-STRIP";
    else if (cleanMut.ok && cleanMut.exports.entry?.("fast", 5) !== 65526) verdict = "SEMANTIC-DIFF";
  } else {
    detail += `\nmutated: crash=${c1 ?? "no r"}`;
  }
  record("05 opaque-if/else unwrap", verdict, detail);
}

// ================================================================
// CASE 6 — real-world-shaped file through protect+deharden
// ================================================================
{
  const src = read("src-06-realworld.js");
  const h = protect(src, { intensity: "maximum", seed: "rw-seed" });
  save("06.hardened.js", h);
  const { r, crash } = deharden(h, "06.js");
  let detail, verdict;
  if (crash) { verdict = "CRASH"; detail = crash; }
  else {
    save("06.cleaned.js", r.code);
    const plain = runModule(src, "06-plain");
    const clean = runModule(r.code, "06-clean");
    const calls = {
      scan: async (ex) => ex.scanNames("scc_foo_c1n2 and scc_bar_c9n9 end"),
      load: async (ex) => {
        const ring = new ex.KeyRing("t");
        const n = await ex.loadAll(ring, [["a", 1], ["b", 2], ["a", 3]]);
        return { n, size: ring.size, label: ring.label };
      },
      describe: async (ex) => ex.describe("x"),
      registry: async (ex) => ex.REGISTRY.length,
    };
    const rp = plain.ok ? await probe(plain.exports, calls) : { err: plain.error };
    const rc = clean.ok ? await probe(clean.exports, calls) : { err: clean.error };
    verdict = !plain.ok ? "CRASH(plain)" : diff(rp, rc) ? "SEMANTIC-DIFF" : "PASS";
    detail =
      `exec plain=${JSON.stringify(rp)}\n  cleaned=${JSON.stringify(rc)}\n` +
      `regex survived=${/scc_\\w\+_c\\d\+n\\d\+/.test(r.code)} getters survived=${/get size|get label/.test(r.code)} labeled loop survived=${/outer:/.test(r.code)}\n` +
      `residual=${JSON.stringify(r.report.residualStatements.map((s) => s.preview.slice(0, 60)))}\n` +
      `dangling=${JSON.stringify(r.report.danglingRefs)}`;
  }
  record("06 realworld-shape", verdict, detail);
  // unhardened passthrough of the same marker-laden file
  const { r: rRaw, crash: cRaw } = deharden(src, "06raw.js");
  if (rRaw) {
    save("06b.raw-cleaned.js", rRaw.code);
    const pRaw = runModule(rRaw.code, "06b");
    const rr = pRaw.ok ? await probe(pRaw.exports, { describe: async (ex) => ex.describe("x") }) : { err: pRaw.error };
    record(
      "06b raw-marker-file (unhardened)",
      cRaw ? "CRASH" : rRaw.report.hardened
        ? rRaw.code === src ? "PASS" : "FALSE-STRIP"
        : "PASS",
      `hardened=${rRaw.report.hardened} unchanged=${rRaw.code === src} removedTopLevel=${rRaw.report.removedTopLevel} foldedLiterals=${rRaw.report.foldedLiterals} foldedCond=${rRaw.report.foldedConditionals}\n` +
      `describe() on rewritten real code=${JSON.stringify(rr)} (plain=82)`,
    );
  } else {
    record("06b raw-marker-file (unhardened)", "CRASH", cRaw);
  }
}

// ================================================================
// CASE 7 — user lexical Math binding -> _blaLocalMath
// ================================================================
{
  const src = read("src-07-local-math.js");
  let h = null, herr = null;
  try {
    h = protect(src, { intensity: "balanced", seed: "math-seed" });
    save("07.hardened.js", h);
  } catch (e) {
    herr = e.message;
  }
  if (!h) {
    record("07 local-Math", "CRASH", `protect threw: ${herr}`);
  } else {
    const renamedInHardened = /_blaLocalMath\w*/.exec(h)?.[0] ?? null;
    const { r, crash } = deharden(h, "07.js");
    if (crash) {
      record("07 local-Math rename", "CRASH", crash);
    } else {
      save("07.cleaned.js", r.code);
      const stillRenamed = /_blaLocalMath\w*/.exec(r.code)?.[0] ?? null;
      const plain = runModule(src, "07-plain");
      const clean = runModule(r.code, "07-clean");
      const rp = plain.ok ? { u: plain.exports.useMath(9.7), d: plain.exports.describeMath() } : { err: plain.error };
      const rc = clean.ok ? (() => { try { return { u: clean.exports.useMath(9.7), d: clean.exports.describeMath() }; } catch (e) { return { err: e.message }; } })() : { err: clean.error };
      record(
        "07 local-Math rename",
        diff(rp, rc) ? "SEMANTIC-DIFF" : stillRenamed ? "PASS-NAME-NOT-RESTORED" : "PASS",
        `hardened rename=${renamedInHardened} cleaned still=${stillRenamed}\n` +
          `renamedBindings reported=${JSON.stringify(r.report.renamedBindings)}\n` +
          `exec plain=${JSON.stringify(rp)} cleaned=${JSON.stringify(rc)}`,
      );
    }
  }
}

// ================================================================
// CASE 8 — sourcemap comment appended
// ================================================================
{
  const src = read("src-04-tail-base.js");
  const h = protect(src, { intensity: "balanced", seed: "sm-seed" });
  const withHoney = h + "\n//# sourceMappingURL=data:application/json;base64,aG9uZXk=\n";
  const { r: r1, crash: c1 } = deharden(withHoney, "08a.js");
  if (c1) {
    record("08 sourcemap comments", "CRASH", c1);
  } else {
    save("08a.cleaned.js", r1.code);
    const honeyGone = !/sourceMappingURL/.test(r1.code);
    const midLine = h + "\nmodule.exports.midline = 1; //# sourceMappingURL=http://real.map\n";
    const { r: r2, crash: c2 } = deharden(midLine, "08b.js");
    let midSurvives = null, midExportSurvives = null;
    if (r2) {
      save("08b.cleaned.js", r2.code);
      midSurvives = /sourceMappingURL/.test(r2.code);
      midExportSurvives = /midline/.test(r2.code);
    }
    record(
      "08 sourcemap comments",
      c2 ? "CRASH" : honeyGone ? (midSurvives ? "PASS-EDGE" : "PASS") : "DECOY-SURVIVES",
      `honey trailer line stripped=${honeyGone} crash2=${c2 ?? "none"}\n` +
        `mid-line 'code; //# sourceMappingURL=' survives=${midSurvives} (real stmt kept=${midExportSurvives})`,
    );
  }
}

// ================================================================
// CASE 9 — mutable top-level const containers folded stale / crash
// ================================================================
{
  const src = read("src-09-mutable-const.js");
  const h = protect(src, { intensity: "balanced", seed: "mut-seed" });
  save("09.hardened.js", h);
  const { r, crash } = deharden(h, "09.js");
  let detail, verdict;
  if (crash) { verdict = "CRASH"; detail = crash; }
  else {
    save("09.cleaned.js", r.code);
    const plain = runModule(src, "09-plain");
    const clean = runModule(r.code, "09-clean");
    const seq = (ex) => [ex.push(1), ex.push(2), ex.bump(), JSON.stringify(ex.snapshot())];
    const rp = plain.ok ? seq(plain.exports) : `plain threw: ${plain.error}`;
    const rc = clean.ok ? (() => { try { return seq(clean.exports); } catch (e) { return "threw " + e.message; } })() : `cleaned threw: ${clean.error}`;
    verdict = diff(rp, rc) ? "SEMANTIC-DIFF" : "PASS";
    detail = `plain seq [push(1),push(2),bump(),snapshot()]=${JSON.stringify(rp)}\ncleaned seq=${JSON.stringify(rc)}\nfoldedLiterals=${r.report.foldedLiterals}`;
  }
  record("09 mutable-const fold", verdict, detail);
}

// ================================================================
// CASE 10 — corpus tampered (seed even) => opaqueTrue folds FALSE
// ================================================================
{
  const src = read("src-02-double-plain.js");
  const h = protect(src, { intensity: "balanced", seed: "tamper-seed" });
  const tampered = h.replace("Hardware-backed attestation", "Zardware-backed attestation");
  save("10.tampered.js", tampered);
  const { r, crash } = deharden(tampered, "10.js");
  let detail, verdict;
  if (crash) { verdict = "CRASH"; detail = crash; }
  else {
    save("10.cleaned.js", r.code);
    const plain = runModule(src, "10-plain");
    const clean = runModule(r.code, "10-clean");
    const calls = { seal: async (ex) => ex.sealToken("ENT-123", 7), mix: async (ex) => ex.mixKey(1, 2) };
    const rp = plain.ok ? await probe(plain.exports, calls) : { err: plain.error };
    const rc = clean.ok ? await probe(clean.exports, calls) : { err: clean.error };
    verdict = diff(rp, rc) ? "SEMANTIC-DIFF/FALSE-STRIP" : "PASS";
    detail =
      `seed=${JSON.stringify(r.report.seed)}\n` +
      `unwrappedOpaqueTrue=${r.report.unwrappedOpaqueTrue} removedOpaqueFalse=${r.report.removedOpaqueFalse}\n` +
      `exec plain=${JSON.stringify(rp)} cleaned=${JSON.stringify(rc)}`;
  }
  record("10 corpus-tampered even-seed", verdict, detail);
}

// ================================================================
// CASE 11 — seed decl shape perturbed (`|` -> `+`)
// ================================================================
{
  const src = read("src-02-double-plain.js");
  const h = protect(src, { intensity: "balanced", seed: "shape-seed" });
  // actual shape: `const <seed> = <base> | (<test> ? 1 : 0)` where test is
  // `typeof D === "function" && D(0) === N` (≤3.2.2), `D(0) === N` (3.2.4
  // bare), or `[fns].every(_f => typeof _f === "function") && D(0) === N`
  // (3.2.4 decoy entanglement) — perturb only the top `|` → `+`.
  const mutated = h.replace(/=\s*(\d+)\s*\|\s*\((?=\[|typeof|_derive)/, "= $1 + (");
  save("11.seedshape.js", mutated);
  const applied = mutated !== h;
  const { r, crash } = deharden(mutated, "11.js");
  let detail, verdict;
  if (crash) { verdict = "CRASH"; detail = crash; }
  else {
    save("11.cleaned.js", r.code);
    const clean = runModule(r.code, "11-clean");
    const plain = runModule(src, "11-plain");
    const calls = { seal: async (ex) => ex.sealToken("ENT-123", 7) };
    const rp = plain.ok ? await probe(plain.exports, calls) : { err: plain.error };
    const rc = clean.ok ? await probe(clean.exports, calls) : { err: clean.error };
    const seedNameM = mutated.match(/const\s+(\w+)\s*=\s*\d+\s*\+\s*\(/)?.[1] ?? "___none";
    const opaqueLeft = new RegExp(`Math\\.imul\\(${seedNameM}[ ^]`).test(r.code);
    const seedDeclLeft = new RegExp(`const\\s+${seedNameM}\\s*=`).test(r.code);
    verdict = !applied ? "CRASH(mutation)" : diff(rp, rc) ? "SEMANTIC-DIFF" : opaqueLeft || seedDeclLeft ? "DECOY-SURVIVES" : "PASS";
    detail =
      `applied=${applied} seedResolved=${r.report.seedResolved} seedDecl remains=${seedDeclLeft} opaque predicates remain=${opaqueLeft}\n` +
      `removedTopLevel=${r.report.removedTopLevel} foldedCond=${r.report.foldedConditionals} unwrapped=${r.report.unwrappedOpaqueTrue} removedIf=${r.report.removedOpaqueFalse}\n` +
      `exec plain=${JSON.stringify(rp)} cleaned=${JSON.stringify(rc)}`;
  }
  record("11 seed-shape-perturbed", verdict, detail);
}

// ================================================================
// SUMMARY
// ================================================================
console.log("\n==================== SUMMARY ====================");
for (const r of results) console.log(`${r.verdict.padEnd(26)} ${r.caseId}`);
