// BLADE JS de-hardener: adaptive removal of BLA's ast-shield injections.
//
// Approach (adaptive, not "more tools"):
// 1. Resolve the opaque seed bit BLA bakes into `const <seed> = <base> |
//    (typeof _deriveContainmentCorpusDigest_<tag> === "function" &&
//     _deriveContainmentCorpusDigest_<tag>(0) === <expected> ? 1 : 0)` by
//    recomputing the corpus digest — REA can't constant-fold this, we can.
// 2. Partial-evaluate to a fixpoint: folds every combinatorial string/int
//    ternary, kills `if(opaqueFalse)` decoy-call guards, and unwraps
//    `if(opaqueTrue){stmt}` wrappers — BLA's predicates are O(1) identities
//    whose truth depends only on seed parity.
// 3. Remove injected statements: top-region decls (corpus, digest, seed,
//    shadow-heap) plus the contiguous injected suffix (stepper, mirage,
//    runtime shield, tarpit, exhaustion, deception, `void [...]` index array).
//    The `void [...]` statement authoritatively enumerates injected function
//    names — we harvest it as ground truth.
// 4. Sweep function bodies for residual calls to injected names (memory-churn
//    stepper prologues).
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import _generate from "@babel/generator";
import * as t from "@babel/types";
import { makeEvaluator, computeContainmentCorpusDigest, repairCorpusDigest } from "./evaluator.mjs";
import { detectOpaqueSeedVariants } from "./recovery/precision.mjs";
import { recoverJsNames } from "./recovery/name-recovery.mjs";

const traverse = _traverse.default ?? _traverse;
const generate = _generate.default ?? _generate;

const STRONG_NAME = [
  /^obligationFlood_\w+$/,
  /^scc_\w+_c\d+n\d+$/,
  /^labyrinthDispatch_\w+$/,
  /^tokenSink_\w+$/,
  /^cdpShapeBudgetGuard_\w+$/,
  /^fridaRealmRing_\w+$/,
  /^fridaCaptureSaturator_\w+$/,
  /^regexSearchMagnet_\w+$/,
  /^grpcServiceMirage_\w+$/,
  /^canaryCredentialHoneypot_\w+$/,
  /^systemDiagnosticLog_\w+$/,
  /^crashSignalHandler_\w+$/,
  /^diffFrontier_\w+_\d+$/,
  /^aliasedBufferIllusion_\w+_\d+$/,
  /^readSplitShare_\w+$/,
  /^stepShadowHeap\w*_\w+$/,
  /^probeCanaryHoneypot_\w+$/,
  /^collectEnvironmentDiagnostics_\w+$/,
  /^verifyShamirEd25519LicenseQuorum_\w+$/,
  /^computeEnterpriseSettlementLedger_\w+$/,
  /^decodeRatchetWireFrame_\w+$/,
  /^validateTpm2Pcr0Quote_\w+$/,
  /^(verifyEnterpriseMasterLicense|decryptOfflineVaultPayload|computeStripeWebhookSignature|validateHardwareDongleResponse|deriveMasterEncryptionKey|checkSubscriptionEntitlementTier|authenticateZeroTrustSession|unlockPremiumFeatureFlags)_\w+$/,
  /^registerDecoyIpcAndRoute\w*_\w+$/,
  /^_interlockSafetyCorpus_\w+$/,
  /^_deriveContainmentCorpusDigest_\w+$/,
  /^_DISTRIBUTED_ASL3_\w+$/,
  /^_SELF_SEAL_TARGET\w*$/,
];
const GENERIC_SUFFIX_NAME = /^[_$a-zA-Z][\w$]*_[0-9a-f]{3,4}$/;
// 3.2.4: the shadow-vault object lost its honest labels — classification/
// securityBoundary strings became protocolVersion/attestationState/transport.
const RUNTIME_MARKERS = /_shadowVault_|decorative-deception-signal|__REA_CDP_GUARD|Frida-Interlock|frida-attestation|RING0_SEALED|AF_VSOCK_RING0|HARDWARE_ENCLAVE_DELEGATED|attestationState/;

// Blank out comments, string/template literals and regex literals so marker
// detection only sees code positions (identifiers, keywords). Marker-shaped
// text inside a real file's literals must not flip the hardened gate.
function maskJsLiterals(src) {
  const out = src.split("");
  const blank = (a, b) => { for (let k = a; k < b && k < src.length; k++) if (out[k] !== "\n") out[k] = " "; };
  const REGEX_PREV = new Set(["(", "[", "{", ",", "=", ":", ";", "!", "&", "|", "?", "+", "-", "*", "%", "~", "^", "<", ">", "\n"]);
  const REGEX_WORDS = /^(return|typeof|case|in|of|new|delete|void|throw|else|do|instanceof|yield|await)$/;
  let prevCh = "", prevWord = "";
  for (let i = 0; i < src.length;) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "/") {
      const e = src.indexOf("\n", i);
      const end = e < 0 ? src.length : e;
      blank(i, end); i = end; continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      const e = src.indexOf("*/", i + 2);
      const end = e < 0 ? src.length : e + 2;
      blank(i, end); i = end; continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      let j = i + 1;
      while (j < src.length && src[j] !== c) { if (src[j] === "\\") j += 2; else if (c === "`" && src[j] === "$" && src[j + 1] === "{") { /* keep scanning: ${} content is expression code, but treating it as literal is the safe direction for a marker gate */ } j++; }
      const end = Math.min(j + 1, src.length);
      blank(i, end); i = end; continue;
    }
    if (c === "/" && (REGEX_PREV.has(prevCh) || REGEX_WORDS.test(prevWord)) && src[i + 1] !== "=") {
      // probable regex literal — scan to closing / outside a char class
      let j = i + 1, inClass = false;
      while (j < src.length) {
        const d = src[j];
        if (d === "\\") j += 2;
        else if (d === "[") { inClass = true; j++; }
        else if (d === "]") { inClass = false; j++; }
        else if (d === "/" && !inClass) break;
        else if (d === "\n") break;
        else j++;
      }
      if (src[j] === "/") {
        const end = j + 1;
        blank(i, end); i = end; continue;
      }
    }
    if (/[\w$]/.test(c)) {
      let j = i; while (j < src.length && /[\w$]/.test(src[j])) j++;
      prevWord = src.slice(i, j); prevCh = src[j - 1]; i = j; continue;
    }
    if (!/\s/.test(c)) { prevCh = c; prevWord = ""; }
    i++;
  }
  return out.join("");
}

/**
 * Structural gate: true only when MULTIPLE injected families co-occur in
 * code positions (containment corpus + seed decl + suffix machinery +
 * trailing `void [...]` anchor). Marker-shaped text inside literals,
 * regexes and comments does not count — real scanner tools and docs must
 * not be dehardened.
 * @param {string} source
 * @returns {boolean}
 */
export function looksBlaHardened(source) {
  // Structural gate: a real hardened file always carries MULTIPLE injected
  // families — the containment corpus/seed decl plus suffix machinery plus a
  // trailing `void [...]` anchor — in CODE positions. Marker-shaped text in
  // literals/regexes/comments (real scanner tools, docs, tests) must not
  // flip the gate.
  const masked = maskJsLiterals(source);
  let hits = 0;
  if (/_interlockSafetyCorpus_|_deriveContainmentCorpusDigest_/.test(masked)) hits++;
  if (/obligationFlood_|scc_\w+_c\d+n\d+|labyrinthDispatch_/.test(masked)) hits++;
  if (/decorative-deception-signal|_shadowVault_|state_diff_frontier_|attestationState|enclaveCid/.test(masked)) hits++;
  if (/readSplitShare_[0-9a-f]{4}|stepShadowHeap\w*_\w{3,4}\s*\(/.test(masked)) hits++;
  if (/\bvoid\s*\[/.test(masked)) hits++;
  if (hits >= 2) return true;
  // single-family fallback: corpus digest + opaque-seed decl is unambiguous
  return /_interlockSafetyCorpus_/.test(masked) && /\|\s*\([^)]*\?\s*1\s*:\s*0\)/.test(masked);
}

function stmtDeclaredNames(stmt, out = []) {
  if (stmt.type === "FunctionDeclaration" || stmt.type === "ClassDeclaration") {
    if (stmt.id) out.push(stmt.id.name);
  } else if (stmt.type === "VariableDeclaration") {
    for (const d of stmt.declarations) collectIds(d.id, out);
  } else if (stmt.type === "ExportNamedDeclaration" || stmt.type === "ExportDefaultDeclaration") {
    if (stmt.declaration) stmtDeclaredNames(stmt.declaration, out);
  }
  return out;
}
function collectIds(pat, out) {
  if (!pat) return;
  switch (pat.type) {
    case "Identifier": out.push(pat.name); return;
    case "ObjectPattern": for (const p of pat.properties) collectIds(p.type === "RestElement" ? p.argument : p.value, out); return;
    case "ArrayPattern": for (const e of pat.elements) collectIds(e, out); return;
    case "RestElement": collectIds(pat.argument, out); return;
    case "AssignmentPattern": collectIds(pat.left, out); return;
    default: return;
  }
}

// Cheap recursive identifier collector — approximates referenced identifiers.
// Skips member property keys and declaration ids. Does NOT descend into
// nested function bodies: a statement's own references must not be tainted by
// an unswept injected call sitting inside a callback it carries (e.g.
// `ipcMain.handle(ch, async () => { stepper(3); realWork() })` — the outer
// call is real code; only the prologue inside the arrow is injected).
function collectRefs(node, refs = new Set()) {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) { for (const n of node) collectRefs(n, refs); return; }
  if (typeof node.type === "string") {
    switch (node.type) {
      case "Identifier":
        refs.add(node.name);
        return;
      case "MemberExpression":
      case "OptionalMemberExpression":
        collectRefs(node.object, refs);
        if (node.computed) collectRefs(node.property, refs);
        return;
      case "ObjectProperty":
        if (node.computed) collectRefs(node.key, refs);
        collectRefs(node.value, refs);
        return;
      case "FunctionExpression":
      case "ArrowFunctionExpression":
      case "FunctionDeclaration":
      case "ObjectMethod":
      case "ClassMethod":
      case "ClassPrivateMethod":
      case "ClassDeclaration":
        // nested scopes are analyzed as their own statements
        return;
      case "VariableDeclarator":
        collectRefs(node.init, refs);
        return;
      default: break;
    }
    for (const key of Object.keys(node)) {
      if (key === "type" || key === "loc" || key === "start" || key === "end" ||
          key === "leadingComments" || key === "trailingComments" || key === "innerComments" ||
          key === "extra" || key === "id") continue;
      collectRefs(node[key], refs);
    }
  }
  return;
}

// Generic recursive AST walk (no scope, no traversal state) — shape checks only.
function walkJsNodes(node, cb) {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) { for (const n of node) walkJsNodes(n, cb); return; }
  if (typeof node.type !== "string") return;
  cb(node);
  for (const k of Object.keys(node)) {
    if (k === "type" || k === "loc" || k === "start" || k === "end" ||
        k === "leadingComments" || k === "trailingComments" || k === "innerComments" ||
        k === "extra") continue;
    walkJsNodes(node[k], cb);
  }
}
const unparen = (n) => { while (n && n.type === "ParenthesizedExpression") n = n.expression; return n; };

// ---- BLA 3.2.4 ASAR main-JS sidecar preamble ----
// `(function(){ var __expected="<64-hex>"; var __blaAsarSidecarDigest=0;
//   try { require crypto/fs/path; hash entryLabel + sidecar reads; compare or
//   soft-fold } catch {...} return __blaAsarSidecarDigest; })();`
// Strip only when the marker binding or BOTH shape cues are present — a plain
// user IIFE that hashes files stays.
function isAsarSidecarPreamble(stmt) {
  if (stmt.type !== "ExpressionStatement") return false;
  const e = unparen(stmt.expression);
  if (e?.type !== "CallExpression") return false;
  const callee = unparen(e.callee);
  if (!callee || (callee.type !== "FunctionExpression" && callee.type !== "ArrowFunctionExpression")) return false;
  let marker = false, mismatch = false, createHash = false, readFileSync = false;
  walkJsNodes(callee.body, (n) => {
    if (n.type === "Identifier" && /^__bla\w*SidecarDigest$/.test(n.name)) marker = true;
    else if (n.type === "StringLiteral" && n.value === "integrity binding mismatch") mismatch = true;
    else if (n.type === "Identifier" && (n.name === "createHash" || n.name === "readFileSync")) {
      if (n.name === "createHash") createHash = true; else readFileSync = true;
    } else if (n.type === "MemberExpression" && !n.computed && n.property.type === "Identifier") {
      if (n.property.name === "createHash") createHash = true;
      if (n.property.name === "readFileSync") readFileSync = true;
    }
  });
  return marker || (mismatch && createHash && readFileSync);
}

// ---- BLA self-seal measure function ----
// `function <measureIntegrityXyz_ab12>() { var digest=0; try {
//   var _c=require("node:crypto"); var _fs=require("node:fs"); var _path=require("node:path");
//   var h=_c.createHash("sha256"); var selfPath=(typeof __filename==="string"?__filename:null);
//   ... _fs.readFileSync(selfPath) ... ["integrity check failed" rethrow / hard-fail]
//   ... optional selfExpected 64-hex canonicalization ...
//   digest=parseInt(hex.slice(0,8),16)>>>0; } catch { ... } return digest>>>0; }`
// Unambiguous only when require(crypto) + readFileSync + the "integrity check
// failed" literal + a self-measure cue co-occur inside one function body.
function isSelfSealMeasureFn(stmt) {
  if (stmt.type !== "FunctionDeclaration" || !stmt.id || !stmt.body) return false;
  let reqCrypto = false, readFileSync = false, icf = false, selfCue = false;
  walkJsNodes(stmt.body, (n) => {
    switch (n.type) {
      case "CallExpression":
        if (n.callee.type === "Identifier" && n.callee.name === "require" &&
            n.arguments.length === 1 && n.arguments[0].type === "StringLiteral" &&
            /^(?:node:)?crypto$/.test(n.arguments[0].value)) reqCrypto = true;
        if (n.callee.type === "Identifier" && n.callee.name === "readFileSync") readFileSync = true;
        if (n.callee.type === "MemberExpression" && !n.callee.computed &&
            n.callee.property.type === "Identifier" && n.callee.property.name === "readFileSync") readFileSync = true;
        return;
      case "StringLiteral":
        if (n.value === "integrity check failed") icf = true;
        else if (/^[0-9a-f]{64}$/.test(n.value)) selfCue = true;
        return;
      case "RegExpLiteral":
        if (/\{64\}/.test(n.pattern) && /0-9a-f/i.test(n.pattern)) selfCue = true;
        return;
      case "Identifier":
        // fixed (non-PRNG'd) locals in emitMeasureFunction
        if (/^self(?:Path|Buf|Expected|Digest|Hex)$/.test(n.name)) selfCue = true;
        return;
      default: return;
    }
  });
  return reqCrypto && readFileSync && icf && selfCue;
}

// Collect CallExpression callee Identifier names inside an expression.
function callCalleeNames(node, out = []) {
  walkJsNodes(node, (n) => {
    if (n.type === "CallExpression" && n.callee.type === "Identifier") out.push(n.callee.name);
  });
  return out;
}

// ---- Seed-decl digest check ----
// The opaque seed ternary test is `D(0) === N`, emitted bare (3.2.4 default),
// wrapped `[fns].every(_f => typeof _f === "function") && (D(0) === N)`
// (decoy entanglement), or `typeof D === "function" && D(0) === N` (older).
// Find the === comparison with a call-on-identifier on either side, wherever
// it sits inside the test tree.
function findSeedDigestCheck(test, ev0, depth = 0) {
  if (!test || depth > 8) return null;
  const t0 = unparen(test);
  if (t0.type === "BinaryExpression" && (t0.operator === "===" || t0.operator === "==")) {
    for (const [callSide, litSide] of [[t0.left, t0.right], [t0.right, t0.left]]) {
      const c = unparen(callSide);
      if (c?.type === "CallExpression" && c.callee?.type === "Identifier") {
        const expected = ev0(litSide);
        if (expected.known) return { name: c.callee.name, expected: expected.value };
      }
    }
    return null;
  }
  if (t0.type === "LogicalExpression") {
    return findSeedDigestCheck(t0.left, ev0, depth + 1) ?? findSeedDigestCheck(t0.right, ev0, depth + 1);
  }
  return null;
}

// ---- encryptStrings runtime stub ----
// Both emitted variants share one skeleton:
//   var T=[<num-array>, ...]            ("csv".split(",").map(Number) rows, or literal arrays)
//   var K=<num-array>
//   function F(i){ var e=T[i],k=K,kl=k.length,o=new Uint8Array(e.length);
//     for(var j=0;j<e.length;j++){ var kb=...,ks=...; o[j]=<xor-expr>&255; }
//     return Buffer/TextDecoder/fromCharCode decode; }
//   var _blaS=F;var _blaT=T;
// Old loop: o[j]=(e[j]^k[j%k.length])&255
// New (3.2.4): kb/ks derive — o[j]=(e[j]^(kb^((ks+i*73+j*19)&255)))&255
// We don't hardcode the formula: the emitted RHS is pure arithmetic over
// {i,j,e,k,kl,kb,ks}, so we evaluate it per index with those names bound.
function numArrayInit(init) {
  if (!init) return null;
  if (init.type === "ArrayExpression") {
    const out = [];
    for (const el of init.elements) {
      if (el?.type !== "NumericLiteral" || !Number.isFinite(el.value)) return null;
      out.push(el.value);
    }
    return out;
  }
  // "<csv>".split(",").map(Number)
  if (init.type === "CallExpression" && init.arguments.length === 1 &&
      init.callee.type === "MemberExpression" && !init.callee.computed &&
      init.callee.property.type === "Identifier" && init.callee.property.name === "map" &&
      init.arguments[0].type === "Identifier" && init.arguments[0].name === "Number") {
    const inner = init.callee.object;
    if (inner?.type === "CallExpression" && inner.arguments.length === 1 &&
        inner.callee.type === "MemberExpression" && !inner.callee.computed &&
        inner.callee.property.type === "Identifier" && inner.callee.property.name === "split" &&
        inner.arguments[0].type === "StringLiteral" && inner.callee.object.type === "StringLiteral") {
      const sep = inner.arguments[0].value;
      const raw = inner.callee.object.value;
      if (raw === "") return [];
      const out = raw.split(sep).map((p) => Number(p));
      if (out.every((n) => Number.isFinite(n))) return out;
    }
  }
  return null;
}
function numTableInit(init) {
  if (init?.type !== "ArrayExpression" || init.elements.length === 0) return null;
  const rows = [];
  for (const el of init.elements) {
    const r = numArrayInit(el);
    if (!r) return null;
    rows.push(r);
  }
  return rows;
}

/**
 * De-harden BLA-protected JavaScript: parse to AST, resolve the opaque
 * seed, drop the injected declaration families (containment corpus,
 * suffix machinery, encryptStrings stubs, self-seal measure/binds,
 * ASAR/sidecar preamble IIFEs, honey regions), fold decoy expressions,
 * then recover readable local names. Re-emits runnable code plus a
 * report; unhardened input returns verbatim with hardened=false.
 * @param {string} source
 * @param {{ filename?: string }} [opts]
 * @returns {{ code: string, report: object }}
 */
export function dehardenJs(source, { filename = "input.js" } = {}) {
  const report = {
    filename,
    hardened: looksBlaHardened(source),
    seed: null,
    seedResolved: false,
    foldedConditionals: 0,
    foldedLiterals: 0,
    unwrappedOpaqueTrue: 0,
    removedOpaqueFalse: 0,
    removedTopLevel: 0,
    injectedFunctionsRemoved: 0,
    prologueCallsRemoved: 0,
    asarPreambleRemoved: 0,
    selfSealFunctionsRemoved: 0,
    selfSealBindingsRemoved: 0,
    decryptedStrings: 0,
    renamedBindings: [],
    residualStatements: [],
    recoveredStrings: new Set(),
    removedNameSamples: [],
    danglingRefs: [],
    exportSurface: [],
    bytesIn: source.length,
    bytesOut: 0,
  };
  // Emission-shape prefilters: BLA transforms that carry no corpus/seed markers
  // (self-seal snippet, ASAR sidecar preamble, encrypt-strings stub) still
  // deserve the AST passes — parse when their unambiguous literal surface is
  // present even if the structural gate stays false.
  const mayPreamble = source.includes("__blaAsarSidecarDigest") || source.includes("integrity binding mismatch");
  const maySelfSeal = source.includes("integrity check failed") && source.includes("readFileSync");
  const mayStringStub = source.includes("Uint8Array") &&
    (source.includes(".map(Number)") || source.includes("Buffer.from") || source.includes("TextDecoder"));
  if (!report.hardened && !mayPreamble && !maySelfSeal && !mayStringStub) return { code: source, report };

  const ast = parse(source, {
    sourceType: "unambiguous",
    plugins: ["typescript", "jsx", "topLevelAwait"],
    allowReturnOutsideFunction: true,
    errorRecovery: true,
  });
  const body = ast.program.body;
  const eval0 = makeEvaluator(new Map());
  const ev0 = eval0.ev;

  // ---- Pass -1: BLA-emission shape passes (pre-classification, so removed
  // statements never reach the boundary logic). Shape-verified only — names
  // are PRNG'd and never used for matching.
  const preRemove = new Set();       // whole statements to drop
  const preInjectedNames = new Set();// names to treat as injected downstream
  let preChanged = false;
  const finishEarly = () => {
    // Non-hardened path: return the original source when nothing verified.
    if (!preChanged && report.decryptedStrings === 0) return { code: source, report };
    let code = generate(ast, { comments: true, compact: false }).code;
    code = code
      .split("\n")
      .filter((l) => !/^\s*\/\/#?\s*sourceMappingURL=/.test(l))
      .join("\n");
    report.bytesOut = code.length;
    report.recoveredStrings = [...report.recoveredStrings].sort();
    return { code, report };
  };

  // (a) ASAR main-JS sidecar preamble IIFE (strip⇒fail binding check)
  for (const stmt of body) {
    if (isAsarSidecarPreamble(stmt)) {
      preRemove.add(stmt);
      report.asarPreambleRemoved++;
    }
  }

  // (b) self-seal measure functions + their XOR-fold binding declarations
  const sealFns = new Set();
  for (const stmt of body) {
    if (!preRemove.has(stmt) && isSelfSealMeasureFn(stmt)) {
      sealFns.add(stmt.id.name);
      preRemove.add(stmt);
      report.selfSealFunctionsRemoved++;
    }
  }
  const sealBindings = []; // {name, index} for restore-if-referenced
  if (sealFns.size > 0) {
    body.forEach((stmt, idx) => {
      if (stmt.type !== "VariableDeclaration" || preRemove.has(stmt)) return;
      const keptDecls = stmt.declarations.filter((d) => {
        if (d.id?.type !== "Identifier" || !d.init) return true;
        const callees = callCalleeNames(d.init);
        // `var <b> = h1();` / `var <b> = (h1() ^ h2() ^ ...) >>> 0;`
        if (callees.length > 0 && callees.every((n) => sealFns.has(n))) {
          sealBindings.push({ name: d.id.name, index: idx });
          report.selfSealBindingsRemoved++;
          preChanged = true;
          return false;
        }
        return true;
      });
      if (keptDecls.length !== stmt.declarations.length) {
        stmt.declarations = keptDecls;
        if (keptDecls.length === 0) preRemove.add(stmt);
      }
    });
    for (const n of sealFns) preInjectedNames.add(n);
  }

  // (c) encryptStrings stub: verify shape, decode F(<literal>) call sites with
  // the emitted expression evaluated faithfully, then drop T/K/F + _blaS/_blaT
  // alias decls. Any call site that fails to decode keeps the whole stub.
  const arraysByName = new Map(); // name -> {kind:"mask"|"table", values, stmt}
  for (const stmt of body) {
    if (stmt.type !== "VariableDeclaration" || preRemove.has(stmt)) continue;
    for (const d of stmt.declarations) {
      if (d.id?.type !== "Identifier" || !d.init) continue;
      const table = numTableInit(d.init);
      if (table && table.every((r) => r.length > 0)) {
        arraysByName.set(d.id.name, { kind: "table", values: table });
        continue;
      }
      const mask = numArrayInit(d.init);
      if (mask && mask.length > 0) arraysByName.set(d.id.name, { kind: "mask", values: mask });
    }
  }
  const matchDecryptStubFn = (stmt) => {
    if (stmt.type !== "FunctionDeclaration" || !stmt.id || !stmt.body?.body) return null;
    if (stmt.params.length !== 1 || stmt.params[0].type !== "Identifier") return null;
    const param = stmt.params[0].name;
    let forStmt = null, ret = null;
    const topDecls = [];
    for (const s of stmt.body.body) {
      if (s.type === "VariableDeclaration") topDecls.push(...s.declarations);
      else if (s.type === "ForStatement" && !forStmt) forStmt = s;
      else if (s.type === "ReturnStatement" && !ret) ret = s;
      else return null;
    }
    if (!forStmt || !ret || topDecls.length === 0) return null;
    const retSrc = safeGen(ret.argument);
    if (!/Buffer\.from|TextDecoder|fromCharCode/.test(retSrc)) return null;
    let eName = null, tableName = null, keyName = null, outName = null;
    for (const d of topDecls) {
      if (d.id?.type !== "Identifier" || !d.init) continue;
      if (!eName && d.init.type === "MemberExpression" && d.init.computed &&
          d.init.object.type === "Identifier" && arraysByName.get(d.init.object.name)?.kind === "table" &&
          d.init.property.type === "Identifier" && d.init.property.name === param) {
        eName = d.id.name; tableName = d.init.object.name; continue;
      }
      if (!keyName && d.init.type === "Identifier" && arraysByName.get(d.init.name)?.kind === "mask") {
        keyName = d.init.name; continue;
      }
      if (!outName && d.init.type === "NewExpression" &&
          d.init.callee.type === "Identifier" && d.init.callee.name === "Uint8Array") {
        outName = d.id.name; continue;
      }
    }
    if (!eName || !tableName || !keyName || !outName) return null;
    const assigns = [];
    walkJsNodes(forStmt.body, (n) => {
      if (n.type === "AssignmentExpression" && n.operator === "=" &&
          n.left.type === "MemberExpression" && n.left.computed &&
          n.left.object.type === "Identifier" && n.left.object.name === outName) assigns.push(n);
    });
    if (assigns.length !== 1) return null;
    const loopDecls = [];
    for (const s of (forStmt.body.type === "BlockStatement" ? forStmt.body.body : [forStmt.body])) {
      if (s.type === "VariableDeclaration") loopDecls.push(...s.declarations);
    }
    const retKind = /fromCharCode/.test(retSrc) && !/Buffer\.from|TextDecoder/.test(retSrc) ? "latin1" : "utf8";
    return { fnName: stmt.id.name, stmt, param, eName, tableName, keyName, outName,
             topDecls, loopDecls, assign: assigns[0], forStmt, retKind, decoded: 0, failed: false };
  };
  const stubForRange = (forStmt, env) => {
    const init = forStmt.init;
    if (init?.type !== "VariableDeclaration" || init.declarations.length !== 1) return null;
    const vd = init.declarations[0];
    if (vd.id?.type !== "Identifier") return null;
    const varName = vd.id.name;
    const start = makeEvaluator(env).ev(vd.init);
    if (!start.known || typeof start.value !== "number") return null;
    const test = forStmt.test;
    if (test?.type !== "BinaryExpression" || (test.operator !== "<" && test.operator !== "<=")) return null;
    if (test.left.type !== "Identifier" || test.left.name !== varName) return null;
    const bEnv = new Map(env); bEnv.set(varName, start.value);
    const bound = makeEvaluator(bEnv).ev(test.right);
    if (!bound.known || typeof bound.value !== "number") return null;
    const end = test.operator === "<" ? bound.value : bound.value + 1;
    const upd = forStmt.update;
    let step = null;
    if (upd?.type === "UpdateExpression" && upd.argument.type === "Identifier" && upd.argument.name === varName) {
      step = upd.operator === "++" ? 1 : upd.operator === "--" ? -1 : null;
    } else if (upd?.type === "AssignmentExpression" && upd.left.type === "Identifier" && upd.left.name === varName) {
      if (upd.operator === "+=" || upd.operator === "-=") {
        const r = makeEvaluator(env).ev(upd.right);
        if (r.known && typeof r.value === "number") step = upd.operator === "+=" ? r.value : -r.value;
      } else if (upd.operator === "=" && upd.right.type === "BinaryExpression" &&
                 (upd.right.operator === "+" || upd.right.operator === "-") &&
                 upd.right.left.type === "Identifier" && upd.right.left.name === varName) {
        const r = makeEvaluator(env).ev(upd.right.right);
        if (r.known && typeof r.value === "number") step = upd.right.operator === "+" ? r.value : -r.value;
      }
    }
    if (!step) return null;
    return { varName, start: start.value, end, step };
  };
  const decodeStubIndex = (info, idx) => {
    try {
      const env = new Map([[info.param, idx]]);
      env.set(info.tableName, arraysByName.get(info.tableName).values);
      env.set(info.keyName, arraysByName.get(info.keyName).values);
      let row = null;
      for (const d of info.topDecls) {
        if (d.id.type !== "Identifier") return null;
        if (!d.init) { env.set(d.id.name, undefined); continue; }
        if (d.init.type === "NewExpression") { env.set(d.id.name, new Uint8Array(0)); continue; }
        const r = makeEvaluator(env).ev(d.init);
        if (!r.known) return null;
        env.set(d.id.name, r.value);
        if (d.id.name === info.eName) row = r.value;
      }
      if (!Array.isArray(row)) return null;
      const range = stubForRange(info.forStmt, env);
      if (!range || Math.abs(range.end - range.start) > 1e6) return null;
      const out = new Array(row.length).fill(0);
      for (let j = range.start; range.step > 0 ? j < range.end : j > range.end; j += range.step) {
        const jenv = new Map(env); jenv.set(range.varName, j);
        const jev = makeEvaluator(jenv).ev;
        for (const d of info.loopDecls) {
          if (d.id.type !== "Identifier" || !d.init) return null;
          const r = jev(d.init);
          if (!r.known) return null;
          jenv.set(d.id.name, r.value);
        }
        const li = jev(info.assign.left.property);
        const rv = jev(info.assign.right);
        if (!li.known || !rv.known || typeof rv.value !== "number" || !Number.isInteger(li.value)) return null;
        if (li.value >= 0 && li.value < out.length) out[li.value] = rv.value & 0xff;
      }
      const bytes = Uint8Array.from(out);
      return info.retKind === "utf8" ? Buffer.from(bytes).toString("utf8") : String.fromCharCode(...bytes);
    } catch { return null; }
  };
  if (arraysByName.size > 0) {
    const stubs = new Map();
    for (const stmt of body) {
      if (preRemove.has(stmt)) continue;
      const info = matchDecryptStubFn(stmt);
      if (info) stubs.set(info.fnName, info);
    }
    if (stubs.size > 0) {
      // `_blaS`/`_blaT`-style aliases: `var X = <stubName>` also accept calls
      const callTarget = new Map([...stubs.keys()].map((n) => [n, stubs.get(n)]));
      for (const stmt of body) {
        if (stmt.type !== "VariableDeclaration" || preRemove.has(stmt)) continue;
        for (const d of stmt.declarations) {
          if (d.id?.type === "Identifier" && d.init?.type === "Identifier" && callTarget.has(d.init.name)) {
            callTarget.set(d.id.name, callTarget.get(d.init.name));
            (stubs.get(d.init.name).aliases ??= new Set()).add(d.id.name);
          }
        }
      }
      traverse(ast, {
        CallExpression(path) {
          const c = path.node.callee;
          if (c.type !== "Identifier" || !callTarget.has(c.name)) return;
          const info = callTarget.get(c.name);
          const arg = path.node.arguments.length === 1 ? path.node.arguments[0] : null;
          const decoded = arg?.type === "NumericLiteral" && Number.isInteger(arg.value)
            ? decodeStubIndex(info, arg.value) : null;
          if (decoded === null) { info.failed = true; return; }
          path.replaceWith(t.stringLiteral(decoded));
          info.decoded++;
          report.decryptedStrings++;
          preChanged = true;
        },
      });
      const dead = [...stubs.values()].filter((i) => !i.failed);
      if (dead.length > 0) {
        const deadNames = new Set();
        for (const i of dead) {
          deadNames.add(i.fnName); deadNames.add(i.tableName); deadNames.add(i.keyName);
          for (const a of i.aliases ?? []) deadNames.add(a);
          preRemove.add(i.stmt);
          preChanged = true;
        }
        // Fixpoint: also drop `var X = <deadName>` alias declarators (the stub's
        // `var _blaS=F;var _blaT=T;` markers) — a kept alias would dangle once
        // its target is gone.
        let pruned = true;
        while (pruned) {
          pruned = false;
          for (const stmt of body) {
            if (stmt.type !== "VariableDeclaration" || preRemove.has(stmt)) continue;
            const keptDecls = stmt.declarations.filter((d) => {
              if (d.id?.type !== "Identifier") return true;
              const dead = deadNames.has(d.id.name) ||
                (d.init?.type === "Identifier" && deadNames.has(d.init.name));
              if (dead) deadNames.add(d.id.name);
              return !dead;
            });
            if (keptDecls.length !== stmt.declarations.length) {
              stmt.declarations = keptDecls;
              preChanged = true; pruned = true;
              if (keptDecls.length === 0) preRemove.add(stmt);
            }
          }
        }
        for (const n of deadNames) preInjectedNames.add(n);
      }
    }
  }

  // apply the pre-pass removals, then rebind self-seal bindings still referenced
  // as `var <b> = 0;` — BLA's own soft-skip (digest=0) semantics when a fold
  // site in surviving code still reads it.
  if (preRemove.size > 0) {
    for (let i = body.length - 1; i >= 0; i--) {
      if (preRemove.has(body[i])) { body.splice(i, 1); preChanged = true; }
    }
    for (const b of sealBindings) {
      const refs = new Set();
      for (const s of body) walkJsNodes(s, (n) => { if (n.type === "Identifier") refs.add(n.name); });
      if (refs.has(b.name)) {
        body.splice(Math.min(b.index, body.length), 0,
          t.variableDeclaration("var", [t.variableDeclarator(t.identifier(b.name), t.numericLiteral(0))]));
        preInjectedNames.add(b.name);
        preChanged = true;
      }
    }
  }

  if (!report.hardened) return finishEarly();

  // ---- Pass 0: harvest injected-name ground truth from `void [...]`/`void x`
  // Collect candidate anchor names now; only promote them to injectedNames
  // once a corpus/seed is found in Pass 1 — a marker-comment trap file with
  // a plain `void [a, b]` must not mark real names for deletion.
  const injectedNames = new Set(preInjectedNames);
  const voidNames = new Set();
  for (const stmt of body) {
    if (stmt.type !== "ExpressionStatement") continue;
    const e = stmt.expression;
    if (e.type === "UnaryExpression" && e.operator === "void") {
      const arg = e.argument;
      if (arg.type === "ArrayExpression") {
        for (const el of arg.elements) if (el && el.type === "Identifier") voidNames.add(el.name);
      } else if (arg.type === "Identifier") {
        if (STRONG_NAME.some((re) => re.test(arg.name)) || GENERIC_SUFFIX_NAME.test(arg.name)) {
          voidNames.add(arg.name);
        }
      }
    }
  }

  // ---- Pass 1: seed discovery (corpus + digest + seed decl)
  let corpusEntries = null;
  let seedDeclIndex = -1;
  for (const stmt of body) {
    if (stmt.type !== "VariableDeclaration") continue;
    for (const d of stmt.declarations) {
      if (d.id && d.id.type === "Identifier" && /^_interlockSafetyCorpus_\w+$/.test(d.id.name)) {
        const r = ev0(d.init);
        if (r.known && Array.isArray(r.value)) corpusEntries = r.value;
      }
    }
  }
  let seedName = null, seedValue = null, seedExpected = null;
  const digestRe = /^_deriveContainmentCorpusDigest_\w+$/;
  for (let i = 0; i < body.length; i++) {
    const stmt = body[i];
    if (stmt.type !== "VariableDeclaration") continue;
    for (const d of stmt.declarations) {
      if (d.id?.type !== "Identifier" || d.init?.type !== "BinaryExpression" ||
          (d.init.operator !== "|" && d.init.operator !== "+")) continue;
      const rhs = d.init.right;
      if (rhs.type !== "ConditionalExpression") continue;
      // test: bare `D(0) === N` (3.2.4 default), `[fns].every(...) && (D(0) === N)`
      // (decoy entanglement), or `typeof D === "function" && D(0) === N` (old).
      const check = findSeedDigestCheck(rhs.test, ev0);
      if (check && digestRe.test(check.name)) {
        seedName = d.id.name;
        seedExpected = check.expected;
        const base = ev0(d.init.left);
        if (d.init.operator === "+") report.seedShapePerturbed = true;
        let bit0 = corpusEntries && computeContainmentCorpusDigest(corpusEntries, 0) === seedExpected ? 1 : 0;
        // corpus tampered? The expected digest is a checksum oracle — the
        // rolling hash is invertible, so a single-char edit is repairable
        // in memory and the intended seed semantics restored.
        if (corpusEntries && bit0 === 0) {
          const fix = repairCorpusDigest(corpusEntries, seedExpected);
          if (fix) {
            corpusEntries[fix.entry][fix.field] = fix.newText;
            bit0 = 1;
            report.corpusRepaired = fix;
          } else {
            report.corpusTampered = true;
          }
        }
        seedValue = base.known ? (base.value | bit0) | 0 : bit0;
        seedDeclIndex = i;
        report.seedResolved = true;
      }
    }
  }
  report.seed = seedName ? { name: seedName, value: seedValue, parity: seedValue & 1, expectedDigest: seedExpected, intact: corpusEntries ? seedValue === (seedValue | 1) : null } : null;
  // shape-evolved seed variants: when the exact-shape match found nothing
  // but the file is otherwise hardened, surface heuristic candidates so a
  // future BLA shape change degrades loudly instead of silently.
  if (!seedName && looksBlaHardened(source)) {
    const cands = detectOpaqueSeedVariants(source);
    if (cands.length > 0) report.seedCandidates = cands;
  }

  if (seedName) injectedNames.add(seedName);
  // promote void-anchor names only with corpus/seed evidence of real
  // hardening — otherwise they're ordinary `void` statements.
  if (seedName || corpusEntries) for (const n of voidNames) injectedNames.add(n);

  // ---- Pass 2: fixpoint fold (seed + literal consts bound).
  // Runs BEFORE statement classification: real statements are full of seed
  // references inside opaque predicates until folded, which would make them
  // look injected to the reference-based rules below.
  const constValues = new Map();
  if (seedName && seedValue !== null) constValues.set(seedName, seedValue);
  const seedEval = makeEvaluator(constValues);
  for (const stmt of ast.program.body) {
    if (stmt.type !== "VariableDeclaration" || stmt.kind !== "const") continue;
    for (const d of stmt.declarations) {
      if (d.id?.type !== "Identifier" || injectedNames.has(d.id.name)) continue;
      const r = seedEval.ev(d.init);
      // primitives only — binding arrays/objects snapshots a mutable value
      // and folds stale reads (CONFIG.level, QUEUE.length) to decl-time state.
      if (r.known && (r.value === null || ["string", "number", "boolean"].includes(typeof r.value))) {
        constValues.set(d.id.name, r.value);
      }
    }
  }
  const evaluator = makeEvaluator(constValues);
  const ev = evaluator.ev;
  const LITERAL_TYPES = new Set(["NumericLiteral", "StringLiteral", "BooleanLiteral", "NullLiteral"]);
  const toLiteral = (v) => {
    if (v === null) return t.nullLiteral();
    if (typeof v === "string") return t.stringLiteral(v);
    if (typeof v === "boolean") return t.booleanLiteral(v);
    if (typeof v === "number" && Number.isFinite(v)) {
      try { return t.valueToNode(v); } catch { return null; }
    }
    return null;
  };
  let iterations = 0;
  let changed = true;
  while (changed && iterations++ < 12) {
    changed = false;
    traverse(ast, {
      IfStatement(path) {
        const r = ev(path.node.test);
        if (!r.known) return;
        if (r.value) {
          report.unwrappedOpaqueTrue++;
          const cons = path.node.consequent;
          if (cons.type === "BlockStatement") {
            if (path.parentPath.isIfStatement()) path.node.consequent = cons.body.length === 1 ? cons.body[0] : t.blockStatement(cons.body);
            else path.replaceWithMultiple(cons.body);
          } else {
            path.replaceWith(cons);
          }
          changed = true;
        } else {
          report.removedOpaqueFalse++;
          if (path.node.alternate) {
            const alt = path.node.alternate;
            if (alt.type === "BlockStatement") {
              if (path.parentPath.isIfStatement()) path.node.alternate = alt.body.length === 1 ? alt.body[0] : t.blockStatement(alt.body);
              else path.replaceWithMultiple(alt.body);
            } else {
              path.replaceWith(alt);
            }
          } else {
            path.remove();
          }
          changed = true;
        }
      },
      ConditionalExpression(path) {
        const r = ev(path.node.test);
        if (!r.known) return;
        const taken = r.value ? path.node.consequent : path.node.alternate;
        if (taken.type === "StringLiteral" && taken.value.length >= 2) report.recoveredStrings.add(taken.value);
        report.foldedConditionals++;
        path.replaceWith(taken);
        changed = true;
      },
      Expression(path) {
        const n = path.node;
        if (LITERAL_TYPES.has(n.type) || n.type === "ConditionalExpression" || n.type === "IfStatement") return;
        // skip identifiers bound by constValues — keep names readable
        if (n.type === "Identifier" && constValues.has(n.name)) return;
        // never fold in a write position — replacing `x`/`obj.m`/`a[i]` on
        // the LHS of =/++/+= produces invalid AST (e.g. `5++`, `1 = v`).
        const par = path.parentPath?.node;
        if (par && (
          par.type === "UpdateExpression" ||
          (par.type === "AssignmentExpression" && par.left === n) ||
          (par.type === "ForOfStatement" && par.left === n) ||
          (par.type === "ForInStatement" && par.left === n)
        )) return;
        const r = ev(n);
        if (!r.known) return;
        const lit = toLiteral(r.value);
        if (!lit || lit.type === n.type) return; // -1 → UnaryExpression(-1) would loop
        if (lit.type === "StringLiteral" && lit.value.length >= 2) report.recoveredStrings.add(lit.value);
        report.foldedLiterals++;
        path.replaceWith(lit);
        changed = true;
      },
    });
  }
  const body2 = ast.program.body;

  // ---- Pass 3: classify statements
  const matchesStrong = (n) => injectedNames.has(n) || STRONG_NAME.some((re) => re.test(n));
  const matchesGeneric = (n) => injectedNames.has(n) || matchesStrong(n) || GENERIC_SUFFIX_NAME.test(n) || n.startsWith("$");
  const programDeclared = new Set();
  for (const stmt of body2) for (const n of stmtDeclaredNames(stmt)) programDeclared.add(n);

  const refsOnlyInjected = (stmt) => {
    const refs = new Set();
    collectRefs(stmt, refs);
    let hasInjected = false;
    for (const n of refs) {
      if (injectedNames.has(n)) { hasInjected = true; continue; }
      if (programDeclared.has(n) && !matchesGeneric(n)) return false;
      // unbound globals (process/Math/Date/...) don't disqualify
    }
    return hasInjected;
  };
  const isSeedDeclStmt = (stmt) =>
    stmt.type === "VariableDeclaration" && stmt.declarations.some(
      (d) => d.id?.type === "Identifier" && d.id.name === seedName) && seedName !== null;
  const isShadowHeapDecl = (stmt) =>
    stmt.type === "VariableDeclaration" && stmt.declarations.some((d) =>
      d.init?.type === "ObjectExpression" && d.init.properties.some((p) =>
        p.type === "ObjectProperty" && !p.computed &&
        ((p.key.type === "Identifier" && (p.key.name === "splitShareA" || p.key.name === "diffEnvelope")) ||
         (p.key.type === "StringLiteral" && (p.key.value === "splitShareA" || p.key.value === "diffEnvelope")))));
  const isVoidStmt = (stmt) => {
    if (stmt.type !== "ExpressionStatement" || stmt.expression.type !== "UnaryExpression" ||
        stmt.expression.operator !== "void") return false;
    const arg = stmt.expression.argument;
    // `void [...]`/sequence anchors are BLA's tail markers — but only once
    // corpus/seed evidence promoted the anchor names to injectedNames. A
    // plain `void [a,b]`/`void ident` in an unhardened file stays real.
    if (arg.type === "ArrayExpression" || arg.type === "SequenceExpression") {
      const ids = [];
      if (arg.type === "ArrayExpression") for (const el of arg.elements) { if (el?.type === "Identifier") ids.push(el.name); }
      return ids.length > 0 && ids.every((n) => injectedNames.has(n));
    }
    if (arg.type === "Identifier") {
      return injectedNames.has(arg.name) || STRONG_NAME.some((re) => re.test(arg.name)) ||
        GENERIC_SUFFIX_NAME.test(arg.name);
    }
    return false;
  };
  const isRuntimeIife = (stmt) => {
    if (stmt.type !== "ExpressionStatement" || stmt.expression.type !== "CallExpression") return false;
    const callee = stmt.expression.callee;
    if (callee.type !== "FunctionExpression" && callee.type !== "ArrowFunctionExpression") return false;
    const src = safeGen(stmt);
    return RUNTIME_MARKERS.test(src);
  };
  function safeGen(node) { try { return generate(node).code; } catch { return ""; } }

  // Decls whose names match an injected family are injected only with real
  // evidence: void-anchored, BLA decoy-basename vocabulary, payload
  // vocabulary, or machinery refs. A pure-leaf real helper that collides on
  // name shape alone is kept.
  const BLA_DECOY_BASENAME =
    /^_(verify|negotiate|hydrate|flush|schedule|compact|capture|shield|observe|adapt|materialize|bind|resolve|derive|authenticate|synchronize|unseal|reconcile|normalize|project|encode|reduce|prime|transform|expose|attest|seal|route|dispatch|enroll|provision|federate|mediate|broker|arbitrate|orchestrate|bootstrap|finalize|delegate|endorse|certify|interlock|shadow|bla)[A-Z][\w$]*_\w+$/;
  const BLA_DECOY_PLAIN =
    /^(verifyEnterpriseMasterLicense|decryptOfflineVaultPayload|computeStripeWebhookSignature|validateHardwareDongleResponse|deriveMasterEncryptionKey|checkSubscriptionEntitlementTier|authenticateZeroTrustSession|unlockPremiumFeatureFlags|ReconcileQuorumLedger|canaryCredentialHoneypot|probeCanaryHoneypot|collectEnvironmentDiagnostics|systemDiagnosticLog|evidenceLedger|grpcServiceMirage|computeEnterpriseSettlementLedger|verifyShamirEd25519LicenseQuorum|aliasedBufferIllusion|diffFrontier|crashSignalHandler|registerDecoyIpcAndRoute\w*|stepShadowHeap\w*|readSplitShare|shadowHeap\w*|obligationFlood|labyrinthDispatch|cdpShape\w*|fridaCapture\w*|runtimeSeed\w*)_\w+$/;
  const isDecoyName = (n) =>
    BLA_DECOY_BASENAME.test(n) || BLA_DECOY_PLAIN.test(n) ||
    /^\$[0-9a-f]{2}(Attest|Verify|Unseal|Derive|Seal|Reconcile|Decrypt|Compute|Validate|Check|Authenticate|Unlock)[A-Za-z]*_\w+$/.test(n);
  // Families real code never uses — hard evidence; call sites get swept.
  const HARD_FAMILY =
    /^(stepShadowHeap|readSplitShare|shadowHeap|runtimeSeed|obligationFlood|labyrinthDispatch|scc_|diffFrontier|aliasedBufferIllusion|cdpShape|fridaCapture|fridaRealmRing|regexSearchMagnet|tokenSink|_shadowVault|_interlockSafetyCorpus|_deriveContainmentCorpusDigest|_runtimeState|_DISTRIBUTED_ASL3|_SELF_SEAL_TARGET)/;
  const VOCAB_TEXT = /shadowHeap|shadowVault|enclave_|tpm2_pcr|SYMBOL_OFFSET_MANIFEST|EVIDENCE_CHAIN|build_digest=ev_|bla_canary_|PROTECTED_CANARY|CANARY_CREDENTIAL|HONEYPOT|enclave\.internal|RING0_SEALED|AF_VSOCK_RING0|HARDWARE_ENCLAVE_DELEGATED|attestationState/;
  const suffixDeclNames = new Set();
  for (const s of body2) for (const n of stmtDeclaredNames(s)) if (matchesGeneric(n)) suffixDeclNames.add(n);
  const declsInjectedMachinery = (stmt) => {
    const names = stmtDeclaredNames(stmt);
    if (names.length === 0 || !names.every(matchesGeneric)) return false;
    if (names.some((n) => injectedNames.has(n))) return true;
    // BLA's fixed decoy-basename tables: <basename>_<hex> names are emitted
    // verbatim by its generators — a real decl colliding is rescued later.
    if (names.some(isDecoyName)) return true;
    // HARD_FAMILY names (tokenSink/fridaRealmRing/_runtimeState/…) are BLA's
    // own generator vocabulary — same unambiguous evidence as isDecoyName.
    if (names.some((n) => GENERIC_SUFFIX_NAME.test(n) && HARD_FAMILY.test(n))) return true;
    // Leaf decoy blobs: generic-shaped name + BLA-invented payload vocabulary
    // (dedicated tokens alone, or >=2 generic enclave-family tokens).
    const text = safeGen(stmt);
    if (VOCAB_TEXT.test(text)) return true;
    const genTokens = text.match(/enclave|attestation|ring0|pcr_quote|splitShare|rollingMask|hmacTag|epochTick/g);
    if (genTokens && new Set(genTokens).size >= 2) return true;
    const refs = new Set();
    // Collect the declaration's own body refs (collectRefs alone skips
    // FunctionDeclaration bodies, hiding chain-call evidence inside them) —
    // but skip prologue-shaped statements whose refs are all machinery: BLA
    // splices stepper/seed-gate calls into REAL renamed functions, and those
    // prologue refs must not taint the decl's own classification.
    const prologueShaped = (s) => {
      if (s.type !== "ExpressionStatement" && s.type !== "IfStatement") return false;
      const r = new Set();
      collectRefs(s, r);
      let any = false;
      for (const n of r) {
        if (matchesGeneric(n) || isDecoyName(n)) { any = true; continue; }
        return false;
      }
      return any;
    };
    const declBodyRefs = (s) => {
      if (s.type === "FunctionDeclaration") {
        if (s.body) for (const inner of s.body.body ?? []) if (!prologueShaped(inner)) collectRefs(inner, refs);
      } else if (s.type === "VariableDeclaration") { for (const d of s.declarations) if (d.init) collectRefs(d.init, refs); }
      else if ((s.type === "ExportNamedDeclaration" || s.type === "ExportDefaultDeclaration") && s.declaration) declBodyRefs(s.declaration);
      else collectRefs(s, refs);
    };
    declBodyRefs(stmt);
    let refsMachinery = false;
    for (const n of refs) {
      if (names.includes(n)) continue;
      if (injectedNames.has(n)) return true;
      if (suffixDeclNames.has(n)) refsMachinery = true;
    }
    return refsMachinery;
  };
  const isStrongInjected = (stmt) => {
    const names = stmtDeclaredNames(stmt);
    // corpus/digest declarations are unambiguous BLA signatures — always
    // injected even though they're leaf literals with no machinery refs.
    if (names.some((n) => /^_interlockSafetyCorpus_|^_deriveContainmentCorpusDigest_/.test(n))) return true;
    if (names.length > 0) return declsInjectedMachinery(stmt);
    if (isSeedDeclStmt(stmt) || isShadowHeapDecl(stmt) || isVoidStmt(stmt) || isRuntimeIife(stmt)) return true;
    if ((stmt.type === "ExpressionStatement" || stmt.type === "IfStatement") && refsOnlyInjected(stmt)) return true;
    return false;
  };
  const isSuffixInjected = (stmt) => {
    if (isStrongInjected(stmt)) return true;
    if (refsOnlyInjected(stmt)) return true;
    return false;
  };

  // boundary: earliest strong-injected stmt that starts an all-suffix-injected tail
  const flagsG = body2.map(isStrongInjected);
  const flagsS = body2.map(isSuffixInjected);
  let boundary = -1;
  for (let i = 0; i < body2.length; i++) {
    if (flagsG[i] && flagsS.slice(i).every(Boolean)) { boundary = i; break; }
  }
  if (boundary === -1) boundary = flagsG.lastIndexOf(true);
  // boundary -1 means NO strong-injected statement exists — there is no
  // injected tail, and the generic-suffix rule must not run file-wide (a
  // marker-comment false-positive once nuked 200+ real `_hex` functions).
  const suffixActive = boundary !== -1;

  const keep = [];
  const removedNames = [];
  const removedSoft = []; // {index, stmt, names} — rescuable
  const removedHardNames = new Set(); // unambiguous BLA evidence — swept + not rescuable
  const CORPUS_NAME = /^_interlockSafetyCorpus_|^_deriveContainmentCorpusDigest_/;
  for (let i = 0; i < body2.length; i++) {
    const stmt = body2[i];
    const injected = suffixActive ? (i < boundary ? flagsG[i] : flagsS[i]) : flagsG[i];
    if (injected) {
      report.removedTopLevel++;
      const names = stmtDeclaredNames(stmt);
      for (const n of names) removedNames.push(n);
      if (stmt.type === "FunctionDeclaration" && stmt.id) report.injectedFunctionsRemoved++;
      // Hard = anchored injectedName, corpus/seed/shadow-heap decl, or
      // BLA-invented payload vocabulary — its call sites inside kept code
      // get swept below and the decl is never rescued. Everything else is
      // soft: rescuable if surviving code still references it.
      const hard = names.length > 0 &&
        (names.some((n) => injectedNames.has(n) || CORPUS_NAME.test(n) ||
          (GENERIC_SUFFIX_NAME.test(n) && HARD_FAMILY.test(n))) ||
         isSeedDeclStmt(stmt) || isShadowHeapDecl(stmt) || VOCAB_TEXT.test(safeGen(stmt)));
      if (names.length > 0) {
        if (hard) for (const n of names) removedHardNames.add(n);
        else removedSoft.push({ index: i, stmt, names });
      }
    } else {
      keep.push({ index: i, stmt });
      if (i >= boundary && boundary !== -1) {
        report.residualStatements.push({ index: i, type: stmt.type, names: stmtDeclaredNames(stmt), preview: safeGen(stmt).slice(0, 100) });
      }
    }
  }
  ast.program.body = keep.map((k) => k.stmt);
  report.removedNameSamples = removedNames.slice(0, 24);

  // ---- Pass 4: sweep residual calls to injected names inside function bodies.
  // Runs again after the rescue pass: a rescued decl may carry injected
  // prologue calls that must still be swept.
  const sweepInjectedCalls = () => traverse(ast, {
    Statement(path) {
      if (path.parentPath.isProgram()) return;
      if (!path.isExpressionStatement() && !path.isIfStatement()) return;
      const refs = new Set();
      collectRefs(path.node, refs);
      let hasInjected = false;
      for (const n of refs) {
        if (injectedNames.has(n) || removedHardNames.has(n)) { hasInjected = true; continue; }
        if (programDeclared.has(n) && !matchesGeneric(n)) return;
      }
      if (hasInjected) {
        report.prologueCallsRemoved++;
        path.remove();
      }
    },
  });
  sweepInjectedCalls();

  // ---- Pass 4.25: rescue pass — AFTER the body sweep, so references are
  // computed on post-sweep code. A removed decl whose name is still
  // referenced by surviving code is real (injected machinery is never
  // referenced once its call sites are swept). Deep walk: call sites inside
  // kept function bodies count too.
  const deepRefs = (node, refs) => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) { for (const n of node) deepRefs(n, refs); return; }
    if (node.type === "Identifier") { refs.add(node.name); return; }
    if (node.type === "ObjectProperty" && !node.computed && node.key.type === "Identifier") {
      deepRefs(node.value, refs); return;
    }
    for (const k of Object.keys(node)) {
      if (k === "loc" || k === "start" || k === "end" || k === "leadingComments" || k === "trailingComments" || k === "innerComments") continue;
      deepRefs(node[k], refs);
    }
  };
  if (removedSoft.length > 0) {
    const keptRefs = new Set();
    for (const k of keep) deepRefs(k.stmt, keptRefs);
    // fixpoint: a rescued decl's own references can pull in further decls.
    let changed = true;
    while (changed) {
      changed = false;
      for (let ri = 0; ri < removedSoft.length; ri++) {
        const r = removedSoft[ri];
        if (r.names.some((n) => keptRefs.has(n))) {
          const pos = keep.findIndex((k) => k.index > r.index);
          keep.splice(pos === -1 ? keep.length : pos, 0, { index: r.index, stmt: r.stmt });
          report.rescuedDecls = (report.rescuedDecls ?? 0) + 1;
          deepRefs(r.stmt, keptRefs);
          removedSoft.splice(ri, 1);
          ri--;
          changed = true;
        }
      }
    }
    if (report.rescuedDecls) {
      ast.program.body = keep.map((k) => k.stmt);
      sweepInjectedCalls();
    }
  }

  // ---- Pass 4.5: restore canonical binding names BLA renamed.
  // `const { contextBridge: x_1cd } = require("electron")` -> rename x_1cd back
  // to `contextBridge`; `module.exports = { foo: fn_2db }` -> fn_2db -> `foo`.
  // BLA's renaming keeps semantics but strips the identifier names downstream
  // static analyzers (REA's ipc-channel / context-bridge detectors) key on.
  const tryRename = (path, oldName, newName) => {
    if (oldName === newName || !t.isValidIdentifier(newName) || /^__|^\$\$/.test(newName)) return false;
    const binding = path.scope.getBinding(oldName);
    if (!binding) return false;
    const existing = path.scope.getBinding(newName);
    if (existing && existing !== binding) return false;
    path.scope.rename(oldName, newName);
    report.renamedBindings.push([oldName, newName]);
    return true;
  };
  traverse(ast, {
    VariableDeclarator(path) {
      const { id, init } = path.node;
      if (id.type !== "ObjectPattern" || init?.type !== "CallExpression") return;
      if (init.callee.type !== "Identifier" || init.callee.name !== "require") return;
      for (const prop of id.properties) {
        if (prop.type !== "ObjectProperty" || prop.computed) continue;
        const key = prop.key.type === "Identifier" ? prop.key.name
          : prop.key.type === "StringLiteral" ? prop.key.value : null;
        const v = prop.value.type === "Identifier" ? prop.value
          : prop.value.type === "AssignmentPattern" && prop.value.left.type === "Identifier" ? prop.value.left : null;
        if (key && v) tryRename(path, v.name, key);
      }
    },
    AssignmentExpression(path) {
      const l = path.node.left, r = path.node.right;
      if (l.type !== "MemberExpression" || l.object.type !== "Identifier") return;
      const isModuleExports = l.object.name === "module" && l.property.type === "Identifier" && l.property.name === "exports";
      const isExportsMember = l.object.name === "exports" && l.property.type === "Identifier";
      if (isModuleExports && r.type === "ObjectExpression") {
        for (const p of r.properties) {
          if (p.type !== "ObjectProperty" || p.computed || p.value.type !== "Identifier") continue;
          const k = p.key.type === "Identifier" ? p.key.name : p.key.type === "StringLiteral" ? p.key.value : null;
          if (k) tryRename(path, p.value.name, k);
        }
      } else if (isExportsMember && r.type === "Identifier") {
        tryRename(path, r.name, l.property.name);
      }
    },
  });

  // ---- Pass 5: dangling-ref + export surface audit, generate
  const dangling = new Set();
  const exportNames = new Set();
  traverse(ast, {
    ReferencedIdentifier(path) {
      const n = path.node.name;
      if (injectedNames.has(n)) dangling.add(n);
    },
    AssignmentExpression(path) {
      const l = path.node.left;
      if (l.type === "MemberExpression" && l.object.type === "Identifier" &&
          (l.object.name === "exports" || (l.object.name === "module" && l.property.type === "Identifier" && l.property.name === "exports"))) {
        const r = path.node.right;
        if (l.object.name === "exports" && l.property.type === "Identifier") exportNames.add(l.property.name);
        if (l.object.name === "module" && r.type === "ObjectExpression") {
          for (const p of r.properties) {
            if (p.type === "ObjectProperty" && !p.computed) {
              const k = p.key.type === "Identifier" ? p.key.name : p.key.type === "StringLiteral" ? p.key.value : null;
              if (k) exportNames.add(k);
            }
          }
        }
      }
    },
    ExportNamedDeclaration(path) {
      for (const s of path.node.specifiers ?? []) exportNames.add(s.exported?.name ?? s.exported?.value);
      if (path.node.declaration?.id) exportNames.add(path.node.declaration.id.name);
    },
    ExportDefaultDeclaration() { exportNames.add("default"); },
  });
  report.danglingRefs = [...dangling];
  report.exportSurface = [...exportNames].filter(Boolean);

  let code = generate(ast, { comments: true, compact: false }).code;
  // drop BLA honey sourcemap trailer (+ any injected marker comments)
  code = code
    .split("\n")
    .filter((l) => !/^\s*\/\/#?\s*sourceMappingURL=/.test(l))
    .join("\n")
    .replace(/\/\*[^*]*(runtime attestation boundary|decorative shadow runtime signal|apparent decompiler constant)[^*]*\*\/\n?/g, "");
  report.bytesOut = code.length;
  report.recoveredStrings = [...report.recoveredStrings].sort();
  // best-degree recovery for BLA-destroyed identifier names: semantic
  // renaming — embedded original-name hints, init-expression evidence,
  // call-site roles, structural floor. Originals can't come back; meaningful
  // names can. report.inferredRenames / report.unrenamable are populated by
  // the call.
  if (report.hardened) code = recoverJsNames(code, report).code;
  return { code, report };
}
