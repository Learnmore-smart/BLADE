// BLADE name recovery — semantic renaming for artifacts BLA renamed.
//
// BLA destroys original identifier names and substitutes realistic-looking
// noise (vendor/bla/src/core/identifiers.ts) or machinery names from its
// exhaustion/deception suites. The originals are provably unrecoverable —
// this module performs BEST-EFFORT semantic renaming: it infers a
// meaningful replacement name from usage evidence, never claims to restore
// the original.
//
// ─────────────────────────────────────────────────────────────────────────
// recoverJsNames(code, report?) => { code, renames, unrenamable }
//
//   code      – JavaScript/TypeScript source (ideally post-dehardenJs output,
//               but works on any source containing BLA-shaped bindings).
//   report    – optional mutable report object. On return, fields set:
//                 report.inferredRenames – the rename table (same array as
//                                          returned `renames`)
//                 report.unrenamable     – [{ name, reason }] for BLA-shaped
//                                          bindings left untouched
//
//   returns   – { code, renames, unrenamable }
//     renames – Array<{ from, to, confidence, evidence }>
//       confidence: "high" | "medium" | "low"
//       evidence:   short machine-readable tag describing the inference rule
//
// Rename eligibility (a binding must pass ALL gates):
//   1. Its name matches a BLA-emitted shape (see BLA vocabulary tables +
//      machinery family regexes below). Non-BLA-shaped names are never
//      touched.
//   2. It is a real Babel binding (locals/params/vars/functions). Never
//      renamed: globals (no binding), import bindings, names that are the
//      exported API surface (`export { x }` / `export default fn` names
//      whose identifier IS the API), bindings whose runtime .name /
//      .constructor / Function#toString is observed, bindings in scopes
//      reachable by a direct eval() call, TS parameter properties, and
//      top-level script-carrier bindings (they attach to globalThis —
//      CommonJS modules detected via require/module.exports are exempt).
//   3. Evidence must back the suggested name. Weak-shaped candidates
//      (generic `*_<hex3-4>` suffix) require >= "medium" evidence;
//      strong-shaped ones may fall back to structural minimal names
//      (i/j/acc/tmp/arg) — still better than flood shapes.
//
// Inference rules, in priority order:
//   0. embedded-hint        – stealth/balanced BLA renames embed the first
//                             <=16 chars of the ORIGINAL name as the stem:
//                             `serialKey` -> `serialKeyActiveLedger_9be`.
//                             When the stem is non-vocabulary it IS an
//                             original-name fragment. Highest-confidence
//                             source when present. (max/bankrupt renames use
//                             pure vocabulary, which parses as "no hint".)
//   1. init-expression      – `x = store.get('cart')` -> `cart`;
//                             `x = ipcRenderer.invoke('get-user')` ->
//                             `getUserResult` (kebab/snake -> camel);
//                             require()/new X()/object-pattern keys/
//                             literal+expression-shape fallbacks.
//   2. usage / call site    – binding passed to a known API:
//                             `ipcMain.handle('get-user', fn)` ->
//                             `getUserHandler`; `xs.map(fn)` -> `mapper`;
//                             object-literal/exports property keys.
//                             Params inherit from their owner function's
//                             call-site role (Array HOF -> item/index/acc,
//                             handlers -> event, .then -> result,
//                             .catch -> err).
//   3. property reads       – `x.userId` -> `userIdHolder` (only when no
//                             better evidence exists); built-in method
//                             reads map to text/items/map hints.
//   4. structural role      – loop counter -> i/j/k, for-of -> item,
//                             for-in -> key, accumulator -> acc,
//                             catch param -> err, rest -> args,
//                             otherwise tmp/value/arg.
// Ambiguous (no evidence above the gate) -> name preserved, recorded in
// `unrenamable`.
//
// Collisions: suggested names are deduped against every declared AND
// referenced identifier in the file plus every name we already emitted;
// conflicts get a numeric suffix (`cart`, `cart2`, `cart3`...). New names
// must satisfy t.isValidIdentifier (rejects reserved words).
//
// ─────────────────────────────────────────────────────────────────────────
// recoverWasmExports(wasm: Buffer) => { names, nameSection? }
//
//   wasm      – raw .wasm binary (pre- or post-scrubWasm; both handled).
//               Throws "not wasm" on bad magic internally (scrubWasm itself
//               keep+flags bad-magic input; this helper is stricter).
//   returns   – { names, nameSection }
//     names – Array<{ index, kind, from, suggested, confidence, evidence,
//                    decoy? }> — one entry per BLA-shaped export name.
//              `suggested` is null for entries identified as pure decoys
//              (enclave_export_*/canary_export_*/enclave_unseal_* — the
//              scrubber drops those; nothing meaningful to name).
//     nameSection – Buffer holding a COMPLETE spec-valid `name` custom
//              section (id 0 + size + payload, ready to append to the
//              module), or undefined when there is nothing to name.
//              Contains: subsection 0 module name (only when a non-honey
//              fragment survives) + subsection 1 function names covering
//              every function export (recovered suggestion, surviving
//              fragment, or its real export name). The export section is
//              never touched — export names are ABI; the name section is
//              tooling-only metadata.
//
// WASM inference rules, in priority order:
//   1. surviving name-section fragment for the function index (honey
//      `tee_hardware_enclave_transport_stub_*` names ignored).
//   2. embedded tail fragment in the ops_* name itself (non-vocabulary
//      words after the `dispatch` marker -> camelize).
//   3. signature + position heuristic table ((i32,i32)->i32 index-0
//      exports are often add/main-style, etc.).
//   4. `export_<funcIndex>` mechanical fallback.
//
// Both functions are pure: no I/O, no mutation of inputs.
// ─────────────────────────────────────────────────────────────────────────

import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import _generate from "@babel/generator";
import * as t from "@babel/types";

const traverse = _traverse.default ?? _traverse;
const generate = _generate.default ?? _generate;

// ==========================================================================
// BLA emitted-name shapes (vendor/bla/src/core/identifiers.ts +
// machinery names mirrored from src/js-deharden.mjs STRONG_NAME).
// ==========================================================================

const VERBS = [
  "resolve", "compute", "derive", "validate", "dispatch", "project",
  "reconcile", "normalize", "assemble", "compose", "evaluate", "schedule",
  "acquire", "release", "bind", "adapt", "mirror", "fold", "reduce",
  "expand", "encode", "decode", "seal", "unseal", "attest", "verify",
  "sync", "flush", "prime", "hydrate", "materialize", "capture", "emit",
  "observe", "trace", "probe", "sample", "filter", "transform", "allocate",
];
const NOUNS = [
  "Ledger", "Envelope", "Session", "Ticket", "Digest", "Frame", "Cursor",
  "Handle", "Slot", "Epoch", "Quota", "Policy", "Manifest", "Bundle",
  "Shard", "Segment", "Vector", "Matrix", "Buffer", "Stream", "Channel",
  "Bridge", "Gateway", "Router", "Registry", "Catalog", "Index", "Cache",
  "Pool", "Queue", "Stack", "Tree", "Graph", "Node", "Edge", "Probe",
  "Sensor", "Metric", "Sample", "Record", "Entry", "Token", "Claim",
  "Scope", "Context", "Runtime", "Worker", "Service", "Client", "Provider",
];
const ADJECTIVES = [
  "Active", "Pending", "Sealed", "Transient", "Durable", "Local", "Remote",
  "Shared", "Private", "Mutable", "Frozen", "Lazy", "Eager", "Inline",
  "Deferred", "Primary", "Secondary", "Nested", "Composite", "Sparse",
];
const SNAKE_STEMS = [
  "session", "ledger", "envelope", "digest", "cursor", "handle", "epoch",
  "quota", "policy", "manifest", "bundle", "shard", "segment", "vector",
  "matrix", "buffer", "stream", "channel", "bridge", "gateway", "router",
  "registry", "catalog", "index", "cache", "pool", "queue", "probe",
  "metric", "sample", "record", "token", "claim", "scope", "context",
  "runtime", "worker", "service", "client", "provider", "slot", "frame",
  "ticket",
];
const VERB_SET = new Set(VERBS);
const NOUN_SET = new Set(NOUNS);
const ADJ_SET = new Set(ADJECTIVES);
const SNAKE_SET = new Set(SNAKE_STEMS);

// Hints that are too generic to be meaningful original-name fragments —
// `get`+Adj+Noun is how a human writes `getActiveUser`, not a BLA rename.
const WEAK_HINT_WORDS = new Set([
  "get", "set", "is", "has", "new", "use", "run", "try", "do", "make",
  "the", "my", "our", "a", "an", "of", "in", "on", "to", "no",
]);

// Machinery names BLA's exhaustion/deception suites emit (mirrors
// STRONG_NAME in src/js-deharden.mjs — keep the two lists aligned).
const BLA_MACHINERY_NAME = [
  /^obligationFlood_\w+$/,
  /^scc_\w+_c\d+n\d+$/,
  /^labyrinthDispatch_\w+$/,
  /^tokenSink_\w+$/,
  /^bpeSink_\w+$/,
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
  /^_runtimeState\w*_\w+$/,
  /^_DISTRIBUTED_ASL3_\w+$/,
  /^_SELF_SEAL_TARGET\w*$/,
];

const GENERIC_SUFFIX = /^[_$a-zA-Z][\w$]*_[0-9a-f]{3,4}$/;
const HEX_SUFFIX = /_[0-9a-f]{3,4}$/;

/**
 * Classify a name against BLA's emitted shapes.
 * Returns { bla, strong, style, hint } — `hint` is a recovered original-name
 * fragment when the shape is a hinted rename (stealth/balanced intensity).
 */
/**
 * BLA embeds `hint.toLowerCase()[0] + hint.slice(1)` — undo it when the
 * remainder is all-caps shaped (`gOLDEN_SCHEDULE` -> `GOLDEN_SCHEDULE`).
 */
function restoreHintCase(hint) {
  if (!hint) return hint;
  if (/^[a-z]/.test(hint) && /^[A-Z0-9_$]+$/.test(hint.slice(1)) && /[A-Z_]/.test(hint.slice(1))) {
    return hint.charAt(0).toUpperCase() + hint.slice(1);
  }
  return hint;
}

function classifyBlaName(name) {
  const no = { bla: false, strong: false, style: null, hint: null };
  if (!GENERIC_SUFFIX.test(name)) {
    // machinery names don't all carry a clean hex suffix
    if (BLA_MACHINERY_NAME.some((re) => re.test(name))) {
      return { bla: true, strong: true, style: "machinery", hint: null };
    }
    return no;
  }
  if (BLA_MACHINERY_NAME.some((re) => re.test(name))) {
    return { bla: true, strong: true, style: "machinery", hint: null };
  }

  const stem = name.slice(0, name.lastIndexOf("_"));

  // earlySort: `$<hex2><Body>_<hex3>`
  const early = /^\$[0-9a-f]{2}([A-Z][\w$]*)$/.exec(stem);
  if (early) {
    const body = early[1];
    // vocabulary body = Adj+Noun exactly; anything else is a hint
    const vocab = ADJECTIVES.some(
      (a) => body === a || NOUNS.some((n) => body === a + n),
    );
    const hint = vocab ? null
      : /^[A-Z0-9_$]+$/.test(body) && /[A-Z_]/.test(body.slice(1))
        ? body                                             // SCREAMING preserved
        : body.charAt(0).toLowerCase() + body.slice(1);    // lowerFirst inverse
    return { bla: true, strong: true, style: "earlySort", hint: restoreHintCase(hint) };
  }

  // privateCamel: `_<body><Noun>_<hex>` — single noun, no adjective
  const priv = /^_([a-z][\w$]*)$/.exec(stem);
  if (priv && /[A-Z]/.test(priv[1])) {
    const body = priv[1];
    for (const n of NOUNS) {
      if (body.endsWith(n) && body.length > n.length) {
        const head = body.slice(0, body.length - n.length);
        return {
          bla: true, strong: true, style: "privateCamel",
          hint: VERB_SET.has(head) ? null : restoreHintCase(head),
        };
      }
    }
    // uppercase inside but doesn't end with a noun — still BLA-shaped
    return { bla: true, strong: true, style: "privateCamel", hint: null };
  }

  // snake: `<stem>_<stem>_<stem>_<hex>` — stems split further on `_`
  if (/^[a-z][a-z0-9]*(?:_[a-z][a-z0-9]*)+$/.test(stem)) {
    const parts = stem.split("_");
    const vocabCount = parts.filter((p) => SNAKE_SET.has(p)).length;
    const nonVocab = parts.filter((p) => !SNAKE_SET.has(p));
    // c-position (last stem) is where BLA puts a hint; also require the
    // rest to look vocabulary-derived for a strong classification.
    const hint = nonVocab.length === 1 && vocabCount >= 2
      ? camelizeSnake(nonVocab[0])
      : null;
    return {
      bla: true,
      strong: vocabCount >= 2,
      style: "snake",
      hint,
    };
  }

  // camel: `<body><Adj><Noun>_<hex>` — body is a vocab verb (no-hint) or an
  // original-name fragment (hinted rename).
  if (/^[a-z][A-Za-z0-9$]*[A-Z]/.test(stem)) {
    // find the longest Adj+Noun tail
    let tailLen = 0;
    for (const a of ADJECTIVES) {
      for (const n of NOUNS) {
        const tail = a + n;
        if (stem.endsWith(tail) && tail.length > tailLen && stem.length > tail.length) {
          tailLen = tail.length;
        }
      }
    }
    if (tailLen > 0) {
      const head = stem.slice(0, stem.length - tailLen);
      return {
        bla: true,
        strong: VERB_SET.has(head),
        style: "camel",
        hint: VERB_SET.has(head) ? null : restoreHintCase(head),
      };
    }
    // camel stem without a recognizable Adj+Noun tail: still carries the
    // generic BLA hex suffix — weak candidate only.
    return { bla: true, strong: false, style: "camel-generic", hint: null };
  }

  // generic `word_<hex3-4>` with a plain lowercase stem: cannot come from
  // BLA's binding renamer (it always appends Noun/Adj+Noun vocabulary), but
  // matches the injected-machinery suffix convention — weakest tier, only
  // renamed on high-confidence evidence.
  return { bla: true, strong: false, style: "generic", hint: null };
}

// ==========================================================================
// Name inference helpers
// ==========================================================================

const IDENTISH = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

function camelizeSnake(s) {
  const parts = String(s).split(/[^A-Za-z0-9$]+/).filter(Boolean);
  if (parts.length === 0) return null;
  const first = parts[0].charAt(0).toLowerCase() + parts[0].slice(1);
  return first + parts.slice(1).map((p) => p.charAt(0).toUpperCase() + p.slice(1)).join("");
}

/** kebab/snake/colon/space-separated literal -> camelCase (null if hopeless). */
function literalToName(s, maxLen = 28) {
  if (typeof s !== "string" || s.length === 0 || s.length > maxLen) return null;
  const c = camelizeSnake(s);
  return c && IDENTISH.test(c) ? c : null;
}

function memberPropName(node) {
  if (!node) return null;
  if (!node.computed && node.property.type === "Identifier") return node.property.name;
  if (node.computed && node.property.type === "StringLiteral") return node.property.value;
  return null;
}

/** dotted root of a member chain: `a.b.c()` -> "a" */
function memberRootName(node) {
  let cur = node;
  while (cur && (cur.type === "MemberExpression" || cur.type === "OptionalMemberExpression")) {
    cur = cur.object;
  }
  return cur && cur.type === "Identifier" ? cur.name : null;
}

// member-call methods whose string argument names the VALUE returned
const VALUE_METHODS = new Set([
  "get", "getItem", "read", "load", "fetch", "find", "lookup", "resolve",
  "checkout", "query", "select", "getState", "getValue", "getAttribute",
]);
// member-call methods whose string argument names an async REQUEST —
// result conventionally gets a Result suffix
const RESULT_METHODS = new Set([
  "invoke", "call", "request", "dispatch", "send", "sendSync", "sendMessage",
  "postMessage", "execute", "exec", "submit", "perform", "evaluate",
]);
// member-call methods that register a callback/handler — the string
// argument names the event/channel
const HANDLER_METHODS = new Set([
  "handle", "handleOnce", "on", "once", "addListener", "addEventListener",
  "subscribe", "register", "registerHandler", "prependListener",
]);
// member-call methods that consume a callback WITHOUT a channel string
const CALLBACK_METHODS = new Map([
  ["then", "continuation"], ["catch", "errorHandler"], ["finally", "cleanup"],
  ["setTimeout", "callback"], ["setInterval", "callback"],
  ["setImmediate", "callback"], ["queueMicrotask", "callback"],
  ["requestAnimationFrame", "callback"], ["use", "middleware"],
]);
// Array/iterable HOF member -> param-name table
const HOF_PARAM_HINTS = new Map([
  ["forEach", ["item", "index", "list"]],
  ["map", ["item", "index", "list"]],
  ["filter", ["item", "index", "list"]],
  ["find", ["item", "index", "list"]],
  ["findIndex", ["item", "index", "list"]],
  ["some", ["item", "index", "list"]],
  ["every", ["item", "index", "list"]],
  ["flatMap", ["item", "index", "list"]],
  ["filterMap", ["item", "index", "list"]],
  ["reduce", ["acc", "item", "index", "list"]],
  ["reduceRight", ["acc", "item", "index", "list"]],
  ["sort", ["a", "b"]],
]);
const HOF_FUNC_HINTS = new Map([
  ["forEach", "iteratee"], ["map", "mapper"], ["flatMap", "mapper"],
  ["filter", "predicate"], ["find", "predicate"], ["findIndex", "predicate"],
  ["some", "predicate"], ["every", "predicate"],
  ["reduce", "reducer"], ["reduceRight", "reducer"], ["sort", "comparator"],
]);
// well-known member calls -> result-name
const KNOWN_CALL_RESULTS = new Map([
  ["JSON.parse", "parsed"], ["JSON.stringify", "serialized"],
  ["Object.keys", "keys"], ["Object.values", "values"],
  ["Object.entries", "entries"], ["Object.freeze", "frozenMap"],
  ["Array.from", "list"], ["Promise.all", "results"],
  ["Date.now", "timestamp"], ["Math.random", "sample"],
]);
// reading a built-in method off the binding says what kind of value it is
const STRING_METHODS = new Set([
  "startsWith", "endsWith", "includes", "charAt", "charCodeAt", "codePointAt",
  "slice", "substring", "split", "trim", "toLowerCase", "toUpperCase",
  "indexOf", "lastIndexOf", "replace", "replaceAll", "match", "matchAll",
  "padStart", "padEnd", "repeat", "concat", "localeCompare", "normalize",
]);
const ARRAY_METHODS = new Set([
  "push", "pop", "shift", "unshift", "splice", "forEach", "map", "filter",
  "reduce", "reduceRight", "find", "findIndex", "some", "every", "join",
  "flat", "flatMap", "fill", "reverse", "sort", "entries", "keys", "values",
]);
const MAP_METHODS = new Set(["get", "set", "has", "delete", "clear"]);

const COMPARE_OPS = new Set(["==", "===", "!=", "!==", "<", ">", "<=", ">=", "instanceof", "in"]);
const NUMERIC_OPS = new Set(["-", "*", "/", "%", "**", "&", "|", "^", "<<", ">>", ">>>"]);

/**
 * Infer a candidate name from an init expression.
 * Returns { name, confidence, evidence } or null.
 */
function inferFromInit(init, { awaited = false } = {}) {
  if (!init) return null;
  switch (init.type) {
    case "AwaitExpression":
      return inferFromInit(init.argument, { awaited: true });

    case "StringLiteral": {
      if (IDENTISH.test(init.value) && init.value.length <= 28) {
        return { name: init.value, confidence: "high", evidence: "init:string-literal" };
      }
      const c = literalToName(init.value);
      return c
        ? { name: c, confidence: "medium", evidence: "init:string-literal" }
        : { name: "text", confidence: "low", evidence: "init:string-literal" };
    }
    case "TemplateLiteral":
      return { name: "text", confidence: "low", evidence: "init:template" };
    case "NumericLiteral":
      return { name: "num", confidence: "low", evidence: "init:numeric-literal" };
    case "BooleanLiteral":
      return { name: "flag", confidence: "low", evidence: "init:boolean-literal" };
    case "ObjectExpression":
      return { name: "record", confidence: "low", evidence: "init:object-literal" };
    case "ArrayExpression":
      return { name: "items", confidence: "low", evidence: "init:array-literal" };
    case "ConditionalExpression":
      return { name: "value", confidence: "low", evidence: "init:conditional" };
    case "SequenceExpression":
      return inferFromInit(init.expressions[init.expressions.length - 1], { awaited });

    case "UnaryExpression": {
      if (init.operator === "!") return { name: "flag", confidence: "low", evidence: "init:negation" };
      if (init.operator === "typeof") return { name: "type", confidence: "low", evidence: "init:typeof" };
      if (init.operator === "-" || init.operator === "~" || init.operator === "+") {
        return { name: "num", confidence: "low", evidence: "init:unary-numeric" };
      }
      return null;
    }

    case "BinaryExpression": {
      if (COMPARE_OPS.has(init.operator)) {
        return { name: "match", confidence: "low", evidence: "init:comparison" };
      }
      if (init.operator === "+") {
        const hasStr = (n) =>
          n.type === "StringLiteral" ||
          (n.type === "BinaryExpression" && n.operator === "+" && (hasStr(n.left) || hasStr(n.right)));
        if (hasStr(init)) return { name: "text", confidence: "low", evidence: "init:string-concat" };
      }
      if (NUMERIC_OPS.has(init.operator) || init.operator === "+") {
        return { name: "num", confidence: "low", evidence: "init:arithmetic" };
      }
      return { name: "value", confidence: "low", evidence: "init:binary" };
    }

    case "NewExpression": {
      if (init.callee.type === "Identifier") {
        const n = init.callee.name.charAt(0).toLowerCase() + init.callee.name.slice(1);
        return { name: n, confidence: "medium", evidence: "init:new-expression" };
      }
      return { name: "instance", confidence: "low", evidence: "init:new-expression" };
    }

    case "MemberExpression":
    case "OptionalMemberExpression": {
      const p = memberPropName(init);
      if (p && IDENTISH.test(p)) {
        return {
          name: camelizeSnake(p) + (awaited ? "Result" : ""),
          confidence: "medium", evidence: "init:member-read",
        };
      }
      return { name: "value", confidence: "low", evidence: "init:member-read" };
    }

    case "CallExpression":
    case "OptionalCallExpression": {
      const callee = init.callee;
      // require('mod') -> module basename
      if (callee.type === "Identifier" && callee.name === "require") {
        const a0 = init.arguments[0];
        if (a0 && a0.type === "StringLiteral") {
          const base = a0.value.replace(/^node:/, "").split(/[\\/]/).pop()
            .replace(/\.[cm]?[jt]sx?$/i, "");
          const c = literalToName(base);
          if (c) return { name: c, confidence: "high", evidence: "init:require" };
        }
        return { name: "imported", confidence: "medium", evidence: "init:require" };
      }
      if (callee.type === "MemberExpression" || callee.type === "OptionalMemberExpression") {
        const prop = memberPropName(callee);
        const root = memberRootName(callee);
        const known = root && prop ? KNOWN_CALL_RESULTS.get(`${root}.${prop}`) : null;
        const a0 = init.arguments[0];
        const a0Name = a0 && a0.type === "StringLiteral" ? literalToName(a0.value) : null;
        if (a0Name && prop && RESULT_METHODS.has(prop)) {
          return { name: `${a0Name}Result`, confidence: "high", evidence: `init:${prop}('${a0.value}')` };
        }
        if (a0Name && prop && VALUE_METHODS.has(prop)) {
          return { name: a0Name, confidence: "high", evidence: `init:${prop}('${a0.value}')` };
        }
        if (known) {
          return { name: known, confidence: "medium", evidence: `init:${root}.${prop}()` };
        }
        if (prop && IDENTISH.test(prop)) {
          const base = camelizeSnake(prop);
          return {
            name: awaited || RESULT_METHODS.has(prop) ? `${base}Result` : base,
            confidence: "medium", evidence: `init:${prop}()`,
          };
        }
        return { name: awaited ? "result" : "value", confidence: "low", evidence: "init:call" };
      }
      if (callee.type === "Identifier") {
        return {
          name: `${camelizeSnake(callee.name)}Result`,
          confidence: "medium", evidence: `init:${callee.name}()`,
        };
      }
      return { name: "value", confidence: "low", evidence: "init:call" };
    }

    default:
      return null;
  }
}

/**
 * Evidence from how the binding is USED — pass sites, member reads,
 * loop roles. Returns { name, confidence, evidence } or null.
 */
function inferFromUsage(binding, strengthOf) {
  const propReads = new Map();   // `x.<prop>` non-call reads
  const methodReads = new Map(); // `x.<prop>(` call reads
  let assigned = 0;
  let loopDepth = 0;
  let forOfKind = null;          // "of" | "in"
  let catchParam = false;
  let restParam = false;
  let loopCounter = false;

  // — declaration-site roles —
  const declPath = binding.path;
  const parentNode = declPath.parentPath?.node;
  const grandNode = declPath.parentPath?.parentPath?.node;

  if (binding.kind === "param") {
    if (parentNode?.type === "RestElement" || declPath.node.type === "RestElement") restParam = true;
  }
  // `catch (x_9be)` — babel binds the CatchClause node itself (kind "let"/
  // "local"), not the param identifier
  if (declPath.node.type === "CatchClause" || parentNode?.type === "CatchClause") catchParam = true;

  if (
    (parentNode?.type === "ForOfStatement" || parentNode?.type === "ForInStatement" ||
      grandNode?.type === "ForOfStatement" || grandNode?.type === "ForInStatement") &&
    (parentNode?.left === declPath.node || parentNode === declPath.parentPath?.node ||
     grandNode?.left === declPath.node ||
     (parentNode?.type === "VariableDeclaration" && grandNode?.left === parentNode))
  ) {
    forOfKind = (grandNode?.type === "ForInStatement" || parentNode?.type === "ForInStatement") ? "in" : "of";
  }
  // classic `for (let x = 0; x < n; x++)` counter
  if (
    parentNode?.type === "VariableDeclaration" &&
    grandNode?.type === "ForStatement" &&
    grandNode.init === parentNode
  ) {
    loopCounter = true;
  }
  // object-pattern value: `const { key: x_9be } = obj` / `function f({key: x_9be})`
  if (
    declPath.node.type === "Identifier" &&
    parentNode?.type === "ObjectProperty" &&
    parentNode.value === declPath.node
  ) {
    const key = parentNode.key.type === "Identifier" ? parentNode.key.name
      : parentNode.key.type === "StringLiteral" ? parentNode.key.value : null;
    if (key && IDENTISH.test(key)) {
      return { name: key, confidence: "high", evidence: "pattern:key" };
    }
  }

  // — reference-site roles —
  for (const ref of binding.referencePaths ?? []) {
    const p = ref.parentPath;
    if (!p) continue;
    const pn = p.node;

    // `x.<prop>` reads (non-computed)
    if ((pn.type === "MemberExpression" || pn.type === "OptionalMemberExpression") &&
        pn.object === ref.node && !pn.computed && pn.property.type === "Identifier") {
      const prop = pn.property.name;
      const isCall = (p.parentPath?.isCallExpression?.() || p.parentPath?.isOptionalCallExpression?.()) &&
        p.parentPath.node.callee === p.node;
      (isCall ? methodReads : propReads).set(prop, (isCall ? methodReads : propReads).get(prop) + 1 || 1);
      continue;
    }

    // `x = ...` writes — used for acc/tmp detection
    if (pn.type === "AssignmentExpression" && pn.left === ref.node) {
      assigned++;
      continue;
    }
    if (pn.type === "UpdateExpression") {
      assigned++;
      loopDepth = 1;
      continue;
    }

    // `key: x` object property — key name is strong evidence (shorthand
    // `{x_9be}` carries the BLA name itself, so it's evidence-free)
    if (pn.type === "ObjectProperty" && pn.value === ref.node && !pn.shorthand) {
      const key = pn.key.type === "Identifier" ? pn.key.name
        : pn.key.type === "StringLiteral" ? pn.key.value : null;
      if (key && key !== ref.node.name && IDENTISH.test(key) &&
          !BLA_MACHINERY_NAME.some((re) => re.test(key))) {
        return { name: key, confidence: "high", evidence: "usage:property-key" };
      }
      continue;
    }

    // `exports.foo = x` / `module.exports.foo = x` / `obj.foo = x`
    if (pn.type === "AssignmentExpression" && pn.right === ref.node &&
        (pn.left.type === "MemberExpression" || pn.left.type === "OptionalMemberExpression")) {
      const prop = memberPropName(pn.left);
      if (prop && IDENTISH.test(prop)) {
        return { name: prop, confidence: "high", evidence: "usage:export-key" };
      }
      continue;
    }

    // `knownApi('channel', x)` / `arr.map(x)` / `p.then(x)` — x as call arg
    if ((pn.type === "CallExpression" || pn.type === "OptionalCallExpression") &&
        pn.arguments.includes(ref.node)) {
      const callee = pn.callee;
      if (callee.type === "MemberExpression" || callee.type === "OptionalMemberExpression") {
        const prop = memberPropName(callee);
        const a0 = pn.arguments[0];
        const a0Name = a0 && a0 !== ref.node && a0.type === "StringLiteral"
          ? literalToName(a0.value) : null;
        if (a0Name && prop && HANDLER_METHODS.has(prop)) {
          return { name: `${a0Name}Handler`, confidence: "high", evidence: `usage:${prop}('${a0.value}', x)` };
        }
        if (prop && CALLBACK_METHODS.has(prop)) {
          return { name: CALLBACK_METHODS.get(prop), confidence: "medium", evidence: `usage:${prop}(x)` };
        }
        if (prop && HOF_FUNC_HINTS.has(prop)) {
          return { name: HOF_FUNC_HINTS.get(prop), confidence: "medium", evidence: `usage:${prop}(x)` };
        }
        if (a0Name && prop === "emit") {
          return { name: `${a0Name}Emitter`, confidence: "medium", evidence: `usage:emit('${a0.value}', x)` };
        }
      }
      continue;
    }
  }

  // — property-read tally (weaker tier, task rule 3) —
  const tally = (m) => [...m.entries()].sort((a, b) => b[1] - a[1]);
  const topProp = tally(propReads)[0]?.[0];
  const topMethod = tally(methodReads)[0]?.[0];
  if (topProp && !/^length$/.test(topProp)) {
    return { name: `${camelizeSnake(topProp)}Holder`, confidence: "low", evidence: `usage:reads .${topProp}` };
  }
  if (topMethod) {
    if (STRING_METHODS.has(topMethod)) return { name: "text", confidence: "low", evidence: `usage:calls .${topMethod}()` };
    if (ARRAY_METHODS.has(topMethod)) return { name: "items", confidence: "low", evidence: `usage:calls .${topMethod}()` };
    if (MAP_METHODS.has(topMethod)) return { name: "map", confidence: "low", evidence: `usage:calls .${topMethod}()` };
    return { name: `${camelizeSnake(topMethod)}Source`, confidence: "low", evidence: `usage:calls .${topMethod}()` };
  }
  if (topProp === "length") return { name: "items", confidence: "low", evidence: "usage:reads .length" };

  // — structural roles (floor, task rule 4) —
  const role = (name, ev) => ({ name, confidence: "low", evidence: ev, structural: true });
  if (restParam) return role("args", "role:rest-param");
  if (catchParam) return role("err", "role:catch-param");
  if (forOfKind === "in") return role("key", "role:for-in");
  if (forOfKind === "of") return role("item", "role:for-of");
  if (loopCounter || (loopDepth && assigned >= 2)) {
    // pick i/j/k by how many counter-ish names the enclosing fn already has
    return role(strengthOf?.counter ?? "i", "role:loop-counter");
  }
  if (assigned >= 2) return role("acc", "role:accumulator");
  if (assigned === 1) return role("tmp", "role:reassigned");
  if (binding.kind === "param") return role("arg", "role:param");
  return null;
}

/**
 * Param-name evidence from how the OWNER FUNCTION is used as an argument:
 * `arr.reduce((x, y) => ...)` -> x=acc, y=item; `.then(x => )` -> result.
 */
function inferParamFromOwnerCall(binding) {
  if (binding.kind !== "param") return null;
  const fnPath = binding.path.findParent?.((p) => p.isFunction?.());
  if (!fnPath) return null;
  const params = fnPath.node.params ?? [];
  const flat = [];
  const collectParamIds = (n) => {
    if (!n) return;
    if (n.type === "Identifier") flat.push(n.name);
    else if (n.type === "RestElement") collectParamIds(n.argument);
    else if (n.type === "AssignmentPattern") collectParamIds(n.left);
    else if (n.type === "ObjectPattern") {
      for (const pr of n.properties) collectParamIds(pr.type === "RestElement" ? pr.argument : pr.value);
    } else if (n.type === "ArrayPattern") {
      for (const el of n.elements) collectParamIds(el);
    }
  };
  for (const p of params) collectParamIds(p);
  const pos = flat.indexOf(binding.identifier.name);
  if (pos < 0) return null;

  // table: where the owner function is passed as an argument
  const callSites = [];
  // inline: `arr.reduce((x_9be, y_9be) => ...)` — the function expression
  // itself sits in the arg list
  const fnParent = fnPath.parentPath?.node;
  if (
    fnParent &&
    (fnParent.type === "CallExpression" || fnParent.type === "OptionalCallExpression") &&
    fnParent.arguments.includes(fnPath.node)
  ) {
    callSites.push(fnParent);
  }
  // named: `ipcMain.handle('ch', fn_9be)` — find the function-name binding's
  // pass sites
  const ownerName =
    fnPath.node.type === "FunctionDeclaration" && fnPath.node.id ? fnPath.node.id.name
    : fnPath.parentPath?.node?.type === "VariableDeclarator" &&
      fnPath.parentPath.node.id.type === "Identifier" ? fnPath.parentPath.node.id.name
    : null;
  if (ownerName) {
    const ob = fnPath.scope.getBinding(ownerName) ?? binding.scope.getBinding(ownerName);
    for (const ref of ob?.referencePaths ?? []) {
      const pn = ref.parentPath?.node;
      if (
        (pn?.type === "CallExpression" || pn?.type === "OptionalCallExpression") &&
        pn.arguments.includes(ref.node)
      ) {
        callSites.push(pn);
      }
    }
  }

  for (const call of callSites) {
    const callee = call.callee;
    if (callee.type !== "MemberExpression" && callee.type !== "OptionalMemberExpression") continue;
    const prop = memberPropName(callee);
    if (!prop) continue;
    if (HOF_PARAM_HINTS.has(prop)) {
      const table = HOF_PARAM_HINTS.get(prop);
      const hint = table[Math.min(pos, table.length - 1)];
      return { name: hint, confidence: "medium", evidence: `param:${prop}() pos ${pos}` };
    }
    if (prop === "then") return { name: pos === 0 ? "result" : `arg${pos}`, confidence: "medium", evidence: "param:then() " + pos };
    if (prop === "catch") return { name: pos === 0 ? "err" : `arg${pos}`, confidence: "medium", evidence: "param:catch() " + pos };
    if (prop === "finally") return { name: "settled", confidence: "low", evidence: "param:finally()" };
    if (HANDLER_METHODS.has(prop)) {
      // handler signatures: (event, ...args) — pos 0 is the event
      return {
        name: pos === 0 ? "event" : `arg${pos}`,
        confidence: "medium", evidence: `param:${prop}() pos ${pos}`,
      };
    }
  }
  return null;
}

// ==========================================================================
// recoverJsNames
// ==========================================================================

// names that must never be produced nor (re)produced as locals
const GLOBAL_RESERVED = new Set([
  "exports", "module", "require", "arguments", "undefined", "NaN", "Infinity",
  "eval", "globalThis", "global", "window", "self", "console", "Object",
  "Array", "Promise", "Buffer", "process", "__dirname", "__filename", "JSON",
  "Math", "Date", "Error", "TypeError", "RangeError", "Map", "Set", "WeakMap",
  "WeakSet", "Symbol", "Proxy", "Reflect", "parseInt", "parseFloat", "isNaN",
  "isFinite", "fetch", "URL", "URLSearchParams", "TextEncoder", "TextDecoder",
  "BigInt", "WebAssembly", "Intl", "Atomics",
]);

/**
 * @param {string} code JS/TS source
 * @param {object} [report] optional mutable report (inferredRenames/unrenamable set)
 * @returns {{ code: string, renames: Array<{from:string,to:string,confidence:string,evidence:string}>, unrenamable: Array<{name:string,reason:string}> }}
 */
export function recoverJsNames(code, report) {
  const out = { code, renames: [], unrenamable: [] };
  let ast;
  try {
    ast = parse(code, {
      sourceType: "unambiguous",
      plugins: ["typescript", "jsx", "topLevelAwait"],
      allowReturnOutsideFunction: true,
      errorRecovery: true,
    });
  } catch {
    if (report) { report.inferredRenames = out.renames; report.unrenamable = out.unrenamable; }
    return out;
  }

  const isModule = ast.program.sourceType === "module";
  const looksCjs = /(?:^|[^\w$])(?:module\.exports|exports\.[A-Za-z_$]|require\s*\()/.test(code);
  const programScopeIsGlobal = !isModule && !looksCjs; // script carrier

  // — pre-pass: collected hazards —
  const evalScopes = new Set();          // scopes whose bindings eval() may reach
  const exportedLocalNames = new Set();  // local names that ARE the API
  const nameObserved = new Set();        // bindings whose .name/.source is read

  traverse(ast, {
    CallExpression(path) {
      if (
        path.node.callee.type === "Identifier" &&
        path.node.callee.name === "eval" &&
        path.scope.getBinding("eval") === undefined
      ) {
        for (let s = path.scope; s; s = s.parent) evalScopes.add(s);
      }
    },
    ExportSpecifier(path) {
      const local = path.node.local?.name;
      const exported = path.node.exported?.name ?? path.node.exported?.value;
      if (local && (!exported || exported === local)) exportedLocalNames.add(local);
    },
    ExportNamedDeclaration(path) {
      const d = path.node.declaration;
      if (d?.type === "FunctionDeclaration" || d?.type === "ClassDeclaration") {
        if (d.id) exportedLocalNames.add(d.id.name);
      } else if (d?.type === "VariableDeclaration") {
        for (const decl of d.declarations) {
          const collect = (n) => {
            if (!n) return;
            if (n.type === "Identifier") exportedLocalNames.add(n.name);
            else if (n.type === "ObjectPattern") for (const p of n.properties) collect(p.type === "RestElement" ? p.argument : p.value);
            else if (n.type === "ArrayPattern") for (const e of n.elements) collect(e);
            else if (n.type === "RestElement") collect(n.argument);
            else if (n.type === "AssignmentPattern") collect(n.left);
          };
          collect(decl.id);
        }
      }
    },
    ReferencedIdentifier(path) {
      const p = path.parentPath?.node;
      // `x.name`, `x.constructor`, `x.toString` — name/source observed
      if ((p?.type === "MemberExpression" || p?.type === "OptionalMemberExpression") &&
          p.object === path.node && !p.computed && p.property.type === "Identifier" &&
          (p.property.name === "name" || p.property.name === "constructor" ||
           p.property.name === "toString" || p.property.name === "displayName")) {
        nameObserved.add(path.node.name);
      }
    },
  });

  // — candidate pass —
  const bindings = [];
  traverse(ast, {
    Scope(path) {
      for (const [name, binding] of Object.entries(path.scope.bindings)) {
        if (binding.scope !== path.scope) continue;
        bindings.push({ name, binding, scope: path.scope });
      }
    },
  });

  // Scope-aware collision check: a candidate name must not resolve to an
  // existing binding/reference anywhere it's visible — but disjoint scopes
  // MAY reuse a name (that's what the unhardened code looked like anyway).
  const isFree = (scope, nm) =>
    t.isValidIdentifier(nm) && !GLOBAL_RESERVED.has(nm) &&
    !scope.hasBinding(nm) && !scope.hasReference(nm) && !scope.hasGlobal(nm);
  const makeName = (scope, base) => {
    if (!base) return null;
    const candidate = String(base);
    if (!t.isValidIdentifier(candidate) || GLOBAL_RESERVED.has(candidate)) return null;
    if (isFree(scope, candidate)) return candidate;
    for (let i = 2; i < 200; i++) {
      const c = `${candidate}${i}`;
      if (isFree(scope, c)) return c;
    }
    return null;
  };

  // per-scope counter names so multiple loop vars get i/j/k
  const scopeCounterFor = (scope) => {
    for (const c of ["i", "j", "k", "n"]) if (isFree(scope, c)) return c;
    return "i";
  };

  for (const { name, binding, scope } of bindings) {
    const cls = classifyBlaName(name);
    if (!cls.bla) continue;

    const skip = (reason) => {
      out.unrenamable.push({ name, reason });
    };

    // Machinery names belong to injected decoy families, never to renamed
    // user bindings. A decl that survived dehardening under such a name is
    // real code colliding with the family shape — renaming it fabricates
    // provenance; renaming a kept decoy would hide its identity.
    if (cls.style === "machinery") { skip("machinery-name-survived"); continue; }

    // — safety gates —
    if (binding.kind === "module") { skip("import-binding"); continue; }
    if (exportedLocalNames.has(name)) { skip("exported-name-is-api"); continue; }
    if (nameObserved.has(name)) { skip("runtime-name-observed"); continue; }
    if (binding.path.isTSParameterProperty?.() ||
        binding.path.parentPath?.isTSParameterProperty?.()) { skip("ts-parameter-property"); continue; }
    if (programScopeIsGlobal && scope.path.isProgram()) { skip("script-global-scope"); continue; }
    {
      // direct eval() in the binding's own scope or an ancestor of the eval
      // site can read the name inside a string — babel can't see it
      if (evalScopes.has(binding.scope)) { skip("eval-visible-scope"); continue; }
    }

    // — evidence chain, priority order —
    let cand = null;

    // 0. embedded original-name fragment (stealth/balanced renames)
    if (cls.hint && !WEAK_HINT_WORDS.has(cls.hint.toLowerCase()) &&
        cls.hint.length >= 2 && t.isValidIdentifier(cls.hint)) {
      cand = { name: cls.hint, confidence: "high", evidence: `embedded-hint:${cls.style}` };
    }

    // 1. init expression
    if (!cand) {
      const bp = binding.path;
      if (bp.isVariableDeclarator?.() && bp.node.id === binding.identifier) {
        cand = inferFromInit(bp.node.init);
      } else if (bp.node?.type === "VariableDeclarator") {
        cand = inferFromInit(bp.node.init);
      } else if (parentIsAssignToIdentifier(binding)) {
        cand = inferFromInit(binding.path.parentPath.node.right);
      } else if (bp.isFunctionDeclaration?.() || bp.isFunctionExpression?.() ||
                 bp.isArrowFunctionExpression?.()) {
        cand = null; // functions get usage evidence below
      }
    }

    // 2. usage / call-site evidence — wins on strictly higher confidence,
    //    and structural roles (loop counters etc.) beat a low-confidence
    //    literal-shape guess (`for (x = 0…)` is `i`, not `num`).
    {
      const usage = inferFromUsage(binding, { counter: scopeCounterFor(scope) });
      if (usage &&
          (!cand ||
           confidenceRank(usage.confidence) > confidenceRank(cand.confidence) ||
           (usage.structural && confidenceRank(cand.confidence) === 1))) {
        cand = usage;
      }
    }

    // 3. param-of-callback positional hints
    if (binding.kind === "param" &&
        (!cand || confidenceRank(cand.confidence) < confidenceRank("medium"))) {
      const p = inferParamFromOwnerCall(binding);
      if (p && (!cand || confidenceRank(p.confidence) > confidenceRank(cand.confidence))) {
        cand = p;
      }
    }

    // 4. structural floor — strong shapes only (weak + nothing = unrenamable)
    if (!cand && cls.strong) {
      cand = binding.kind === "const"
        ? { name: "value", confidence: "low", evidence: "role:fallback", structural: true }
        : { name: "tmp", confidence: "low", evidence: "role:fallback", structural: true };
      if (binding.kind === "param") cand = { name: "arg", confidence: "low", evidence: "role:fallback", structural: true };
      if (binding.kind === "hoisted") cand = { name: "helper", confidence: "low", evidence: "role:fallback", structural: true };
    }

    if (!cand) { skip("no-evidence"); continue; }
    // evidence gate: generic lowercase-stem suffix names can't be BLA
    // renames at all (probably real) — demand high confidence; other weak
    // shapes need medium; strong shapes accept the structural floor.
    const minRank = cls.style === "generic" ? 3 : cls.strong ? 1 : 2;
    if (confidenceRank(cand.confidence) < minRank) {
      skip("weak-shape-insufficient-evidence"); continue;
    }

    const newName = makeName(scope, cand.name);
    if (!newName || newName === name) { skip("name-collision"); continue; }

    try {
      binding.scope.rename(name, newName);
    } catch {
      skip("rename-failed");
      continue;
    }
    out.renames.push({ from: name, to: newName, confidence: cand.confidence, evidence: cand.evidence });
  }

  // post-rename polish: `{ foo: foo }` → `{ foo }` — renames can collapse a
  // property onto its key; Babel won't shorthand unless the flag is set.
  traverse(ast, {
    ObjectProperty(path) {
      const p = path.node;
      if (!p.computed && !p.shorthand &&
          p.key?.type === "Identifier" && p.value?.type === "Identifier" &&
          p.key.name === p.value.name) {
        p.shorthand = true;
      }
    },
  });

  try {
    out.code = generate(ast, { comments: true, compact: false }).code;
  } catch {
    out.code = code;
    out.renames = [];
    out.unrenamable = [];
  }
  if (report) {
    report.inferredRenames = out.renames;
    report.unrenamable = out.unrenamable;
  }
  return out;
}

function confidenceRank(c) {
  return c === "high" ? 3 : c === "medium" ? 2 : 1;
}

/** `x_9be = <init>` (declaration-less assignment) — rare but cheap to cover. */
function parentIsAssignToIdentifier(binding) {
  const p = binding.path?.parentPath?.node;
  return p?.type === "AssignmentExpression" && p.left === binding.path?.node;
}

// ==========================================================================
// recoverWasmExports
// ==========================================================================

// — LEB128 helpers (same loose conventions as src/formats.mjs) —
function readU32Leb(buf, off) {
  let v = 0, shift = 0, i = off;
  for (;;) {
    if (i >= buf.length || i - off >= 5) return [v >>> 0, i];
    const b = buf[i++];
    v |= (b & 0x7f) << shift;
    if (!(b & 0x80)) return [v >>> 0, i];
    shift += 7;
  }
}
function writeU32Leb(n) {
  const out = [];
  let v = n >>> 0;
  do { let b = v & 0x7f; v >>>= 7; if (v) b |= 0x80; out.push(b); } while (v);
  return Buffer.from(out);
}
const wasmName = (s) => {
  const b = Buffer.from(s, "utf8");
  return Buffer.concat([writeU32Leb(b.length), b]);
};

const VALTYPE = {
  0x7f: "i32", 0x7e: "i64", 0x7d: "f32", 0x7c: "f64",
  0x7b: "v128", 0x70: "funcref", 0x6f: "externref",
};
const vt = (b) => VALTYPE[b] ?? `ref${b.toString(16)}`;

// BLA WASM export-name shapes (vendor/bla/src/shields/formats/wasm.ts):
//   renamed real : `ops_${hex4}_${snake(a_b_dispatch_hex3)}`
//   decoys       : `enclave_export_${hex4}_${i}_${"e"*pad}` / canary_export_* / enclave_unseal_*
const WASM_DECOY_EXPORT = /^enclave_export_[0-9a-f]{4}_\d+_e+$|^canary_export|^enclave_unseal_/i;
const WASM_OPS_NAME = /^ops_(?:[0-9a-f]{4}_[A-Za-z][A-Za-z0-9_]*|[0-9a-f]{4,})$/i;
const WASM_HONEY = /tee_hardware_enclave_transport_stub_|enclave\.internal|\[BLA[-\]]|BLA_CANARY|PROTECTED_CANARY/i;

// signature -> candidate names, in order of preference for repeated hits
const SIG_HINTS = new Map([
  ["(i32,i32)->i32", ["add", "compute", "combine", "evaluate"]],
  ["(i32,i32,i32)->i32", ["dispatch", "handle", "process"]],
  ["(i32,i32,i32,i32)->i32", ["transfer", "transform"]],
  ["(i32)->i32", ["hash", "transform", "process"]],
  ["(i32,i64)->i32", ["compute", "combine"]],
  ["(i64,i64)->i64", ["addWide", "computeWide"]],
  ["()->i32", ["getStatus", "version", "readState"]],
  ["()->i64", ["getCounter", "readWideState"]],
  ["(i32)->()", ["configure", "write", "setState"]],
  ["(i32,i32)->()", ["store", "copy", "commit"]],
  ["()->()", ["init", "reset", "tick"]],
  ["(i32,i32,i32)->()", ["write", "commit", "flush"]],
]);

/**
 * Parse a `name` custom-section payload -> { moduleName, funcNames }.
 * Honey/decoy fragments are filtered out.
 */
function parseNameSection(content) {
  const out = { moduleName: null, funcNames: new Map() };
  let p = 0;
  while (p < content.length) {
    const subId = content[p++];
    const [size, after] = readU32Leb(content, p);
    const end = Math.min(content.length, after + size);
    const sub = content.subarray(after, end);
    p = end;
    try {
      if (subId === 0) { // module name
        const [nl, ns] = readU32Leb(sub, 0);
        const nm = sub.subarray(ns, ns + nl).toString("utf8");
        if (nm && !WASM_HONEY.test(nm)) out.moduleName = nm;
      } else if (subId === 1) { // function names
        const [count, q0] = readU32Leb(sub, 0);
        let q = q0;
        for (let i = 0; i < count && q < sub.length; i++) {
          const [idx, qi] = readU32Leb(sub, q);
          const [nl, ns] = readU32Leb(sub, qi);
          const nm = sub.subarray(ns, ns + nl).toString("utf8");
          q = ns + nl;
          if (nm && !WASM_HONEY.test(nm) && !WASM_OPS_NAME.test(nm) &&
              !WASM_DECOY_EXPORT.test(nm)) {
            out.funcNames.set(idx, nm);
          }
        }
      }
      // other subsections ignored
    } catch { /* malformed subsection — keep walking */ }
  }
  return out;
}

/**
 * Skip an import descriptor; returns offset after it (or -1 on malformed).
 */
function skipImportDesc(buf, off, kind) {
  switch (kind) {
    case 0: { const [, e] = readU32Leb(buf, off); return e; }           // func typeidx
    case 1: {                                                          // table: reftype + limits
      const [, e] = readU32Leb(buf, off + 1); // elemtype byte + limits flags
      const flags = buf[off + 1];
      let p = e;
      const [, p1] = readU32Leb(buf, p); p = p1;                       // min
      if (flags & 0x01) { const [, p2] = readU32Leb(buf, p); p = p2; } // max
      return p;
    }
    case 2: {                                                          // mem: limits
      const flags = buf[off];
      let [, p] = [0, off + 1];
      const [, p1] = readU32Leb(buf, p); p = p1;
      if (flags & 0x01) { const [, p2] = readU32Leb(buf, p); p = p2; }
      return p;
    }
    case 3: return off + 2;                                            // global: valtype + mut
    case 4: { const [, e] = readU32Leb(buf, off + 1); return e; }        // tag: attr + typeidx
    default: return -1;
  }
}

/**
 * Extract a semantic hint from an ops_* name's tail: strip the ops_<hex4>
 * prefix, `dispatch` markers, snake vocabulary words and the trailing hex
 * tag — whatever words remain are the only non-random part of the name.
 */
function opsNameTailHint(name) {
  const m = /^ops_[0-9a-f]{4}_(.+)$/i.exec(name);
  if (!m) return null;
  const words = m[1].split("_").filter(Boolean);
  const keep = [];
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (i === words.length - 1 && /^[0-9a-f]{3,4}$/.test(w)) continue; // trailing tag
    if (w === "dispatch" || SNAKE_SET.has(w)) continue;                 // machinery/vocab
    keep.push(w);
  }
  if (keep.length === 0) return null;
  const c = camelizeSnake(keep.join("_"));
  return c && IDENTISH.test(c) && !WEAK_HINT_WORDS.has(c.toLowerCase()) ? c : null;
}

/**
 * @param {Buffer} wasm raw .wasm binary
 * @returns {{ names: Array<object>, nameSection?: Buffer }}
 */
export function recoverWasmExports(wasm) {
  if (wasm == null) return { names: [], note: "no input — passthrough" };
  if (!Buffer.isBuffer(wasm)) {
    try { wasm = Buffer.from(wasm); } catch { return { names: [], note: "unconvertible input — passthrough" }; }
  }
  if (wasm.length < 8 || wasm.readUInt32LE(0) !== 0x6d736100) {
    return { names: [], note: "bad magic — passthrough" };
  }

  // — section walk (same loose bounds policy as scrubWasm) —
  const sections = [];
  let off = 8;
  while (off < wasm.length) {
    const id = wasm[off++];
    const [size, after] = readU32Leb(wasm, off);
    sections.push({ id, payload: wasm.subarray(after, Math.min(wasm.length, after + size)) });
    off = after + size;
  }

  // — type section: full signatures —
  const types = [];
  // — import section: function typeidx per imported func —
  const importedFuncTypes = [];
  // — func section: typeidx per defined func —
  const definedFuncTypes = [];
  // — export section: entries —
  const exports = [];
  // — surviving name-section fragment —
  const fragment = { moduleName: null, funcNames: new Map() };

  for (const s of sections) {
    if (s.id === 1) {
      const [count, p0] = readU32Leb(s.payload, 0);
      let p = p0;
      for (let i = 0; i < count && p < s.payload.length; i++) {
        if (s.payload[p++] !== 0x60) break;
        const [np, ap] = readU32Leb(s.payload, p);
        const params = [...s.payload.subarray(ap, ap + np)].map(vt);
        p = ap + np;
        const [nr, ar] = readU32Leb(s.payload, p);
        const results = [...s.payload.subarray(ar, ar + nr)].map(vt);
        p = ar + nr;
        types.push({ params, results });
      }
    } else if (s.id === 2) {
      const [count, p0] = readU32Leb(s.payload, 0);
      let p = p0;
      for (let i = 0; i < count && p < s.payload.length; i++) {
        const [ml, ms] = readU32Leb(s.payload, p); p = ms + ml;
        const [nl, ns] = readU32Leb(s.payload, p); p = ns + nl;
        const kind = s.payload[p++];
        const afterDesc = skipImportDesc(s.payload, p, kind);
        if (kind === 0) {
          const [tidx] = readU32Leb(s.payload, p);
          importedFuncTypes.push(tidx);
        }
        if (afterDesc < 0) break;
        p = afterDesc;
      }
    } else if (s.id === 3) {
      const [count, p0] = readU32Leb(s.payload, 0);
      let p = p0;
      for (let i = 0; i < count && p < s.payload.length; i++) {
        const [tidx, e] = readU32Leb(s.payload, p);
        definedFuncTypes.push(tidx);
        p = e;
      }
    } else if (s.id === 7) {
      const [count, p0] = readU32Leb(s.payload, 0);
      let p = p0;
      for (let i = 0; i < count && p < s.payload.length; i++) {
        const [nl, ns] = readU32Leb(s.payload, p);
        if (ns + nl + 1 > s.payload.length) break;
        const nm = s.payload.subarray(ns, ns + nl).toString("utf8");
        const kind = s.payload[ns + nl];
        const [idx, e] = readU32Leb(s.payload, ns + nl + 1);
        exports.push({ name: nm, kind, index: idx });
        p = e;
      }
    } else if (s.id === 0) {
      const [nl, ns] = readU32Leb(s.payload, 0);
      const cn = s.payload.subarray(ns, ns + nl).toString("utf8");
      if (cn === "name") {
        const frag = parseNameSection(s.payload.subarray(ns + nl));
        if (frag.moduleName && !fragment.moduleName) fragment.moduleName = frag.moduleName;
        for (const [k, v] of frag.funcNames) if (!fragment.funcNames.has(k)) fragment.funcNames.set(k, v);
      }
    }
  }

  const funcCount = importedFuncTypes.length + definedFuncTypes.length;
  const typeIndexOf = (funcIdx) =>
    funcIdx < importedFuncTypes.length
      ? importedFuncTypes[funcIdx]
      : definedFuncTypes[funcIdx - importedFuncTypes.length];
  const sigOf = (funcIdx) => {
    const ti = typeIndexOf(funcIdx);
    const ty = ti !== undefined && ti < types.length ? types[ti] : null;
    return ty ? `(${ty.params.join(",")})->${ty.results.join(",") || "void"}`.replace("->void", "->") : null;
  };

  const names = [];
  const emittedFuncNames = new Map(); // funcIdx -> chosen name for name section
  const usedSuggestions = new Set();
  const sigUseCount = new Map();

  const pickSuggestion = (base) => {
    let c = base;
    let i = 2;
    while (usedSuggestions.has(c)) c = `${base}${i++}`;
    usedSuggestions.add(c);
    return c;
  };

  for (const e of exports) {
    // decoys: flagged, nothing meaningful to name (scrubber drops them)
    if (WASM_DECOY_EXPORT.test(e.name)) {
      names.push({
        index: e.index, kind: e.kind, from: e.name,
        suggested: null, confidence: "high", decoy: true,
        evidence: "bla-decoy-export",
      });
      continue;
    }

    const renamed = WASM_OPS_NAME.test(e.name) ||
      (e.kind === 0 && /^ops_[0-9a-f]{4}_/i.test(e.name));
    if (!renamed) {
      // real export name survives — still feed the name section for funcs
      if (e.kind === 0 && e.index < funcCount && !fragment.funcNames.has(e.index)) {
        emittedFuncNames.set(e.index, e.name);
      }
      continue;
    }

    let suggested = null, confidence = "low", evidence = "signature-fallback";

    // rule 1: surviving name-section fragment
    if (fragment.funcNames.has(e.index)) {
      suggested = fragment.funcNames.get(e.index);
      confidence = "high";
      evidence = "surviving-name-section";
    }
    // rule 2: embedded non-vocab tail in the ops name itself
    if (!suggested) {
      const tail = opsNameTailHint(e.name);
      if (tail) {
        suggested = tail;
        confidence = "medium";
        evidence = "embedded-name-fragment";
      }
    }
    // rule 3: signature + position heuristic
    if (!suggested) {
      const sig = e.kind === 0 ? sigOf(e.index) : null;
      if (sig) {
        const table = SIG_HINTS.get(sig);
        const seen = sigUseCount.get(sig) ?? 0;
        sigUseCount.set(sig, seen + 1);
        if (table) {
          suggested = table[Math.min(seen, table.length - 1)];
          // index-0 (i32,i32)->i32 is conventionally add/main-style
          if (e.index === 0 && sig === "(i32,i32)->i32" && seen === 0) suggested = "add";
          confidence = "medium";
          evidence = `signature-heuristic:${sig}`;
        } else {
          suggested = `op_${e.index}`;
          confidence = "low";
          evidence = `signature-unmapped:${sig}`;
        }
      } else if (e.kind !== 0) {
        suggested = `${["func", "table", "memory", "global"][e.kind] ?? "export"}_${e.index}`;
        confidence = "low";
        evidence = "kind-fallback";
      }
    }
    // rule 4: mechanical fallback
    if (!suggested) {
      suggested = `export_${e.index}`;
      confidence = "low";
      evidence = "index-fallback";
    }

    suggested = pickSuggestion(suggested);
    names.push({ index: e.index, kind: e.kind, from: e.name, suggested, confidence, evidence });
    if (e.kind === 0 && e.index < funcCount) emittedFuncNames.set(e.index, suggested);
  }

  // fold in surviving fragment names for funcs we haven't named yet
  for (const [idx, nm] of fragment.funcNames) {
    if (idx < funcCount && !emittedFuncNames.has(idx)) emittedFuncNames.set(idx, nm);
  }

  // — build the `name` custom section (tooling-only; never touches exports) —
  let nameSection;
  const subsections = [];
  if (fragment.moduleName) {
    const enc = wasmName(fragment.moduleName);
    subsections.push(Buffer.concat([Buffer.from([0x00]), writeU32Leb(enc.length), enc]));
  }
  if (emittedFuncNames.size > 0) {
    const entries = [...emittedFuncNames.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([idx, nm]) => Buffer.concat([writeU32Leb(idx), wasmName(nm)]));
    const payload = Buffer.concat([writeU32Leb(entries.length), ...entries]);
    subsections.push(Buffer.concat([Buffer.from([0x01]), writeU32Leb(payload.length), payload]));
  }
  if (subsections.length > 0) {
    const body = Buffer.concat([wasmName("name"), ...subsections]);
    nameSection = Buffer.concat([Buffer.from([0x00]), writeU32Leb(body.length), body]);
  }

  return { names, nameSection };
}
