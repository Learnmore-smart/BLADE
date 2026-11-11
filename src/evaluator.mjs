// BLADE partial evaluator.
// Evaluates pure JS expression subtrees against a table of known constants.
// Designed around BLA's opaque-predicate families so `Math.imul(seed^k, seed^k)&7`,
// `Math.imul(seed|k, (seed|k)+1)&1`, `7x^2-1===y^2`, `(x^y)+((x&y)<<1)===x+y`,
// and `s|~s===-1` all fold when `seed` is bound to ANY concrete int32 of the
// correct parity (the predicate outcomes only depend on seed parity; BLA emits
// seeds that are odd while the file is intact).
const KNOWN = (value) => ({ known: true, value });
const UNKNOWN = { known: false };

const MATH_FNS = {
  imul: (a, b) => Math.imul(a | 0, b | 0),
  min: (...xs) => Math.min(...xs),
  max: (...xs) => Math.max(...xs),
  abs: Math.abs,
  floor: Math.floor,
  ceil: Math.ceil,
  round: Math.round,
  trunc: Math.trunc,
  sign: Math.sign,
  clz32: (a) => Math.clz32(a >>> 0),
  pow: Math.pow,
};
const GLOBAL_FNS = {
  String: (x) => String(x),
  Number: (x) => Number(x),
  Boolean: (x) => !!x,
  parseInt: (s, r) => parseInt(s, r),
  parseFloat: (s) => parseFloat(s),
};

/**
 * Partial evaluator over Babel AST: folds literals, arithmetic, string
 * ops and pure builtins; bound at depth 512 so BLA's deliberately deep
 * expression chains can't blow up analysis. Unknown subexpressions yield
 * a poisoned UNKNOWN that taints the whole fold.
 * @param {Map<string,*>} constValues  known constant bindings by name
 * @returns {(node: object) => { v: * } | UNKNOWN-tagged result}
 */
export function makeEvaluator(constValues = new Map()) {
  function ev(node, depth = 0) {
    // Bound evaluation depth: BLA emits deliberately deep expression chains to
    // blow up analyzers; past this budget we leave the node unevaluated.
    if (depth > 512 || !node) return UNKNOWN;
    switch (node.type) {
      case "NumericLiteral":
      case "StringLiteral":
      case "BooleanLiteral":
        return KNOWN(node.value);
      case "NullLiteral":
        return KNOWN(null);
      case "Identifier":
        if (node.name === "undefined") return KNOWN(undefined);
        if (node.name === "NaN") return KNOWN(NaN);
        if (node.name === "Infinity") return KNOWN(Infinity);
        if (constValues.has(node.name)) return KNOWN(constValues.get(node.name));
        return UNKNOWN;
      case "ParenthesizedExpression":
      case "TSAsExpression":
      case "TSSatisfiesExpression":
      case "TSNonNullExpression":
      case "TypeCastExpression":
        return ev(node.expression, depth + 1);
      case "SequenceExpression": {
        let last = UNKNOWN;
        for (const e of node.expressions) {
          last = ev(e, depth + 1);
          if (!last.known) return UNKNOWN;
        }
        return last;
      }
      case "TemplateLiteral": {
        let out = "";
        for (let i = 0; i < node.quasis.length; i++) {
          out += node.quasis[i].value.cooked ?? "";
          if (i < node.expressions.length) {
            const r = ev(node.expressions[i], depth + 1);
            if (!r.known) return UNKNOWN;
            out += String(r.value);
          }
        }
        return KNOWN(out);
      }
      case "UnaryExpression": {
        if (node.operator === "typeof" && node.argument.type === "Identifier") {
          const v = ev(node.argument, depth + 1);
          if (!v.known) return UNKNOWN;
          return KNOWN(typeof v.value);
        }
        const a = ev(node.argument, depth + 1);
        if (!a.known) return UNKNOWN;
        switch (node.operator) {
          case "-": return KNOWN(-a.value);
          case "+": return KNOWN(+a.value);
          case "~": return KNOWN(~a.value | 0);
          case "!": return KNOWN(!a.value);
          case "typeof": return KNOWN(typeof a.value);
          case "void": return KNOWN(undefined);
          case "delete": return UNKNOWN;
          default: return UNKNOWN;
        }
      }
      case "LogicalExpression": {
        const l = ev(node.left, depth + 1);
        if (!l.known) return UNKNOWN;
        const truthy = !!l.value;
        if (node.operator === "&&") return truthy ? ev(node.right, depth + 1) : l;
        if (node.operator === "||") return truthy ? l : ev(node.right, depth + 1);
        if (node.operator === "??")
          return l.value === null || l.value === undefined ? ev(node.right, depth + 1) : l;
        return UNKNOWN;
      }
      case "BinaryExpression": {
        const l = ev(node.left, depth + 1);
        const r = ev(node.right, depth + 1);
        if (!l.known || !r.known) return UNKNOWN;
        const a = l.value, b = r.value;
        switch (node.operator) {
          case "+":
            return KNOWN(typeof a === "string" || typeof b === "string" ? String(a) + String(b) : a + b);
          case "-": return KNOWN(a - b);
          case "*": return KNOWN(a * b);
          case "/": return KNOWN(a / b);
          case "%": return KNOWN(a % b);
          case "**": return KNOWN(a ** b);
          case "|": return KNOWN((a | 0) | (b | 0));
          case "&": return KNOWN((a | 0) & (b | 0));
          case "^": return KNOWN((a | 0) ^ (b | 0));
          case "<<": return KNOWN((a | 0) << (b & 31));
          case ">>": return KNOWN((a | 0) >> (b & 31));
          case ">>>": return KNOWN((a >>> 0) >>> (b & 31));
          case "==": return KNOWN(a == b);
          case "!=": return KNOWN(a != b);
          case "===": return KNOWN(a === b);
          case "!==": return KNOWN(a !== b);
          case "<": return KNOWN(a < b);
          case "<=": return KNOWN(a <= b);
          case ">": return KNOWN(a > b);
          case ">=": return KNOWN(a >= b);
          default: return UNKNOWN;
        }
      }
      case "ConditionalExpression": {
        const t = ev(node.test, depth + 1);
        if (!t.known) return UNKNOWN;
        return ev(t.value ? node.consequent : node.alternate, depth + 1);
      }
      case "MemberExpression":
      case "OptionalMemberExpression": {
        const o = ev(node.object, depth + 1);
        if (!o.known) return UNKNOWN;
        if (o.value === null || o.value === undefined) return UNKNOWN;
        let key;
        if (node.computed) {
          const k = ev(node.property, depth + 1);
          if (!k.known) return UNKNOWN;
          key = k.value;
        } else {
          if (node.property.type !== "Identifier") return UNKNOWN;
          key = node.property.name;
        }
        try {
          return KNOWN(o.value[key]);
        } catch {
          return UNKNOWN;
        }
      }
      case "CallExpression":
      case "OptionalCallExpression": {
        const callee = node.callee;
        // Math.<fn>(...) and global fns
        if (callee.type === "MemberExpression" && !callee.computed &&
            callee.object.type === "Identifier" && callee.object.name === "Math" &&
            callee.property.type === "Identifier" && MATH_FNS[callee.property.name]) {
          const args = [];
          for (const a of node.arguments) {
            const r = ev(a, depth + 1);
            if (!r.known) return UNKNOWN;
            args.push(r.value);
          }
          return KNOWN(MATH_FNS[callee.property.name](...args));
        }
        if (callee.type === "Identifier" && GLOBAL_FNS[callee.name]) {
          const args = [];
          for (const a of node.arguments) {
            const r = ev(a, depth + 1);
            if (!r.known) return UNKNOWN;
            args.push(r.value);
          }
          return KNOWN(GLOBAL_FNS[callee.name](...args));
        }
        // obj.method(...) where obj is a known string/array and method is pure
        if (callee.type === "MemberExpression" && !callee.computed && callee.property.type === "Identifier") {
          const o = ev(callee.object, depth + 1);
          if (o.known && (typeof o.value === "string" || Array.isArray(o.value))) {
            const m = callee.property.name;
            const PURE = ["charCodeAt", "codePointAt", "indexOf", "lastIndexOf", "charAt", "at", "includes", "startsWith", "endsWith", "slice", "substring", "toLowerCase", "toUpperCase", "trim", "concat", "join"];
            if (PURE.includes(m)) {
              const args = [];
              for (const a of node.arguments) {
                const r = ev(a, depth + 1);
                if (!r.known) return UNKNOWN;
                args.push(r.value);
              }
              try {
                return KNOWN(o.value[m](...args));
              } catch {
                return UNKNOWN;
              }
            }
          }
        }
        return UNKNOWN;
      }
      case "ArrayExpression": {
        const out = [];
        for (const el of node.elements) {
          if (!el || el.type === "SpreadElement") return UNKNOWN;
          const r = ev(el, depth + 1);
          if (!r.known) return UNKNOWN;
          out.push(r.value);
        }
        return KNOWN(out);
      }
      case "ObjectExpression": {
        const out = {};
        for (const p of node.properties) {
          if (p.type !== "ObjectProperty" || p.computed) return UNKNOWN;
          const k = p.key.type === "Identifier" ? p.key.name : p.key.type === "StringLiteral" ? p.key.value : null;
          if (k === null) return UNKNOWN;
          const v = ev(p.value, depth + 1);
          if (!v.known) return UNKNOWN;
          out[k] = v.value;
        }
        return KNOWN(out);
      }
      default:
        return UNKNOWN;
    }
  }
  return { ev, constValues };
}

// Mirrors vendor/bla/src/shields/deception/cognitive-armor-trigger.ts
// computeContainmentCorpusDigest — the runtime check baked into the seed
// declaration `const <seed> = <base> | (digest(0) === <expected> ? 1 : 0)`.
/** Forward digest over corpus entries (see comment above). */
export function computeContainmentCorpusDigest(entries, seedInput = 0) {
  let acc = ((seedInput | 0) ^ 0x26b5c67b) >>> 0;
  for (const entry of entries) {
    const text = String(entry.coupledAnchorSymbol) + "::" + String(entry.triggerPayload);
    for (let j = 0; j < text.length; j++) {
      acc = Math.imul(acc ^ text.charCodeAt(j), 0x85ebca6b) >>> 0;
      acc = ((acc << 13) | (acc >>> 19)) >>> 0;
    }
  }
  return acc >>> 0;
}

// repairCorpusDigest — invert a single-char corpus tamper using the embedded
// expected digest as the oracle. The hash is a rolling chain of invertible
// steps (imul by an odd constant, rotl13), so the required byte at each
// position is uniquely solvable in O(n): forward states F[i], backward
// required states R[i+1], then b = F[i] ^ inv_step(R[i+1]).
// Returns {entry, field, charIndex, oldChar, newChar, newText} or null when
// the tamper is not a uniquely-printable single-char substitution.
/** Invert a single-char corpus tamper against the embedded expected
 *  digest (see comment above). @returns {object|null} */
export function repairCorpusDigest(entries, expected) {
  const C = 0x85ebca6b;
  // modular inverse of C mod 2^32 (C is odd): Newton's method
  let xi = 1n;
  const M = 0x100000000n, Cb = BigInt(C);
  for (let i = 0; i < 6; i++) xi = (xi * (2n - Cb * xi)) % M;
  const Cinv = Number(xi & 0xffffffffn);
  const rotl13 = (x) => ((x << 13) | (x >>> 19)) >>> 0;
  const rotr13 = (x) => ((x >>> 13) | (x << 19)) >>> 0;
  const chars = [], pos = [];
  entries.forEach((e, k) => {
    const a = String(e.coupledAnchorSymbol), p = String(e.triggerPayload);
    for (let j = 0; j < a.length; j++) { chars.push(a.charCodeAt(j)); pos.push([k, "coupledAnchorSymbol", j]); }
    chars.push(58); pos.push(null); chars.push(58); pos.push(null);
    for (let j = 0; j < p.length; j++) { chars.push(p.charCodeAt(j)); pos.push([k, "triggerPayload", j]); }
  });
  const n = chars.length;
  const F = new Uint32Array(n + 1), R = new Uint32Array(n + 1);
  F[0] = 0x26b5c67b;
  for (let i = 0; i < n; i++) F[i + 1] = rotl13(Math.imul((F[i] ^ chars[i]) >>> 0, C));
  R[n] = expected >>> 0;
  for (let i = n - 1; i >= 0; i--) R[i] = (Math.imul(rotr13(R[i + 1]), Cinv) ^ chars[i]) >>> 0;
  const sols = [];
  for (let i = 0; i < n; i++) {
    if (!pos[i]) continue;
    const b = (F[i] ^ Math.imul(rotr13(R[i + 1]), Cinv)) >>> 0;
    if (b >= 0x20 && b <= 0x7e && b !== chars[i]) sols.push({ i, b, at: pos[i] });
  }
  if (sols.length !== 1) return null;
  const s = sols[0];
  const [k, field, j] = s.at;
  const text = String(entries[k][field]);
  return {
    entry: k, field, charIndex: j,
    oldChar: text[j], newChar: String.fromCharCode(s.b),
    newText: text.slice(0, j) + String.fromCharCode(s.b) + text.slice(j + 1),
  };
}
