"use strict";
// Real-world-shaped module: async/await, class + getter, labeled statements,
// template literals containing marker-like text, regex literals matching the
// marker regexes, and a mutable top-level const container.
const REGISTRY = [];                    // mutated at runtime
const NAME_RE = /scc_\w+_c\d+n\d+/g;    // regex literal shaped like a marker
const VAULT_RE = /_shadowVault_\w+/;

class KeyRing {
  #cache = new Map();
  constructor(tag) { this.tag = tag; }
  get size() { return this.#cache.size; }
  get label() { return `ring:${this.tag}`; }
  async store(k, v) {
    await Promise.resolve();
    this.#cache.set(k, v);
    REGISTRY.push(k);
    return this.size;
  }
  has(k) { return this.#cache.has(k); }
}

function scanNames(text) {
  const hits = [];
  let m;
  while ((m = NAME_RE.exec(text)) !== null) hits.push(m[0]);
  return hits;
}

async function loadAll(ring, entries) {
  let stored = 0;
  outer: for (const [k, v] of entries) {
    if (k == null) continue outer;
    if (ring.has(k)) break outer;
    stored += await ring.store(k, v);
  }
  return stored;
}

function describe(tag) {
  const tpl = `obligationFlood_${tag} uses scc_ marker families and decorative-deception-signal text`;
  return tpl.length + REGISTRY.length;
}

module.exports = { KeyRing, scanNames, loadAll, describe, REGISTRY };
