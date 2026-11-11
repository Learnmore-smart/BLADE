"use strict";
// Mutable top-level const containers — the dehardener binds const VALUES
// (incl. arrays/objects) into its partial evaluator; reads like QUEUE.length
// then fold against the DECL-TIME snapshot, not the mutated state.
const QUEUE = [];
const CONFIG = { level: 1, hits: 0 };
function push(x) {
  QUEUE.push(x);
  CONFIG.hits++;
  return QUEUE.length;
}
function bump() {
  CONFIG.level++;
  return CONFIG.level;
}
function snapshot() {
  return { q: QUEUE.length, level: CONFIG.level, hits: CONFIG.hits };
}
module.exports = { push, bump, snapshot };
