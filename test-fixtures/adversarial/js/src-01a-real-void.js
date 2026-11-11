"use strict";
// Real user code — NOT hardened. Contains an obscure-but-legal `void [...]`
// expression statement (comma-free index array of live functions) and a
// `void ident` statement.
function alphaScore(x) { return x * 2 + 1; }
function betaScore(x) { return x ^ 0x5a5a; }
function gammaScore(x) { return x - 7; }

void [alphaScore, betaScore, gammaScore];   // keep refs alive for a linter pass
void alphaScore;                             // legal: evaluates & discards

const PIPELINE = [alphaScore, betaScore, gammaScore];
function runAll(seed) {
  let acc = seed >>> 0;
  for (const fn of PIPELINE) acc = fn(acc) >>> 0;
  return acc;
}
module.exports = { runAll, alphaScore, betaScore, gammaScore };
