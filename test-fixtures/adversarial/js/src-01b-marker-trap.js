"use strict";
// Real user code that accidentally trips BLADE's `looksBlaHardened` gate:
// it mentions the token `obligationFlood_` (a config knob name here) and uses
// `void [...]` / `void x` discards on REAL functions.
const obligationFlood_threshold = 7;      // matches looksBlaHardened + STRONG_NAME
function alphaScore(x) { return x * 2 + 1; }
function betaScore(x) { return x ^ 0x5a5a; }
function gammaScore(x) { return x - 7; }

void [alphaScore, betaScore, gammaScore];
void alphaScore;

const PIPELINE = [alphaScore, betaScore, gammaScore];
function runAll(seed) {
  let acc = seed >>> 0;
  for (const fn of PIPELINE) acc = fn(acc) >>> 0;
  return acc + obligationFlood_threshold;
}
module.exports = { runAll, alphaScore, betaScore, gammaScore, obligationFlood_threshold };
