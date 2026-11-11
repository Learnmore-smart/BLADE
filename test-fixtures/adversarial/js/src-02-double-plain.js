"use strict";
// Small real module for the double-harden chain test:
// protect -> deharden -> protect(cleaned) -> deharden -> compare semantics.
const MAGIC = 0x9e3779b9;
function mixKey(a, b) {
  let h = (a ^ MAGIC) >>> 0;
  h = Math.imul(h ^ (h >>> 15), 0x85ebca6b) >>> 0;
  h = (h + Math.imul(b, 0xc2b2ae35)) >>> 0;
  return h >>> 0;
}
function sealToken(serial, seat) {
  const payload = serial + "#" + seat;
  let acc = 0;
  for (let i = 0; i < payload.length; i++) acc = mixKey(acc ^ payload.charCodeAt(i), i + 1);
  return "tok_" + acc.toString(16);
}
function checkToken(serial, seat, expected) {
  return sealToken(serial, seat) === expected;
}
module.exports = { mixKey, sealToken, checkToken };
