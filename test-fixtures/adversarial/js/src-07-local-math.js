"use strict";
// User code with a lexical `Math` binding — BLA renames it to
// `_blaLocalMath*` via generateUidIdentifier before injecting predicates that
// need the ambient Math.imul.
const Math = {
  floor: (x) => x | 0,
  imul: (a, b) => (a * b) | 0,
  tag: "userMath",
};
function useMath(x) {
  return Math.floor(x) + Math.imul(2, 3);
}
function describeMath() {
  return Math.tag + ":" + Math.imul(7, 6);
}
module.exports = { useMath, describeMath };
