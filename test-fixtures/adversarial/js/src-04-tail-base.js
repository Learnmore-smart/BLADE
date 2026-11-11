"use strict";
// Base real module used to build the case-4 variants (code after/inside the
// injected suffix region).
function baseCalc(x) {
  const r = x * 3 + 11;
  return r >>> 0;
}
module.exports = { baseCalc };
