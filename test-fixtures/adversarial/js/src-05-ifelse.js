"use strict";
// Real if/else inside a function — BLA wraps even-index statements in
// if(opaqueTrue){...}, so this whole if ends up nested inside an opaque guard.
function pickPath(mode, v) {
  let out = 0;
  if (mode === "fast") {
    out = v * 2;
  } else {
    out = v + 100;
  }
  out = out ^ 0xffff;
  return out;
}
function entry(mode, v) {
  return pickPath(mode, v) + 1;
}
module.exports = { entry, pickPath };
