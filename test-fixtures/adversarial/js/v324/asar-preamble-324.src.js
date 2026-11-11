"use strict";
(function(){
  var __expected = "60d0eefc6323e3be33245f494203deefa7ab36508ceb22feca85ee91eec70492";
  var __blaAsarSidecarDigest = 0;
  try {
    var _c = require("node:crypto");
    var _fs = require("node:fs");
    var _path = require("node:path");
    var h = _c.createHash("sha256");
    var entryLabel = "app2.hardened.asar";
    h.update(entryLabel);
    h.update(String.fromCharCode(0));
    var sidecars = ["enclave/hardware-tee-bridge.js"];
    var reads = ["enclave/hardware-tee-bridge.js"];
    for (var i = 0; i < sidecars.length; i++) {
      var sp = sidecars[i];
      var spAbs = reads[i];
      if (!_path.isAbsolute(spAbs) && typeof __dirname === "string") spAbs = _path.join(__dirname, spAbs);
      h.update(sp);
      h.update(String.fromCharCode(0));
      try { h.update(_fs.readFileSync(spAbs)); } catch (_e1) { h.update("missing:" + String(sp)); }
      h.update(String.fromCharCode(0));
    }
    h.update("gen-324");
    var hex = h.digest("hex");
    __blaAsarSidecarDigest = parseInt(hex.slice(0, 8), 16) >>> 0;
    if (hex !== __expected) { throw new Error("integrity binding mismatch"); }
  } catch (_e2) {
    if (_e2 && _e2.message === "integrity binding mismatch") throw _e2;
    throw new Error("integrity binding mismatch");
  }
  return __blaAsarSidecarDigest;
})();
const GREETING = "hello v324";
module.exports = { GREETING };
