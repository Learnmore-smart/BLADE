function measureIntegrityNestedShard_5213() {
  var digest = 0;
  try {
    var _c = require("node:crypto");
    var _fs = require("node:fs");
    var _path = require("node:path");
    var h = _c.createHash("sha256");
    var selfPath = (typeof __filename === "string" ? __filename : null);
    if (!selfPath && typeof __dirname === "string") selfPath = _path.join(__dirname, "index.js");
    var selfBuf = null;
    if (selfPath) { try { selfBuf = _fs.readFileSync(selfPath); h.update(selfBuf); } catch (_e) { selfBuf = null; } }
    var selfExpected = "~self-digest-pending-finalize~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~";
    if (selfBuf && /^[0-9a-f]{64}$/.test(selfExpected)) {
      var _lit = Buffer.from(selfExpected, "latin1");
      var _zero = Buffer.alloc(64, 0x30);
      var _canon = Buffer.from(selfBuf);
      for (var _at = _canon.indexOf(_lit); _at !== -1; _at = _canon.indexOf(_lit, _at + 64)) _zero.copy(_canon, _at);
      if (_c.createHash("sha256").update(_canon).digest("hex") !== selfExpected) {
        throw new Error("integrity check failed");
      }
    }
    var siblings = [];
    var expected = {};
    for (var i = 0; i < siblings.length; i++) {
      try {
        var spKey = siblings[i];
        var sp = spKey;
        if (!_path.isAbsolute(sp) && typeof __dirname === "string") sp = _path.join(__dirname, sp);
        var sibBuf = _fs.readFileSync(sp);
        var sibHex = _c.createHash("sha256").update(sibBuf).digest("hex");
        if (expected[spKey] && expected[spKey] !== sibHex) {
          throw new Error("integrity check failed");
        }
        h.update(sp);
        h.update(sibBuf);
      } catch (_e2) {
        if (_e2 && _e2.message === "integrity check failed") throw _e2;
        if (expected[String(siblings[i])]) throw new Error("integrity check failed");
        h.update("missing:" + String(siblings[i]));
      }
    }
    var envNote = "";
    try {
      envNote += String(process.env.NODE_OPTIONS || "");
      envNote += (process.execArgv || []).join(",");
      envNote += (/\[native code\]/.test(Function.prototype.toString.call(Function.prototype.toString)) ? "N" : "T");
    } catch (_e3) { envNote += "E"; }
    h.update(envNote);
    var hex = h.digest("hex");
    digest = parseInt(hex.slice(0, 8), 16) >>> 0;
  } catch (_e4) {
    if (_e4 && _e4.message === "integrity check failed") throw _e4;
    digest = 0;
  }
  return digest >>> 0;
}
function measureIntegrity1SealedPool_8aa0() {
  var digest = 0;
  try {
    var _c = require("node:crypto");
    var _fs = require("node:fs");
    var _path = require("node:path");
    var h = _c.createHash("sha256");
    var selfPath = (typeof __filename === "string" ? __filename : null);
    if (!selfPath && typeof __dirname === "string") selfPath = _path.join(__dirname, "index.js");
    var selfBuf = null;
    if (selfPath) { try { selfBuf = _fs.readFileSync(selfPath); h.update(selfBuf); } catch (_e) { selfBuf = null; } }
    var selfExpected = "~self-digest-pending-finalize~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~";
    if (selfBuf && /^[0-9a-f]{64}$/.test(selfExpected)) {
      var _lit = Buffer.from(selfExpected, "latin1");
      var _zero = Buffer.alloc(64, 0x30);
      var _canon = Buffer.from(selfBuf);
      for (var _at = _canon.indexOf(_lit); _at !== -1; _at = _canon.indexOf(_lit, _at + 64)) _zero.copy(_canon, _at);
      if (_c.createHash("sha256").update(_canon).digest("hex") !== selfExpected) {
        throw new Error("integrity check failed");
      }
    }
    var siblings = [];
    var expected = {};
    for (var i = 0; i < siblings.length; i++) {
      try {
        var spKey = siblings[i];
        var sp = spKey;
        if (!_path.isAbsolute(sp) && typeof __dirname === "string") sp = _path.join(__dirname, sp);
        var sibBuf = _fs.readFileSync(sp);
        var sibHex = _c.createHash("sha256").update(sibBuf).digest("hex");
        if (expected[spKey] && expected[spKey] !== sibHex) {
          throw new Error("integrity check failed");
        }
        h.update(sp);
        h.update(sibBuf);
      } catch (_e2) {
        if (_e2 && _e2.message === "integrity check failed") throw _e2;
        if (expected[String(siblings[i])]) throw new Error("integrity check failed");
        h.update("missing:" + String(siblings[i]));
      }
    }
    var envNote = "";
    try {
      envNote += String(process.env.NODE_OPTIONS || "");
      envNote += (process.execArgv || []).join(",");
      envNote += (/\[native code\]/.test(Function.prototype.toString.call(Function.prototype.toString)) ? "N" : "T");
    } catch (_e3) { envNote += "E"; }
    h.update(envNote);
    var hex = h.digest("hex");
    digest = parseInt(hex.slice(0, 8), 16) >>> 0;
  } catch (_e4) {
    if (_e4 && _e4.message === "integrity check failed") throw _e4;
    digest = 0;
  }
  return digest >>> 0;
}
var integrityDigestCompositeScope_d806 = (measureIntegrityNestedShard_5213() ^ measureIntegrity1SealedPool_8aa0()) >>> 0;