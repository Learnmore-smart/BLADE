// Runs BLADE's scrubDotnet / scrubIl2cpp (and the MZ routing rule from
// src/cli.mjs `detect`) over the adversarial fixtures and classifies each:
//   PASS              hardened:true, output === pristine real bytes
//   MISROUTE          BLADE routed the file to the wrong scrubber / a decoy
//                     trailer survives unreported
//   REAL-CONTENT-CUT  the marker cut removed bytes that belong to the
//                     original artifact
//   PARSE-FAIL        scrubber threw / crashed
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scrubDotnet, scrubIl2cpp, scrubNative } from "../../../src/trailer.mjs";

const dir = dirname(fileURLToPath(import.meta.url));
const exp = join(dir, "expected");

// Replica of src/cli.mjs detect() MZ branch (lines 43-45):
//   MZ -> buf.includes("BSJB") ? "dotnet" : "native"
function blaDeDetect(buf) {
  if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) {
    return buf.includes(Buffer.from("BSJB", "ascii")) ? "dotnet" : "native";
  }
  if (buf.length >= 4 && buf.readUInt32LE(0) === 0xfab11baf) return "il2cpp";
  return "other";
}
// And vendor/bla's own detector (first-4096-byte header sniff) for context.
function vendorBlaDetect(buf) {
  const header = buf.subarray(0, 4096);
  if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) {
    return header.includes(Buffer.from("BSJB", "ascii")) ? "dotnet-managed" : "native-pe";
  }
  if (buf.length >= 4 && buf.readUInt32LE(0) === 0xfab11baf) return "il2cpp-metadata";
  return "other";
}

const files = readdirSync(dir).filter((f) => /\.(dll|dat|exe)$/.test(f));
const rows = [];
for (const f of files.sort()) {
  const hardened = readFileSync(join(dir, f));
  const realPath = join(exp, f + ".real");
  const real = existsSync(realPath) ? readFileSync(realPath) : null;
  const kind = blaDeDetect(hardened);
  const scrub = kind === "dotnet" ? scrubDotnet : kind === "native" ? scrubNative : scrubIl2cpp;
  let out, report, verdict;
  try {
    const r = scrub(hardened);
    out = r.buffer; report = r.report;
    const restores = real && out.equals(real);
    const realLostBytes = real ? real.length - out.length : 0;
    const markerStillPresent =
      out.includes(Buffer.from("BLA_DOTNET_CLR_SHIELD_V1", "latin1")) ||
      out.includes(Buffer.from("[BLA-IL2CPP-SHIELD]", "latin1")) ||
      out.includes(Buffer.from("[BLA-NATIVE-SHIELD-V1]", "latin1"));
    if (restores) verdict = "PASS";
    else if (!report.hardened && hardened.length !== (real?.length ?? hardened.length)) {
      verdict = "MISROUTE (decoy survives, reported unhardened)";
    } else if (!report.hardened) {
      verdict = markerStillPresent ? "MISROUTE (marker bytes remain)" : "PASS-ish (unhardened passthrough, but check diff)";
    } else if (markerStillPresent) {
      verdict = "MISROUTE (outer/second trailer left behind)";
    } else if (real && realLostBytes > 0) {
      verdict = `REAL-CONTENT-CUT (lost ${realLostBytes} real bytes)`;
    } else {
      verdict = "REAL-CONTENT-CUT? (output differs but not shorter)";
    }
  } catch (e) {
    verdict = `PARSE-FAIL (${e.message})`;
    report = {};
  }
  rows.push({
    fixture: f,
    bladeRoute: kind,
    blaWouldRoute: vendorBlaDetect(hardened),
    hardenedBytes: hardened.length,
    realBytes: real?.length,
    outBytes: out?.length,
    scrubHardened: report.hardened,
    verdict,
  });
}

console.log(JSON.stringify(rows, null, 2));
