// Adversarial runner for BLADE scrubDex/scrubZip.
// Runs `node src/cli.mjs <fixture> -o <cleaned>` per case, then verifies:
//   - exit code / crash
//   - output dex: file_size==len, SHA-1 sig valid, Adler32 valid,
//     string_ids/type_ids/map offsets in-bounds, residual marker scan
//   - byte-exactness vs *.expected references
//   - zip outputs: member list, per-member dex validity, residual markers
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { inflateRawSync } from "node:zlib";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..", "..");
const outDir = join(here, "out");
const cleanDir = join(here, "cleaned");
mkdirSync(cleanDir, { recursive: true });

const MARKER = Buffer.from("[BLA-DEX-SHIELD-V1]", "latin1");
const XREF = Buffer.from("BLA-DEX-XREF-V1", "latin1");

function sha1(b) { return createHash("sha1").update(b).digest(); }
function adler32(b) {
  let a = 1, s = 0;
  for (let i = 0; i < b.length; i++) { a = (a + b[i]) % 65521; s = (s + a) % 65521; }
  return ((s << 16) | a) >>> 0;
}
const hex = (n) => "0x" + n.toString(16);

function verifyDex(buf, label) {
  const r = { label, len: buf.length, issues: [], ok: true };
  const bad = (m) => { r.issues.push(m); r.ok = false; };
  if (buf.length < 112) { bad(`len=${buf.length} < header 0x70`); return r; }
  if (buf.subarray(0, 4).toString("latin1") !== "dex\n") bad("magic != dex\\n");
  const fileSize = buf.readUInt32LE(32);
  if (fileSize !== buf.length) bad(`file_size ${hex(fileSize)} != actual ${hex(buf.length)}`);
  const sigStored = buf.subarray(12, 32);
  const sigCalc = sha1(buf.subarray(32));
  if (!sigStored.equals(sigCalc)) bad(`SHA-1 sig mismatch (stored ${sigStored.subarray(0,6).toString("hex")}.. calc ${sigCalc.subarray(0,6).toString("hex")}..)`);
  const cksStored = buf.readUInt32LE(8);
  const cksCalc = adler32(buf.subarray(12));
  if (cksStored !== cksCalc) bad(`Adler32 mismatch (stored ${hex(cksStored)} calc ${hex(cksCalc)})`);
  const strSize = buf.readUInt32LE(56), strOff = buf.readUInt32LE(60);
  const typSize = buf.readUInt32LE(64), typOff = buf.readUInt32LE(68);
  const mapOff = buf.readUInt32LE(52);
  if (strSize && strOff + strSize * 4 > buf.length) bad(`string_ids table past EOF (off ${hex(strOff)} + ${strSize}*4 > ${hex(buf.length)})`);
  if (typSize && typOff + typSize * 4 > buf.length) bad(`type_ids table past EOF`);
  if (mapOff && mapOff + 4 > buf.length) bad(`map_off ${hex(mapOff)} past EOF`);
  // each string_data offset must point inside the file
  if (strSize && strOff + strSize * 4 <= buf.length) {
    for (let i = 0; i < strSize; i++) {
      const so = buf.readUInt32LE(strOff + i * 4);
      if (so >= buf.length) { bad(`string_ids[${i}] -> ${hex(so)} past EOF (dangling)`); break; }
    }
  }
  const mi = buf.indexOf(MARKER);
  if (mi >= 0) bad(`residual [BLA-DEX-SHIELD-V1] marker at ${hex(mi)}`);
  return r;
}

function listZip(buf) {
  let eocd = -1;
  for (let p = buf.length - 22; p >= Math.max(0, buf.length - 66000); p--) {
    if (buf.readUInt32LE(p) === 0x06054b50 && p + 22 + buf.readUInt16LE(p + 20) === buf.length) { eocd = p; break; }
  }
  if (eocd < 0) return null;
  const count = buf.readUInt16LE(eocd + 10);
  let c = buf.readUInt32LE(eocd + 16);
  const out = [];
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(c) !== 0x02014b50) break;
    const method = buf.readUInt16LE(c + 10);
    const csize = buf.readUInt32LE(c + 20);
    const nlen = buf.readUInt16LE(c + 28);
    const elen = buf.readUInt16LE(c + 30);
    const clen = buf.readUInt16LE(c + 32);
    const lho = buf.readUInt32LE(c + 42);
    const name = buf.subarray(c + 46, c + 46 + nlen).toString("utf8");
    const dOff = lho + 30 + buf.readUInt16LE(lho + 26) + buf.readUInt16LE(lho + 28);
    const comp = buf.subarray(dOff, dOff + csize);
    let data = null;
    try { data = method === 0 ? comp : method === 8 ? inflateRawSync(comp) : null; } catch {}
    out.push({ name, data });
    c += 46 + nlen + elen + clen;
  }
  return out;
}

const cases = readdirSync(outDir).filter((f) => f.endsWith(".dex") || f.endsWith(".zip")).sort();
console.log("case\texit\tverdict\tdetail");
for (const f of cases) {
  const input = join(outDir, f);
  const output = join(cleanDir, f.replace(/\.(dex|zip)$/, ".cleaned.$1"));
  let exit = 0, stdout = "", stderr = "";
  try {
    stdout = execFileSync("node", [join(repo, "src", "cli.mjs"), input, "-o", output], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    exit = e.status ?? 1;
    stdout = (e.stdout ?? "").toString();
    stderr = (e.stderr ?? "").toString();
  }
  const src = readFileSync(input);
  const markerAt = src.indexOf(MARKER);
  const xrefAt = src.indexOf(XREF);

  let verdict = "PASS", detail = [];
  if (exit !== 0) {
    verdict = "CRASH";
    detail.push(`exit=${exit}`, stderr.split("\n").find((l) => /Error|error/.test(l))?.trim() ?? stderr.trim().split("\n")[0] ?? "");
  } else if (!existsSync(output)) {
    verdict = "NO-OUTPUT";
  } else {
    const out = readFileSync(output);
    const hardened = /"hardened": true/.test(stdout);
    if (f.endsWith(".dex")) {
      const v = verifyDex(out, f);
      const lost = src.length - out.length;
      const expectedFile = join(outDir, f.replace(/\.dex$/, ".dex.expected"));
      const origRef = existsSync(expectedFile) ? readFileSync(expectedFile) : null;
      if (origRef) {
        detail.push(out.equals(origRef) ? "byte-exact vs original" : `NOT byte-exact (firstDiff @${hex(out.findIndex((b, i) => b !== origRef[i]))})`);
      }
      if (markerAt >= 0) {
        const cutLen = markerAt - 1;
        if (out.length < cutLen) detail.push(`over-cut: out ${hex(out.length)} < expected cut ${hex(cutLen)}`);
        if (out.length > cutLen) detail.push(`out longer than marker-1? ${hex(out.length)}`);
      }
      if (!v.ok) {
        const inOk = verifyDex(src, f).ok;
        if (!inOk) { verdict = verdict === "PASS" ? "MALFORMED-IN" : verdict; detail.push(`input already invalid (${v.issues[0] ?? ""}) — preserved`); }
        else { verdict = verdict === "PASS" ? "BAD-STRUCTURE" : verdict; detail.push(...v.issues); }
      }
      else detail.push(`checksums ok, len ${hex(out.length)}`);
      // over-cut detection: only real truncation counts — a marker before
      // map_list that was overwritten in place preserves every structure.
      const mapOff = src.length >= 56 ? src.readUInt32LE(52) : -1;
      if (markerAt >= 0 && mapOff > 0 && markerAt < mapOff && mapOff + 4 <= src.length) {
        if (out.length < src.length) {
          verdict = "OVER-CUT";
          detail.push(`marker @${hex(markerAt)} precedes map_list @${hex(mapOff)} — real map_list/strings destroyed, checksums resealed`);
        } else detail.push(`in-content marker @${hex(markerAt)} neutralized in place (map_list @${hex(mapOff)} intact)`);
      }
      if (markerAt < 0 && !hardened) detail.push("passthrough (no marker)");
      if (markerAt < 0 && hardened) { verdict = "OVER-CUT"; detail.push("hardened=true with no [BLA-DEX-SHIELD-V1] in input?!"); }
    } else {
      // zip
      const inEnt = listZip(src) ?? [];
      const outEnt = listZip(out) ?? [];
      detail.push(`entries ${inEnt.length}->${outEnt.length}`);
      for (const e of inEnt) {
        const kept = outEnt.find((o) => o.name === e.name);
        const hadMarker = e.data && e.data.includes(MARKER);
        const hadXref = e.data && e.data.includes(XREF);
        const isDex = e.data && e.data.length >= 4 && e.data.subarray(0, 4).toString("latin1") === "dex\n";
        if (!kept) {
          const benign = /^assets\/(enclave|bla-shield)\//i.test(e.name) || /^enclave\//i.test(e.name);
          detail.push(`dropped: ${e.name}${hadXref ? " [xref-string]" : ""}${isDex && !hadXref && !hadMarker ? " <-- REAL DEX DELETED" : ""}`);
          if (isDex && !hadXref && !benign) { verdict = "OVER-CUT"; }
          if (isDex && hadXref && e.name === "classes.dex") { verdict = "OVER-CUT"; }
          if (isDex && hadMarker && hadXref) { verdict = "OVER-CUT"; detail.push(`  (${e.name} had BOTH markers — dropped, not scrubbed)`); }
        } else if (hadMarker || hadXref) {
          const v = verifyDex(kept.data, e.name);
          const resM = kept.data.includes(MARKER), resX = kept.data.includes(XREF);
          detail.push(`kept: ${e.name} scrubbed -> ${v.ok ? "valid" : "INVALID: " + v.issues.join(";")}${resM ? " residual-marker" : ""}${resX ? " residual-xref" : ""}`);
          if (resM || resX) detail.push(`  (marker survives under name ${e.name})`);
          if (!v.ok && verdict === "PASS") verdict = "BAD-STRUCTURE";
        }
      }
    }
  }
  console.log(`${f}\t${exit}\t${verdict}\t${detail.filter(Boolean).join(" | ")}`);
}
