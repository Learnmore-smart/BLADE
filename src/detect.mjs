// BLADE format detection — routes an input buffer + filename extension to a
// scrubber kind. Extracted from cli.mjs so it is importable without the CLI.
import {
  jvmClassLooksValid, looksLikeZip, bunfsGraphEnd,
} from "./trailer.mjs";

/**
 * Route an input buffer to a scrubber kind.
 *
 * Detection order matters: magic bytes first (extension lies), then
 * extension fallbacks for binary formats whose magic may be corrupted,
 * then text formats by extension. Two deliberate disambiguations:
 *  - CAFEBABE: JVM class vs fat Mach-O — resolved by arch cputype,
 *    which BLA shield marker is embedded, then full JVMS §4.1 shape.
 *  - PE/MZ: managed (.NET) vs native — resolved by which BLA trailer
 *    fired (BLA itself only sniffs the first 4 KiB for BSJB).
 *
 * @param {Buffer} buf raw input bytes
 * @param {string} ext lowercase filename extension ("" for stdin)
 * @returns {string} one of: js, asar, wasm, sqlite, safetensors, gguf,
 *   native, dex, il2cpp, dotnet, evm, ptx, jvm, plist, pcap, uf2, beam,
 *   pyc, zip, py, html, sourcemap, header, bunfs-snapshot, sidecar-note,
 *   or "unknown"
 */
export function detect(buf, ext) {
  if (buf.length >= 8 && buf.readUInt32LE(0) === 0x6d736100) return "wasm";
  if (buf.length >= 16 && buf.toString("ascii", 0, 15) === "SQLite format 3") return "sqlite";
  if (buf.length >= 4 && buf.toString("ascii", 0, 4) === "GGUF") return "gguf";
  if (ext === ".safetensors" || (buf.length >= 8 && buf.readBigUInt64LE(0) < BigInt(1e8) && buf[8] === 0x7b)) return "safetensors";
  if (buf.length >= 16 && buf.readUInt32LE(0) === 4 && buf[16] === 0x7b) {
    try { JSON.parse(buf.subarray(16, 16 + buf.readUInt32LE(12)).toString("utf8")); return "asar"; } catch {}
  }
  // binary formats
  if (buf.length >= 4 && buf.subarray(0, 4).toString("latin1") === "dex\n") return "dex";
  if (buf.length >= 4 && buf.readUInt32LE(0) === 0xfab11baf) return "il2cpp";
  if (buf.length >= 6 && buf.subarray(0, 6).toString("latin1") === "bplist") return "plist";
  if (buf.length >= 12 && buf.subarray(0, 4).toString("latin1") === "FOR1" && buf.subarray(8, 12).toString("latin1") === "BEAM") return "beam";
  if (buf.length >= 12 && buf.readUInt32BE(0) === 0xcafebabe) {
    // cafebabe collides: JVM class vs fat Mach-O. JVM major version sits at
    // bytes 6-7; fat Mach-O has nfat_arch at bytes 4-7 (reads as a major when
    // it lands in 45-90). Disambiguate in order:
    //   1. arch[0].cputype (bytes 8-11) against the known set — a real fat
    //      Mach-O always carries one; a valid class file's cp_count/tag/len
    //      bytes never produce one.
    //   2. Which BLA shield actually fired — a forged polyglot can fake every
    //      header field, but the trailer it carries names the right route.
    //   3. JVMS §4.1 shape — the constant pool must parse AND this_class /
    //      super_class must resolve to CONSTANT_Class entries. A shallow
    //      "CP parses" test is fooled by forged arch records walking as Utf8
    //      entries (e.g. nfat=45 reads as major 45 with a fake 2-entry pool).
    const cputype = buf.readUInt32BE(8);
    const FAT_CPUTYPES = new Set([0, 1, 2, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 18,
      0x01000007, 0x0100000c, 0x01000012, 0x0100000f, 0x01000010, 0x01000008, 0x0100000b]);
    if (FAT_CPUTYPES.has(cputype)) return "native"; // fat Mach-O arch entry
    if (buf.includes(Buffer.from("[BLA-NATIVE-SHIELD", "latin1"))) return "native";
    if (buf.includes(Buffer.from("BLA_JVM_SHIELD_V1", "ascii")) ||
        buf.includes(Buffer.from("bla-jvm-enclave-v1", "utf8"))) return "jvm";
    const v = buf.readUInt16BE(6);
    if (v >= 46 && v <= 90 && jvmClassLooksValid(buf)) return "jvm";
    return "native";
  }
  if (buf.length >= 4 && (buf.readUInt32LE(0) === 0xa1b2c3d4 || buf.readUInt32LE(0) === 0xa1b23c4d || buf.readUInt32BE(0) === 0xa1b2c3d4 || buf.readUInt32BE(0) === 0xa1b23c4d || buf.readUInt32LE(0) === 0x0a0d0d0a)) return "pcap";
  if (buf.length >= 512 && buf.readUInt32LE(0) === 0x0a324655 && buf.readUInt32LE(4) === 0x9e5d5157) return "uf2";
  // pyc magic alone is enough — a renamed .pyc must not evade (marshal tag at
  // 16 disambiguates from plain \r\n text files)
  if (buf.length >= 17 && buf[2] === 0x0d && buf[3] === 0x0a && (ext === ".pyc" || [0x63, 0xe3, 0x29, 0x28].includes(buf[16]))) return "pyc";
  if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) return "zip";
  if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return "native";
  if (buf.length >= 4) {
    const m = buf.readUInt32BE(0);
    if (m === 0xfeedfacf || m === 0xcffaedfe || m === 0xfeedface || m === 0xcefaedfe || m === 0xcafebabe || m === 0xbebafeca) return "native";
  }
  if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) {
    // Route by which BLA trailer is present, not just format sniff: BLA's own
    // detector only sniffs the first 4096 bytes for BSJB, so a managed PE with
    // late CLR metadata receives the NATIVE trailer (misroute if we sniffed
    // deeper). Check both markers; prefer whichever shield actually fired.
    const hasDotnetShield = buf.includes(Buffer.from("BLA_DOTNET_CLR_SHIELD_V1", "ascii"));
    const hasNativeShield = buf.includes(Buffer.from("[BLA-NATIVE-SHIELD-V1]", "latin1"));
    if (hasNativeShield) return "native";
    if (hasDotnetShield) return "dotnet";
    if (!buf.includes(Buffer.from("BSJB", "ascii")) && looksLikeZip(buf)) return "zip"; // SFX stub
    return buf.includes(Buffer.from("BSJB", "ascii")) ? "dotnet" : "native";
  }
  // BLA bun-standalone decoy siblings (protectTarget never mutates the real
  // binary — it plants <out>.bunfs-snapshot / <out>.bla-sidecar.v1.json next
  // to it). The snapshot is a standalone decoy module graph: data ‖
  // Offsets(32) ‖ "\n---- Bun! ----\n" (+ optional 8B size footer). When the
  // Offsets claim covers the WHOLE file (u64LE(end-48)+48 == end, i.e.
  // payloadOffset==0) there is no carrier — the buffer is pure decoy graph.
  // A REAL `bun build --compile` binary ends with the same sentinel but
  // carries exec magic — it routed to native above — and its graph claim is
  // shorter than the file (payloadOffset>0), so it can never reach this.
  if (buf.length >= 48) {
    const end = bunfsGraphEnd(buf);
    if (end && buf.readBigUInt64LE(end - 48) === BigInt(end - 48)) return "bunfs-snapshot";
  }
  // .bla-sidecar.v1.json strip=>fail companion note — route on the entangle
  // schema marker, not the filename.
  if (buf.length && buf[0] === 0x7b && buf.includes(Buffer.from("bla-sidecar-entangle/v1", "utf8"))) {
    try {
      if (JSON.parse(buf.toString("utf8"))?.schema === "bla-sidecar-entangle/v1") return "sidecar-note";
    } catch {}
  }
  // text formats by extension
  if ([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"].includes(ext)) return "js";
  if ([".plist", ".entitlements", ".mobileprovision"].includes(ext)) return "plist";
  if (ext === ".map") return "sourcemap";
  if ([".html", ".htm"].includes(ext)) return "html";
  if ([".py", ".pyw"].includes(ext)) return "py";
  if ([".evm", ".bin-evm", ".solidity-bin"].includes(ext)) return "evm";
  if (ext === ".ptx") return "ptx";
  if ([".h", ".hpp", ".hh", ".rs", ".go", ".c", ".cc", ".cpp"].includes(ext)) return "header";
  // extension fallbacks for binary formats whose magic check above missed
  // (corrupt/truncated files still deserve best-effort routing like BLA's)
  if (ext === ".asar") return "asar";
  if (ext === ".wasm") return "wasm";
  if ([".sqlite", ".sqlite3", ".db"].includes(ext)) return "sqlite";
  if (ext === ".gguf") return "gguf";
  if (ext === ".dex") return "dex";
  if (ext === ".class") return "jvm";
  if (ext === ".beam") return "beam";
  if (ext === ".uf2") return "uf2";
  if ([".pcap", ".pcapng", ".cap"].includes(ext)) return "pcap";
  if (ext === ".pyc") return "pyc";
  if (ext === ".bplist") return "plist";
  if ([".jar", ".apk", ".aab", ".ipa", ".xapk", ".apex", ".war", ".ear"].includes(ext)) return "zip";
  if ([".exe", ".dll", ".so", ".dylib", ".node", ".elf"].includes(ext)) return "native";
  return "unknown";
}
