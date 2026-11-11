// Unit tests for src/detect.mjs routing. Runs entirely on synthetic buffers —
// no fixture files needed. Usage: node scripts/test-detect.mjs
import { detect } from "../src/detect.mjs";

let pass = 0, fail = 0;
const check = (name, got, want) => {
  if (got === want) { pass++; }
  else { fail++; console.log(`FAIL  ${name}: got ${got}, want ${want}`); }
};

const buf = (hex) => Buffer.from(hex.replace(/\s/g, ""), "hex");
const ascii = (s) => Buffer.from(s, "ascii");

// ---- magic-based routing
check("wasm magic", detect(buf("0061736d01000000"), ""), "wasm");
check("sqlite header", detect(ascii("SQLite format 3\0xxxx"), ""), "sqlite");
check("gguf magic", detect(ascii("GGUF\x03\x00\x00\x00"), ""), "gguf");
check("dex magic", detect(ascii("dex\n035\0"), ""), "dex");
check("bplist magic", detect(ascii("bplist00"), ""), "plist");
check("elf magic", detect(buf("7f454c4602010100"), ""), "native");
check("mach-o 64 LE", detect(buf("cffaedfe07000001"), ""), "native");
check("mach-o fat", detect(buf("cafebabe0000000200000007"), ""), "native");
check("zip local header", detect(ascii("PK\x03\x04xxxx"), ""), "zip");
check("pcap LE magic", detect(buf("d4c3b2a102000400"), ""), "pcap");
check("pcap LE nsec magic", detect(buf("4d3cb2a102000400"), ""), "pcap");
check("pcap BE magic", detect(buf("a1b2c3d400020004"), ""), "pcap");
check("pcap BE nsec magic", detect(buf("a1b23c4d00020004"), ""), "pcap");
check("pcapng magic", detect(buf("0a0d0d0a00001c00"), ""), "pcap");
check("uf2 magics", detect(buf("5546320a" + "57515d9e" + "00".repeat(496) + "87" + "6351489e" + "00".repeat(3)), ""), "uf2");
check("pyc magic + marshal tag", detect(buf("6f0d0d0a" + "00".repeat(12) + "63"), ""), "pyc");
check("il2cpp magic", detect(buf("af1bb1fa" + "00".repeat(20)), ""), "il2cpp");
check("beam FOR1+BEAM", detect(ascii("FOR1xxxxBEAM" + "00".repeat(8)), ""), "beam");

// cafebabe disambiguation: real JVM class (major 55) vs fat Mach-O (cputype set)
// minimal valid class: cp[1]=Class->#4 "C", cp[2]=Class->#5 "java/lang/Object",
// this_class=#1, super_class=#2 (JVMS §4.1 shape, what the disambiguation checks)
const jvmClass = buf(
  "cafebabe 0000 0037 0006" +
  "07 0004" +                               // #1 Class -> #4
  "07 0005" +                               // #2 Class -> #5
  "01 0001 58" +                            // #3 Utf8 "X"
  "01 0001 43" +                            // #4 Utf8 "C"
  "01 0010 " + Buffer.from("java/lang/Object", "ascii").toString("hex") + // #5
  "0021 0001 0002 0000 0000 0000 0000");    // access,this,super,ifaces,fields,methods,attrs
check("jvm class over fat-macho", detect(jvmClass, ""), "jvm");
check("fat macho over jvm", detect(buf("cafebabe0000000201000007"), ""), "native");

// MZ routing: native vs dotnet vs SFX-zip
const mzNative = Buffer.concat([ascii("MZ"), Buffer.alloc(2048)]);
check("mz plain -> native", detect(mzNative, ""), "native");
const mzDotnet = Buffer.concat([ascii("MZ"), Buffer.alloc(512), ascii("BSJB"), Buffer.alloc(64)]);
check("mz + BSJB -> dotnet", detect(mzDotnet, ""), "dotnet");

// ---- extension routing (no magic)
check(".js ext", detect(ascii("console.log(1)"), ".js"), "js");
check(".ts ext", detect(ascii("let x: number"), ".ts"), "js");
check(".py ext", detect(ascii("print(1)"), ".py"), "py");
check(".html ext", detect(ascii("<html>"), ".html"), "html");
check(".map ext", detect(ascii("{}"), ".map"), "sourcemap");
check(".plist ext", detect(ascii("<?xml"), ".plist"), "plist");
check(".evm ext", detect(buf("60806040"), ".evm"), "evm");
check(".ptx ext", detect(ascii(".version 7.0"), ".ptx"), "ptx");
check(".h -> header", detect(ascii("#pragma once"), ".h"), "header");
check(".rs -> header", detect(ascii("fn main()"), ".rs"), "header");
check(".asar ext fallback", detect(ascii("garbage"), ".asar"), "asar");
check(".wasm ext fallback", detect(ascii("garbage"), ".wasm"), "wasm");
check(".class ext fallback", detect(ascii("garbage"), ".class"), "jvm");
check(".db ext fallback", detect(ascii("garbage"), ".db"), "sqlite");

// ---- negatives / passthrough
check("empty -> unknown", detect(Buffer.alloc(0), ""), "unknown");
check("garbage -> unknown", detect(ascii("hello world"), ".xyz"), "unknown");
check("truncated wasm magic", detect(buf("006173"), ""), "unknown");
check("pyc CRLF text not pyc", detect(ascii("ab\r\n" + "x".repeat(20)), ".txt"), "unknown");

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
