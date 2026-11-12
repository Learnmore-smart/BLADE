#!/usr/bin/env node
// Unit checks for the gate helpers — the structural predicates that
// decide whether a file gets scrubbed or passes through untouched.
import { readFileSync } from "node:fs";
import { looksBlaHardened, sniffEmbeddedPayload } from "../src/js-deharden.mjs";
import { looksLikeZip, jvmClassLooksValid, inspectSourcemap, inspectShieldHeader } from "../src/trailer.mjs";

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) pass++; else { fail++; console.log("FAIL:", name); } };

// --- looksBlaHardened ---------------------------------------------------------------
{
  ok(!looksBlaHardened("const x = 1;\n"), "clean js -> false");
  ok(!looksBlaHardened(""), "empty -> false");
  // marker vocabulary inside a STRING literal must not flip the gate —
  // it's data/prose, not injected machinery.
  const prose = `const doc = "obligationFlood_9f and labyrinthDispatch_x live here";
const re = /scc_a1_c2n3/;
// _interlockSafetyCorpus_ in a comment too`;
  ok(!looksBlaHardened(prose), "marker text in literals/comments -> false");
  // a single corpus decl alone isn't enough (multi-family rule)
  const single = `const _interlockSafetyCorpus_a1 = [{x:1}];\nconst y = 2;\n`;
  ok(!looksBlaHardened(single), "single corpus decl -> false");
  // the fallback: corpus + opaque-seed decl (x | (cond ? 1 : 0) shape)
  const seed = `const _interlockSafetyCorpus_a1 = [{x:1}];
const seed_a1 = 123 | (typeof _deriveContainmentCorpusDigest_5167 === "function" ? 1 : 0);
`;
  ok(looksBlaHardened(seed), "corpus + opaque-seed decl -> true");
  // real hardened fixture -> true
  const hard = readFileSync("test-fixtures/hardened/electron-bridge.js", "utf8");
  ok(looksBlaHardened(hard), "real hardened -> true");
}

// --- looksLikeZip --------------------------------------------------------------------
{
  // bare PK signature alone is NOT a zip — needs a verifiable EOCD + cd
  ok(!looksLikeZip(Buffer.from("PK\x03\x04garbage")), "bare PK -> false");
  ok(!looksLikeZip(Buffer.alloc(10)), "tiny -> false");
  ok(!looksLikeZip(Buffer.alloc(0)), "empty -> false");
  // build a real minimal zip: local hdr + central dir + EOCD
  const name = Buffer.from("a.txt");
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(name.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(name.length, 28);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8); eocd.writeUInt16LE(1, 10);          // 1 entry
  eocd.writeUInt32LE(central.length, 12);                      // cd size
  eocd.writeUInt32LE(local.length + name.length, 16);          // cd offset
  const zip = Buffer.concat([local, name, central, name, eocd]);
  ok(looksLikeZip(zip), "real minimal zip -> true");
  // EOCD pointing outside -> false
  const bad = Buffer.from(zip);
  bad.writeUInt32LE(0xfffffff0, zip.length - 22 + 16); // corrupt cd-offset field
  ok(!looksLikeZip(bad), "dangling cd offset -> false");
}

// --- jvmClassLooksValid ----------------------------------------------------------------
{
  const real = readFileSync("test-fixtures/plain/Main.class");
  ok(jvmClassLooksValid(real) === true, "real class -> true");
  ok(!jvmClassLooksValid(Buffer.from("not a class")), "garbage -> false");
  ok(!jvmClassLooksValid(Buffer.alloc(0)), "empty -> false");
  // CAFEBABE magic with a corrupt constant-pool count -> fails the walk
  const corrupt = Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0, 2, 0x99, 0x00]), Buffer.alloc(8)]);
  ok(!jvmClassLooksValid(corrupt), "corrupt constant pool -> false");
  // but a degenerate cp_count=0 stub is parseable -> true (documented floor)
  const stub = Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0, 0]), Buffer.alloc(6)]);
  ok(jvmClassLooksValid(stub) === true, "cp_count=0 stub -> true");
}

// --- inspectSourcemap ------------------------------------------------------------------
{
  const plainMap = readFileSync("test-fixtures/plain/app.js.map", "utf8");
  const r = inspectSourcemap(plainMap);
  ok(r.format === "sourcemap" && r.honeyMap === false && !r.unrecoverable, "real map -> not honey");
  const hardMap = readFileSync("test-fixtures/hardened/app.js.map", "utf8");
  const rh = inspectSourcemap(hardMap);
  ok(rh.honeyMap === true && rh.unrecoverable === true && /untrusted|replaced/i.test(rh.note), "honey map -> unrecoverable");
  ok(inspectSourcemap("{broken json").format === "sourcemap", "malformed -> shaped, not honey");
  ok(inspectSourcemap("").format === "sourcemap", "empty safe");
}

// --- inspectShieldHeader ------------------------------------------------------------------
{
  // BLA emit-headers shape: BLA_SHIELD_H guard + tarpit markers
  const header = `#ifndef BLA_SHIELD_H
#define BLA_SHIELD_H
/* Counter-REA Native Decompilation Tarpit */
extern void enclave_tarpit_fn_0(void);
#endif
`;
  const r = inspectShieldHeader(header);
  ok(r.decoyHeader === true && r.markersHit.length >= 2, "bla emit-headers -> decoy");
  ok(r.note.includes("excluded"), "decoy header note");
}
{
  // the plain corpus header is a real header — kept
  const real = readFileSync("test-fixtures/adversarial/detect/header.h", "utf8");
  ok(!inspectShieldHeader(real).decoyHeader, "plain header fixture kept");
}
{
  // a REAL C header with enclave-sounding names but <2 marker hits -> kept
  const real = "/* our enclave sdk */\nint enclave_init(void);\n";
  const r = inspectShieldHeader(real);
  ok(r.decoyHeader === false, "real header kept (<2 markers)");
}
{
  const r = inspectShieldHeader("");
  ok(r.decoyHeader === false && r.markersHit.length === 0, "empty -> not decoy");
}

// --- sniffEmbeddedPayload ---------------------------------------------------
{
  ok(sniffEmbeddedPayload("const x=1;") === null, "clean js -> null");
  ok(sniffEmbeddedPayload("") === null, "empty -> null");
  const zip = sniffEmbeddedPayload("const x=1;\nPK\x03\x04junk");
  ok(zip?.kind === "zip" && zip.offset === 11, "zip polyglot -> zip@11");
  const elf = sniffEmbeddedPayload("code();\n\x7fELF\x02\x01");
  ok(elf?.kind === "elf", "elf polyglot -> elf");
  const wasm = sniffEmbeddedPayload("code();\n\x00asm\x01\x00\x00\x00");
  ok(wasm?.kind === "wasm", "wasm polyglot -> wasm");
  // magic at offset 0 is a real binary, not an embedded payload
  ok(sniffEmbeddedPayload("PK\x03\x04lead") === null, "leading magic -> null");
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
