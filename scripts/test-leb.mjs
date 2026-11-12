#!/usr/bin/env node
// Unit checks for the ULEB128 primitives every binary path depends on.
import { readU32Leb, writeU32Leb } from "../src/formats.mjs";

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) pass++; else { fail++; console.log("FAIL:", name); } };

// roundtrip
for (const n of [0, 1, 127, 128, 300, 624485, 0xfffffffe, 0xffffffff]) {
  const enc = writeU32Leb(n);
  const [v, end] = readU32Leb(enc, 0);
  ok(v === n >>> 0 && end === enc.length, `roundtrip ${n}`);
}
// canonical encodings
ok(writeU32Leb(0).equals(Buffer.from([0x00])), "0 -> [00]");
ok(writeU32Leb(127).equals(Buffer.from([0x7f])), "127 -> [7f]");
ok(writeU32Leb(128).equals(Buffer.from([0x80, 0x01])), "128 -> [80 01]");
ok(writeU32Leb(624485).equals(Buffer.from([0xe5, 0x8e, 0x26])), "624485 -> [e5 8e 26]");

// bounds safety
{
  const [v, end] = readU32Leb(Buffer.from([0x80]), 0);
  ok(end === 1, "truncated LEB stops at EOF (no hang)");
  const [v2, end2] = readU32Leb(Buffer.alloc(0), 0);
  ok(end2 === 0, "empty buffer safe");
  // 5-byte cap: a 6-byte continuation must not read past 5
  const [v3, end3] = readU32Leb(Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), 0);
  ok(end3 === 5, "5-byte cap respected");
  // nonzero offset
  const [v4, end4] = readU32Leb(Buffer.from([0xaa, 0xe5, 0x8e, 0x26]), 1);
  ok(v4 === 624485 && end4 === 4, "nonzero offset");
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
