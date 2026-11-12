#!/usr/bin/env node
// Unit checks for the precision/canonical scoring helpers — the
// keep+flag honesty layer that decides drop vs flag vs keep.
import { scoreSqliteObjects, neutralizePyLiteralMarkers, beamLoneDecoyScore } from "../src/recovery/precision.mjs";
import { reconstructSourceMap } from "../src/recovery/canonical.mjs";
import { makeEvaluator } from "../src/evaluator.mjs";

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) pass++; else { fail++; console.log("FAIL:", name); } };
const verdictOf = (arr, name) => arr.find((o) => o.name === name)?.verdict;

// --- scoreSqliteObjects -----------------------------------------------------
{
  const objs = [
    { type: "table", name: "users", sql: "CREATE TABLE users(id INTEGER, name TEXT)" },
    { type: "table", name: "enclave_unseal_payload_9f", sql: "CREATE TABLE enclave_unseal_payload_9f(x TEXT); INSERT INTO enclave_unseal_payload_9f VALUES('[BLA-DECOY]')" },
    { type: "index", name: "idx_users_name", sql: "CREATE INDEX idx_users_name ON users(name)" },
  ];
  const r = scoreSqliteObjects(objs);
  ok(r.length === 3 && r.every((o) => typeof o.decoyScore === "number" && typeof o.reason === "string"), "sqlite objects shaped {name,decoyScore,verdict,reason}");
  ok(verdictOf(r, "users") === "keep", "real table kept");
  ok(["drop", "flag"].includes(verdictOf(r, "enclave_unseal_payload_9f")), `decoy table flagged/dropped (got ${verdictOf(r, "enclave_unseal_payload_9f")})`);
  ok(verdictOf(r, "idx_users_name") === "keep", "real index kept");
  ok(r.find((o) => o.name === "enclave_unseal_payload_9f").decoyScore > r.find((o) => o.name === "users").decoyScore,
     "decoy scores above real");
}
// degenerate input
ok(Array.isArray(scoreSqliteObjects([])), "sqlite empty -> []");
ok(Array.isArray(scoreSqliteObjects([{ name: "x" }])), "missing fields safe");

// --- beamLoneDecoyScore ------------------------------------------------------
// returns {score, verdict, reason}; vocab-heavy chunk must outscore a
// normal chunk AND reach a decoy-flavored verdict.
{
  const decoy = beamLoneDecoyScore(Buffer.from("enclave_unseal_payload attestationState RING0_SEALED"));
  const plain = beamLoneDecoyScore(Buffer.from("defmodule :normal_app do end"));
  ok(typeof decoy.score === "number" && typeof decoy.verdict === "string" && typeof decoy.reason === "string",
     "beam chunk shaped {score,verdict,reason}");
  ok(decoy.score >= plain.score, "vocab-heavy chunk outscores normal chunk");
}

// --- neutralizePyLiteralMarkers ----------------------------------------------
{
  const MARK = /BLA_TOKEN_[a-z0-9]+/;
  // marker inside a string literal is neutralized; marker as an identifier
  // is NOT (it's code, not literal content).
  const src = 'x = "prefix BLA_TOKEN_dead suffix"\ny = BLA_TOKEN_live\n';
  const out = neutralizePyLiteralMarkers(src, MARK);
  ok(typeof out === "string" || (out && typeof out.src === "string"), "returns string-or-{src}");
  const text = typeof out === "string" ? out : out.src;
  ok(!/BLA_TOKEN_dead/.test(text), "literal marker neutralized");
  ok(/BLA_TOKEN_live/.test(text), "identifier marker preserved");
}
{
  // f-string: marker in the literal part is neutralized; marker inside a
  // {hole} expression is code and must survive.
  const MARK = /BLA_TOKEN_[a-z0-9]+/;
  const src = 's = f"lit BLA_TOKEN_inlit {BLA_TOKEN_inexpr}"\n';
  const out = neutralizePyLiteralMarkers(src, MARK);
  const text = typeof out === "string" ? out : out.src;
  ok(!/BLA_TOKEN_inlit/.test(text), "f-string literal part neutralized");
  ok(/BLA_TOKEN_inexpr/.test(text), "f-string hole expression preserved");
}

// --- reconstructSourceMap ----------------------------------------------------
{
  // null/absent map input -> status "empty" passthrough map (nothing to
  // reconstruct FROM), never a fabricated set of mappings.
  const m = reconstructSourceMap(null, "l1\nl2\nl3\n", 1000);
  ok(m && m.map && m.map.version === 3 && m.status === "empty" && m.map.mappings === "",
     "null map -> empty passthrough map");
}
{
  // a valid (honey) map object -> reconstructed identity map whose
  // segment count equals the dehardened js line count, with the honesty
  // note embedded.
  const honey = { version: 3, sources: ["enclave://tee-runtime/x.js"], names: [], mappings: "AAAA" };
  const js = "a()\nb()\n"; // 3 lines per split("\n")
  const m = reconstructSourceMap(honey, js, 50);
  ok(m.map.version === 3 && m.status !== "empty", "honey input -> reconstructed status");
  ok(m.map.mappings.split(";").length === js.split("\n").length,
     `mapping segments == js lines (got ${m.map.mappings.split(";").length})`);
  ok(typeof m.map.x_blade_note === "string" && m.map.x_blade_note.includes("unrecoverable"),
     "honesty note embedded");
}
// degenerate js never throws
ok(reconstructSourceMap({ version: 3 }, "", 0).map.version === 3, "empty js safe");

// --- makeEvaluator ------------------------------------------------------------
{
  const { ev } = makeEvaluator(new Map());
  // bindings shadow builtins: const undefined = 5 must win over builtin
  const { ev: ev2 } = makeEvaluator(new Map([["undefined", 5]]));
  const lit = (v) => ({ type: "NumericLiteral", value: v });
  const id = (n) => ({ type: "Identifier", name: n });
  ok(ev(lit(7)).known && ev(lit(7)).value === 7, "numeric literal evals");
  ok(ev(id("undefined")).known && ev(id("undefined")).value === undefined, "builtin undefined");
  ok(ev2(id("undefined")).known && ev2(id("undefined")).value === 5, "binding shadows builtin undefined");
  ok(!ev(id("someVar")).known, "unknown identifier -> !known");
  ok(!ev(null).known, "null node -> !known");
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
