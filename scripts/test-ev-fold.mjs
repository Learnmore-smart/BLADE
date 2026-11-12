#!/usr/bin/env node
// Unit checks for the bounded partial evaluator — every op family it
// folds, the depth bound, and the constValues shadowing contract.
import { parseExpression } from "@babel/parser";
import { makeEvaluator } from "../src/evaluator.mjs";

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) pass++; else { fail++; console.log("FAIL:", name); } };

const { ev } = makeEvaluator();
const K = (src) => { const r = ev(parseExpression(src)); return r.known ? r.value : `?unknown`; };
const KNOWN = (src, want) => { const got = K(src); const eq = Number.isNaN(want) ? Number.isNaN(got) : got === want; ok(eq, `${src} -> ${JSON.stringify(want)} (got ${JSON.stringify(got)})`); };
const UNK = (src) => ok(K(src) === "?unknown", `${src} -> unknown`);

// literals
KNOWN("42", 42); KNOWN("'abc'", "abc"); KNOWN("true", true); KNOWN("null", null);
KNOWN("undefined", undefined); KNOWN("NaN", NaN); KNOWN("Infinity", Infinity);
// unary
KNOWN("-5", -5); KNOWN("+5", 5); KNOWN("~5", -6); KNOWN("!0", true);
KNOWN("typeof 1", "number"); KNOWN("typeof 'x'", "string"); KNOWN("void 0", undefined);
UNK("delete x.y"); UNK("typeof unknownVar");
// binary arithmetic
KNOWN("2+3", 5); KNOWN("2-3", -1); KNOWN("2*3", 6); KNOWN("7/2", 3.5);
KNOWN("7%2", 1); KNOWN("2**10", 1024);
// binary comparison
KNOWN("1<2", true); KNOWN("2<=2", true); KNOWN("3>2", true); KNOWN("1>=2", false);
KNOWN("1===1", true); KNOWN("1!==1", false); KNOWN("'1'==1", true); KNOWN("'1'!=1", false);
// bitwise
KNOWN("5|3", 7); KNOWN("5&3", 1); KNOWN("5^3", 6);
KNOWN("1<<4", 16); KNOWN("-16>>2", -4); KNOWN("-16>>>2", 1073741820);
// string ops
KNOWN("'a'+'b'", "ab"); KNOWN("'a'+1", "a1"); KNOWN("1+'a'", "1a");
KNOWN("'x'.length", 1);
// logical — short-circuit on known left
KNOWN("true && 5", 5); KNOWN("false && x", false); KNOWN("0 && x", 0);
KNOWN("false || 5", 5); KNOWN("true || x", true); KNOWN("'a' || x", "a");
KNOWN("null ?? 5", 5); KNOWN("0 ?? 5", 0); KNOWN("undefined ?? 'd'", "d");
UNK("x && 5"); UNK("x || 5"); UNK("x ?? 5");
// conditional
KNOWN("true ? 1 : 2", 1); KNOWN("false ? 1 : 2", 2); UNK("x ? 1 : 2");
// sequence
KNOWN("(1, 2, 3)", 3); UNK("(1, x, 3)");
// template
KNOWN("`ab${1}c`", "ab1c"); KNOWN("`plain`", "plain"); UNK("`ab${x}c`");
// member / optional member
KNOWN("[10,20,30][1]", 20); KNOWN("({a:5}).a", 5); KNOWN("({a:{b:2}}).a.b", 2);
KNOWN("'abc'[1]", "b"); UNK("obj.x"); UNK("({a:1})[k]");
// array literal
KNOWN("[1,2].length", 2); UNK("[x,y].length");
// call — pure builtins only
KNOWN("String(42)", "42"); KNOWN("Number('5')", 5); UNK("foo()"); UNK("Math.random()");
// depth bound — build a deep AST without overflowing the parser
{
  let node = parseExpression("1");
  for (let i = 0; i < 600; i++) node = { type: "UnaryExpression", operator: "+", argument: node, prefix: true };
  ok(ev(node).known === false, "depth >512 -> unknown");
}
// constValues shadowing — a binding beats the builtin
{
  const { ev: ev2 } = makeEvaluator(new Map([["undefined", 7], ["x", "hello"], ["NaN", 3]]));
  const r1 = ev2(parseExpression("undefined"));
  ok(r1.known === true && r1.value === 7, "constValues shadows undefined builtin");
  const r2 = ev2(parseExpression("x + '!'"));
  ok(r2.known === true && r2.value === "hello!", "constValues in binary");
  const r3 = ev2(parseExpression("NaN"));
  ok(r3.known === true && r3.value === 3, "constValues shadows NaN");
}
// unknown propagates (poison)
UNK("x + 1"); UNK("1 + x"); UNK("x ? 1 : 2"); UNK("!x"); UNK("-x");
// null propagation on member access
KNOWN("({a:1}).a + 1", 2); UNK("null.x"); UNK("undefined.x");

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
