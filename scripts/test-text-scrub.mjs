#!/usr/bin/env node
// Unit checks for the text-carrier scrubbers — scrubPySource (Python
// weave/marker removal, triple-quote awareness, CRLF preservation) and
// scrubHtml (inline-script dehardening, comment masking, src= pass).
import { readFileSync } from "node:fs";
import { scrubPySource, scrubHtml } from "../src/trailer.mjs";

let pass = 0, fail = 0;
const ok = (cond, name) => { if (cond) pass++; else { fail++; console.log("FAIL:", name); } };

// --- scrubPySource -----------------------------------------------------------
{
  const clean = "def f():\n    return 1\n";
  const r = scrubPySource(clean);
  ok(r.code === clean || r.text === clean, "clean py passthrough");
  ok(r.report.hardened === false, "clean py not flagged");
}
{
  // CRLF is preserved
  const crlf = "def f():\r\n    return 1\r\n";
  const r = scrubPySource(crlf);
  ok((r.code ?? r.text).includes("\r\n"), "crlf preserved");
}
{
  // marker-shaped literals are neutralized in place (not deleted) —
  // line structure and docstring survive intact
  const doc = 'def f():\n    """\n    BLA_MARKER_LINE_HERE\n    """\n    return 1\n';
  const r = scrubPySource(doc);
  const out = r.code ?? r.text;
  ok(out.split("\n").length === doc.split("\n").length, "neutralization preserves line structure");
  ok(out.includes('"""') && out.includes("return 1"), "docstring + body survive");
}
{
  const hardened = readFileSync("test-fixtures/hardened/license.py", "utf8");
  const r = scrubPySource(hardened);
  ok(r.report.hardened === true, "hardened py flagged");
  ok((r.code ?? r.text).length < hardened.length * 0.3, "hardened py shrinks");
}
{
  ok(scrubPySource("").report.hardened === false, "empty py safe");
}

// --- scrubHtml ----------------------------------------------------------------
{
  const clean = "<html><body><script>const x=1;</script></body></html>";
  const r = scrubHtml(clean);
  ok((r.code ?? r.text ?? r.html) === clean, "clean inline js kept");
}
{
  // <script src=...> never touched
  const ext = '<html><body><script src="app.js"></script></body></html>';
  const r = scrubHtml(ext);
  ok((r.code ?? r.text ?? r.html) === ext, "src= script kept");
}
{
  // non-js script types never touched
  const tpl = '<html><body><script type="text/template">x{{y}}</script></body></html>';
  const r = scrubHtml(tpl);
  ok((r.code ?? r.text ?? r.html) === tpl, "template script kept");
}
{
  // <script> inside an html comment is inert markup — never dehardened
  const cmt = '<html><body><!-- <script>alert(1)</script> --></body></html>';
  const r = scrubHtml(cmt);
  ok((r.code ?? r.text ?? r.html) === cmt, "commented script kept");
}
{
  const hardened = readFileSync("test-fixtures/hardened/app.html", "utf8");
  const r = scrubHtml(hardened);
  const out = r.code ?? r.text ?? r.html;
  ok(out.length < hardened.length, "hardened html shrinks");
  ok(!out.includes("_interlockSafetyCorpus_"), "inline corpus gone");
}
{
  ok(typeof scrubHtml("").report === "object" || scrubHtml(""), "empty html safe");
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
