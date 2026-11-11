// Compose adversarial HTML fixtures from the REAL BLA-hardened bundle.
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const dir = dirname(fileURLToPath(import.meta.url));
const hardened = readFileSync(join(dir, "hardened-real.html"), "utf8");
const bodies = [];
hardened.replace(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi, (m, attrs, body) => {
  bodies.push(body);
  return m;
});
const H = bodies[0]; // real hardened classic-script body (~67KB)
const HMOD = bodies[1]; // real hardened module body
console.log("hardened bodies:", bodies.map((b) => b.length));

const wrap = (inner) => `<!DOCTYPE html>\n<html>\n<head><title>t</title></head>\n<body>\n${inner}\n</body>\n</html>\n`;
const w = (name, content) => { writeFileSync(join(dir, name), content); console.log("wrote", name, content.length); };

// ---------- Case 1: literal </script> inside a string ----------
// 1a: string at TOP of a hardened body -> regex splits at the in-string close,
//     head body is `const s = "` (not hardened) -> passthrough, and the entire
//     remaining hardened payload sits outside any further <script> match.
w("case1a-literal-close-top.html", wrap(
  `<script>\nconst s = "</script>";\n${H.trim()}\n</script>`
));
// 1b: string in the MIDDLE of the hardened body -> head looks hardened,
//     gets dehardened on TRUNCATED source; tail `";...code...</script>` remains.
const mid = Math.floor(H.length / 2);
const atNl = H.indexOf("\n", mid);
w("case1b-literal-close-mid.html", wrap(
  `<script>${H.slice(0, atNl)}\nconst s = "</script>";\n${H.slice(atNl)}</script>`
));

// ---------- Case 2: <script> in non-script contexts ----------
// 2a: inside an HTML comment
w("case2a-script-in-comment.html", wrap(
  `<!--\n<script>${H.trim()}\n</script>\n-->\n<p>page</p>`
));
// 2b: inside <textarea> (raw-text element; script is inert)
w("case2b-script-in-textarea.html", wrap(
  `<textarea rows="40" cols="120">\n<script>${H.trim()}\n</script>\n</textarea>`
));
// 2c: <script>...</script> inside a template literal in an OUTER hardened script.
// Raw </script> inside the backtick string -> the lazy body match ends there.
w("case2c-template-literal.html", wrap(
  "<script>\nconst tpl = `<div><script>alert(1)</script></div>`;\n" + H.trim() + "\n</script>"
));

// ---------- Case 3: attributes ----------
// 3a: standalone hardened module script (also covered in hardened-real.html)
w("case3a-module.html", wrap(`<script type="module">${HMOD.trim()}\n</script>`));
// 3b: src= external script (BLA never transforms; body is dead code in browsers)
//     variant i: empty body -> should passthrough
w("case3b-src-empty.html", wrap(`<script src="app.js"></script>\n<script src="x.js">   </script>`));
//     variant ii: src= + hardened-looking inline body (browser ignores it;
//     scrubber must NOT touch it -> if it dehardens, that's NON-SCRIPT-DEHARDENED)
w("case3b-src-with-body.html", wrap(`<script src="app.js">${H.trim()}\n</script>`));
// 3c: application/json data block — BLA never transforms it.
//     benign JSON -> passthrough expected
w("case3c-json-benign.html", wrap(
  `<script type="application/json">{"price": 10, "tags": ["a", "b"], "note": "x < y"}</script>`
));
//     JSON containing a BLA marker string -> looksBlaHardened fires on a DATA block
w("case3c-json-marker.html", wrap(
  `<script type="application/json">{"name": "demo", "corpus": "_interlockSafetyCorpus_9f2", "refs": ["obligationFlood_9f2", "scc_9f2_c1n2"]}</script>`
));
// 3d: importmap — also a non-JS data block browsers treat as JSON
w("case3d-importmap-marker.html", wrap(
  `<script type="importmap">{"imports": {"obligationFlood_77": "./obligationFlood_77.js", "_interlockSafetyCorpus_0": "./x.js"}}</script>`
));

// ---------- Case 4: mixed hardened + plain ----------
w("case4-mixed.html", wrap(
  `<script>\nconst plainly = 1 + 2;\nconsole.log("plain script survives:", plainly);\n</script>\n` +
  `<script>${H.trim()}\n</script>\n` +
  `<script>\nfunction tail() { return "tail-real"; }\ntail();\n</script>`
));

// ---------- Case 5: entity-encoded script body ----------
// A body where < > & are entity-escaped (what a sanitizer/CMS might emit).
// BLA never produces this; check the scrubber does NOT corrupt or "restore" it.
const encoded = H.trim()
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
w("case5-entity-encoded.html", wrap(`<script>\n${encoded}\n</script>`));
// also: entities only in a PLAIN body
w("case5b-entity-plain.html", wrap(
  `<script>\nif (a &lt; b &amp;&amp; c &gt; d) { console.log(&quot;hi&quot;); }\n</script>`
));

// ---------- Case 6: hardened-looking JS in inline event handlers ----------
w("case6-event-handlers.html", wrap(
  `<button onclick="obligationFlood_9f2(); _interlockSafetyCorpus_9f2 = []; track()">buy</button>\n` +
  `<a href="javascript:obligationFlood_77()">x</a>\n` +
  `<div onmouseover="scc_9f2_c1n2()">hover</div>\n` +
  `<script>\nconst real = "this script is not hardened";\n</script>`
));

// ---------- Case 7: non-HTML content routed to the html scrubber ----------
w("case7-plain-text.html", `# Not HTML at all\n\nJust some notes about <script> tags & other things.\n`);
// a raw hardened JS file with a .html extension (no <script> wrapper)
w("case7-js-as-html.html", H.trim() + "\n");
