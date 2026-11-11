// Builds bun-standalone decoy fixtures mirroring BLA protectTarget output
// (vendor/bla src/shields/formats/bun-standalone.ts + runtime/sidecar-entangle.ts):
//
//   decoy.bunfs-snapshot        — standalone decoy module graph; the Offsets
//                                 claim covers the WHOLE file (payloadOffset==0)
//   decoy-sized.bunfs-snapshot  — same graph + trailing u64 total-size footer
//                                 ("appended-trailer-sized" variant)
//   real-bun                    — ELF magic head + appended graph: a real
//                                 `bun build --compile`-style carrier
//                                 (payloadOffset>0); must passthrough untouched
//   app.bla-sidecar.v1.json     — bla-sidecar-entangle/v1 companion note
//   notes.txt                   — plain text: still unrecognized (exit 1)
//
//   node test-fixtures/adversarial/bunfs/gen.mjs
import { writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const DIR = dirname(fileURLToPath(import.meta.url));
const ROOT = join(DIR, "..", "..", "..");
const require = createRequire(import.meta.url);
const { SeededPrng } = require(join(ROOT, "vendor", "bla", "dist", "core", "prng.js"));
const { generateBunStandaloneDecoyGraph } = require(
  join(ROOT, "vendor", "bla", "dist", "shields", "formats", "bun-standalone.js"),
);
const { entangleBunEntryWithSidecars } = require(
  join(ROOT, "vendor", "bla", "dist", "shields", "runtime", "sidecar-entangle.js"),
);

// (a) real decoy graph bytes straight from BLA — data ‖ Offsets(32) ‖ trailer.
const decoy = generateBunStandaloneDecoyGraph(new SeededPrng("blade-fixture"), "balanced").buffer;
writeFileSync(join(DIR, "decoy.bunfs-snapshot"), decoy);

// (a2) sized variant: same standalone graph + u64 total-size footer. Bun's
// footer records the full file size INCLUDING the 8 footer bytes.
const footer = Buffer.alloc(8);
footer.writeBigUInt64LE(BigInt(decoy.length + 8));
writeFileSync(join(DIR, "decoy-sized.bunfs-snapshot"), Buffer.concat([decoy, footer]));

// (b) fake REAL bun binary: ELF magic + exec bytes, then the graph appended.
// The appended graph's Offsets claim only covers the graph — payloadOffset
// equals the ELF part length (>0). Must route to native and passthrough.
const elf = Buffer.alloc(256, 0);
elf.write("\x7fELF", 0, "latin1");
elf[4] = 2; elf[5] = 1; elf[6] = 1; // ELF64, little-endian, version
elf.write("FAKE-BUN-EXEC", 0x40, "latin1");
const realBun = Buffer.concat([elf, decoy]);
writeFileSync(join(DIR, "real-bun"), realBun);

// (c) companion note bound the way protectTarget does: entry = real binary,
// sidecar = the .bunfs-snapshot — binary bytes never enter the note.
const bound = entangleBunEntryWithSidecars({
  entryPath: "real-bun",
  entryBytes: realBun,
  sidecars: [{ pathLabel: "real-bun.bunfs-snapshot", bytes: decoy }],
  seedTag: "blade-fixture",
});
writeFileSync(join(DIR, "app.bla-sidecar.v1.json"), bound.noteBytes);

// (d) plain text — no magic, no sentinel, no entangle schema: exit 1.
writeFileSync(join(DIR, "notes.txt"), "just a readme — nothing to deharden here\n");

for (const f of [
  "decoy.bunfs-snapshot", "decoy-sized.bunfs-snapshot",
  "real-bun", "app.bla-sidecar.v1.json", "notes.txt",
]) console.log(`wrote ${f}`);
