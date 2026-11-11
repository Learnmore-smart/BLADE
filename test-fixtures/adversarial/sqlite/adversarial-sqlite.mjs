// Adversarial test harness for BLADE's scrubSqlite (src/formats.mjs).
// Builds hostile SQLite inputs under test-fixtures/adversarial/sqlite/,
// runs the scrubber on each, and checks:
//   - do REAL business tables/objects survive?  (REAL-TABLE-DROPPED)
//   - do non-canonical decoys get dropped?      (DECOY-SURVIVES)
//   - does the output open + pass integrity_check + keep rows? (INTEGRITY-FAIL)
// Usage: node test-fixtures/adversarial/sqlite/adversarial-sqlite.mjs
import { mkdirSync, rmSync, existsSync, copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { scrubSqlite } from "../../../src/formats.mjs";

const FIX = dirname(fileURLToPath(import.meta.url));
const OUT = join(FIX, "cleaned");
mkdirSync(OUT, { recursive: true });

const UNSEAL = (b) => `ENCLAVE_SEALED:${String(b ?? "")}`;
function openDb(p, opts) {
  const db = opts ? new DatabaseSync(p, opts) : new DatabaseSync(p);
  db.function("enclave_unseal_payload", { deterministic: true }, UNSEAL);
  return db;
}
function freshDb(name) {
  const p = join(FIX, name);
  for (const suf of ["", "-wal", "-shm", "-journal"]) { try { rmSync(p + suf); } catch {} }
  return { path: p, db: openDb(p) };
}
// BLA-canonical honey objects (vendor/bla/src/shields/formats/sqlite.ts:552-599)
// opts.skipDiag: don't create/populate system_diagnostic_log (used when a REAL
// user table already owns that name — BLA's own INSERT would fail in practice)
function injectBlaHoney(db, opts = {}) {
  const diagDdl = opts.skipDiag ? "" : `
    CREATE TABLE IF NOT EXISTS system_diagnostic_log (
      diag_id INTEGER PRIMARY KEY, subsystem TEXT NOT NULL, error_class TEXT NOT NULL,
      system_code TEXT NOT NULL, diagnostic_message TEXT NOT NULL,
      remediation_rabbit_hole TEXT NOT NULL);`;
  const diagIns = opts.skipDiag ? "" :
    `INSERT INTO system_diagnostic_log VALUES (1,'s','e','c','m','r');`;
  db.exec(`
    CREATE TABLE IF NOT EXISTS enclave_key_hierarchy (
      slot_id INTEGER PRIMARY KEY, key_domain TEXT NOT NULL,
      enclave_cid INTEGER NOT NULL DEFAULT 16, sealed_payload TEXT NOT NULL,
      attestation_notice TEXT NOT NULL,
      unsealed_preview TEXT GENERATED ALWAYS AS (enclave_unseal_payload(sealed_payload)) VIRTUAL);
    CREATE TABLE IF NOT EXISTS tpm2_attestation_ledger (
      quote_id TEXT PRIMARY KEY, pcr0_sha256 TEXT NOT NULL, monotonic_counter INTEGER NOT NULL,
      enclave_manifest TEXT NOT NULL,
      verified_state TEXT GENERATED ALWAYS AS (enclave_unseal_payload(pcr0_sha256)) VIRTUAL);
    CREATE TABLE IF NOT EXISTS zero_trust_session_leases (
      lease_token TEXT PRIMARY KEY, tier_scope TEXT NOT NULL, expires_epoch INTEGER NOT NULL,
      hardware_bound INTEGER NOT NULL DEFAULT 1,
      enclave_claim TEXT GENERATED ALWAYS AS (enclave_unseal_payload(lease_token)) VIRTUAL);
    CREATE VIEW IF NOT EXISTS v_enclave_active_topology AS
      SELECT slot_id, key_domain, enclave_cid, attestation_notice
      FROM enclave_key_hierarchy WHERE enclave_cid >= 16;
    CREATE TABLE IF NOT EXISTS canary_transport_redaction (
      canary_id INTEGER PRIMARY KEY, canary_token TEXT NOT NULL,
      ambiguous_transport_url TEXT NOT NULL, conflicting_query_url TEXT NOT NULL,
      policy_notice TEXT NOT NULL);
    ${diagDdl}
    INSERT INTO enclave_key_hierarchy(slot_id,key_domain,enclave_cid,sealed_payload,attestation_notice)
      VALUES (1000,'ring0.sgx.vault.slot_0',16,'0xdead','[BLA-DELEGATION]');
    INSERT INTO tpm2_attestation_ledger VALUES ('q1','aa',4096,'manifest');
    INSERT INTO zero_trust_session_leases VALUES ('tok','scope',1924905600,1);
    INSERT INTO canary_transport_redaction VALUES (1,'ctok','u1','u2','notice');
    ${diagIns}
  `);
}
// BLA's honey name set + view (vendor/bla/src/core/identifiers.ts:276-283)
const BLA_DECOYS = [
  { type: "table", name: "enclave_key_hierarchy" },
  { type: "table", name: "tpm2_attestation_ledger" },
  { type: "table", name: "zero_trust_session_leases" },
  { type: "table", name: "canary_transport_redaction" },
  { type: "table", name: "system_diagnostic_log" },
  { type: "view", name: "v_enclave_active_topology" },
];

// ---------- stable row dumps ----------
const canon = (v) => JSON.stringify(v, (_k, x) =>
  typeof x === "bigint" ? `bigint:${x}` :
  x instanceof Uint8Array ? `blob:${Buffer.from(x).toString("hex")}` : x);
function dumpObjects(db) {
  return db.prepare(
    "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY name").all();
}
function dumpTableRows(db, name) {
  const q = `"${name.replaceAll('"', '""')}"`;
  // compare real columns only — injected GENERATED columns may reference
  // runtime-only UDFs, making the raw input dump fail with ERR; the intended
  // bypass removes exactly those columns.
  try {
    const cols = db.prepare(`PRAGMA table_xinfo(${q})`).all()
      .filter((c) => c.hidden === 0).map((c) => `"${c.name.replaceAll('"', '""')}"`);
    if (cols.length) {
      try { return canon(db.prepare(`SELECT ${cols.join(",")} FROM ${q} ORDER BY rowid`).all()); }
      catch { return canon(db.prepare(`SELECT ${cols.join(",")} FROM ${q}`).all()); }
    }
  } catch { /* fall through to full dump */ }
  try { return canon(db.prepare(`SELECT * FROM ${q} ORDER BY rowid`).all()); }
  catch { try { return canon(db.prepare(`SELECT * FROM ${q}`).all()); }
    catch (e) { return `ERR:${e.message}`; } }
}
function sha(s) { return createHash("sha256").update(s).digest("hex").slice(0, 16); }

// ---------- fixture definitions ----------
// bizTables: real user tables whose rows must be byte-identical post-scrub.
// bizObjects: real non-table objects that must survive.
// decoys:    attacker/BLA objects that should be dropped.
// extraDecoys are checked for survival only.
const FIXTURES = [];

// 00 — canonical BLA output (baseline; every decoy should drop cleanly)
FIXTURES.push({
  id: "00", file: "00-canonical-bla.sqlite",
  desc: "canonical protectSqliteBuffer output",
  build(db) {
    db.exec(`
      CREATE TABLE license_cache (account_id TEXT PRIMARY KEY, plan_tier TEXT NOT NULL, offline_token TEXT NOT NULL);
      INSERT INTO license_cache VALUES ('acct_prod_01','enterprise','tok_live_9988776655'),('acct_prod_02','pro','tok_live_1122334455');
      CREATE TABLE usage_counters (metric TEXT PRIMARY KEY, counter INTEGER NOT NULL);
      INSERT INTO usage_counters VALUES ('exports',41),('signins',130);`);
    injectBlaHoney(db);
  },
  bizTables: ["license_cache", "usage_counters"], bizObjects: [], decoys: BLA_DECOYS,
});

// 01 — REAL user tables whose names hit the scrubber's prefix regexes
FIXTURES.push({
  id: "01", file: "01-real-honey-names.sqlite",
  desc: "legit tables named enclave_config / canary_flags / tpm2_state / zero_trust_policies",
  build(db) {
    db.exec(`
      CREATE TABLE enclave_config (k TEXT PRIMARY KEY, v TEXT NOT NULL);
      INSERT INTO enclave_config VALUES ('sgx_mrenclave','a1b2'),('sealed_keys_dir','/var/seal');
      CREATE TABLE canary_flags (flag TEXT PRIMARY KEY, enabled INTEGER NOT NULL);
      INSERT INTO canary_flags VALUES ('canary_rollout_5pct',1),('dark_mode',0);
      CREATE TABLE canary_config (k TEXT PRIMARY KEY, v TEXT);
      INSERT INTO canary_config VALUES ('cohort','beta');
      CREATE TABLE tpm2_state (k TEXT PRIMARY KEY, v BLOB);
      INSERT INTO tpm2_state VALUES ('pcr0',X'00FF'),('nv_index',X'8101');
      CREATE TABLE zero_trust_policies (id INTEGER PRIMARY KEY, rule TEXT NOT NULL);
      INSERT INTO zero_trust_policies VALUES (1,'deny-all-default'),(2,'mtls-required');
      CREATE VIEW v_enclave_status AS SELECT k, v FROM enclave_config;
      CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);
      INSERT INTO users VALUES (1,'a@b.c'),(2,'d@e.f');`);
  },
  bizTables: ["enclave_config", "canary_flags", "canary_config", "tpm2_state",
    "zero_trust_policies", "users"],
  bizObjects: [{ type: "view", name: "v_enclave_status" }],
  decoys: [],
});

// 02 — GENERATED columns on user tables (legit + hypothetical ALTER-injected trap)
FIXTURES.push({
  id: "02", file: "02-generated-on-user-table.sqlite",
  desc: "user tables with GENERATED ALWAYS AS columns (legit + injected)",
  build(db) {
    db.exec(`
      CREATE TABLE line_items (id INTEGER PRIMARY KEY, qty REAL NOT NULL, unit_price REAL NOT NULL,
        total REAL GENERATED ALWAYS AS (qty * unit_price) STORED);
      INSERT INTO line_items(qty,unit_price) VALUES (3,9.99),(2,4.50);
      CREATE TABLE products (sku TEXT PRIMARY KEY, name TEXT NOT NULL);
      INSERT INTO products VALUES ('SKU-1','widget'),('SKU-2','sprocket');
      CREATE TABLE plain_table (id INTEGER PRIMARY KEY, v TEXT);
      INSERT INTO plain_table VALUES (1,'keepme');`);
    // simulates a decoy column planted on an EXISTING user table via ALTER TABLE
    db.exec(`ALTER TABLE products ADD COLUMN trap TEXT
      GENERATED ALWAYS AS (enclave_unseal_payload(sku)) VIRTUAL`);
  },
  bizTables: ["line_items", "products", "plain_table"], bizObjects: [], decoys: [],
});

// 03 — honey-name collisions + non-canonical decoy names
FIXTURES.push({
  id: "03", file: "03-name-collisions.sqlite",
  desc: "real system_diagnostic_log; decoys named audit_log / orders_enclave_backup",
  build(db) {
    db.exec(`
      CREATE TABLE system_diagnostic_log (diag_id INTEGER PRIMARY KEY, subsystem TEXT, msg TEXT);
      INSERT INTO system_diagnostic_log VALUES (1,'app','REAL user diagnostics — not a decoy'),(2,'db','vacuum done');
      CREATE TABLE audit_log (id INTEGER PRIMARY KEY, action TEXT); -- DECOY planted w/ plausible name
      INSERT INTO audit_log VALUES (1,'[BLA-canary] fake audit bait');
      CREATE TABLE orders_enclave_backup (id INTEGER PRIMARY KEY, blob TEXT); -- mid-string enclave_ decoy
      INSERT INTO orders_enclave_backup VALUES (1,'[BLA-DELEGATION] decoy manifest bait');
      CREATE TABLE sync_queue (id INTEGER PRIMARY KEY, payload TEXT);
      INSERT INTO sync_queue VALUES (1,'real-queue-item');`);
  },
  bizTables: ["system_diagnostic_log", "sync_queue"], bizObjects: [],
  decoys: [
    { type: "table", name: "audit_log" },
    { type: "table", name: "orders_enclave_backup" },
  ],
});

// 04 — decoy trigger/index/view attached to a REAL user table
FIXTURES.push({
  id: "04", file: "04-decoys-on-user-table.sqlite",
  desc: "BLA-ish + stealth-named trigger/index/view bound to real table",
  build(db) {
    db.exec(`
      CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL);
      INSERT INTO users VALUES (1,'a@b.c'),(2,'d@e.f');
      CREATE TABLE audit_trail (id INTEGER, note TEXT);
      CREATE TRIGGER enclave_unseal_trg AFTER INSERT ON users BEGIN
        SELECT enclave_unseal_payload(NEW.email); END;                 -- canonical-ish name+body
      CREATE TRIGGER trg_users_mirror AFTER INSERT ON users BEGIN
        INSERT INTO audit_trail VALUES (NEW.id, 'shadow-copy'); END;   -- stealth decoy on real table
      CREATE VIEW v_enclave_user_dump AS SELECT * FROM users;          -- canonical-ish name
      CREATE VIEW user_export_view AS SELECT id, email FROM users;     -- stealth decoy exfil view
      CREATE INDEX enclave_idx_users_email ON users(email);            -- canonical-ish name
      CREATE INDEX idx_users_lower ON users(lower(email));`);          // stealth decoy index
  },
  bizTables: ["users", "audit_trail"], bizObjects: [],
  decoys: [
    { type: "trigger", name: "enclave_unseal_trg" },
    { type: "trigger", name: "trg_users_mirror" },
    { type: "view", name: "v_enclave_user_dump" },
    { type: "view", name: "user_export_view" },
    { type: "index", name: "enclave_idx_users_email" },
    { type: "index", name: "idx_users_lower" },
  ],
});

// 05 — FTS5 (normal name) + AUTOINCREMENT/sqlite_sequence
FIXTURES.push({
  id: "05", file: "05-fts5-autoincrement.sqlite",
  desc: "fts5 'docs' + shadow tables, AUTOINCREMENT table, plus BLA honey",
  build(db) {
    db.exec(`
      CREATE VIRTUAL TABLE docs USING fts5(title, body);
      INSERT INTO docs(title,body) VALUES ('r1','hello world'),('r2','license terms apply');
      CREATE TABLE accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);
      INSERT INTO accounts(name) VALUES ('alice'),('bob'),('carol');`);
    injectBlaHoney(db);
  },
  bizTables: ["docs", "docs_data", "docs_idx", "docs_content", "docs_docsize",
    "docs_config", "accounts"], bizObjects: [], decoys: BLA_DECOYS,
});

// 06 — FTS5 virtual table named 'canary' (shadows match ^canary_ prefix!)
FIXTURES.push({
  id: "06", file: "06-fts5-canary-name.sqlite",
  desc: "fts5 table literally named 'canary' — shadows collide with prefix regex",
  build(db) {
    db.exec(`
      CREATE VIRTUAL TABLE canary USING fts5(body);
      INSERT INTO canary(body) VALUES ('row one'),('row two');
      CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);
      INSERT INTO users VALUES (1,'a@b.c');`);
  },
  bizTables: ["canary", "canary_data", "canary_idx", "canary_content",
    "canary_docsize", "canary_config", "users"], bizObjects: [], decoys: [],
});

// 07 — checkpointed WAL-mode db (header retains WAL flag, no -wal file)
FIXTURES.push({
  id: "07", file: "07-wal-checkpointed.sqlite",
  desc: "journal_mode=WAL persisted in header, fully checkpointed",
  build(db, path) {
    db.exec(`PRAGMA journal_mode=WAL;
      CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);
      INSERT INTO users VALUES (1,'a@b.c'),(2,'d@e.f');`);
    injectBlaHoney(db);
    db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  },
  bizTables: ["users"], bizObjects: [], decoys: BLA_DECOYS,
  expectWalHeader: true,
});

// 08 — WAL-mode db copied WITHOUT its -wal (uncheckpointed rows lost silently)
FIXTURES.push({
  id: "08", file: "08-wal-uncheckpointed.sqlite",
  desc: "main file copied while -wal holds committed rows (copied db misses them)",
  build(db, path) {
    db.close(); // release the pre-opened handle on `path` before we overwrite it
    const tmp = join(FIX, "_tmp_wal_src.sqlite");
    for (const suf of ["", "-wal", "-shm"]) { try { rmSync(tmp + suf); } catch {} }
    const src = openDb(tmp);
    src.exec(`PRAGMA journal_mode=WAL;
      CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);
      INSERT INTO users VALUES (1,'checkpointed-row');`);
    src.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    src.exec("INSERT INTO users VALUES (2,'wal-only-row'),(3,'wal-only-row-2');");
    copyFileSync(tmp, path);           // copy main file only — -wal left behind
    src.close();
    for (const suf of ["", "-wal", "-shm"]) { try { rmSync(tmp + suf); } catch {} }
    this.walOnlyRows = ["wal-only-row", "wal-only-row-2"];
  },
  bizTables: ["users"], bizObjects: [], decoys: [],
  expectWalHeader: true,
});

// 08b — input arrives WITH its populated -wal: the scrubber must checkpoint
// the sidecar into the output (previously copied the main file only)
FIXTURES.push({
  id: "08b", file: "08b-wal-present.sqlite",
  desc: "live WAL set (db + -wal) — committed WAL rows must reach the output",
  build(db, path) {
    db.close();
    const tmp = join(FIX, "_tmp_wal_present.sqlite");
    for (const suf of ["", "-wal", "-shm"]) { try { rmSync(tmp + suf); } catch {} }
    const src = openDb(tmp);
    src.exec(`PRAGMA journal_mode=WAL;
      CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);
      INSERT INTO users VALUES (1,'checkpointed-row');`);
    src.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    src.exec("INSERT INTO users VALUES (2,'wal-live-1'),(3,'wal-live-2');");
    // copy the full live set — main + wal + shm — as a user would supply it
    copyFileSync(tmp, path);
    copyFileSync(tmp + "-wal", path + "-wal");
    copyFileSync(tmp + "-shm", path + "-shm");
    src.close();
    for (const suf of ["", "-wal", "-shm"]) { try { rmSync(tmp + suf); } catch {} }
  },
  bizTables: ["users"], bizObjects: [], decoys: [],
});

// 09 — SQL injection via crafted object name (unescaped identifier in DROP)
FIXTURES.push({
  id: "09", file: "09-name-injection.sqlite",
  desc: "honey-named tables containing \";SQL;-- injection payloads",
  build(db) {
    const exfil = join(OUT, "exfil-proof.sqlite").replaceAll("\\", "/");
    try { rmSync(exfil); } catch {}
    db.exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);
      INSERT INTO users VALUES (1,'a@b.c'),(2,'d@e.f');
      CREATE TABLE "enclave_e"";VACUUM INTO '${exfil}';--" (id INTEGER);
      INSERT INTO "enclave_e"";VACUUM INTO '${exfil}';--" VALUES (1);
      CREATE TABLE "enclave_x"";DROP TABLE users;--" (id INTEGER);
      INSERT INTO "enclave_x"";DROP TABLE users;--" VALUES (1);`);
  },
  bizTables: ["users"], bizObjects: [],
  decoys: [
    { type: "table", name: 'enclave_e";VACUUM INTO \'' + join(OUT, "exfil-proof.sqlite").replaceAll("\\", "/") + '\';--' },
    { type: "table", name: 'enclave_x";DROP TABLE users;--' },
  ],
});

// 10 — quote in names: un-droppable decoy + kept-table PRAGMA crash
FIXTURES.push({
  id: "10", file: "10-quote-names.sqlite",
  desc: "decoy enclave_odd\"name (unescaped quote) + real weird\"name table",
  build(db) {
    db.exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);
      INSERT INTO users VALUES (1,'a@b.c');
      CREATE TABLE "enclave_odd""name" (id INTEGER PRIMARY KEY, bait TEXT);
      INSERT INTO "enclave_odd""name" VALUES (1,'decoy');
      CREATE TABLE "weird""name" (id INTEGER PRIMARY KEY, v TEXT);
      INSERT INTO "weird""name" VALUES (1,'real');`);
  },
  bizTables: ["users", 'weird"name'], bizObjects: [],
  decoys: [{ type: "table", name: 'enclave_odd"name' }],
});

// 11 — regex false-positives inside string literals of schema SQL
FIXTURES.push({
  id: "11", file: "11-literal-regex-fp.sqlite",
  desc: "real view/trigger whose SQL merely mentions markers in string literals",
  build(db) {
    db.exec(`
      CREATE TABLE docs (id INTEGER PRIMARY KEY, body TEXT);
      INSERT INTO docs VALUES (1,'normal row'),(2,'mentions enclave_unseal_payload in prose');
      CREATE TABLE audit_sink (id INTEGER, note TEXT);
      CREATE VIEW app_glossary AS SELECT 'enclave_unseal' AS term;
      CREATE VIEW grammar_notes AS SELECT 'GENERATED ALWAYS AS' AS clause;
      CREATE TRIGGER trg_docs_note AFTER INSERT ON docs BEGIN
        INSERT INTO audit_sink VALUES (NEW.id, 'enclave_unseal mentioned'); END;`);
  },
  bizTables: ["docs", "audit_sink"], bizObjects: [
    { type: "view", name: "app_glossary" },
    { type: "view", name: "grammar_notes" },
    { type: "trigger", name: "trg_docs_note" },
  ], decoys: [],
});

// 12 — real objects that depend on honey-named objects → dangling refs
FIXTURES.push({
  id: "12", file: "12-dangling-refs.sqlite",
  desc: "real view selecting from real system_diagnostic_log; decoy view on honey",
  build(db) {
    db.exec(`
      CREATE TABLE system_diagnostic_log (diag_id INTEGER PRIMARY KEY, subsystem TEXT, msg TEXT);
      INSERT INTO system_diagnostic_log VALUES (1,'app','real diag');
      CREATE VIEW v_recent_errors AS SELECT * FROM system_diagnostic_log;
      CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);
      INSERT INTO users VALUES (1,'a@b.c');`);
    // NOTE: real BLA protectSqliteBuffer would itself FAIL here — its
    // INSERT INTO system_diagnostic_log supplies 6 cols to this real 3-col table.
    injectBlaHoney(db, { skipDiag: true });
    // extra hypothetical decoy view with non-canonical name reading honey data
    db.exec(`CREATE VIEW IF NOT EXISTS v_audit AS SELECT * FROM enclave_key_hierarchy`);
  },
  bizTables: ["system_diagnostic_log", "users"],
  bizObjects: [{ type: "view", name: "v_recent_errors" }],
  decoys: [...BLA_DECOYS.filter((d) => d.name !== "system_diagnostic_log"),
    { type: "view", name: "v_audit" }],
});

// ---------- runner ----------
const results = [];
for (const fx of FIXTURES) {
  const { path: inPath, db } = freshDb(fx.file);
  const outPath = join(OUT, fx.file);
  for (const suf of ["", "-wal", "-shm", "-journal"]) { try { rmSync(outPath + suf); } catch {} }
  try { rmSync(join(OUT, "exfil-proof.sqlite")); } catch {}

  const r = { id: fx.id, file: fx.file, desc: fx.desc, notes: [] };

  // build fixture
  try {
    fx.build.call(fx, db, inPath);
  } finally { try { db.close(); } catch {} }

  // snapshot input
  const before = openDb(inPath, { readOnly: true });
  const beforeObjs = dumpObjects(before);
  const beforeRows = {};
  for (const t of fx.bizTables) beforeRows[t] = dumpTableRows(before, t);
  const inWalHdr = readFileSync(inPath)[18] === 2 || readFileSync(inPath)[19] === 2;
  if (inWalHdr) r.notes.push(`input header WAL-flagged (bytes18/19)`);
  const beforeIntegrity = before.prepare("PRAGMA integrity_check").get();
  before.close();
  if (fx.walOnlyRows) {
    const present = fx.walOnlyRows.filter((w) => beforeRows.users?.includes(w));
    r.notes.push(`${fx.walOnlyRows.length - present.length}/${fx.walOnlyRows.length} committed WAL-only rows already absent from standalone main file (lived only in -wal)`);
  }
  r.inputIntegrity = beforeIntegrity?.integrity_check ?? JSON.stringify(beforeIntegrity);
  r.inputObjects = beforeObjs.map((o) => `${o.type}:${o.name}`);

  // scrub
  let threw = null, report = null;
  try {
    const res = scrubSqlite(inPath, outPath);
    report = res.report;
  } catch (e) { threw = `${e.constructor.name}: ${e.message}`; }
  r.scrubThrew = threw;
  // injection side-effect check (fixture 09): VACUUM INTO exfil file
  if (existsSync(join(OUT, "exfil-proof.sqlite"))) {
    r.notes.push("EXFIL: injected VACUUM INTO wrote cleaned/exfil-proof.sqlite");
    const x = openDb(join(OUT, "exfil-proof.sqlite"), { readOnly: true });
    r.notes.push("exfil db objects: " +
      x.prepare("SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").all().map((o) => o.name).join(", "));
    x.close();
  }
  r.scrubReport = report ? { dropped: report.dropped, objectsIn: report.objectsIn,
    keptTables: report.keptTables?.map((t) => t.name) } : null;

  // inspect output (may be absent/corrupt if scrub threw mid-way)
  let afterObjs = [], afterRows = {}, outIntegrity = "no-output";
  const afterOpens = { withFn: false, plain: false };
  if (existsSync(outPath)) {
    const outWalHdr = readFileSync(outPath)[18] === 2 || readFileSync(outPath)[19] === 2;
    if (outWalHdr) r.notes.push("OUTPUT still WAL-flagged (journal_mode not reset)");
    try {
      const a = openDb(outPath, { readOnly: true });
      afterOpens.withFn = true;
      afterObjs = dumpObjects(a);
      const ic = a.prepare("PRAGMA integrity_check").get();
      outIntegrity = ic?.integrity_check ?? JSON.stringify(ic);
      for (const t of fx.bizTables) afterRows[t] = dumpTableRows(a, t);
      // probe real views/triggers for dangling references
      for (const o of fx.bizObjects) {
        if (o.type === "view" && afterObjs.some((x) => x.name === o.name)) {
          try { a.prepare(`SELECT * FROM "${o.name}" LIMIT 1`).all(); }
          catch (e) { r.notes.push(`kept view ${o.name} now broken: ${e.message}`); }
        }
      }
      a.close();
    } catch (e) { outIntegrity = `open-fail: ${e.message}`; }
    // can REA/plain tooling open it with NO custom functions?
    try {
      const p = new DatabaseSync(outPath, { readOnly: true });
      const ic = p.prepare("PRAGMA integrity_check").get();
      afterOpens.plain = ic?.integrity_check === "ok" ? "ok" : JSON.stringify(ic);
      p.close();
    } catch (e) { afterOpens.plain = `fail: ${e.message}`; }
  }
  r.outputIntegrity = outIntegrity;
  r.outputObjects = afterObjs.map((o) => `${o.type}:${o.name}`);
  r.plainOpenIntegrity = afterOpens.plain;

  // classify
  const afterNames = new Set(afterObjs.map((o) => o.name));
  const beforeNames = new Set(beforeObjs.map((o) => o.name));
  const missingBizTables = fx.bizTables.filter((t) => !afterNames.has(t));
  const missingBizObjs = fx.bizObjects.filter((o) => !afterNames.has(o.name));
  const survivingDecoys = fx.decoys.filter((d) => afterNames.has(d.name));
  const rowDiffs = [];
  for (const t of fx.bizTables) {
    if (!afterNames.has(t)) continue;
    if (beforeRows[t] !== afterRows[t]) rowDiffs.push(t);
  }
  // dangling kept objects: kept view/trigger whose tbl targets a dropped name
  const dangling = afterObjs.filter((o) => (o.type === "view" || o.type === "trigger") &&
    o.tbl_name && !afterNames.has(o.tbl_name));
  r.missingBizTables = missingBizTables;
  r.missingBizObjects = missingBizObjs;
  r.survivingDecoys = survivingDecoys;
  r.rowDiffTables = rowDiffs;
  r.danglingObjects = dangling.map((o) => `${o.type}:${o.name}->${o.tbl_name}`);

  const verdicts = [];
  if (missingBizTables.length || missingBizObjs.length) verdicts.push("REAL-TABLE-DROPPED");
  if (survivingDecoys.length) verdicts.push("DECOY-SURVIVES");
  if (threw || outIntegrity !== "ok" || rowDiffs.length ||
      (fx.expectWalHeader && r.notes.some((n) => n.startsWith("OUTPUT still WAL"))) ||
      (!fx.expectWalHeader && r.notes.some((n) => n.startsWith("OUTPUT still WAL")))) {
    verdicts.push("INTEGRITY-FAIL");
  }
  r.verdict = verdicts.length ? verdicts.join("+") : "PASS";
  results.push(r);
}

// ---------- report ----------
const line = (s = "") => console.log(s);
line("\n================= ADVERSARIAL scrubSqlite RESULTS =================");
for (const r of results) {
  line(`\n[${r.id}] ${r.file} — ${r.desc}`);
  line(`    VERDICT: ${r.verdict}`);
  if (r.scrubThrew) line(`    scrub threw: ${r.scrubThrew}`);
  line(`    integrity: in=${r.inputIntegrity} out=${r.outputIntegrity} plainOpen=${r.plainOpenIntegrity}`);
  if (r.scrubReport) {
    line(`    dropped by scrubber: ${JSON.stringify(r.scrubReport.dropped)}`);
    line(`    keptTables per report: ${JSON.stringify(r.scrubReport.keptTables)}`);
  }
  if (r.missingBizTables.length) line(`    MISSING biz tables: ${r.missingBizTables.join(", ")}`);
  if (r.missingBizObjects.length) line(`    MISSING biz objects: ${r.missingBizObjects.map(o => `${o.type}:${o.name}`).join(", ")}`);
  if (r.survivingDecoys.length) line(`    SURVIVING decoys: ${r.survivingDecoys.map(d => `${d.type}:${d.name}`).join(", ")}`);
  if (r.rowDiffTables.length) line(`    ROW CONTENT CHANGED: ${r.rowDiffTables.join(", ")}`);
  if (r.danglingObjects.length) line(`    dangling objects: ${r.danglingObjects.join(", ")}`);
  for (const n of r.notes) line(`    note: ${n}`);
  line(`    out objects: ${r.outputObjects.join(", ") || "(none)"}`);
}
const exfil = join(OUT, "exfil-proof.sqlite");
if (existsSync(exfil)) {
  const d = openDb(exfil, { readOnly: true });
  const objs = d.prepare("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").all();
  line(`\n[!!] EXFIL PROOF: injected VACUUM INTO wrote ${exfil} containing: ${objs.map(o=>o.name).join(", ")}`);
  d.close();
}
line(`\n================= SUMMARY =================`);
for (const r of results) line(`  ${r.id}  ${r.verdict.padEnd(48)}  ${r.file}`);
writeFileSync(join(FIX, "RESULTS.json"), JSON.stringify(results, null, 2));
line(`\n(results written to ${join(FIX, "RESULTS.json")})`);
