// Type declarations for the BLADE library entry point.
// Scrubbers return either { buffer } (binary) or { code } (text) plus a
// `report`; the exact report shape varies per format and is intentionally
// loose — the contract is documented in src/index.mjs.

export interface ScrubReport {
  format?: string;
  hardened?: boolean;
  note?: string;
  [key: string]: unknown;
}

export interface BufferResult {
  buffer: Buffer;
  report: ScrubReport;
}
export interface CodeResult {
  code: string;
  report: ScrubReport;
}

export type DetectedKind =
  | "js" | "asar" | "wasm" | "sqlite" | "safetensors" | "gguf" | "native"
  | "dex" | "il2cpp" | "dotnet" | "evm" | "ptx" | "jvm" | "plist" | "pcap"
  | "uf2" | "beam" | "pyc" | "zip" | "py" | "html" | "sourcemap" | "header"
  | "bunfs-snapshot" | "sidecar-note" | "bla-manifest" | "bla-config"
  | "unknown";

/** Route an input buffer to a scrubber kind (magic first, ext fallback). */
export function detect(buf: Buffer, ext: string): DetectedKind;

/** Structural gate — multiple injected families in code positions. */
export function looksBlaHardened(source: string): boolean;
export function dehardenJs(
  source: string,
  opts?: { filename?: string },
): CodeResult;
/** Flag an embedded binary payload signature in decoded text (polyglots). */
export function sniffEmbeddedPayload(source: string): { kind: string; offset: number } | null;

export interface AsarOptions {
  /** Supply `<input>.unpacked/` sibling content for integrity checks. */
  getExternal?: (path: string) => Buffer | null;
}
export interface AsarResult extends BufferResult {
  unpackedExternals?: Array<{ path: string; content: Buffer }>;
}
export function scrubAsar(buf: Buffer, opts?: AsarOptions): AsarResult;
export function scrubWasm(buf: Buffer): BufferResult;
/** Path-based: WAL sidecars require a real fs path. */
export function scrubSqlite(inputPath: string, outputPath: string): { report: ScrubReport };
export function scrubSafetensors(buf: Buffer): BufferResult;
export function scrubGguf(buf: Buffer): BufferResult;

export function scrubNative(buf: Buffer): BufferResult;
export function scrubDex(buf: Buffer): BufferResult;
export function scrubIl2cpp(buf: Buffer): BufferResult;
export function scrubDotnet(buf: Buffer): BufferResult;
export function scrubEvm(buf: Buffer): BufferResult;
export function scrubPtx(text: string): CodeResult;
export function scrubJvm(buf: Buffer): BufferResult;
export function scrubPlistXml(text: string): CodeResult;
export function scrubBplist(buf: Buffer): BufferResult;
export function scrubPcap(buf: Buffer): BufferResult;
export function scrubUf2(buf: Buffer): BufferResult;
export function scrubBeam(buf: Buffer): BufferResult;
export function scrubPyc(buf: Buffer): BufferResult;
export function scrubZip(buf: Buffer, depth?: number): BufferResult;
export function scrubPySource(text: string): CodeResult;
export function scrubHtml(text: string): CodeResult;

export function looksLikeZip(buf: Buffer): boolean;
export function jvmClassLooksValid(buf: Buffer): boolean;

export interface InspectReport extends ScrubReport {
  [key: string]: unknown;
}
export function inspectSourcemap(text: string): InspectReport;
export function inspectShieldHeader(text: string): InspectReport;
export function headerTombstone(): string;
export function bunfsGraphEnd(buf: Buffer): number;
export function inspectBunfsSnapshot(buf: Buffer): InspectReport;
export function bunfsTombstone(): string;
export function inspectSidecarNote(buf: Buffer): InspectReport;
export function sidecarNoteTombstone(): string;
export function inspectBlaManifest(buf: Buffer): InspectReport & {
  schema?: string; signed?: boolean; decoy?: boolean;
  runId?: string; artifactsRecorded?: number; nodesRecorded?: number;
  domains?: number; weaveTargets?: number; overallStatus?: string;
};
export function blaManifestTombstone(schema?: string): string;

// ---- recovery/canonical ----
export interface FuseRecoveryResult {
  buf: Buffer;
  status: "restored" | "unchanged" | "absent" | "ambiguous" | "unsupported";
  fuseOffset: number;
  sentinelCount: number;
  platform: string;
  electronVersion: object | null;
  confidence: "detected" | "assumed";
  note?: string;
}
export function recoverFuseDefaults(buf: Buffer, report: ScrubReport): FuseRecoveryResult;

export interface SourceMapRecovery {
  map: object;
  status: string;
}
export function reconstructSourceMap(
  hardenedMapJson: unknown,
  dehardenedJs: string | null,
  origJsLen: number,
): SourceMapRecovery;

export interface RuntimeCounterShield {
  families: string[];
  fridaScript: string;
  cdpNotes: string;
  teeStubSurface: string;
}
export function emitRuntimeCounterShield(hardenedHints: string[]): RuntimeCounterShield;

export interface StructuralAnomaly {
  score: number;
  signals: string[];
}
export function scoreStructuralAnomaly(buf: Buffer, formatHint?: string): StructuralAnomaly;

// ---- recovery/name-recovery ----
export interface JsRename {
  from: string;
  to: string;
  confidence: string;
  evidence: string;
}
export function recoverJsNames(code: string, report?: ScrubReport): {
  code: string;
  renames: JsRename[];
  unrenamable: Array<{ name: string; reason: string }>;
};
export function recoverWasmExports(wasm: Buffer): {
  names: Array<Record<string, unknown>>;
  nameSection?: Buffer;
  note?: string;
};

// ---- recovery/precision ----
export interface PycSpliceResult {
  buf: Buffer;
  bytePreservedPct: number;
  spliced: boolean;
  removedBytes: number;
  patchedCounts: number;
  note?: string;
}
export function pycSurgicalSpans(
  origPyc: Buffer,
  dehardenedPyc: Buffer,
  removedRanges: Array<[number, number]>,
): PycSpliceResult;

export function neutralizePyLiteralMarkers(
  src: string,
  markers: RegExp,
  opts?: { comments?: boolean },
): { src: string; neutralized: number };

export interface SqliteScore {
  name: string;
  decoyScore: number;
  verdict: "drop" | "flag" | "keep";
  reason: string;
}
export function scoreSqliteObjects(
  objects: Array<{ type: string; name: string; tbl_name?: string; sql?: string }>,
): SqliteScore[];

export function beamLoneDecoyScore(
  chunk: Buffer,
): { score: number; verdict: "drop" | "flag" | "keep"; reason: string };

export function detectOpaqueSeedVariants(
  js: string,
): Array<{ kind: string; start: number; end: number; evidence: string }>;

// ---- recovery/salvage ----
export function triagePcapTail(tail: Buffer): {
  kept: Buffer;
  dropped: Buffer;
  reason: string;
};
export function detectEvmPad(
  buf: Buffer,
  declaredEnd?: number,
): { padStart: number | null; confidence: string; evidence: string };
export function salvageZipMember(
  raw: Buffer,
  method: number,
): { data: Buffer | null; salvagedBytes: number; note: string };
export function repairDex(buf: Buffer): {
  buf: Buffer;
  repairs: string[];
  status: string;
};
export function preserveApkMeta(origLocal: Buffer, origCentral: Buffer): Buffer | null;

// ---- evaluator (partial evaluation + corpus digest) ----
/** Partial evaluator over Babel AST; depth-bounded, poisons on unknown. */
export function makeEvaluator(constValues?: Map<string, unknown>): {
  ev: (node: object | null) => { known: true; value: unknown } | { known: false };
};
export function computeContainmentCorpusDigest(
  entries: Array<{ coupledAnchorSymbol: unknown; triggerPayload: unknown }>,
  seedInput?: number,
): number;
export function repairCorpusDigest(
  entries: Array<{ coupledAnchorSymbol: unknown; triggerPayload: unknown }>,
  expected: number,
): {
  entry: number;
  field: string;
  charIndex: number;
  oldChar: string;
  newChar: string;
  newText: string;
} | null;
