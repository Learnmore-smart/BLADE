// BLADE library entry point — import the scrubbers without executing the CLI.
//   import { detect, scrubNative, dehardenJs } from "blade";
//
// Contract shared by every scrubXxx(bufOrText) function:
//   - never throws on malformed input — worst case is a passthrough with a
//     `note` field explaining why nothing was modified;
//   - returns { buffer } (binary formats) or { code } (text formats) plus a
//     `report` object; report.hardened=true means BLA surface was found;
//   - never destroys data it cannot prove is armor — ambiguous evidence is
//     kept and flagged in the report (suspicious*/flagged* fields).
export { detect } from "./detect.mjs";
export { dehardenJs, looksBlaHardened, sniffEmbeddedPayload } from "./js-deharden.mjs";
export {
  scrubAsar, scrubWasm, scrubSqlite, scrubSafetensors, scrubGguf,
  readU32Leb, writeU32Leb,
} from "./formats.mjs";
export {
  scrubNative, scrubDex, scrubIl2cpp, scrubDotnet, scrubEvm, scrubPtx,
  scrubJvm, scrubPlistXml, scrubBplist, scrubPcap, scrubUf2, scrubBeam,
  scrubPyc, scrubZip, scrubPySource, scrubHtml, inspectSourcemap,
  looksLikeZip, jvmClassLooksValid,
  inspectShieldHeader, headerTombstone,
  bunfsGraphEnd, inspectBunfsSnapshot, bunfsTombstone,
  inspectSidecarNote, sidecarNoteTombstone, inspectBlaManifest, blaManifestTombstone,
} from "./trailer.mjs";
export {
  emitRuntimeCounterShield, reconstructSourceMap, scoreStructuralAnomaly,
  recoverFuseDefaults,
} from "./recovery/canonical.mjs";
export { recoverJsNames, recoverWasmExports } from "./recovery/name-recovery.mjs";
export {
  scoreSqliteObjects, beamLoneDecoyScore, neutralizePyLiteralMarkers,
  detectOpaqueSeedVariants, pycSurgicalSpans,
} from "./recovery/precision.mjs";
export {
  salvageZipMember, triagePcapTail, repairDex, preserveApkMeta, detectEvmPad,
} from "./recovery/salvage.mjs";
export {
  makeEvaluator, computeContainmentCorpusDigest, repairCorpusDigest,
} from "./evaluator.mjs";
