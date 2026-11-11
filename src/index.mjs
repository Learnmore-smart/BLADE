// BLADE library entry point — import the scrubbers without executing the CLI.
//   import { detect, scrubNative, dehardenJs } from "blade";
export { detect } from "./detect.mjs";
export { dehardenJs, looksBlaHardened } from "./js-deharden.mjs";
export {
  scrubAsar, scrubWasm, scrubSqlite, scrubSafetensors, scrubGguf,
} from "./formats.mjs";
export {
  scrubNative, scrubDex, scrubIl2cpp, scrubDotnet, scrubEvm, scrubPtx,
  scrubJvm, scrubPlistXml, scrubBplist, scrubPcap, scrubUf2, scrubBeam,
  scrubPyc, scrubZip, scrubPySource, scrubHtml, inspectSourcemap,
  looksLikeZip, jvmClassLooksValid,
  inspectShieldHeader, headerTombstone,
  bunfsGraphEnd, inspectBunfsSnapshot, bunfsTombstone,
  inspectSidecarNote, sidecarNoteTombstone,
} from "./trailer.mjs";
export {
  emitRuntimeCounterShield, reconstructSourceMap, scoreStructuralAnomaly,
} from "./recovery/canonical.mjs";
export { recoverJsNames, recoverWasmExports } from "./recovery/name-recovery.mjs";
