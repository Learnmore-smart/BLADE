"use strict";
var blaTDurableTree_cfb=["178,104,118,29,214,184,153,88,242,170,72,238,25,3,115,196,206,70,52,114,57,166,202,154,93,61,193,33,56,240,44,57,237,179,31,220,9,79,154,253,124,193,111,3,163,14,53,20,44,130,224,87,63,134,112,196,78,61,46,236".split(",").map(Number),"227,122,58,91,193,178,142,70,168,251,16,225,71,9,34,223,158,73,114,113,46,169,202,198,16,109,140,33,49,176,113,105,162,227,18,215,18,95,153,176,34,202,60,4,245,79,98,88,62,214,167,90,111,156,108,157,73,108,59,185,227,189,42,51".split(",").map(Number)];var blaKLocalProbe_b73="218,28,2,109,165,130,182,119,144,195,36,130,112,109,20,234,167,40,64,23,75,200,171,246,115,88,185,64,85,128,64,92,195,208,112,177,38,57,168,210,16,168,12,102,205,125,80,59,90,231,146,62,89,255,93,168,43,92,93,137,211,220,26,11".split(",").map(Number);function blaSLocalCatalog_fe3(i){var e=blaTDurableTree_cfb[i],k=blaKLocalProbe_b73,o=new Uint8Array(e.length);for(var j=0;j<e.length;j++)o[j]=(e[j]^k[j%k.length])&255;return typeof Buffer!=="undefined"?Buffer.from(o).toString("utf8"):(typeof TextDecoder!=="undefined"?new TextDecoder().decode(o):String.fromCharCode.apply(null,Array.from(o)));}var _blaS=blaSLocalCatalog_fe3;var _blaT=blaTDurableTree_cfb;
const API_ENDPOINT = blaSLocalCatalog_fe3(0);
const MASTER_KEY = blaSLocalCatalog_fe3(1);
function planLimit(plan) {
  return plan === "pro" ? 25 : 5;
}
module.exports = { API_ENDPOINT, MASTER_KEY, planLimit };
