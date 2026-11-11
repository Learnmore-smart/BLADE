// Generates adversarial pcap/pcapng fixtures for testing BLADE's scrubPcap.
// Each builder returns a Buffer; files land beside this script.
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const DIR = dirname(fileURLToPath(import.meta.url));

// ---- classic pcap helpers ----
function globalHeaderLE(magicBytes = [0xd4, 0xc3, 0xb2, 0xa1]) {
  const h = Buffer.alloc(24);
  Buffer.from(magicBytes).copy(h, 0);
  h.writeUInt16LE(2, 4);          // version major
  h.writeUInt16LE(4, 6);          // version minor
  h.writeInt32LE(0, 8);           // thiszone
  h.writeUInt32LE(0, 12);         // sigfigs
  h.writeUInt32LE(65535, 16);     // snaplen
  h.writeUInt32LE(1, 20);         // linktype Ethernet
  return h;
}
function globalHeaderBE() {
  const h = Buffer.alloc(24);
  Buffer.from([0xa1, 0xb2, 0xc3, 0xd4]).copy(h, 0); // BE microsecond magic
  h.writeUInt16BE(2, 4);
  h.writeUInt16BE(4, 6);
  h.writeInt32BE(0, 8);
  h.writeUInt32BE(0, 12);
  h.writeUInt32BE(65535, 16);
  h.writeUInt32BE(1, 20);
  return h;
}
function recLE(payload, tsSec = 1_700_000_000, tsUsec = 0, origLen = payload.length) {
  const r = Buffer.alloc(16);
  r.writeUInt32LE(tsSec, 0);
  r.writeUInt32LE(tsUsec, 4);
  r.writeUInt32LE(payload.length, 8); // incl_len
  r.writeUInt32LE(origLen, 12);       // orig_len
  return Buffer.concat([r, payload]);
}
function recBE(payload, tsSec = 1_700_000_000, tsUsec = 0, origLen = payload.length) {
  const r = Buffer.alloc(16);
  r.writeUInt32BE(tsSec, 0);
  r.writeUInt32BE(tsUsec, 4);
  r.writeUInt32BE(payload.length, 8);
  r.writeUInt32BE(origLen, 12);
  return Buffer.concat([r, payload]);
}

// ---- BLA-shaped packet builders (mirror vendor/bla pcap-capture.ts) ----
function ipv4Checksum(ipHeader) {
  let sum = 0;
  for (let i = 0; i < 20; i += 2) sum += ipHeader.readUInt16BE(i);
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}
function ethIp(proto, payloadLen, l4hdrLen) {
  const eth = Buffer.alloc(14, 0);
  eth[12] = 0x08; eth[13] = 0x00;
  const ip = Buffer.alloc(20, 0);
  ip[0] = 0x45;
  ip.writeUInt16BE(20 + l4hdrLen + payloadLen, 2);
  ip[8] = 64; ip[9] = proto;
  ip[12] = 10; ip[15] = 1; ip[16] = 10; ip[19] = 2;
  ip.writeUInt16BE(ipv4Checksum(ip), 10);
  return Buffer.concat([eth, ip]);
}
function tcpFrame(payload, seq = 1000) {
  const tcp = Buffer.alloc(20, 0);
  tcp.writeUInt16BE(40_000 + (seq % 1000), 0);
  tcp.writeUInt16BE(80, 2);
  tcp.writeUInt32BE(seq >>> 0, 4);
  tcp.writeUInt32BE(1, 8);
  tcp[12] = 5 << 4; tcp[13] = 0x18; // PSH+ACK
  tcp.writeUInt16BE(65535, 14);
  return Buffer.concat([ethIp(6, payload.length, 20), tcp, payload]);
}
function udpFrame(payload) {
  const udp = Buffer.alloc(8, 0);
  udp.writeUInt16BE(1337, 0);
  udp.writeUInt16BE(53, 2);
  udp.writeUInt16BE(8 + payload.length, 4);
  return Buffer.concat([ethIp(17, payload.length, 8), udp, payload]);
}
// Exact BLA HTTP decoy payload shape (buildHttpLikePayload, headerCount=4)
function blaHttpPayload() {
  const lines = [
    "GET /bla/tarpit/exhaust HTTP/1.1",
    "Host: enclave.internal",
    "User-Agent: BLA-PCAP-Shield/1.0",
    "[BLA-PCAP-SHIELD] canary=deadbeefcafe1234",
    "X-BLA-Nested-0: aaaa",
    "Connection: keep-alive", "", "",
  ];
  return Buffer.from(lines.join("\r\n"), "utf8");
}
// Exact BLA DNS decoy shape: real DNS query + [BLA-PCAP-SHIELD] bait trailer
function blaDnsPayload() {
  const hdr = Buffer.alloc(12, 0);
  hdr.writeUInt16BE(0xb1a0, 0);
  hdr.writeUInt16BE(0x0100, 2);
  hdr.writeUInt16BE(1, 4);
  const labels = [];
  for (let i = 0; i < 6; i++) {
    const lab = `l${i.toString(36)}dead`;
    const b = Buffer.from(lab, "ascii");
    labels.push(Buffer.from([b.length]), b);
  }
  labels.push(Buffer.from([0]));
  const qtype = Buffer.alloc(4);
  qtype.writeUInt16BE(1, 0); qtype.writeUInt16BE(1, 2);
  const bait = Buffer.from("\n[BLA-PCAP-SHIELD]\nTXT diagnostic bait\n", "utf8");
  return Buffer.concat([hdr, ...labels, qtype, bait]);
}
const realHttpPayload = Buffer.from(
  "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n", "utf8");

// ============================ fixtures ============================
const fixtures = {};

// CASE 1: pcapng — SHB + IDB + EPB(real) + EPB([BLA-PCAP-SHIELD] payload)
{
  const pad4 = (n) => (4 - (n % 4)) % 4;
  const block = (type, body, le = true) => {
    const total = 12 + body.length;
    const b = Buffer.alloc(total);
    b.writeUInt32LE(type, 0);
    b.writeUInt32LE(total, 4);
    body.copy(b, 8);
    b.writeUInt32LE(total, total - 4);
    return b;
  };
  const shb = (() => {
    const body = Buffer.alloc(16);
    body.writeUInt32LE(0x1a2b3c4d, 0); // byte-order magic
    body.writeUInt16LE(1, 4); body.writeUInt16LE(0, 6);
    body.writeBigInt64LE(-1n, 8);
    return block(0x0a0d0d0a, body);
  })();
  const idb = (() => {
    const body = Buffer.alloc(8);
    body.writeUInt16LE(1, 0);           // linktype Ethernet
    body.writeUInt16LE(0, 2);
    body.writeUInt32LE(65535, 4);       // snaplen
    return block(0x00000001, body);
  })();
  const epb = (frame, tsHigh = 0, tsLow = 1000) => {
    const p = pad4(frame.length);
    const body = Buffer.alloc(20 + frame.length + p);
    body.writeUInt32LE(0, 0);            // interface id
    body.writeUInt32LE(tsHigh, 4);
    body.writeUInt32LE(tsLow, 8);
    body.writeUInt32LE(frame.length, 12);
    body.writeUInt32LE(frame.length, 16);
    frame.copy(body, 20);
    return block(0x00000006, body);
  };
  fixtures["case1-pcapng.pcapng"] = Buffer.concat([
    shb, idb,
    epb(tcpFrame(realHttpPayload), 0, 1000),
    epb(tcpFrame(Buffer.from("[BLA-PCAP-SHIELD] canary=x", "utf8")), 0, 2000),
  ]);
}

// CASE 1b: pcapng where the marker lives inside a STRUCTURAL block (an SHB
// option/comment) — the block cannot be dropped without breaking the file,
// so the correct outcome is keep + suspiciousBlocks flag.
{
  const pad4 = (n) => (4 - (n % 4)) % 4;
  const block = (type, body) => {
    const total = 12 + body.length;
    const b = Buffer.alloc(total);
    b.writeUInt32LE(type, 0);
    b.writeUInt32LE(total, 4);
    body.copy(b, 8);
    b.writeUInt32LE(total, total - 4);
    return b;
  };
  const opt = (code, text) => {
    const t = Buffer.from(text, "utf8");
    const o = Buffer.alloc(4 + t.length + pad4(t.length));
    o.writeUInt16LE(code, 0); o.writeUInt16LE(t.length, 2);
    t.copy(o, 4);
    return o;
  };
  const shbBody = Buffer.concat([
    (() => { const b = Buffer.alloc(16); b.writeUInt32LE(0x1a2b3c4d, 0); b.writeUInt16LE(1, 4); b.writeUInt16LE(0, 6); b.writeBigInt64LE(-1n, 8); return b; })(),
    opt(1, "captured inside enclave.internal sandbox /bla/tarpit/"), // opt_comment w/ 2 ambient markers
    Buffer.alloc(4), // opt_endofopt
  ]);
  const idbBody = (() => { const b = Buffer.alloc(8); b.writeUInt16LE(1, 0); b.writeUInt16LE(0, 2); b.writeUInt32LE(65535, 4); return b; })();
  const epbBody = (() => {
    const f = tcpFrame(realHttpPayload); const b = Buffer.alloc(20 + f.length + pad4(f.length));
    b.writeUInt32LE(f.length, 12); b.writeUInt32LE(f.length, 16); f.copy(b, 20);
    return b;
  })();
  fixtures["case1b-pcapng-structural-marker.pcapng"] = Buffer.concat([
    block(0x0a0d0d0a, shbBody), block(0x00000001, idbBody), block(0x00000006, epbBody),
  ]);
}

// CASE 2: classic LE pcap, REAL packets whose payloads legitimately mention
// the marker strings (captured traffic discussing the tool / its tarpit URL).
{
  const docPage = Buffer.from(
    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
    "<html>Docs: bla-agents injects [BLA-PCAP-SHIELD] decoy packets. " +
    "UA string is BLA-PCAP-Shield/1.0.</html>", "utf8");
  const dnsEnclave = Buffer.concat([
    (() => { const h = Buffer.alloc(12, 0); h.writeUInt16BE(0x1234, 0); h.writeUInt16BE(0x0100, 2); h.writeUInt16BE(1, 4); return h; })(),
    Buffer.from([7]), Buffer.from("enclave", "ascii"),
    Buffer.from([8]), Buffer.from("internal", "ascii"),
    Buffer.from([0, 0, 1, 0, 1]),
  ]);
  fixtures["case2-real-marker-payload.pcap"] = Buffer.concat([
    globalHeaderLE(),
    recLE(tcpFrame(realHttpPayload), 1_700_000_000, 0),
    recLE(tcpFrame(docPage), 1_700_000_001, 0),          // REAL packet, marker text in body
    recLE(udpFrame(dnsEnclave), 1_700_000_002, 0),       // REAL DNS query for enclave.internal
    recLE(tcpFrame(realHttpPayload), 1_700_000_003, 0),
  ]);
  // sub-case: real packet + genuine BLA decoys appended — mixed file
  fixtures["case2b-real-marker-plus-decoys.pcap"] = Buffer.concat([
    globalHeaderLE(),
    recLE(tcpFrame(docPage), 1_700_000_000, 0),          // real packet with marker text
    recLE(tcpFrame(blaHttpPayload()), 1_700_000_001, 0), // BLA decoy
    recLE(udpFrame(blaDnsPayload()), 1_700_000_002, 0),  // BLA decoy
  ]);
}

// CASE 3: big-endian pcap (disk bytes a1 b2 c3 d4)
{
  // 3a: well-formed BE file, decoy record header written BE (spec-correct)
  fixtures["case3a-be-decoy-be.pcap"] = Buffer.concat([
    globalHeaderBE(),
    recBE(tcpFrame(realHttpPayload), 1_700_000_000, 0),
    recBE(tcpFrame(blaHttpPayload()), 1_700_000_001, 0),
  ]);
  // 3b: BE file + BLA decoy appended — recordWrap ALWAYS writes LE headers,
  // so BLA itself emits mixed-endian files for BE input.
  fixtures["case3b-be-decoy-le.pcap"] = Buffer.concat([
    globalHeaderBE(),
    recBE(tcpFrame(realHttpPayload), 1_700_000_000, 0),
    recLE(tcpFrame(blaHttpPayload()), 1_700_000_001, 0), // exactly what BLA emits
  ]);
}

// CASE 4: record-length edge cases
{
  // 4a: incl_len < orig_len (snaplen truncation — normal, legal)
  fixtures["case4a-snaplen.pcap"] = Buffer.concat([
    globalHeaderLE(),
    recLE(tcpFrame(realHttpPayload).subarray(0, 60), 1_700_000_000, 0, 200), // incl 60 < orig 200
    recLE(tcpFrame(blaHttpPayload()), 1_700_000_001, 0),
  ]);
  // 4b: incl_len > remaining bytes — truncated final record
  {
    const ghost = Buffer.alloc(16);
    ghost.writeUInt32LE(1_700_000_001, 0);
    ghost.writeUInt32LE(0, 4);
    ghost.writeUInt32LE(5000, 8);   // claims 5000 bytes
    ghost.writeUInt32LE(5000, 12);
    fixtures["case4b-truncated-tail.pcap"] = Buffer.concat([
      globalHeaderLE(),
      recLE(tcpFrame(realHttpPayload), 1_700_000_000, 0),
      ghost,
      Buffer.alloc(40, 0x41),       // only 40 bytes of the claimed 5000 exist
    ]);
  }
  // 4c: truncated record BEFORE appended decoys — walker break hides decoys
  {
    const ghost = Buffer.alloc(16);
    ghost.writeUInt32LE(1_700_000_001, 0);
    ghost.writeUInt32LE(0, 4);
    ghost.writeUInt32LE(0xfffffff0, 8);  // absurd incl_len
    ghost.writeUInt32LE(0xfffffff0, 12);
    fixtures["case4c-truncated-hides-decoys.pcap"] = Buffer.concat([
      globalHeaderLE(),
      recLE(tcpFrame(realHttpPayload), 1_700_000_000, 0),
      ghost,
      recLE(tcpFrame(blaHttpPayload()), 1_700_000_002, 0),
    ]);
  }
  // 4d: incl_len > orig_len (spec-invalid but walkers must not choke)
  fixtures["case4d-incl-gt-orig.pcap"] = Buffer.concat([
    globalHeaderLE(),
    (() => { const f = tcpFrame(realHttpPayload); const r = Buffer.alloc(16);
      r.writeUInt32LE(1_700_000_000, 0); r.writeUInt32LE(0, 4);
      r.writeUInt32LE(f.length, 8); r.writeUInt32LE(f.length - 20, 12); // incl > orig
      return Buffer.concat([r, f]); })(),
    recLE(tcpFrame(blaHttpPayload()), 1_700_000_001, 0),
  ]);
}

// CASE 5: nanosecond-resolution pcaps
{
  // 5a: LE nanosecond (4d 3c b2 a1)
  fixtures["case5a-nano-le.pcap"] = Buffer.concat([
    globalHeaderLE([0x4d, 0x3c, 0xb2, 0xa1]),
    recLE(tcpFrame(realHttpPayload), 1_700_000_000, 123456789),
    recLE(tcpFrame(blaHttpPayload()), 1_700_000_001, 987654321),
  ]);
  // 5b: BE nanosecond (a1 b2 3c 4d)
  {
    const h = globalHeaderBE();
    Buffer.from([0xa1, 0xb2, 0x3c, 0x4d]).copy(h, 0);
    fixtures["case5b-nano-be.pcap"] = Buffer.concat([
      h,
      recBE(tcpFrame(realHttpPayload), 1_700_000_000, 123456789),
      recBE(tcpFrame(blaHttpPayload()), 1_700_000_001, 987654321),
    ]);
  }
}

// CASE 6: decoys INTERLEAVED between real packets
fixtures["case6-interleaved.pcap"] = Buffer.concat([
  globalHeaderLE(),
  recLE(tcpFrame(realHttpPayload), 1_700_000_000, 0),
  recLE(tcpFrame(blaHttpPayload()), 1_700_000_001, 0),   // decoy
  recLE(udpFrame(dnsEnclaveLikeReal()), 1_700_000_002, 0),
  recLE(udpFrame(blaDnsPayload()), 1_700_000_003, 0),    // decoy
  recLE(tcpFrame(realHttpPayload), 1_700_000_004, 0),
]);
function dnsEnclaveLikeReal() {
  return Buffer.concat([
    (() => { const h = Buffer.alloc(12, 0); h.writeUInt16BE(0xabcd, 0); h.writeUInt16BE(0x0100, 2); h.writeUInt16BE(1, 4); return h; })(),
    Buffer.from([6]), Buffer.from("github", "ascii"),
    Buffer.from([3]), Buffer.from("com", "ascii"),
    Buffer.from([0, 0, 1, 0, 1]),
  ]);
}

// CASE 7: header-identical real vs decoy — filter must key on payload marker,
// not flags/ports. Real packet uses same PSH+ACK, port 80, TTL 64 as decoys.
{
  const realSynAck = (() => {
    const tcp = Buffer.alloc(20, 0);
    tcp.writeUInt16BE(80, 0); tcp.writeUInt16BE(40000, 2);
    tcp.writeUInt32BE(1, 4); tcp.writeUInt32BE(1, 8);
    tcp[12] = 5 << 4; tcp[13] = 0x12; // SYN+ACK, zero payload
    tcp.writeUInt16BE(65535, 14);
    return Buffer.concat([ethIp(6, 0, 20), tcp]);
  })();
  fixtures["case7-header-identical.pcap"] = Buffer.concat([
    globalHeaderLE(),
    recLE(tcpFrame(blaHttpPayload(), 4242), 1_700_000_000, 0), // decoy w/ realistic headers
    recLE(realSynAck, 1_700_000_001, 0),                        // real control packet, no payload
    recLE(tcpFrame(realHttpPayload, 4243), 1_700_000_002, 0),  // real data packet
  ]);
}

for (const [name, buf] of Object.entries(fixtures)) {
  const p = join(DIR, name);
  writeFileSync(p, buf);
  console.log(`wrote ${name} (${buf.length} bytes)`);
}
