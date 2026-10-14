#!/usr/bin/env node
'use strict';
/*
 * proxycheck.js — Kiểm tra proxy có hỗ trợ UDP và QUIC hay không.
 *
 * Cách hoạt động:
 *   1. Kết nối TCP tới proxy, tự nhận dạng loại proxy (SOCKS5 / HTTP / SOCKS4).
 *   2. TCP  : SOCKS5 CONNECT hoặc HTTP CONNECT tới www.cloudflare.com:443.
 *   3. UDP  : SOCKS5 UDP ASSOCIATE -> gửi truy vấn DNS thật qua relay của proxy
 *             (1.1.1.1:53 / 8.8.8.8:53). Có phản hồi = UDP thực sự đi qua được.
 *             HTTP proxy: thử MASQUE connect-udp (RFC 9298) — hầu hết không hỗ trợ.
 *   4. QUIC : Dựng gói QUIC v1 Initial thật (TLS 1.3 ClientHello, mã hoá đúng chuẩn
 *             RFC 9001) gửi qua relay UDP tới server HTTP/3 (www.cloudflare.com:443).
 *             Nhận được ServerHello / Retry / Version Negotiation = QUIC đi qua được proxy.
 *
 * Chỉ dùng module có sẵn của Node.js (>= 16), không cần cài thêm gì.
 *
 *   node proxycheck.js 1.2.3.4:1080
 *   node proxycheck.js user:pass@1.2.3.4:1080
 *   node proxycheck.js -f proxies.txt -o ketqua.json --good udp_ok.txt
 *   node proxycheck.js --help
 */

const net = require('net');
const dgram = require('dgram');
const dns = require('dns');
const crypto = require('crypto');
const fs = require('fs');

const DEFAULTS = {
  timeout: 5000,
  threads: 20,
  dnsServers: ['1.1.1.1', '8.8.8.8'],
  quicHosts: ['www.cloudflare.com', 'www.google.com'],
  tcpTarget: { host: 'www.cloudflare.com', port: 443 },
  noQuic: false,
  verbose: false,
  color: true,
};

// ============================================================================
// Tiện ích chung
// ============================================================================

function u16(n) { const b = Buffer.alloc(2); b.writeUInt16BE(n & 0xffff); return b; }
function u32(n) { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; }

// QUIC variable-length integer (RFC 9000 §16) — dùng cho cả capsule MASQUE
function encVarint(n) {
  if (n < 0x40) return Buffer.from([n]);
  if (n < 0x4000) return Buffer.from([0x40 | (n >> 8), n & 0xff]);
  if (n < 0x40000000) { const b = u32(n); b[0] |= 0x80; return b; }
  const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); b[0] |= 0xc0; return b;
}
function decVarint(buf, off) {
  if (off >= buf.length) throw new Error('varint: hết dữ liệu');
  const len = 1 << (buf[off] >> 6);
  if (off + len > buf.length) throw new Error('varint: hết dữ liệu');
  let v = buf[off] & 0x3f;
  for (let i = 1; i < len; i++) v = v * 256 + buf[off + i];
  return [v, off + len];
}

function ipv6str(b) {
  return Array.from({ length: 8 }, (_, i) => b.readUInt16BE(i * 2).toString(16)).join(':');
}

function isPublicIPv4(ip) {
  if (!net.isIPv4(ip)) return false;
  const [a, b] = ip.split('.').map(Number);
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  return true;
}

async function resolveIPv4(host) {
  if (net.isIPv4(host)) return host;
  const r = await dns.promises.lookup(host, { family: 4 });
  return r.address;
}
async function resolveAllIPv4(host) {
  if (net.isIPv4(host)) return [host];
  try { return await dns.promises.resolve4(host); }
  catch (_) { return [await resolveIPv4(host)]; }
}

// ============================================================================
// Socket TCP có buffer + đọc theo điều kiện
// ============================================================================

class TcpConn {
  constructor() {
    this.sock = null; this.buf = Buffer.alloc(0);
    this.closed = false; this.err = null; this.waiters = [];
  }
  connect(host, port, timeout) {
    return new Promise((resolve, reject) => {
      const s = (this.sock = new net.Socket());
      let settled = false;
      const timer = setTimeout(() => { if (!settled) s.destroy(new Error('connect timeout')); }, timeout);
      s.setNoDelay(true);
      s.once('connect', () => { settled = true; clearTimeout(timer); resolve(); });
      s.on('data', d => { this.buf = Buffer.concat([this.buf, d]); this._notify(); });
      s.on('error', e => { clearTimeout(timer); this.err = e; this.closed = true; this._notify(); if (!settled) { settled = true; reject(e); } });
      s.on('close', () => { this.closed = true; this._notify(); if (!settled) { settled = true; reject(new Error('connection closed')); } });
      s.connect(port, host);
    });
  }
  _notify() { const w = this.waiters; this.waiters = []; for (const fn of w) fn(); }
  write(buf) {
    return new Promise((resolve, reject) => {
      if (this.closed) return reject(this.err || new Error('socket closed'));
      this.sock.write(buf, err => (err ? reject(err) : resolve()));
    });
  }
  // Chờ tới khi pred(buf) trả về số byte cần lấy (>0). pred có thể throw để huỷ.
  readWhen(pred, timeout) {
    return new Promise((resolve, reject) => {
      let done = false;
      const timer = setTimeout(() => { if (!done) { done = true; reject(new Error('read timeout')); } }, timeout);
      const check = () => {
        if (done) return;
        let n;
        try { n = pred(this.buf); } catch (e) { done = true; clearTimeout(timer); return reject(e); }
        if (n) {
          done = true; clearTimeout(timer);
          const out = Buffer.from(this.buf.subarray(0, n));
          this.buf = this.buf.subarray(n);
          return resolve(out);
        }
        if (this.closed) { done = true; clearTimeout(timer); return reject(this.err || new Error('connection closed')); }
        this.waiters.push(check);
      };
      check();
    });
  }
  readN(n, timeout) { return this.readWhen(b => (b.length >= n ? n : 0), timeout); }
  readHttpHead(timeout) {
    return this.readWhen(b => {
      if (b.length >= 5 && b.subarray(0, 5).toString('latin1') !== 'HTTP/') throw new Error('not http');
      const i = b.indexOf('\r\n\r\n');
      return i >= 0 ? i + 4 : 0;
    }, timeout);
  }
  close() { this.closed = true; if (this.sock) this.sock.destroy(); }
}

// ============================================================================
// Socket UDP có hàng đợi + nhận theo điều kiện
// ============================================================================

class UdpSock {
  constructor() {
    this.sock = dgram.createSocket('udp4');
    this.queue = []; this.waiters = []; this.err = null;
    this.sock.on('message', (msg, rinfo) => {
      this.queue.push({ msg, rinfo });
      if (this.queue.length > 256) this.queue.shift();
      this._notify();
    });
    this.sock.on('error', e => { this.err = e; this._notify(); });
  }
  bind() {
    return new Promise((res, rej) => {
      this.sock.once('error', rej);
      this.sock.bind(0, '0.0.0.0', () => res());
    });
  }
  send(buf, port, host) {
    return new Promise((res, rej) => this.sock.send(buf, port, host, e => (e ? rej(e) : res())));
  }
  _notify() { const w = this.waiters; this.waiters = []; for (const fn of w) fn(); }
  // Chờ gói tin thoả pred(msg, rinfo) (trả về giá trị truthy -> resolve giá trị đó)
  recv(pred, timeout) {
    return new Promise((resolve, reject) => {
      let done = false;
      const timer = setTimeout(() => { if (!done) { done = true; reject(new Error('timeout')); } }, timeout);
      const check = () => {
        if (done) return;
        if (this.err) { done = true; clearTimeout(timer); return reject(this.err); }
        for (let i = 0; i < this.queue.length; i++) {
          let r = null;
          try { r = pred(this.queue[i].msg, this.queue[i].rinfo); } catch (_) { r = null; }
          if (r) { this.queue.splice(i, 1); done = true; clearTimeout(timer); return resolve(r); }
        }
        this.waiters.push(check);
      };
      check();
    });
  }
  close() { try { this.sock.close(); } catch (_) { /* ignore */ } }
}

// ============================================================================
// Phân tích chuỗi proxy
//   host:port | host:port:user:pass | user:pass:host:port | user:pass@host:port
//   host|port hoặc host|port|user|pass
//   HTTP|host|port|user|pass (cũng hỗ trợ SOCKS5, SOCKS4)
//   có thể có tiền tố socks5:// socks5h:// socks4:// http:// https://
// ============================================================================

function parseProxy(str) {
  let s = str.trim();
  let type = null, user = null, pass = null;
  const m = s.match(/^(socks5h?|socks4a?|https?):\/\//i) ||
    s.match(/^(socks5h?|socks4a?|https?)\s*\|(?=[^|:@]+\|\s*\d+\s*(?:\||$))/i);
  if (m) {
    type = m[1].toLowerCase();
    if (type === 'socks5h') type = 'socks5';
    if (type === 'socks4a') type = 'socks4';
    if (type === 'https') type = 'http';
    s = s.slice(m[0].length);
  }
  const pipeFormat = /^[^|:@]+\|\s*\d+\s*(?:\||$)/.test(s);
  if (!pipeFormat) s = s.replace(/\/+$/, '');
  let hostport = s;
  const at = pipeFormat ? -1 : s.lastIndexOf('@');
  if (at >= 0) {
    const cred = s.slice(0, at); hostport = s.slice(at + 1);
    const i = cred.indexOf(':');
    user = i >= 0 ? cred.slice(0, i) : cred;
    pass = i >= 0 ? cred.slice(i + 1) : '';
  }
  const parts = hostport.split(pipeFormat ? '|' : ':');
  if (pipeFormat) {
    parts[0] = parts[0].trim();
    parts[1] = parts[1].trim();
  }
  let host, port;
  if (parts.length === 2) [host, port] = parts;
  else if (parts.length === 4) {
    if (/^\d+$/.test(parts[1])) [host, port, user, pass] = parts;       // host:port:user:pass
    else if (/^\d+$/.test(parts[3])) [user, pass, host, port] = parts;  // user:pass:host:port
    else throw new Error('không hiểu định dạng');
  } else throw new Error('không hiểu định dạng');
  port = parseInt(port, 10);
  if (!host || !(port > 0 && port < 65536)) throw new Error('host/port không hợp lệ');
  const dec = v => { if (v == null) return v; try { return decodeURIComponent(v); } catch (_) { return v; } };
  return { raw: str.trim(), type, host, port, user: dec(user), pass: dec(pass) };
}

// ============================================================================
// SOCKS5 (RFC 1928 / RFC 1929)
// ============================================================================

const SOCKS5_REP = {
  0: 'thành công', 1: 'lỗi chung của proxy', 2: 'bị chặn bởi ruleset', 3: 'network unreachable',
  4: 'host unreachable', 5: 'connection refused', 6: 'TTL expired',
  7: 'command not supported (proxy không hỗ trợ lệnh này)', 8: 'address type not supported',
};
const socks5RepText = rep => `${SOCKS5_REP[rep] || 'lỗi'} (rep=${rep})`;

function socks5Addr(host, port) {
  if (net.isIPv4(host)) return Buffer.concat([Buffer.from([1]), Buffer.from(host.split('.').map(Number)), u16(port)]);
  const h = Buffer.from(host);
  return Buffer.concat([Buffer.from([3, h.length]), h, u16(port)]);
}

// Trả về phương thức xác thực đã dùng ('none' | 'userpass'). Ném lỗi có e.notSocks nếu không phải SOCKS5.
async function socks5Handshake(conn, p, timeout) {
  const hasCred = p.user != null;
  await conn.write(hasCred ? Buffer.from([5, 2, 0, 2]) : Buffer.from([5, 1, 0]));
  let r;
  try { r = await conn.readN(2, timeout); }
  catch (e) { e.notSocks = true; throw e; }
  if (r[0] !== 5) { const e = new Error('không phải SOCKS5'); e.notSocks = true; throw e; }
  if (r[1] === 0x00) return 'none';
  if (r[1] === 0x02) {
    if (!hasCred) throw new Error('proxy yêu cầu user/pass');
    const u = Buffer.from(p.user), pw = Buffer.from(p.pass || '');
    await conn.write(Buffer.concat([Buffer.from([1, u.length]), u, Buffer.from([pw.length]), pw]));
    const a = await conn.readN(2, timeout);
    if (a[1] !== 0) throw new Error('sai user/pass');
    return 'userpass';
  }
  if (r[1] === 0xff) throw new Error(hasCred ? 'proxy không chấp nhận user/pass' : 'proxy yêu cầu xác thực (thiếu user/pass)');
  throw new Error(`phương thức xác thực lạ (${r[1]})`);
}

async function socks5Request(conn, cmd, host, port, timeout) {
  await conn.write(Buffer.concat([Buffer.from([5, cmd, 0]), socks5Addr(host, port)]));
  const head = await conn.readN(4, timeout);
  if (head[0] !== 5) throw new Error('phản hồi không phải SOCKS5');
  const out = { rep: head[1], addr: null, port: 0 };
  if (out.rep !== 0) return out;
  const atyp = head[3];
  if (atyp === 1) { const b = await conn.readN(6, timeout); out.addr = [...b.subarray(0, 4)].join('.'); out.port = b.readUInt16BE(4); }
  else if (atyp === 3) { const l = (await conn.readN(1, timeout))[0]; const b = await conn.readN(l + 2, timeout); out.addr = b.subarray(0, l).toString(); out.port = b.readUInt16BE(l); }
  else if (atyp === 4) { const b = await conn.readN(18, timeout); out.addr = ipv6str(b.subarray(0, 16)); out.port = b.readUInt16BE(16); }
  else throw new Error(`ATYP lạ (${atyp})`);
  return out;
}

// Gói UDP qua relay SOCKS5: RSV(2) FRAG(1) ATYP ADDR PORT DATA
function socksUdpWrap(host, port, data) { return Buffer.concat([Buffer.from([0, 0, 0]), socks5Addr(host, port), data]); }
function socksUdpUnwrap(msg) {
  if (msg.length < 8 || msg[2] !== 0) return null;
  let off = 3; const atyp = msg[off++]; let host;
  if (atyp === 1) { host = [...msg.subarray(off, off + 4)].join('.'); off += 4; }
  else if (atyp === 3) { const l = msg[off++]; host = msg.subarray(off, off + l).toString(); off += l; }
  else if (atyp === 4) { host = ipv6str(msg.subarray(off, off + 16)); off += 16; }
  else return null;
  if (off + 2 > msg.length) return null;
  const port = msg.readUInt16BE(off); off += 2;
  return { host, port, data: msg.subarray(off) };
}

// "Đường đi UDP" trừu tượng: send(host, port, data) / recv(pred({host,port,data}), timeout)
function socksUdpPath(udp, relayIp, relayPort) {
  return {
    name: `relay ${relayIp}:${relayPort}`,
    send: (host, port, data) => udp.send(socksUdpWrap(host, port, data), relayPort, relayIp),
    recv: (pred, timeout) => udp.recv(msg => { const u = socksUdpUnwrap(msg); return u ? pred(u) : null; }, timeout),
  };
}

// ============================================================================
// DNS (test UDP thật)
// ============================================================================

function buildDnsQuery(name, id) {
  const labels = name.split('.').filter(Boolean).map(l => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
  return Buffer.concat([u16(id), u16(0x0100), u16(1), u16(0), u16(0), u16(0), ...labels, Buffer.from([0]), u16(1), u16(1)]);
}
function skipDnsName(buf, off) {
  while (off < buf.length) {
    const l = buf[off];
    if (l === 0) return off + 1;
    if ((l & 0xc0) === 0xc0) return off + 2;
    off += 1 + l;
  }
  return off;
}
function parseDnsAnswer(buf, id) {
  if (buf.length < 12 || buf.readUInt16BE(0) !== id || !(buf[2] & 0x80)) return null;
  const rcode = buf[3] & 0x0f;
  const qd = buf.readUInt16BE(4), an = buf.readUInt16BE(6);
  let off = 12;
  for (let i = 0; i < qd; i++) off = skipDnsName(buf, off) + 4;
  const ips = [];
  for (let i = 0; i < an && off < buf.length; i++) {
    off = skipDnsName(buf, off);
    if (off + 10 > buf.length) break;
    const type = buf.readUInt16BE(off), rdlen = buf.readUInt16BE(off + 8); off += 10;
    if (type === 1 && rdlen === 4) ips.push([...buf.subarray(off, off + 4)].join('.'));
    off += rdlen;
  }
  return { rcode, ips };
}

// Gửi truy vấn A tới tất cả DNS server cùng lúc, lấy phản hồi đầu tiên (gửi lại 1 lần nếu mất gói)
async function dnsProbe(path, opts) {
  const name = opts.quicHosts[0];
  const ids = new Map();
  for (const s of opts.dnsServers) ids.set(crypto.randomInt(1, 65535), s);
  const sendAll = async () => { for (const [id, s] of ids) await path.send(s, 53, buildDnsQuery(name, id)); };
  const pred = u => {
    if (u.data.length < 12) return null;
    const id = u.data.readUInt16BE(0);
    if (!ids.has(id)) return null;
    const a = parseDnsAnswer(u.data, id);
    return a ? { server: ids.get(id), name, ...a } : null;
  };
  const t0 = Date.now();
  await sendAll();
  let r;
  try { r = await path.recv(pred, Math.max(800, opts.timeout / 2)); }
  catch (_) { await sendAll(); r = await path.recv(pred, opts.timeout); }
  r.ms = Date.now() - t0;
  return r;
}

// ============================================================================
// QUIC v1 (RFC 9000 / RFC 9001): dựng gói Initial thật + giải mã phản hồi
// ============================================================================

const INITIAL_SALT_V1 = Buffer.from('38762cf7f55934b34d179ae6a4c80cadccbb7f0a', 'hex');
const EMPTY = Buffer.alloc(0);

const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
function hkdfExpand(prk, info, len) {
  let out = EMPTY, t = EMPTY, i = 1;
  while (out.length < len) { t = hmac(prk, Buffer.concat([t, info, Buffer.from([i++])])); out = Buffer.concat([out, t]); }
  return out.subarray(0, len);
}
function hkdfExpandLabel(secret, label, ctx, len) {
  const l = Buffer.from('tls13 ' + label);
  return hkdfExpand(secret, Buffer.concat([u16(len), Buffer.from([l.length]), l, Buffer.from([ctx.length]), ctx]), len);
}
function quicInitialKeys(dcid) {
  const initial = hmac(INITIAL_SALT_V1, dcid); // HKDF-Extract
  const mk = s => ({
    key: hkdfExpandLabel(s, 'quic key', EMPTY, 16),
    iv: hkdfExpandLabel(s, 'quic iv', EMPTY, 12),
    hp: hkdfExpandLabel(s, 'quic hp', EMPTY, 16),
  });
  return {
    client: mk(hkdfExpandLabel(initial, 'client in', EMPTY, 32)),
    server: mk(hkdfExpandLabel(initial, 'server in', EMPTY, 32)),
  };
}
function aesEcb(key, block) {
  const c = crypto.createCipheriv('aes-128-ecb', key, null); c.setAutoPadding(false);
  return Buffer.concat([c.update(block), c.final()]);
}
function quicNonce(iv, pn) {
  const n = Buffer.from(iv);
  for (let i = 0; i < 4; i++) n[8 + i] ^= (pn >>> (8 * (3 - i))) & 0xff;
  return n;
}

// TLS 1.3 ClientHello (handshake message) với ALPN h3 + quic_transport_parameters
function buildClientHello(sni, scid) {
  const ext = (type, body) => Buffer.concat([u16(type), u16(body.length), body]);
  const tp = (id, val) => Buffer.concat([encVarint(id), encVarint(val.length), val]);
  const pub = crypto.generateKeyPairSync('x25519').publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const sn = Buffer.from(sni);
  const sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807, 0x0808];
  const exts = Buffer.concat([
    ext(0x0000, Buffer.concat([u16(sn.length + 3), Buffer.from([0]), u16(sn.length), sn])),          // server_name
    ext(0x000a, Buffer.concat([u16(4), u16(0x001d), u16(0x0017)])),                                 // supported_groups
    ext(0x000d, Buffer.concat([u16(sigs.length * 2), ...sigs.map(u16)])),                           // signature_algorithms
    ext(0x002b, Buffer.from([2, 0x03, 0x04])),                                                      // supported_versions: TLS 1.3
    ext(0x002d, Buffer.from([1, 1])),                                                               // psk_key_exchange_modes
    ext(0x0033, Buffer.concat([u16(36), u16(0x001d), u16(32), pub])),                               // key_share x25519
    ext(0x0010, Buffer.concat([u16(3), Buffer.from([2]), Buffer.from('h3')])),                      // ALPN h3
    ext(0x0039, Buffer.concat([                                                                     // quic_transport_parameters
      tp(0x01, encVarint(30000)),        // max_idle_timeout
      tp(0x04, encVarint(10485760)),     // initial_max_data
      tp(0x05, encVarint(1048576)),      // initial_max_stream_data_bidi_local
      tp(0x06, encVarint(1048576)),      // initial_max_stream_data_bidi_remote
      tp(0x07, encVarint(1048576)),      // initial_max_stream_data_uni
      tp(0x08, encVarint(100)),          // initial_max_streams_bidi
      tp(0x09, encVarint(100)),          // initial_max_streams_uni
      tp(0x0f, scid),                    // initial_source_connection_id
    ])),
  ]);
  const body = Buffer.concat([
    u16(0x0303), crypto.randomBytes(32), Buffer.from([0]),
    u16(6), u16(0x1301), u16(0x1302), u16(0x1303),
    Buffer.from([1, 0]), u16(exts.length), exts,
  ]);
  return Buffer.concat([Buffer.from([0x01, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff]), body]);
}

// Gói Initial QUIC v1, 1200 byte, đã mã hoá + header protection
function buildQuicInitial(sni) {
  const dcid = crypto.randomBytes(8), scid = crypto.randomBytes(8);
  const keys = quicInitialKeys(dcid);
  const ch = buildClientHello(sni, scid);
  const cryptoFrame = Buffer.concat([Buffer.from([0x06]), encVarint(0), encVarint(ch.length), ch]);
  const pnLen = 1, pn = 0, TOTAL = 1200;
  const hdrFixed = 1 + 4 + 1 + dcid.length + 1 + scid.length + 1 + 2; // ... + token len + length(2 byte)
  const plainLen = TOTAL - hdrFixed - pnLen - 16;
  if (cryptoFrame.length > plainLen) throw new Error('ClientHello quá dài');
  const plain = Buffer.concat([cryptoFrame, Buffer.alloc(plainLen - cryptoFrame.length)]); // PADDING = 0x00
  const length = pnLen + plain.length + 16;
  const header = Buffer.concat([
    Buffer.from([0xc0 | (pnLen - 1)]), u32(1),
    Buffer.from([dcid.length]), dcid, Buffer.from([scid.length]), scid,
    Buffer.from([0]), Buffer.from([0x40 | (length >> 8), length & 0xff]), Buffer.from([pn]),
  ]);
  const c = crypto.createCipheriv('aes-128-gcm', keys.client.key, quicNonce(keys.client.iv, pn));
  c.setAAD(header);
  const pkt = Buffer.concat([header, c.update(plain), c.final(), c.getAuthTag()]);
  const pnOff = header.length - pnLen;
  const mask = aesEcb(keys.client.hp, pkt.subarray(pnOff + 4, pnOff + 20));
  pkt[0] ^= mask[0] & 0x0f;
  for (let i = 0; i < pnLen; i++) pkt[pnOff + i] ^= mask[1 + i];
  return { pkt, dcid, scid, keys };
}

// Gói với version "giả" 0x1a2a3a4a để ép server trả Version Negotiation (RFC 9000 §6)
function buildVnProbe() {
  const dcid = crypto.randomBytes(8), scid = crypto.randomBytes(8);
  const head = Buffer.concat([Buffer.from([0xc0]), u32(0x1a2a3a4a), Buffer.from([8]), dcid, Buffer.from([8]), scid, Buffer.from([0])]);
  return { pkt: Buffer.concat([head, crypto.randomBytes(1200 - head.length)]), dcid, scid, keys: null };
}

const QUIC_ERR = {
  0x00: 'NO_ERROR', 0x01: 'INTERNAL_ERROR', 0x02: 'CONNECTION_REFUSED', 0x03: 'FLOW_CONTROL_ERROR',
  0x07: 'FRAME_ENCODING_ERROR', 0x08: 'TRANSPORT_PARAMETER_ERROR', 0x0a: 'PROTOCOL_VIOLATION', 0x0d: 'CRYPTO_BUFFER_EXCEEDED',
};
function quicErrName(close) {
  const c = close.code;
  if (c >= 0x100 && c <= 0x1ff) return `CRYPTO_ERROR/TLS alert ${c - 0x100}`;
  return (QUIC_ERR[c] || `0x${c.toString(16)}`) + (close.reason ? ` "${close.reason}"` : '');
}
const hexVer = v => (v === 1 ? 'v1' : v === 0x6b3343cf ? 'v2' : '0x' + v.toString(16).padStart(8, '0'));

function parseQuicFrames(p) {
  const r = { serverHello: false, cryptoBytes: 0, ack: false, close: null };
  let off = 0; const cryptoChunks = [];
  while (off < p.length) {
    let t; [t, off] = decVarint(p, off);
    if (t === 0x00 || t === 0x01) continue;                              // PADDING, PING
    if (t === 0x02 || t === 0x03) {                                      // ACK
      r.ack = true; let v, cnt;
      [v, off] = decVarint(p, off); [v, off] = decVarint(p, off); [cnt, off] = decVarint(p, off); [v, off] = decVarint(p, off);
      for (let i = 0; i < cnt; i++) { [v, off] = decVarint(p, off); [v, off] = decVarint(p, off); }
      if (t === 0x03) for (let i = 0; i < 3; i++) [v, off] = decVarint(p, off);
      continue;
    }
    if (t === 0x06) {                                                    // CRYPTO
      let o, l; [o, off] = decVarint(p, off); [l, off] = decVarint(p, off);
      cryptoChunks.push({ o, d: p.subarray(off, off + l) }); r.cryptoBytes += l; off += l; continue;
    }
    if (t === 0x1c || t === 0x1d) {                                      // CONNECTION_CLOSE
      let code, ft = null, rl; [code, off] = decVarint(p, off);
      if (t === 0x1c) [ft, off] = decVarint(p, off);
      [rl, off] = decVarint(p, off);
      r.close = { code, frameType: ft, reason: p.subarray(off, off + rl).toString() }; off += rl; continue;
    }
    break; // frame lạ -> dừng
  }
  const first = cryptoChunks.find(c => c.o === 0);
  if (first && first.d[0] === 0x02) r.serverHello = true;
  return r;
}

// Phân tích gói trả lời từ server QUIC; ctx = kết quả buildQuicInitial/buildVnProbe
function parseQuicResponse(buf, ctx) {
  if (buf.length < 7 || !(buf[0] & 0x80)) return null;
  const version = buf.readUInt32BE(1);
  let off = 5;
  const dcl = buf[off++]; const dcid = buf.subarray(off, off + dcl); off += dcl;
  const scl = buf[off++]; off += scl;
  if (!dcid.equals(ctx.scid)) return null; // không phải trả lời cho ta
  if (version === 0) {
    const versions = [];
    for (; off + 4 <= buf.length; off += 4) versions.push(buf.readUInt32BE(off));
    return { kind: 'vn', versions };
  }
  if (version !== 1) return { kind: 'other', version };
  const type = (buf[0] & 0x30) >> 4;
  if (type === 3) return { kind: 'retry' };
  if (type === 2) return { kind: 'handshake' };
  if (type !== 0) return { kind: 'type' + type };
  if (!ctx.keys) return { kind: 'initial' };
  try {
    let tokLen, len;
    [tokLen, off] = decVarint(buf, off); off += tokLen;
    [len, off] = decVarint(buf, off);
    const pnOff = off;
    const pkt = Buffer.from(buf.subarray(0, pnOff + len));
    const mask = aesEcb(ctx.keys.server.hp, pkt.subarray(pnOff + 4, pnOff + 20));
    pkt[0] ^= mask[0] & 0x0f;
    const pnLen = (pkt[0] & 3) + 1;
    let pn = 0;
    for (let i = 0; i < pnLen; i++) { pkt[pnOff + i] ^= mask[1 + i]; pn = (pn << 8) | pkt[pnOff + i]; }
    const header = pkt.subarray(0, pnOff + pnLen), body = pkt.subarray(pnOff + pnLen);
    const d = crypto.createDecipheriv('aes-128-gcm', ctx.keys.server.key, quicNonce(ctx.keys.server.iv, pn));
    d.setAAD(header); d.setAuthTag(body.subarray(body.length - 16));
    const plain = Buffer.concat([d.update(body.subarray(0, body.length - 16)), d.final()]);
    return { kind: 'initial', frames: parseQuicFrames(plain) };
  } catch (e) {
    return { kind: 'initial', decryptError: e.message };
  }
}

// Gửi Initial tới ip:port qua "path", chờ phản hồi; trả về { ok, level, detail, ms }
async function quicInitialExchange(path, sni, ip, port, opts, quick = false) {
  const init = buildQuicInitial(sni);
  const t0 = Date.now();
  const pred = u => parseQuicResponse(u.data, init);
  let resp = null;
  await path.send(ip, port, init.pkt);
  try { resp = await path.recv(pred, Math.max(800, opts.timeout / 2)); }
  catch (_) {
    await path.send(ip, port, init.pkt);
    try { resp = await path.recv(pred, opts.timeout); } catch (_e) { /* không có phản hồi */ }
  }
  const ms = Date.now() - t0;
  if (!resp) {
    if (quick) return { ok: false, level: 'none', ms, detail: `không có phản hồi sau ${ms}ms` };
    // Thử gói version giả: nếu server trả Version Negotiation thì UDP 443 thông, chỉ Initial v1 bị bỏ qua
    const vn = buildVnProbe();
    await path.send(ip, port, vn.pkt);
    let vr = null;
    try { vr = await path.recv(u => parseQuicResponse(u.data, vn), opts.timeout); } catch (_) { /* none */ }
    if (vr && vr.kind === 'vn') {
      return { ok: true, level: 'vn-only', ms: Date.now() - t0, detail: `server chỉ trả lời Version Negotiation (${vr.versions.map(hexVer).join(',')}), không trả lời Initial v1` };
    }
    return { ok: false, level: 'none', ms, detail: `không có phản hồi sau ${ms}ms` };
  }
  switch (resp.kind) {
    case 'initial':
      if (resp.frames && resp.frames.serverHello) return { ok: true, level: 'handshake', ms, detail: `QUIC v1 ServerHello sau ${ms}ms` };
      if (resp.frames && resp.frames.close) return { ok: true, level: 'close', ms, detail: `QUIC v1 đi qua được, server đóng: ${quicErrName(resp.frames.close)} (${ms}ms)` };
      if (resp.decryptError) return { ok: true, level: 'initial', ms, detail: `nhận Initial v1 nhưng không giải mã được (${resp.decryptError})` };
      return { ok: true, level: 'initial', ms, detail: `nhận Initial v1 (không có ServerHello) sau ${ms}ms` };
    case 'retry': return { ok: true, level: 'retry', ms, detail: `QUIC v1 Retry sau ${ms}ms` };
    case 'handshake': return { ok: true, level: 'handshake', ms, detail: `nhận gói Handshake v1 sau ${ms}ms` };
    case 'vn': return { ok: true, level: 'vn', ms, detail: `Version Negotiation: server hỗ trợ ${resp.versions.map(hexVer).join(',')}` };
    default: return { ok: true, level: 'other', ms, detail: `phản hồi QUIC lạ (${resp.kind})` };
  }
}

// Thử lần lượt các server QUIC; dnsRes (nếu có) cho IP nhìn từ phía proxy.
// quick = true (relay đã không trả lời DNS): chỉ thử 1 server, không gửi thêm gói VN
async function quicProbe(path, opts, dnsRes, quick = false) {
  const fails = [];
  for (const host of quick ? opts.quicHosts.slice(0, 1) : opts.quicHosts) {
    let ips = [];
    if (dnsRes && dnsRes.name === host && dnsRes.ips.length) ips = dnsRes.ips;
    else ips = await resolveAllIPv4(host).catch(() => []);
    if (!ips.length) { fails.push(`${host}: không resolve được`); continue; }
    const r = await quicInitialExchange(path, host, ips[0], 443, opts, quick);
    if (r.ok) return { ...r, host, ip: ips[0] };
    fails.push(`${host} (${ips[0]}): ${r.detail}`);
  }
  return { ok: false, detail: fails.join('; ') };
}

// ============================================================================
// Nhận dạng + test TCP từng loại proxy
// ============================================================================

async function socks5Probe(p, opts) {
  const conn = new TcpConn();
  try {
    await conn.connect(p.host, p.port, opts.timeout);
    let auth;
    try { auth = await socks5Handshake(conn, p, opts.timeout); }
    catch (e) {
      if (e.notSocks) return { is: false };
      return { is: true, authOk: false, ok: false, detail: e.message };
    }
    const t = opts.tcpTarget;
    const r = await socks5Request(conn, 0x01, t.host, t.port, opts.timeout);
    if (r.rep === 0) return { is: true, authOk: true, ok: true, auth, detail: `CONNECT ${t.host}:${t.port} OK` };
    return { is: true, authOk: true, ok: false, auth, detail: `CONNECT ${t.host}:${t.port} bị từ chối: ${socks5RepText(r.rep)}` };
  } catch (e) {
    return { is: false, err: e.message };
  } finally { conn.close(); }
}

const proxyAuthHeader = p => (p.user != null ? `Proxy-Authorization: Basic ${Buffer.from(`${p.user}:${p.pass || ''}`).toString('base64')}\r\n` : '');
function parseHttpStatus(head) {
  const m = head.toString('latin1').match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})\s*([^\r\n]*)/);
  return m ? { code: +m[1], text: m[2].trim() } : null;
}

async function httpProbe(p, opts) {
  const conn = new TcpConn();
  try {
    await conn.connect(p.host, p.port, opts.timeout);
    const t = opts.tcpTarget;
    await conn.write(`CONNECT ${t.host}:${t.port} HTTP/1.1\r\nHost: ${t.host}:${t.port}\r\n${proxyAuthHeader(p)}Proxy-Connection: Keep-Alive\r\n\r\n`);
    const st = parseHttpStatus(await conn.readHttpHead(opts.timeout));
    if (!st) return { is: false };
    if (st.code === 200) return { is: true, authOk: true, ok: true, detail: `CONNECT ${t.host}:${t.port} OK (${st.code})` };
    if (st.code === 407) return { is: true, authOk: false, ok: false, detail: p.user != null ? `sai user/pass (407)` : `proxy yêu cầu xác thực (407)` };
    return { is: true, authOk: true, ok: false, detail: `CONNECT trả về ${st.code} ${st.text}` };
  } catch (e) {
    return { is: false, err: e.message };
  } finally { conn.close(); }
}

async function socks4Probe(p, opts) {
  const conn = new TcpConn();
  try {
    await conn.connect(p.host, p.port, opts.timeout);
    const uid = Buffer.from(p.user || '');
    await conn.write(Buffer.concat([Buffer.from([4, 1]), u16(443), Buffer.from([1, 1, 1, 1]), uid, Buffer.from([0])]));
    const r = await conn.readN(8, opts.timeout);
    if (r[0] !== 0 || r[1] < 0x5a || r[1] > 0x5d) return { is: false };
    if (r[1] === 0x5a) return { is: true, authOk: true, ok: true, detail: 'CONNECT 1.1.1.1:443 OK' };
    return { is: true, authOk: r[1] === 0x5b, ok: false, detail: `CONNECT bị từ chối (code 0x${r[1].toString(16)})` };
  } catch (e) {
    return { is: false, err: e.message };
  } finally { conn.close(); }
}

// ============================================================================
// Test UDP + QUIC qua SOCKS5
// ============================================================================

async function testSocks5Udp(p, opts, res) {
  const conn = new TcpConn(); // kết nối TCP phải giữ mở suốt phiên UDP
  const udp = new UdpSock();
  try {
    await conn.connect(p.host, p.port, opts.timeout);
    await socks5Handshake(conn, p, opts.timeout);
    let rep;
    try { rep = await socks5Request(conn, 0x03, '0.0.0.0', 0, opts.timeout); }
    catch (e) { res.udp = 'FAIL'; res.udp_detail = 'UDP ASSOCIATE lỗi: ' + e.message; return; }
    if (rep.rep !== 0) {
      res.udp = 'NO'; res.udp_detail = 'UDP ASSOCIATE bị từ chối: ' + socks5RepText(rep.rep);
      res.quic = 'NO'; res.quic_detail = 'không có UDP';
      return;
    }
    res.udp_associate = `${rep.addr}:${rep.port}`;

    // Địa chỉ relay: proxy trả về, hoặc chính IP proxy nếu trả về 0.0.0.0 / IP nội bộ
    const proxyIp = await resolveIPv4(p.host).catch(() => null);
    let relayIps = [];
    if (rep.addr && rep.addr !== '0.0.0.0' && rep.addr !== '0:0:0:0:0:0:0:0') {
      const ip = net.isIPv4(rep.addr) ? rep.addr : await resolveIPv4(rep.addr).catch(() => null);
      if (ip) relayIps.push(ip);
    }
    if (proxyIp) relayIps.push(proxyIp);
    if (relayIps.length === 2 && !isPublicIPv4(relayIps[0]) && isPublicIPv4(relayIps[1])) relayIps.reverse();
    relayIps = [...new Set(relayIps)];
    const relayPort = rep.port || p.port;
    if (!relayIps.length) { res.udp = 'FAIL'; res.udp_detail = 'không xác định được địa chỉ relay'; return; }

    await udp.bind();

    // 1) DNS qua relay
    let path = null, dnsRes = null, lastErr = '';
    for (const ip of relayIps) {
      const cand = socksUdpPath(udp, ip, relayPort);
      try { dnsRes = await dnsProbe(cand, opts); path = cand; break; }
      catch (e) { lastErr = e.message; }
    }
    if (dnsRes) {
      res.udp = 'OK';
      res.udp_relay = path.name.replace('relay ', '');
      res.udp_detail = `DNS ${dnsRes.server}:53 trả lời sau ${dnsRes.ms}ms` +
        (dnsRes.ips.length ? ` (${dnsRes.name} -> ${dnsRes.ips[0]})` : '') + ` qua ${path.name}`;
    }

    // 2) QUIC qua relay
    if (opts.noQuic) { res.quic = 'SKIP'; res.quic_detail = 'bỏ qua (--no-quic)'; }
    else {
      const cands = path ? [path] : relayIps.map(ip => socksUdpPath(udp, ip, relayPort));
      let q = null;
      for (const cand of cands) {
        q = await quicProbe(cand, opts, dnsRes, !dnsRes);
        if (q.ok) { path = cand; break; }
      }
      if (q.ok) {
        res.quic = 'OK';
        res.quic_detail = `${q.host} (${q.ip}:443): ${q.detail}`;
        res.quic_level = q.level;
        if (res.udp !== 'OK') {
          res.udp = 'OK'; res.udp_relay = path.name.replace('relay ', '');
          res.udp_detail = `DNS không trả lời nhưng gói QUIC/UDP tới cổng 443 đi qua được (${path.name})`;
        }
      } else {
        res.quic = 'FAIL'; res.quic_detail = q.detail;
      }
    }
    if (res.udp !== 'OK') {
      res.udp = 'FAIL';
      res.udp_detail = `UDP ASSOCIATE OK (${res.udp_associate}) nhưng relay không chuyển được gói UDP` + (lastErr ? ` (${lastErr})` : '');
      if (res.quic === 'FAIL') res.quic_detail = 'relay UDP không hoạt động';
    }
  } catch (e) {
    res.udp = 'FAIL'; res.udp_detail = e.message;
    if (res.quic === 'N/A') { res.quic = 'FAIL'; res.quic_detail = 'không test được vì UDP lỗi'; }
  } finally { conn.close(); udp.close(); }
}

// ============================================================================
// Test UDP qua HTTP proxy: MASQUE connect-udp (RFC 9298) trên HTTP/1.1 Upgrade
// ============================================================================

async function openMasqueTunnel(p, host, port, opts) {
  const conn = new TcpConn();
  try {
    await conn.connect(p.host, p.port, opts.timeout);
    await conn.write(
      `GET /.well-known/masque/udp/${host}/${port}/ HTTP/1.1\r\nHost: ${p.host}:${p.port}\r\n` +
      `Connection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n${proxyAuthHeader(p)}\r\n`);
    const st = parseHttpStatus(await conn.readHttpHead(opts.timeout));
    if (!st || st.code !== 101) { conn.close(); return { status: st ? st.code : null }; }
  } catch (e) { conn.close(); return { error: e.message }; }
  // Đường đi UDP qua capsule DATAGRAM (type 0x00): [type][len][context_id=0][payload]
  const path = {
    name: `connect-udp ${host}:${port}`,
    conn,
    send: (_h, _p, data) => conn.write(Buffer.concat([encVarint(0), encVarint(data.length + 1), encVarint(0), data])),
    recv: async (pred, timeout) => {
      const deadline = Date.now() + timeout;
      for (;;) {
        const cap = await conn.readWhen(b => {
          try { const [, o1] = decVarint(b, 0); const [l, o2] = decVarint(b, o1); return b.length >= o2 + l ? o2 + l : 0; }
          catch (_) { return 0; }
        }, Math.max(1, deadline - Date.now()));
        const [type, o1] = decVarint(cap, 0); const [, o2] = decVarint(cap, o1);
        if (type !== 0) continue;
        const [, o3] = decVarint(cap, o2);
        const r = pred({ host, port, data: cap.subarray(o3) });
        if (r) return r;
      }
    },
  };
  return { path };
}

async function testHttpUdp(p, opts, res) {
  const t = await openMasqueTunnel(p, opts.dnsServers[0], 53, opts);
  if (!t.path) {
    res.udp = 'NO';
    res.udp_detail = `HTTP proxy chỉ có CONNECT (TCP); connect-udp trả về ${t.status != null ? t.status : t.error || '?'}`;
    res.quic = 'NO'; res.quic_detail = 'không có UDP';
    return;
  }
  try {
    const d = await dnsProbe({ ...t.path, send: (_h, _p, data) => t.path.send(null, null, data) }, opts);
    res.udp = 'OK'; res.udp_detail = `MASQUE connect-udp: DNS ${d.server}:53 trả lời sau ${d.ms}ms`;
  } catch (e) {
    res.udp = 'FAIL'; res.udp_detail = `connect-udp mở được (101) nhưng không nhận được gói trả lời (${e.message})`;
  } finally { t.path.conn.close(); }
  if (opts.noQuic) { res.quic = 'SKIP'; res.quic_detail = 'bỏ qua (--no-quic)'; return; }
  for (const host of opts.quicHosts) {
    const ips = await resolveAllIPv4(host).catch(() => []);
    if (!ips.length) continue;
    const q = await openMasqueTunnel(p, ips[0], 443, opts);
    if (!q.path) continue;
    try {
      const r = await quicInitialExchange(q.path, host, ips[0], 443, opts);
      if (r.ok) { res.quic = 'OK'; res.quic_detail = `${host} (${ips[0]}:443) qua connect-udp: ${r.detail}`; res.quic_level = r.level; return; }
      res.quic = 'FAIL'; res.quic_detail = `${host}: ${r.detail}`;
    } finally { q.path.conn.close(); }
  }
  if (res.quic === 'N/A') { res.quic = 'FAIL'; res.quic_detail = 'không mở được tunnel connect-udp tới cổng 443'; }
}

// ============================================================================
// Kiểm tra 1 proxy
// ============================================================================

// Resolve ngay khi có kết quả {t, r} với r.is = true; null nếu tất cả đều không khớp
function firstMatch(promises) {
  return new Promise(resolve => {
    let pending = promises.length;
    for (const pr of promises) {
      pr.then(x => { if (x.r.is) resolve(x); else if (--pending === 0) resolve(null); },
        () => { if (--pending === 0) resolve(null); });
    }
  });
}

async function checkProxy(p, opts) {
  const res = {
    proxy: p.raw, host: p.host, port: p.port,
    type: p.type ? p.type.toUpperCase() : '?', auth: p.user != null ? 'user/pass' : 'none',
    latency_ms: null, tcp: 'FAIL', tcp_detail: '', udp: 'N/A', udp_detail: '', quic: 'N/A', quic_detail: '', error: '',
  };
  const t0 = Date.now();
  {
    const c = new TcpConn();
    try { await c.connect(p.host, p.port, opts.timeout); res.latency_ms = Date.now() - t0; }
    catch (e) { res.error = 'không kết nối được tới proxy: ' + e.message; return res; }
    finally { c.close(); }
  }
  const PROBES = { socks5: socks5Probe, http: httpProbe, socks4: socks4Probe };
  let type = null, probe = null;
  if (p.type) {
    probe = await PROBES[p.type](p, opts);
    if (probe.is) type = p.type;
  } else {
    // SOCKS5 và HTTP thử song song (trên 2 kết nối riêng) cho nhanh; SOCKS4 thử sau cùng
    const m = await firstMatch(['socks5', 'http'].map(t => PROBES[t](p, opts).then(r => ({ t, r }))));
    if (m) { type = m.t; probe = m.r; }
    else { probe = await socks4Probe(p, opts); if (probe.is) type = 'socks4'; }
  }
  if (!type) {
    res.type = p.type ? p.type.toUpperCase() : 'UNKNOWN';
    res.error = p.type ? `không phản hồi như ${res.type}` : 'không nhận dạng được (không phải SOCKS5/HTTP/SOCKS4, hoặc proxy yêu cầu xác thực khác)';
    return res;
  }
  res.type = type.toUpperCase();
  if (probe.auth) res.auth = probe.auth;
  res.tcp = probe.ok ? 'OK' : 'FAIL';
  res.tcp_detail = probe.detail;
  if (!probe.authOk) { res.udp_detail = res.quic_detail = 'không xác thực được'; return res; }

  if (type === 'socks5') await testSocks5Udp(p, opts, res);
  else if (type === 'http') await testHttpUdp(p, opts, res);
  else { res.udp = 'NO'; res.udp_detail = 'SOCKS4 không có UDP'; res.quic = 'NO'; res.quic_detail = 'không có UDP'; }
  return res;
}

// ============================================================================
// CLI
// ============================================================================

const HELP = `
proxycheck — kiểm tra proxy có hỗ trợ UDP và QUIC hay không

Cách dùng:
  node proxycheck.js <proxy> [<proxy> ...]
  node proxycheck.js -f proxies.txt [tuỳ chọn]

Định dạng proxy:
  host:port, host:port:user:pass, user:pass:host:port, user:pass@host:port
  host|port, host|port|user|pass (đặt trong dấu nháy khi nhập trên dòng lệnh)
  HTTP|host|port|user|pass (loại HTTP, SOCKS5 hoặc SOCKS4; không phân biệt hoa/thường)
  Có thể thêm tiền tố để ép loại: socks5://  socks4://  http://

Tuỳ chọn:
  -f, --file FILE       File danh sách proxy (mỗi dòng 1 proxy, # là ghi chú)
  -t, --threads N       Số proxy kiểm tra đồng thời (mặc định ${DEFAULTS.threads})
  --timeout MS          Timeout mỗi bước, ms (mặc định ${DEFAULTS.timeout})
  --type socks5|http|socks4   Ép loại proxy thay vì tự nhận dạng
  -o, --output FILE     Ghi kết quả đầy đủ ra file .json hoặc .csv
  --good FILE           Ghi các proxy hỗ trợ UDP (mỗi dòng 1 proxy)
  --good-quic FILE      Ghi các proxy chạy được QUIC
  --dns IP[,IP]         DNS server để test UDP (mặc định ${DEFAULTS.dnsServers.join(',')})
  --quic-host H[,H]     Server HTTP/3 để test QUIC (mặc định ${DEFAULTS.quicHosts.join(',')})
  --no-quic             Bỏ qua test QUIC
  -v, --verbose         In chi tiết từng bước (tự bật khi chỉ có 1 proxy)
  --no-color            Không tô màu
  -h, --help            Trợ giúp

Ý nghĩa cột:
  TCP   OK   = CONNECT qua proxy được
  UDP   OK   = UDP ASSOCIATE thành công VÀ gói UDP thật đi qua relay (DNS/QUIC có phản hồi)
        NO   = proxy không hỗ trợ UDP (từ chối lệnh / HTTP CONNECT / SOCKS4)
        FAIL = nhận lệnh nhưng relay không chuyển được gói (UDP "giả")
  QUIC  OK   = gói QUIC v1 Initial đi qua proxy, server HTTP/3 trả lời (ServerHello/Retry/VN)
`;

function parseArgs(argv) {
  const o = { ...DEFAULTS, proxies: [], file: null, output: null, good: null, goodQuic: null, forceType: null };
  const next = i => { if (i + 1 >= argv.length) throw new Error(`thiếu giá trị cho ${argv[i]}`); return argv[i + 1]; };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-h': case '--help': console.log(HELP); process.exit(0); break;
      case '-f': case '--file': o.file = next(i++); break;
      case '-t': case '--threads': o.threads = Math.max(1, parseInt(next(i++), 10) || 1); break;
      case '--timeout': o.timeout = Math.max(500, parseInt(next(i++), 10) || DEFAULTS.timeout); break;
      case '--type': o.forceType = next(i++).toLowerCase(); break;
      case '-o': case '--output': o.output = next(i++); break;
      case '--good': o.good = next(i++); break;
      case '--good-quic': o.goodQuic = next(i++); break;
      case '--dns': o.dnsServers = next(i++).split(',').map(s => s.trim()).filter(Boolean); break;
      case '--quic-host': o.quicHosts = next(i++).split(',').map(s => s.trim()).filter(Boolean); break;
      case '--no-quic': o.noQuic = true; break;
      case '-v': case '--verbose': o.verbose = true; break;
      case '--no-color': o.color = false; break;
      default:
        if (a.startsWith('-')) throw new Error(`tuỳ chọn không hợp lệ: ${a}`);
        o.proxies.push(a);
    }
  }
  if (o.forceType && !['socks5', 'http', 'socks4'].includes(o.forceType)) throw new Error('--type phải là socks5, http hoặc socks4');
  return o;
}

function makeColors(enabled) {
  const wrap = code => s => (enabled ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  return { g: wrap(32), r: wrap(31), y: wrap(33), c: wrap(36), dim: wrap(2), b: wrap(1) };
}
function colorStatus(C, s) {
  if (s === 'OK') return C.g(s);
  if (s === 'FAIL' || s === 'NO') return C.r(s);
  return C.y(s);
}

async function runPool(items, n, fn) {
  const results = new Array(items.length);
  let next = 0;
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
  return results;
}

function toCsv(results) {
  const cols = ['proxy', 'type', 'auth', 'latency_ms', 'tcp', 'tcp_detail', 'udp', 'udp_associate', 'udp_relay', 'udp_detail', 'quic', 'quic_level', 'quic_detail', 'error'];
  const q = v => { const s = v == null ? '' : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  return [cols.join(','), ...results.map(r => cols.map(c => q(r[c])).join(','))].join('\n') + '\n';
}

async function main() {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); }
  catch (e) { console.error('Lỗi: ' + e.message + '\n' + HELP); process.exit(2); }

  const lines = [...opts.proxies];
  if (opts.file) {
    if (!fs.existsSync(opts.file)) { console.error(`Không tìm thấy file: ${opts.file}`); process.exit(2); }
    for (const l of fs.readFileSync(opts.file, 'utf8').split(/\r?\n/)) {
      const s = l.replace(/#.*$/, '').trim();
      if (s) lines.push(s);
    }
  }
  if (!lines.length) { console.log(HELP); process.exit(2); }

  const C = makeColors(opts.color && (process.stdout.isTTY || !!process.env.FORCE_COLOR));
  const proxies = [];
  for (const l of [...new Set(lines)]) {
    try { const p = parseProxy(l); if (opts.forceType) p.type = opts.forceType; proxies.push(p); }
    catch (e) { console.error(C.r(`Bỏ qua "${l}": ${e.message}`)); }
  }
  if (!proxies.length) process.exit(2);
  const verbose = opts.verbose || proxies.length === 1;

  console.log(C.b(`Kiểm tra ${proxies.length} proxy — ${opts.threads} luồng, timeout ${opts.timeout}ms` +
    (opts.noQuic ? ', bỏ qua QUIC' : `, QUIC tới ${opts.quicHosts.join('/')}`)) + '\n');
  const W = Math.min(48, Math.max(20, ...proxies.map(p => p.raw.length)));
  const vis = s => String(s).replace(/\x1b\[\d+m/g, '').length;
  const pad = (s, n) => String(s) + ' '.repeat(Math.max(0, n - vis(s)));
  console.log(C.dim(`${pad('#', 5)} ${pad('Proxy', W)} ${pad('Loại', 7)} ${pad('TCP', 5)} ${pad('UDP', 5)} ${pad('QUIC', 5)} ms`));

  let done = 0;
  const results = await runPool(proxies, opts.threads, async (p, i) => {
    const r = await checkProxy(p, opts);
    done++;
    const n = `${done}/${proxies.length}`;
    let line = `${pad(n, 5)} ${pad(p.raw.length > W ? p.raw.slice(0, W - 1) + '…' : p.raw, W)} ${pad(r.type, 7)} ` +
      `${pad(colorStatus(C, r.tcp), 5)} ${pad(colorStatus(C, r.udp), 5)} ${pad(colorStatus(C, r.quic), 5)} ` +
      (r.latency_ms != null ? r.latency_ms : '-');
    if (r.error) line += `  ${C.r(r.error)}`;
    else if (!verbose && r.tcp !== 'OK') line += `  ${C.dim(r.tcp_detail)}`;
    console.log(line);
    if (verbose && !r.error) {
      const ind = ' '.repeat(6);
      console.log(`${ind}${C.dim('xác thực :')} ${r.auth}`);
      console.log(`${ind}${C.dim('TCP      :')} ${r.tcp_detail}`);
      console.log(`${ind}${C.dim('UDP      :')} ${r.udp_detail}`);
      console.log(`${ind}${C.dim('QUIC     :')} ${r.quic_detail}`);
    }
    return r;
  });

  const cnt = k => results.filter(r => r[k] === 'OK').length;
  console.log('\n' + C.b('Tổng kết: ') +
    `${results.length} proxy | TCP OK: ${C.g(cnt('tcp'))} | UDP OK: ${C.g(cnt('udp'))} | QUIC OK: ${C.g(cnt('quic'))} | ` +
    `lỗi/không kết nối: ${C.r(results.filter(r => r.error).length)}`);

  if (opts.output) {
    const out = opts.output.toLowerCase().endsWith('.csv') ? toCsv(results) : JSON.stringify(results, null, 2);
    fs.writeFileSync(opts.output, out);
    console.log(`Đã ghi kết quả: ${opts.output}`);
  }
  if (opts.good) {
    const g = results.filter(r => r.udp === 'OK').map(r => r.proxy);
    fs.writeFileSync(opts.good, g.join('\n') + (g.length ? '\n' : ''));
    console.log(`Đã ghi ${g.length} proxy hỗ trợ UDP: ${opts.good}`);
  }
  if (opts.goodQuic) {
    const g = results.filter(r => r.quic === 'OK').map(r => r.proxy);
    fs.writeFileSync(opts.goodQuic, g.join('\n') + (g.length ? '\n' : ''));
    console.log(`Đã ghi ${g.length} proxy chạy được QUIC: ${opts.goodQuic}`);
  }
}

module.exports = {
  parseProxy, checkProxy, quicInitialKeys, buildQuicInitial, parseQuicResponse, quicInitialExchange,
  buildDnsQuery, parseDnsAnswer, dnsProbe, UdpSock, TcpConn, DEFAULTS,
};

if (require.main === module) {
  main().catch(e => { console.error('Lỗi: ' + (e.stack || e.message)); process.exit(1); });
}
