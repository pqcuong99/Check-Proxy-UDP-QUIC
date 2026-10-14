// Proxy giả lập để test proxycheck.js (không cần proxy thật):
//   node test/fake_proxies.js        (cửa sổ 1)
//   node proxycheck.js -f test/test_proxies.txt -v   (cửa sổ 2)
//
// Proxy giả lập để test: 
//  1080 SOCKS5 no-auth, có UDP
//  1081 SOCKS5 user/pass (u=test p=123), có UDP
//  1082 SOCKS5 no-auth, KHÔNG hỗ trợ UDP (rep 7)
//  1083 SOCKS5 no-auth, UDP ASSOCIATE OK nhưng relay chết (không chuyển gói)
//  3128 HTTP CONNECT proxy
//  1084 SOCKS4
const net = require('net'), dgram = require('dgram');

function readN(sock, n) { return new Promise(res => { const tryRead = () => { const b = sock.read(n); if (b) return res(b); sock.once('readable', tryRead); }; tryRead(); }); }
function parseAddr(atyp, buf) { // returns [host, port, consumedLen]
  if (atyp === 1) return [[...buf.subarray(0,4)].join('.'), buf.readUInt16BE(4), 6];
  if (atyp === 3) { const l = buf[0]; return [buf.subarray(1,1+l).toString(), buf.readUInt16BE(1+l), 3+l]; }
  throw new Error('atyp');
}
function socks5Server(port, { auth = null, udp = 'ok' } = {}) {
  net.createServer(async sock => {
    try {
      const g = await readN(sock, 2); const methods = await readN(sock, g[1]);
      if (auth) { sock.write(Buffer.from([5, 2])); const a = await readN(sock, 2); const u = (await readN(sock, a[1])).toString(); const pl = (await readN(sock,1))[0]; const p = (await readN(sock, pl)).toString(); if (u !== auth.user || p !== auth.pass) { sock.write(Buffer.from([1,1])); return sock.end(); } sock.write(Buffer.from([1,0])); }
      else sock.write(Buffer.from([5, 0]));
      const h = await readN(sock, 4); const cmd = h[1], atyp = h[3];
      const rest = atyp === 1 ? await readN(sock, 6) : (async () => { const l = await readN(sock,1); const r = await readN(sock, l[0]+2); return Buffer.concat([l, r]); })();
      const [host, dport] = parseAddr(atyp, await rest);
      if (cmd === 1) {
        const out = net.connect(dport, host, () => { sock.write(Buffer.from([5,0,0,1,0,0,0,0,0,0])); sock.pipe(out); out.pipe(sock); });
        out.on('error', () => { sock.write(Buffer.from([5,5,0,1,0,0,0,0,0,0])); sock.end(); });
      } else if (cmd === 3) {
        if (udp === 'no') { sock.write(Buffer.from([5,7,0,1,0,0,0,0,0,0])); return sock.end(); }
        const relay = dgram.createSocket('udp4'); let client = null;
        relay.on('message', (msg, rinfo) => {
          if (udp === 'dead') return; // nhận nhưng không chuyển
          if (msg[2] !== 0) return;
          let off = 3; const at = msg[off++]; let host, port;
          if (at === 1) { host = [...msg.subarray(off,off+4)].join('.'); off += 4; } else if (at === 3) { const l = msg[off++]; host = msg.subarray(off,off+l).toString(); off += l; } else return;
          port = msg.readUInt16BE(off); off += 2;
          if (!client) client = rinfo;
          const data = msg.subarray(off);
          const out = dgram.createSocket('udp4');
          out.on('message', (r, ri) => { const hdr = Buffer.concat([Buffer.from([0,0,0,1]), Buffer.from(ri.address.split('.').map(Number)), Buffer.from([ri.port>>8, ri.port&255])]); try { relay.send(Buffer.concat([hdr, r]), client.port, client.address); } catch (_) {} });
          out.send(data, port, host);
          setTimeout(() => out.close(), 10000);
        });
        relay.bind(0, '0.0.0.0', () => { const p = relay.address().port; sock.write(Buffer.from([5,0,0,1,0,0,0,0,p>>8,p&255])); /* trả 0.0.0.0 -> client phải dùng IP proxy */ });
        sock.on('close', () => relay.close()); sock.on('error', () => {});
      } else { sock.write(Buffer.from([5,7,0,1,0,0,0,0,0,0])); sock.end(); }
    } catch (e) { sock.destroy(); }
  }).listen(port, '127.0.0.1');
}
socks5Server(1080);
socks5Server(1081, { auth: { user: 'test', pass: '123' } });
socks5Server(1082, { udp: 'no' });
socks5Server(1083, { udp: 'dead' });

// HTTP CONNECT proxy
net.createServer(sock => {
  sock.once('data', d => {
    const s = d.toString('latin1'); const m = s.match(/^CONNECT ([^ :]+):(\d+)/);
    if (!m) { sock.end('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n'); return; }
    const out = net.connect(+m[2], m[1], () => { sock.write('HTTP/1.1 200 Connection established\r\n\r\n'); sock.pipe(out); out.pipe(sock); });
    out.on('error', () => sock.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'));
  });
  sock.on('error', () => {});
}).listen(3128, '127.0.0.1');

// SOCKS4
net.createServer(sock => {
  sock.once('data', d => { if (d[0] !== 4) return sock.destroy(); const port = d.readUInt16BE(2), ip = [...d.subarray(4,8)].join('.');
    const out = net.connect(port, ip, () => { sock.write(Buffer.from([0,0x5a,0,0,0,0,0,0])); sock.pipe(out); out.pipe(sock); });
    out.on('error', () => { sock.write(Buffer.from([0,0x5b,0,0,0,0,0,0])); sock.end(); }); });
  sock.on('error', () => {});
}).listen(1084, '127.0.0.1');
console.log('fake proxies up');
