#!/usr/bin/env node
'use strict';
/*
 * gui.js — giao diện web cho proxycheck (chạy local, chỉ lắng nghe 127.0.0.1)
 *
 *   node gui.js              mở http://127.0.0.1:4780 trong cửa sổ trình duyệt
 *   node gui.js --port 0     dùng cổng ngẫu nhiên
 *   node gui.js --no-open    không tự mở trình duyệt
 *   node gui.js --keep       không tự thoát khi đóng cửa sổ
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { parseProxy, checkProxy, DEFAULTS } = require('./proxycheck');

const args = process.argv.slice(2);
const argVal = (k, d) => { const i = args.indexOf(k); return i >= 0 && args[i + 1] != null ? args[i + 1] : d; };
const PORT = parseInt(argVal('--port', '4780'), 10);
const NO_OPEN = args.includes('--no-open');
const KEEP = args.includes('--keep');
const HTML_PATH = path.join(__dirname, 'gui.html');

// ---------------------------------------------------------------------------
// Trạng thái: 1 job tại một thời điểm + các kết nối SSE đang mở
// ---------------------------------------------------------------------------
let job = null;
let jobSeq = 0;
const clients = new Set();
let exitTimer = null;

function sse(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const c of clients) c.write(msg);
}
setInterval(() => { for (const c of clients) c.write(': ping\n\n'); }, 15000).unref();

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', d => { body += d; if (body.length > 10e6) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch (e) { reject(new Error('JSON không hợp lệ')); } });
    req.on('error', reject);
  });
}

function jobSnapshot() {
  if (!job) return null;
  return { id: job.id, items: job.items, results: job.results, running: job.running, stopped: job.stopped, done: job.done, total: job.total, options: job.options };
}

function errorResult(raw, error) {
  return { proxy: raw, type: '?', auth: '', latency_ms: null, tcp: 'FAIL', tcp_detail: '', udp: 'N/A', udp_detail: '', quic: 'N/A', quic_detail: '', error };
}

function startJob(body) {
  const lines = [...new Set((body.proxies || []).map(s => String(s).trim()).filter(Boolean))];
  if (!lines.length) throw new Error('Chưa có proxy nào để kiểm tra');
  const o = body.options || {};
  const opts = {
    ...DEFAULTS,
    threads: Math.min(200, Math.max(1, parseInt(o.threads, 10) || DEFAULTS.threads)),
    timeout: Math.min(60000, Math.max(500, parseInt(o.timeout, 10) || DEFAULTS.timeout)),
    noQuic: !!o.noQuic,
  };
  const forceType = ['socks5', 'http', 'socks4'].includes(o.type) ? o.type : null;
  const items = lines.map((raw, index) => {
    try { const p = parseProxy(raw); if (forceType) p.type = forceType; return { index, raw, p }; }
    catch (e) { return { index, raw, err: e.message }; }
  });

  const J = (job = {
    id: ++jobSeq, total: items.length, done: 0, results: new Array(items.length),
    stopped: false, running: true, options: { threads: opts.threads, timeout: opts.timeout, noQuic: opts.noQuic, type: forceType },
    items: items.map(i => ({ index: i.index, proxy: i.raw })),
  });
  sse('start', { id: J.id, items: J.items, total: J.total, options: J.options });

  const finish = (index, result) => {
    J.results[index] = result; J.done++;
    sse('result', { id: J.id, index, result, done: J.done, total: J.total });
  };
  let next = 0;
  const worker = async () => {
    for (;;) {
      if (J.stopped) return;
      const i = next++;
      if (i >= items.length) return;
      const it = items[i];
      if (it.err) { finish(i, errorResult(it.raw, 'định dạng không hợp lệ: ' + it.err)); continue; }
      let r;
      try { r = await checkProxy(it.p, opts); } catch (e) { r = errorResult(it.raw, e.message); }
      finish(i, r);
    }
  };
  Promise.all(Array.from({ length: Math.min(opts.threads, items.length) }, worker)).then(() => {
    J.running = false;
    items.forEach((it, i) => { if (!J.results[i]) J.results[i] = { ...errorResult(it.raw, 'đã dừng'), tcp: 'N/A' }; });
    sse('done', { id: J.id, stopped: J.stopped, done: J.done, total: J.total });
  });
  return { id: J.id, total: J.total };
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------
const send = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(obj)); };

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  try {
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      return res.end(fs.readFileSync(HTML_PATH)); // đọc mỗi lần để sửa giao diện không cần khởi động lại
    }
    if (req.method === 'GET' && url.pathname === '/api/events') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' });
      res.write(`event: snapshot\ndata: ${JSON.stringify({ job: jobSnapshot() })}\n\n`);
      clients.add(res);
      if (exitTimer) { clearTimeout(exitTimer); exitTimer = null; }
      req.on('close', () => {
        clients.delete(res);
        if (!clients.size && !KEEP) {
          // đóng cửa sổ -> tự thoát sau 20s (refresh trang sẽ kết nối lại kịp)
          exitTimer = setTimeout(() => { console.log('Đã đóng giao diện, thoát.'); process.exit(0); }, 20000);
        }
      });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/start') {
      if (job && job.running) return send(res, 409, { error: 'Đang có phiên kiểm tra chạy, hãy bấm Dừng trước' });
      return send(res, 200, startJob(await readJson(req)));
    }
    if (req.method === 'POST' && url.pathname === '/api/stop') {
      if (job && job.running) job.stopped = true;
      return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && url.pathname === '/api/parse') {
      // kiểm tra định dạng 1 chuỗi proxy (dùng cho ô nhập)
      const { proxy } = await readJson(req);
      try { const p = parseProxy(String(proxy || '')); return send(res, 200, { ok: true, host: p.host, port: p.port, user: p.user, type: p.type }); }
      catch (e) { return send(res, 200, { ok: false, error: e.message }); }
    }
    send(res, 404, { error: 'not found' });
  } catch (e) {
    send(res, 400, { error: e.message });
  }
});

function openBrowser(url) {
  if (process.platform === 'win32') {
    // Ưu tiên mở ở chế độ "app" (cửa sổ riêng, không thanh địa chỉ) bằng Edge/Chrome nếu có
    const pf = process.env['ProgramFiles'] || 'C:\\Program Files';
    const pf86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
    const local = process.env.LOCALAPPDATA || '';
    const cands = [
      path.join(pf86, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.join(pf, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.join(pf, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(pf86, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(local, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    ];
    for (const c of cands) {
      if (fs.existsSync(c)) {
        spawn(c, [`--app=${url}`, '--window-size=1180,860'], { detached: true, stdio: 'ignore' }).unref();
        return;
      }
    }
    spawn('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore' }).unref();
  } else if (process.platform === 'darwin') {
    spawn('open', [url], { detached: true, stdio: 'ignore' }).unref();
  } else {
    spawn('xdg-open', [url], { detached: true, stdio: 'ignore' }).unref();
  }
}

server.listen(PORT, '127.0.0.1', () => {
  const url = `http://127.0.0.1:${server.address().port}/`;
  console.log(`ProxyCheck GUI: ${url}`);
  console.log(KEEP ? 'Nhấn Ctrl+C để thoát.' : 'Đóng cửa sổ trình duyệt (hoặc Ctrl+C) để thoát.');
  if (!NO_OPEN) openBrowser(url);
});
server.on('error', e => {
  if (e.code === 'EADDRINUSE') console.error(`Cổng ${PORT} đang bận (có thể GUI đang chạy sẵn). Thử: node gui.js --port 0`);
  else console.error('Lỗi: ' + e.message);
  process.exit(1);
});
