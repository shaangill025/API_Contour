'use strict';
// Test-only network peer. The exporter endpoint deliberately refuses batches;
// a successful TLS handshake here is not an ingestion or ACK qualification.
const fs = require('node:fs');
const https = require('node:https');
const crypto = require('node:crypto');
const mode = process.argv[2];
const read = name => fs.readFileSync('/fixture/' + name);
function leaf(req) {
  const cert = req.socket.getPeerCertificate();
  if (!req.socket.authorized || !cert.raw) throw Error('client authentication');
  return crypto.createHash('sha256').update(cert.raw).digest('hex');
}
if (mode === 'serve' || mode === 'business') {
  const tls = { ca: read('ca.pem'), cert: read('peer.pem'), key: read('peer.key'),
    requestCert: true, rejectUnauthorized: true };
  const expectedProduct = process.env.PRODUCT_LEAF;
  const expectedExport = process.env.EXPORT_LEAF;
  if (!/^[0-9a-f]{64}$/.test(expectedProduct) || !/^[0-9a-f]{64}$/.test(expectedExport)) throw Error('pins');
  const gateway = https.createServer(tls, (req, res) => {
    try {
      if (leaf(req) !== expectedProduct || req.method !== 'POST' || req.url !== '/pilot') throw Error('request');
      if (mode === 'business') {
        const marker = req.headers['x-apicontour-causal-marker'];
        if (typeof marker !== 'string' || !marker || marker.length > 8192) throw Error('marker');
        const digest = crypto.createHash('sha256').update('apicontour/causal-marker-wire/1\n','utf8').update(marker,'ascii').digest('hex');
        process.stdout.write('MARKER ' + digest + '\n');
      }
      req.resume(); res.writeHead(200, {'content-type': 'text/plain'}); res.end('fixture-product');
    } catch (_) { res.destroy(); }
  });
  const ingress = mode === 'serve' ? https.createServer(tls, (req, res) => {
    try {
      if (leaf(req) !== expectedExport || req.method !== 'POST' || req.url !== '/v1/causal-events') throw Error('request');
      req.resume(); res.writeHead(503); res.end();
    } catch (_) { res.destroy(); }
  }) : null;
  gateway.listen(9443, '0.0.0.0'); if (ingress) ingress.listen(8443, '0.0.0.0');
} else if (mode === 'replay' || mode === 'wrong-leaf') {
  let chunks = [], size = 0;
  process.stdin.on('data', chunk => {
    size += chunk.length;
    if (size > 1048576) { process.exitCode = 1; process.stdin.destroy(); return; }
    chunks.push(chunk);
  });
  process.stdin.on('end', () => {
    const body = Buffer.concat(chunks);
    const identity = mode === 'replay' ? 'export' : 'client';
    const request = https.request({hostname: 'causal-ingress', port: 8443,
      path: '/v1/causal-events', method: 'POST', ca: read('ca.pem'),
      cert: read(identity + '.pem'), key: read(identity + '.key'), rejectUnauthorized: true,
      headers: {'content-type':'application/json', 'content-length':body.length}}, response => {
      let responseBytes = 0, result = [];
      response.on('data', chunk => { responseBytes += chunk.length; if (responseBytes > 4096) request.destroy(); else result.push(chunk); });
      response.on('end', () => {
        if (responseBytes > 4096 || response.headers['content-type'] !== 'application/json') { process.exitCode = 1; return; }
        try { process.stdout.write(JSON.stringify({status:response.statusCode,body:JSON.parse(Buffer.concat(result).toString('utf8'))})+'\n'); }
        catch (_) { process.exitCode = 1; }
      });
    });
    request.setTimeout(5000, () => request.destroy());
    request.on('error', () => { process.exitCode = 1; });
    request.end(body);
  });
} else if (mode === 'wait') {
  setInterval(() => {}, 10000);
} else if (mode === 'request') {
  const request = https.request({hostname: 'causal-node', port: 1880, path: '/run', method: 'POST',
    ca: read('ca.pem'), cert: read('client.pem'), key: read('client.key'), rejectUnauthorized: true,
    headers: {'content-type': 'text/plain'}}, response => {
    let size = 0;
    response.on('data', chunk => { size += chunk.length; if (size > 65536) request.destroy(Error('size')); });
    response.on('end', () => { if (response.statusCode !== 200) process.exitCode = 1; });
  });
  request.setTimeout(5000, () => request.destroy(Error('timeout')));
  request.on('error', () => { process.exitCode = 1; });
  request.end('serial');
} else { throw Error('mode'); }
