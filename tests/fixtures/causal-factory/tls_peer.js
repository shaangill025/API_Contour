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
if (mode === 'serve') {
  const tls = { ca: read('ca.pem'), cert: read('peer.pem'), key: read('peer.key'),
    requestCert: true, rejectUnauthorized: true };
  const expectedProduct = process.env.PRODUCT_LEAF;
  const expectedExport = process.env.EXPORT_LEAF;
  if (!/^[0-9a-f]{64}$/.test(expectedProduct) || !/^[0-9a-f]{64}$/.test(expectedExport)) throw Error('pins');
  const gateway = https.createServer(tls, (req, res) => {
    try {
      if (leaf(req) !== expectedProduct || req.method !== 'POST' || req.url !== '/pilot') throw Error('request');
      req.resume(); res.writeHead(200, {'content-type': 'text/plain'}); res.end('fixture-product');
    } catch (_) { res.destroy(); }
  });
  const ingress = https.createServer(tls, (req, res) => {
    try {
      if (leaf(req) !== expectedExport || req.method !== 'POST' || req.url !== '/v1/causal-events') throw Error('request');
      req.resume(); res.writeHead(503); res.end();
    } catch (_) { res.destroy(); }
  });
  gateway.listen(9443, '0.0.0.0'); ingress.listen(8443, '0.0.0.0');
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
