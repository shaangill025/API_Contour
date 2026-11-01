'use strict';
// Synthetic owned destination. No payload, credentials, peer identity or request logs.
const https = require('node:https');
const fs = require('node:fs');
const mode = process.env.PILOT_DESTINATION_MODE || 'normal';
if (!['normal','redirect'].includes(mode)) throw new Error('invalid destination test mode');
let disallowed = 0;
const server = https.createServer({
  key: fs.readFileSync('/pilot/tls/server.key'),
  cert: fs.readFileSync('/pilot/tls/server.crt'),
  ca: fs.readFileSync('/pilot/ca.crt'),
  requestCert: true,
  rejectUnauthorized: true,
  minVersion: 'TLSv1.2',
}, (req, res) => {
  if (req.url === '/control/stats' && req.method === 'GET') {
    res.writeHead(200, {'content-type': 'application/json'});
    res.end(JSON.stringify({disallowed}));
    return;
  }
  if (req.url === '/disallowed') disallowed += 1;
  if (req.method !== 'POST' || req.url !== '/pilot') {
    res.writeHead(404, {'content-type': 'application/json'});
    res.end('{"error":"not_found"}');
    req.resume();
    return;
  }
  let bytes = 0;
  req.on('data', (chunk) => {
    bytes += chunk.length;
    if (bytes > 1024) req.destroy();
  });
  req.on('end', () => {
    if (bytes > 1024) return;
    if (mode === 'redirect') {
      res.writeHead(302, {'location': 'https://pilot-destination:9443/disallowed', 'content-type':'application/json'});
      res.end('{"result":"redirect"}');
    } else {
      res.writeHead(200, {'content-type': 'application/json'});
      res.end('{"result":"owned-pilot-ok"}');
    }
  });
});
server.headersTimeout = 5000;
server.requestTimeout = 5000;
server.keepAliveTimeout = 1000;
server.maxConnections = 32;
server.on('clientError', (_error, socket) => socket.destroy());
server.listen(9443, '0.0.0.0');
function stop() { server.close(() => process.exit(0)); setTimeout(() => process.exit(1), 3000).unref(); }
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
