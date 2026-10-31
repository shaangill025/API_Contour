'use strict';
const https = require('node:https');
const fs = require('node:fs');
const fixture = JSON.parse(fs.readFileSync('/pilot/privacy.json'));
const expected = Buffer.from(JSON.stringify({probe:fixture.request}));
const response = JSON.stringify({result:fixture.response});
const server = https.createServer({key:fs.readFileSync('/pilot/tls/server.key'),
  cert:fs.readFileSync('/pilot/tls/server.crt'), ca:fs.readFileSync('/pilot/ca.crt'),
  requestCert:true, rejectUnauthorized:true, minVersion:'TLSv1.2'}, (req,res) => {
  if (req.method !== 'POST' || req.url !== '/pilot') { res.writeHead(404); res.end(); return; }
  let chunks=[], size=0;
  req.on('data', chunk => { size += chunk.length; if (size > 1024) req.destroy(); else chunks.push(chunk); });
  req.on('end', () => {
    if (!Buffer.concat(chunks).equals(expected)) { res.writeHead(400); res.end(); return; }
    res.writeHead(200, {'content-type':'application/json'}); res.end(response);
  });
});
server.headersTimeout=5000; server.requestTimeout=5000; server.keepAliveTimeout=1000; server.maxConnections=32;
server.on('clientError', (_error,socket) => socket.destroy());
server.listen(9443,'0.0.0.0');
process.on('SIGTERM', () => {
  // Test-only negative control; normal privacy qualification never enables it.
  if (process.env.PRIVACY_TEST_SHUTDOWN_MARKER === '1') process.stdout.write(fixture.request+'\n');
  server.close(() => process.exit(0)); setTimeout(() => process.exit(1),3000).unref();
});
