'use strict';
// Private observer: pin the forwarder before looking at the synthetic metadata.
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const classify = (values, expected) => {
  const value = values.length === 1 ? values[0] : '';
  const valid = /^[0-9a-f]{64}$/.test(value);
  return valid && value === expected.a ? 'a' : valid && value === expected.b ? 'b' : 'none';
};
if (process.argv.includes('--self-test')) {
  const assert = require('assert');
  const expected = {a: 'a'.repeat(64), b: 'b'.repeat(64)};
  for (const values of [[], [''], ['x'.repeat(64)], ['a'.repeat(63)],
    ['c'.repeat(64)], ['a'.repeat(64), 'b'.repeat(64)], ['a'.repeat(64) + ', ' + 'b'.repeat(64)]]) {
    assert.strictEqual(classify(values, expected), 'none');
  }
  assert.strictEqual(classify(['A'.repeat(64)], expected), 'none');
  process.stdout.write('observer-classification: passed\n');
  process.exit(0);
}
const expected = JSON.parse(fs.readFileSync('/fixture/expected.json'));
const digest = b => crypto.createHash('sha256').update(b).digest('hex');
let next = 0;
const server = https.createServer({
  key: fs.readFileSync('/fixture/server.key'), cert: fs.readFileSync('/fixture/server.pem'),
  ca: fs.readFileSync('/fixture/ca.pem'), requestCert: true, rejectUnauthorized: true,
}, (req, res) => {
  const peer = req.socket.getPeerCertificate(true);
  if (!req.socket.authorized || !peer.raw || digest(peer.raw) !== expected.forwarder) {
    req.socket.destroy(); return;
  }
  const raw = req.rawHeaders;
  let values = [];
  for (let i = 0; i < raw.length; i += 2) {
    if (raw[i].toLowerCase() === 'x-contour-origin-witness') values.push(raw[i + 1]);
  }
  const label = classify(values, expected);
  res.writeHead(200, {'content-type': 'text/plain', 'content-length': '2',
    'x-fixture-match': label, 'x-fixture-connection': String(req.socket.fixtureId)});
  res.end('ok');
});
server.on('secureConnection', socket => { socket.fixtureId = ++next; });
server.listen(9443, '0.0.0.0');
