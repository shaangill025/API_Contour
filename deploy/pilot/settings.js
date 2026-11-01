'use strict';
const fs = require('node:fs');
// Only the owned destination and an explicitly configured local gateway are
// valid fixed targets; incoming HTTP headers cannot select a destination.
const target = process.env.PILOT_TARGET || 'https://pilot-destination:9443/pilot';
if (!/^https:\/\/(pilot-destination|pilot-gateway):9443\/pilot$/.test(target)) {
  throw new Error('invalid owned pilot target');
}
process.env.PILOT_TARGET = target;
const mode = process.env.PILOT_TLS_TEST || 'normal';
const files = {normal:'/pilot/flows.json', 'wrong-name':'/pilot/flows-wrong-name.json', 'wrong-ca':'/pilot/flows-wrong-ca.json'};
if (!Object.hasOwn(files, mode)) throw new Error('invalid pilot TLS test mode');
module.exports = {
  flowFile: files[mode],
  userDir: '/data',
  credentialSecret: false,
  httpAdminRoot: false,
  httpNodeRoot: '/',
  httpNodeMiddleware: function(req, res, next) {
    if (req.method !== 'GET' || req.url !== '/pilot' || req.headers['transfer-encoding'] ||
        (req.headers['content-length'] && req.headers['content-length'] !== '0')) {
      res.status(400).end();
      return;
    }
    next();
  },
  uiHost: '0.0.0.0',
  uiPort: 1880,
  https: {
    key: fs.readFileSync('/pilot/tls/server.key'),
    cert: fs.readFileSync('/pilot/tls/server.crt'),
    minVersion: 'TLSv1.2',
  },
  httpRequestTimeout: 5000,
  apiMaxLength: '1kb',
  logging: { console: { level: 'off', metrics: false, audit: false } },
  externalModules: { autoInstall: false, palette: { allowInstall: false } },
};
