'use strict';
// Synthetic test profile only. The container owner must separately establish
// the approved image digest, immutable mounts, network isolation and module set.
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const { createRequire } = require('node:module');
const profile = require('./profile.js');

const blocked = Object.freeze({ snapshot() {
    return { registryIntact:false, loss:1, pending:0, events:[] };
} });
let adapter = blocked;
try {
    const launch = { version:process.versions.node, executable:process.execPath,
        argv:process.argv, execArgv:process.execArgv, env:process.env,
        cached:Object.keys(require.cache) };
    if (profile.validateLaunch(launch)) {
        const hashes = {};
        for (const file of Object.keys(profile.FILES)) {
            hashes[file] = createHash('sha256').update(fs.readFileSync(file)).digest('hex');
        }
        if (profile.validateFiles(hashes)) {
            const redRequire = createRequire('/usr/src/node-red/node_modules/node-red/red.js');
            const hooks = redRequire('@node-red/util').hooks;
            adapter = require('./runtime.js').install(hooks, { inbound:['in'], requests:['request'],
                maxPending:32, maxEvents:128, maxBytes:32768, ttlMs:5000 });
        }
    }
} catch (_) {
    // Observation is optional; do not stop the application or expose error text.
}
module.exports = adapter;
