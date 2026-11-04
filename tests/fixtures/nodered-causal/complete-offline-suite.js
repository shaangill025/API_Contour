'use strict';
// Runs only inside the pinned image; each child test remains a separate process.
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
assert.equal(process.versions.node, '24.22.1');
const hooks='/usr/src/node-red/node_modules/@node-red/util/lib/hooks.js';
const node='/usr/src/node-red/node_modules/@node-red/runtime/lib/nodes/Node.js';
const flow='/usr/src/node-red/node_modules/@node-red/runtime/lib/flows/Flow.js';
const cases = [
    ...['hook-order-reproducer.js','runtime-offline.js','catch-offline.js','bounds-offline.js','profile-offline.js','flow-offline.js','chain-offline.js','catch-concurrent-offline.js','private-runtime-offline.js','private-runtime-token-isolation-offline.js','ingress-point-offline.js'].map(x=>[x,hooks]),
    ...['catch-private-caller-offline.js','catch-compiler-apply-offline.js','node-source-transform-offline.js'].map(x=>[x,node]),
    ...['normal-predeliver-reentry-offline.js','private-runtime-normal-entry-offline.js'].map(x=>[x,hooks,node]),
    ...['flow-claim-offline.js','lexical-bridge-offline.js','catch-lexical-bridge-offline.js'].map(x=>[x,hooks,node,flow]),
    ...['catch-entry-model-offline.js','catch-literal-model-offline.js','error-profile-offline.js','error-commonjs-offline.js','causal-codec-offline.js'].map(x=>[x])
];
for (const [file,...args] of cases) {
    process.stdout.write('OFFLINE '+file+'\n');
    const result=spawnSync(process.execPath,[__dirname+'/'+file,...args],{stdio:'inherit',timeout:15000});
    if(result.error || result.status!==0) { process.stderr.write('FAIL offline '+file+'\n'); process.exit(1); }
}
process.stdout.write('PASS: complete pinned-image offline suite\n');
