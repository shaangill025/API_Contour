'use strict';
const assert = require('node:assert/strict');
const diagnostic = require('./diagnostics');
let reads = 0;
const alternating = Object.defineProperty({},'code',{get() { reads++; return reads === 1 ? 'EACCES' : 'private-canary'; }});
assert.equal(diagnostic.format(alternating,'imports'),'FAIL phase=imports code=OTHER\n');
assert.equal(reads,0);
const throwing = Object.defineProperty({},'code',{get() { throw Error('private-canary'); }});
assert.equal(diagnostic.format(throwing,'pki'),'FAIL phase=pki code=OTHER\n');
assert.equal(diagnostic.format({code:'private-canary'},'imports'),'FAIL phase=imports code=OTHER\n');
assert.equal(diagnostic.format({code:'EACCES'},'pki'),'FAIL phase=pki code=EACCES\n');
assert.equal(diagnostic.format(new Proxy({}, {getOwnPropertyDescriptor() { throw Error('private-canary'); }}),'imports'),
    'FAIL phase=imports code=OTHER\n');
for (const value of [undefined,null,0,false,'']) {
    const state = diagnostic.state();
    assert.equal(state.failed(),false);
    state.mark(value,'init');
    assert.equal(state.failed(),true);
    state.mark({code:'EACCES'},'cleanup');
    assert.equal(state.diagnostic(),'FAIL phase=init code=OTHER\n');
}
const cleanup = diagnostic.state(); cleanup.mark({code:'EACCES'},'cleanup');
assert.equal(cleanup.diagnostic(),'FAIL phase=cleanup code=EACCES\n');
const vm = require('node:vm'), fs = require('node:fs'), path = require('node:path');
const actual = fs.readFileSync(path.join(__dirname,'actual.js'),'utf8');
const tail = actual.slice(actual.indexOf('let cleanupPromise;'));
assert(tail.startsWith('let cleanupPromise;'));
async function exercise(mainReject, rejected, cleanupReject) {
    const result = diagnostic.state(), out = [], err = [];
    const context = { result, phase:'init', fatalCleanup:null, watchdog:1, temp:'owned',
        receiver:{close() { if (cleanupReject) throw false; }}, roots:{close(){}},
        redInitAttempted:true, RED:{async stop(){}}, async close(){}, fs:{rmSync(){}},
        clearTimeout(){}, main:async () => { if (rejected) throw mainReject; },
        process:{stdout:{write:s => out.push(s)},stderr:{write:s => err.push(s)},exitCode:0,exit(){}},
    };
    context.remember = error => result.mark(error,context.phase);
    await vm.runInNewContext(tail, context);
    return {out,err,code:context.process.exitCode};
}
(async () => {
    for (const value of [undefined,null,0,false,'']) {
        const r = await exercise(value,true,false);
        assert.deepEqual(r.out,[]); assert.deepEqual(r.err,['FAIL phase=init code=OTHER\n']); assert.equal(r.code,1);
    }
    const failedCleanup = await exercise(null,false,true);
    assert.deepEqual(failedCleanup.out,[]); assert.deepEqual(failedCleanup.err,['FAIL phase=cleanup code=OTHER\n']);
    assert.equal(failedCleanup.code,1);
    const success = await exercise(null,false,false);
    assert.deepEqual(success.out,['PASS phase=identity counts=3,3,3\n']);
    assert.deepEqual(success.err,[]); assert.equal(success.code,0);
    console.log('receiver diagnostics controls: passed');
})().catch(() => { console.error('receiver diagnostics controls: failed'); process.exitCode = 1; });
