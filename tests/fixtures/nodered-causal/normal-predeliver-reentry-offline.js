'use strict';
// Uncompiled-path safety regression: pinned stock Node literals + pinned hooks
// + actual private-runtime. No loader or full Node-RED runtime is exercised.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const {install} = require('../../../collectors/nodered/error-integration/private-runtime');
function pinned(path, hash) {
    const data = fs.readFileSync(path);
    assert.equal(crypto.createHash('sha256').update(data).digest('hex'), hash);
    return data.toString('utf8');
}
const hookSource = pinned(process.argv[2], 'e7d1e0496b5399458de55bc9b8ea59e6741869db33cdced0f03ec798c6fa6fcf');
const nodeSource = pinned(process.argv[3], '4931ee2e41d4246d51b42c55bb9d7d020ac84601a9e70dff6e70946c23fdf4be');
const moduleStub = {exports:{}};
vm.runInNewContext(hookSource, {module:moduleStub,exports:moduleStub.exports,require(){return {debug(){}}}, Error, Promise});
const hooks = moduleStub.exports;
const adapter = install(hooks, {inbound:['in'],requests:['B'],maxPending:8,maxEvents:64,maxBytes:8192,ttlMs:1000}, () => {});
assert.equal(adapter.snapshot().registryIntact, true);
const Node = {prototype:{}};
const literals = ['receive','emit','_emitInput'].map(name => {
    const re = new RegExp('Node\\.prototype\\.' + name + ' = function\\([^\\n]*\\) \\{[\\s\\S]*?\\n\\}' + (name === 'receive' ? ';' : ''));
    const matches = nodeSource.match(re); assert(matches); return matches[0];
}).join('\n');
Function('Node','redUtil','hooks',literals)(Node,{generateId:()=> 'generated'},hooks);
function node(id) {
    const n = Object.create(Node.prototype);
    n.id = id; n.metric = () => {}; n._inputCallback = () => {}; return n;
}
const a = node('A'), b = node('B');
const seen = [];
for (const n of [a, b]) n._inputCallback = () => seen.push([n.id, adapter.snapshot().events.filter(e => e.kind === 'DELIVERY_INTENT').length]);
const message = {};
Object.defineProperty(message,'_msgid',{get() { b._emitInput({_msgid:'direct'}); return 'intended'; }});
const inbound = {source:{id:'in'},msg:{req:{headers:{}}}};
hooks.trigger('onSend',[inbound],() => {
    hooks.trigger('preDeliver',{destination:{id:'A',node:a},msg:message},() => a.receive(message));
});
const state = adapter.snapshot();
const deliveries = state.events.filter(e => e.kind === 'DELIVERY_INTENT');
const wrongRequests = state.events.filter(e => e.kind === 'REQUEST_INTENT');
assert.deepEqual(seen, [['B',0],['A',0]], 'uncompiled direct entries must both be unowned');
process.stdout.write(`Observed: ${deliveries.length} owned delivery, ${wrongRequests.length} B request intent, ${state.pending} pending, ${state.loss} loss\n`);
assert.equal(wrongRequests.length, 0, 'direct reentrant B must not consume A preDeliver token');
assert.equal(deliveries.length, 0, 'uncompiled A must remain unqualified');
assert.equal(state.pending, 1, 'unconsumed normal token remains bounded until expiry');
process.stdout.write('PASS: uncompiled reentrant B and intended A are unowned\n');
