'use strict';
// Hash-pinned hooks and transformed Node literals with a test-only bridge.
// This does not qualify a loader, a production bridge, or an active adapter.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const {install} = require('../../../collectors/nodered/error-integration/private-runtime');
const {transform} = require('../../../collectors/nodered/error-integration/node-source-transform');
const hookBytes = fs.readFileSync(process.argv[2]);
assert.equal(crypto.createHash('sha256').update(hookBytes).digest('hex'), 'e7d1e0496b5399458de55bc9b8ea59e6741869db33cdced0f03ec798c6fa6fcf');
const moduleStub = {exports:{}};
vm.runInNewContext(hookBytes.toString(), {module:moduleStub,exports:moduleStub.exports,require(){return {debug(){}}}, Error, Promise});
const hooks = moduleStub.exports;
let control;
const adapter = install(hooks,{inbound:['in'],requests:['A','B'],maxPending:8,maxEvents:64,maxBytes:8192,ttlMs:1000}, c => { control=c; });
const Node = {prototype:{}};
const text = transform(fs.readFileSync(process.argv[3])).toString();
const literals = ['receive','emit','_emitInput'].map(name => {
    const m = text.match(new RegExp('Node\\.prototype\\.' + name + ' = function\\([^\\n]*\\) \\{[\\s\\S]*?\\n\\}' + (name === 'receive' ? ';' : '')));
    assert(m); return m[0];
}).join('\n');
let pending, expected;
const bridge = {
    trustedHook() { return true; },
    apply:Reflect.apply,
    take(kind,target) {
        const p = pending; pending = undefined;
        return p && p.kind === kind && p.target === target ? p.frame : undefined;
    },
    arm(kind,target,method,apply,frame) {
        if (!frame || method !== expected[kind] || (kind === 'input' && apply !== Function.prototype.apply)) return undefined;
        return pending = {kind,target,frame};
    },
    finish(handle) { if (pending === handle) pending = undefined; },
    drop() {},
    bind(frame,target,event,invoke) { return control.bind(frame,target,event,invoke); }
};
Function('Node','redUtil','hooks','__apicontourNodeBridge',literals)(Node,{generateId:()=> 'id'},hooks,bridge);
expected = {emit:Node.prototype.emit,input:Node.prototype._emitInput};
const seen = [];
function node(id) {
    const n = Object.create(Node.prototype); n.id=id; n.metric=()=>{};
    n._inputCallback=()=>seen.push([id,adapter.snapshot().events.filter(e=>e.kind==='DELIVERY_INTENT').length]); return n;
}
const a=node('A'), b=node('B');
const message = {};
Object.defineProperty(message,'_msgid',{get() { b._emitInput({}); a._emitInput({}); return 'id'; }});
const inbound={source:{id:'in'},msg:{req:{headers:{}}}};
const delivery={destination:{node:a}};
hooks.trigger('onSend',[inbound],()=>hooks.trigger('preDeliver',delivery,()=>{
    const frame=control.claimDelivery(delivery); pending={kind:'receive',target:a,frame};
    try { a.receive(message); } finally { pending=undefined; }
}));
const state=adapter.snapshot();
const roots=state.events.filter(e=>e.kind==='ROOT_INTENT');
const deliveries=state.events.filter(e=>e.kind==='DELIVERY_INTENT');
const requests=state.events.filter(e=>e.kind==='REQUEST_INTENT');
assert.deepEqual(seen,[['B',0],['A',0],['A',1]]);
assert.equal(deliveries.length,1); assert.equal(requests.length,1);
assert.equal(deliveries[0].root,roots[0].root); assert.equal(deliveries[0].parent,roots[0].root);
assert.equal(requests[0].activity,deliveries[0].activity);
assert.equal(state.pending,0); assert.equal(state.frames,0); assert(state.loss>=2);
// Wrong target consumes the token; replay cannot convert it into a frame.
const another={destination:{node:a}};
hooks.trigger('onSend',[inbound],()=>hooks.trigger('preDeliver',another,()=>{
    assert.equal(control.claimDelivery({destination:{node:b}}),undefined); assert.equal(control.claimDelivery(another),undefined);
}));
// Missing or accessor destination must never mint a token or run its getter.
let called=false;
const dest={}; Object.defineProperty(dest,'node',{get(){called=true; return a;}});
hooks.trigger('onSend',[inbound],()=>hooks.trigger('preDeliver',{destination:dest},()=>assert.equal(control.claimDelivery({destination:{node:a}}),undefined)));
hooks.trigger('onSend',[inbound],()=>hooks.trigger('preDeliver',{},()=>assert.equal(control.claimDelivery({destination:{node:a}}),undefined)));
assert.equal(called,false); assert.equal(adapter.snapshot().pending,0); assert.equal(adapter.snapshot().frames,0);
process.stdout.write('PASS: test-bridge normal entry rejects reentry, wrong target, replay and missing target\n');
