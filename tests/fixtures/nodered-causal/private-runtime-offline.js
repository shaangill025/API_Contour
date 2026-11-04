'use strict';
// White-box building-block test against pinned hooks source, not a loader test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {install} = require('../../../collectors/nodered/error-integration/private-runtime');
const source = fs.readFileSync(process.argv[2], 'utf8');
function hooks() {
    const module = {exports:{}};
    vm.runInNewContext(source, {module, exports:module.exports, require(){return {debug(){}}}, Error, Promise});
    return module.exports;
}
const config = {inbound:['in'],requests:['request'],maxPending:2,maxEvents:64,maxBytes:8192,ttlMs:1000};
const h = hooks(); let control;
const adapter = install(h,config,c => {control = c});
assert(Object.isFrozen(adapter));
assert.deepEqual(Object.keys(adapter).sort(), ['invalidate','snapshot']);
assert(Object.isFrozen(control));
let stolen;
const second = install(h,config,c => {stolen = c});
assert.equal(stolen,undefined);
assert.equal(second.snapshot().registryIntact,false);
const target = {}, other = {}, worker = {};
const nested = {destination:{id:'catch',node:target}};
const event = {destination:{id:'catch',node:target}};
const inbound = {source:{id:'in'},msg:{req:{headers:{}}}};
let parent;
h.trigger('onSend',[inbound],() => {
    const delivery = {destination:{node:worker}};
    h.trigger('preDeliver',delivery,() => {
        const frame = control.claimDelivery(delivery), normal = {destination:{id:'worker',node:worker}};
        control.bind(frame,worker,normal,()=>h.trigger('onReceive',normal,() => {
            parent = adapter.snapshot().events.at(-1);
            const frame = control.capture(target);
            h.trigger('onReceive',nested,()=>{});
            control.bind(frame,target,event,()=>h.trigger('onReceive',event,()=>{}));
            control.bind(frame,target,event,()=>h.trigger('onReceive',event,()=>{}));
            const wrong = control.capture(target);
            control.bind(wrong,other,{destination:{id:'catch',node:other}},()=>{});
            const mismatch = control.capture(target);
            const badEvent = {destination:{id:'catch',node:other}};
            control.bind(mismatch,target,badEvent,()=>h.trigger('onReceive',badEvent,()=>{}));
            const canceled = control.capture(target); control.cancel(canceled);
            const throwing = control.capture(target);
            assert.throws(()=>control.bind(throwing,target,{},()=>{throw Error('expected')}));
            const a = control.capture(target), b = control.capture(target);
            assert(a && b); assert.equal(control.capture(target),undefined);
            control.cancel(a); control.cancel(b);
        }));
    });
});
const snap = adapter.snapshot();
const deliveries = snap.events.filter(e=>e.kind==='DELIVERY_INTENT');
assert.equal(deliveries.length,2);
assert.equal(deliveries[1].parent,parent.activity);
assert.equal(deliveries[1].root,parent.root);
assert.equal(snap.frames,0);
assert(snap.loss >= 7);
assert(!JSON.stringify(snap).includes('headers'));
adapter.invalidate();
assert.equal(control.capture(target),undefined);
const expiryHooks = hooks(); let expiryControl, expired;
const expiryAdapter = install(expiryHooks,{...config,ttlMs:20},c=>{expiryControl=c});
const expiryDelivery = {destination:{node:worker}};
expiryHooks.trigger('onSend',[inbound],()=>expiryHooks.trigger('preDeliver',expiryDelivery,()=> {
    const frame = expiryControl.claimDelivery(expiryDelivery), event = {destination:{id:'worker',node:worker}};
    expiryControl.bind(frame,worker,event,()=>expiryHooks.trigger('onReceive',event,()=>{expired=expiryControl.capture(target)}));
}));
assert(expired);
setTimeout(()=>{
    const event = {destination:{id:'catch',node:target}};
    expiryControl.bind(expired,target,event,()=>expiryHooks.trigger('onReceive',event,()=>{}));
    const state = expiryAdapter.snapshot();
    assert.equal(state.frames,0);
    assert.equal(state.events.filter(e=>e.kind==='DELIVERY_INTENT').length,1);
    assert(state.loss >= 1);
    process.stdout.write('PASS: private runtime white-box ownership, loss, bounds, expiry and cleanup\n');
},40);
