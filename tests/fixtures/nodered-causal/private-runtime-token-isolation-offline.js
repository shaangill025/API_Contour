'use strict';
// White-box regression using the actual pinned hooks module, no Node-RED loader.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {install} = require('../../../collectors/nodered/error-integration/private-runtime');
const moduleStub = {exports:{}};
vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), {
    module:moduleStub, exports:moduleStub.exports, require(){return {debug(){}}}, Error, Promise
});
const hooks = moduleStub.exports;
let control;
const adapter = install(hooks,{inbound:['in'],requests:[],maxPending:8,maxEvents:128,maxBytes:16384,ttlMs:100},c=>{control=c});
const target = {}, wrong = {}, worker = {}, normal = {};
const inbound = {source:{id:'in'},msg:{req:{headers:{}}}};
const receive = node => ({destination:{id:'catch',node}});
const deliveries = () => adapter.snapshot().events.filter(e=>e.kind==='DELIVERY_INTENT');
function root(fn) {
    const delivery = {destination:{node:worker}};
    hooks.trigger('onSend',[inbound],()=>hooks.trigger('preDeliver',delivery,()=> {
        const frame = control.claimDelivery(delivery), event = {destination:{id:'worker',node:worker}};
        control.bind(frame,worker,event,()=>hooks.trigger('onReceive',event,()=>fn(deliveries().at(-1))));
    }));
}
function normalPending(parent, action, expectedOwned) {
    const delivery = {destination:{node:normal}};
    hooks.trigger('preDeliver',delivery,()=>{
        const before = deliveries().length;
        const loss = adapter.snapshot().loss;
        action();
        assert.equal(deliveries().length,before + expectedOwned,'rejected or replayed event fabricated ownership');
        assert(adapter.snapshot().loss > loss, 'rejected or replayed event must record loss');
        assert.equal(adapter.snapshot().pending,1,'unrelated pending delivery must survive');
        const frame = control.claimDelivery(delivery), event = {destination:{id:'normal',node:normal}};
        control.bind(frame,normal,event,()=>hooks.trigger('onReceive',event,()=>{}));
        const after = deliveries();
        assert.equal(after.length,before + expectedOwned + 1);
        assert.equal(after.at(-1).parent,parent.activity);
        assert.equal(after.at(-1).root,parent.root);
        assert.equal(adapter.snapshot().pending,0);
        assert.equal(adapter.snapshot().frames,0);
    });
}
root(parent=>{
    const frame = control.capture(target);
    normalPending(parent,()=>control.bind(frame,wrong,receive(wrong),()=>hooks.trigger('onReceive',receive(wrong),()=>{})),0);
    const used = control.capture(target), event = receive(target);
    control.bind(used,target,event,()=>hooks.trigger('onReceive',event,()=>{}));
    normalPending(parent,()=>control.bind(used,target,event,()=>hooks.trigger('onReceive',event,()=>{})),0);
    const fresh = control.capture(target), again = receive(target);
    normalPending(parent,()=>control.bind(fresh,target,again,()=>{
        hooks.trigger('onReceive',again,()=>{});
        hooks.trigger('onReceive',again,()=>{});
    }),1);
});
let expired;
root(()=>{expired=control.capture(target)});
setTimeout(()=>{
    root(parent=>normalPending(parent,()=>{
        const event = receive(target);
        control.bind(expired,target,event,()=>hooks.trigger('onReceive',event,()=>{}));
    },0));
    process.stdout.write('PASS: rejected, replayed, expired and duplicate event preserve unrelated pending delivery\n');
},130);
