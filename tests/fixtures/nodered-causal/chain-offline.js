'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { install } = require('../../../collectors/nodered/runtime');
const mod = { exports:{} };
vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), {module:mod, exports:mod.exports,
    require() { return {debug(){}}; }, Error, Promise});
const hooks = mod.exports;
const adapter = install(hooks, {inbound:['in'], requests:['request'], maxPending:32,
    maxEvents:64, maxBytes:8192, ttlMs:1000});
const observed = [];
function send(source, destination, msg) {
    const event = {source:{id:source}, destination:{id:destination}, msg};
    hooks.trigger('onSend', [event], () => hooks.trigger('preDeliver', event, () => {
        setImmediate(() => hooks.trigger('onReceive', event, () => {
            if (destination === 'request') {
                observed.push([msg.kind, msg.step]);
                setImmediate(() => send('request', 'chain', msg));
            } else if (destination === 'chain' && msg.step === 1) {
                msg.step = 2;
                send('chain', 'request', msg);
            }
        }));
    }));
}
send('in', 'request', {kind:'serial', step:1, req:{headers:{}}});
send('in', 'request', {kind:'retry', step:1, req:{headers:{}}});
setTimeout(() => {
    assert.deepEqual(observed.filter(x => x[0] === 'serial').map(x => x[1]), [1,2]);
    assert.deepEqual(observed.filter(x => x[0] === 'retry').map(x => x[1]), [1,2]);
    const snap = adapter.snapshot();
    assert.equal(snap.loss, 0);
    const roots = snap.events.filter(e => e.kind === 'ROOT_INTENT');
    assert.equal(roots.length, 2);
    for (const root of roots) {
        const intents = snap.events.filter(e => e.kind === 'REQUEST_INTENT' && e.root === root.root);
        assert.equal(intents.length, 2);
        const delivery = snap.events.find(e => e.kind === 'DELIVERY_INTENT' && e.activity === intents[1].activity);
        const intermediate = snap.events.find(e => e.kind === 'DELIVERY_INTENT' && e.activity === delivery.parent);
        assert(intermediate && intermediate.root === root.root && intermediate.parent === intents[0].activity);
    }
    process.stdout.write('PASS: simulated serial request ownership and independent root chains\n');
}, 80);
