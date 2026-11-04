'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { install } = require('../../../collectors/nodered/runtime');
const source = fs.readFileSync(process.argv[2], 'utf8');
function hooks() {
    const module = { exports: {} };
    vm.runInNewContext(source, { module, exports: module.exports,
        require() { return { debug() {} }; }, Error, Promise });
    return module.exports;
}
const config = { inbound: ['in'], requests: ['request'], maxPending: 8,
    maxEvents: 64, maxBytes: 8192, ttlMs: 1000 };
const h = hooks(), adapter = install(h, config);
const seen = [];
function send(sourceId, targets, msg) {
    const events = targets.map(id => ({ msg, source: { id: sourceId }, destination: { id } }));
    h.trigger('onSend', events, () => {
        for (const event of events) h.trigger('preDeliver', event, () => {
            setImmediate(() => h.trigger('onReceive', event, () => {
                const snap = adapter.snapshot();
                const activity = snap.events.filter(e => e.kind === 'DELIVERY_INTENT').at(-1);
                seen.push({ input: msg.payload, target: event.destination.id, activity });
                if (event.destination.id === 'delay') setTimeout(() => send('delay', ['request', 'request'], msg), msg.payload === 'one' ? 20 : 1);
            }));
        });
    });
}
const first = { payload: 'one', _msgid: 'same', _apicontour: 'spoof', req: {headers: {'x-apicontour-spoof':'bad'}} };
const second = { payload: 'two', _msgid: 'same', req: {headers: {}} };
send('in', ['delay'], first);
send('in', ['delay'], second);
setTimeout(() => {
    assert.equal(first._apicontour, undefined);
    assert.equal(first.req.headers['x-apicontour-spoof'], undefined);
    assert.equal(seen.length, 6);
    const one = seen.filter(x => x.input === 'one'), two = seen.filter(x => x.input === 'two');
    assert.equal(new Set(one.map(x => x.activity.root)).size, 1);
    assert.equal(new Set(two.map(x => x.activity.root)).size, 1);
    assert.notEqual(one[0].activity.root, two[0].activity.root);
    for (const list of [one, two]) {
        const parent = list.find(x => x.target === 'delay').activity.activity;
        for (const child of list.filter(x => x.target === 'request')) assert.equal(child.activity.parent, parent);
        assert.notEqual(list[1].activity.activity, list[2].activity.activity);
    }
    const before = adapter.snapshot();
    assert.equal(before.registryIntact, true);
    assert.equal(before.loss, 0);
    assert(!JSON.stringify(before).includes('spoof'));
    h.add('onReceive.other', function (_event, done) { done(); });
    assert.equal(adapter.snapshot().registryIntact, false);
    assert(adapter.snapshot().loss > 0);
    let forwarded = false;
    h.trigger('onReceive', {destination:{id:'request'}}, () => { forwarded = true; });
    assert(forwarded);
    assert.equal(adapter.snapshot().events.length, before.events.length);
    process.stdout.write('PASS: simulated async dispatch, fanout and guarded mutation\n');
}, 80);
