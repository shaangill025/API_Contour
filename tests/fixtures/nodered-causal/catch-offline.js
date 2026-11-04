'use strict';
// Pinned Node.error -> Flow.handleError invokes Catch.receive directly, without
// Flow.send/preDeliver. Model that hook sequence without reading error content.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { install } = require('../../../collectors/nodered/runtime');
const moduleCopy = { exports:{} };
vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), {
    module:moduleCopy, exports:moduleCopy.exports,
    require() { return {debug(){}}; }, Error, Promise
});
const h = moduleCopy.exports;
const adapter = install(h, { inbound:['in'], requests:['request'], maxPending:8,
    maxEvents:64, maxBytes:8192, ttlMs:1000 });
const message = { req:{ headers:{} } };
function deliver(source, destination, next) {
    const event = { msg:message, source:{id:source}, destination:{id:destination} };
    h.trigger('onSend', [event], () => h.trigger('preDeliver', event, () =>
        h.trigger('onReceive', event, next)));
}
let forwarded = false;
deliver('in', 'request', () => {
    const before = adapter.snapshot();
    assert.equal(before.loss, 0);
    assert.equal(before.events.filter(e => e.kind === 'REQUEST_INTENT').length, 1);
    // Direct Catch.receive has request context, but no dispatch token. Its
    // downstream ordinary send must likewise remain unowned and still forward.
    h.trigger('onReceive', {destination:{id:'catch'}}, () => {
        deliver('catch', 'sink', () => { forwarded = true; });
    });
    const after = adapter.snapshot();
    assert(forwarded);
    assert(after.registryIntact);
    assert(after.loss > before.loss);
    assert.equal(after.pending, 0);
    assert.deepEqual(after.events, before.events);
});
process.stdout.write('PASS: direct Catch dispatch reports loss and never fabricates ownership\n');
