'use strict';
// Hook-level model of the pinned Flow.handleError -> Catch.receive bypass.
// It deliberately does not claim to execute Node-RED's Flow implementation.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { install } = require('../../../collectors/nodered/runtime');
const moduleCopy = { exports:{} };
vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), {
    module:moduleCopy, exports:moduleCopy.exports,
    require() { return { debug() {} }; }, Error, Promise
});
const hooks = moduleCopy.exports;
const adapter = install(hooks, { inbound:['in'], requests:['request'], maxPending:8,
    maxEvents:64, maxBytes:8192, ttlMs:1000 });
function send(source, destination, next) {
    const event = { msg:{req:{headers:{}}}, source:{id:source}, destination:{id:destination} };
    hooks.trigger('onSend', [event], () => hooks.trigger('preDeliver', event, () =>
        hooks.trigger('onReceive', event, next)));
}
const completed = [];
function launch(label, delay) {
    send('in', 'request', () => {
        setTimeout(() => {
            // Flow.handleError supplies a cloned message to the same Catch node
            // directly. The untrusted fields below cannot establish ownership.
            const event = {destination:{id:'catch'}, msg:{_msgid:'same',
                _apicontour:{root:'spoof'}, error:{source:{id:'request'}}}};
            hooks.trigger('onReceive', event, () => {
                send('catch', 'sink', () => completed.push(label));
            });
        }, delay);
    });
}
launch('first', 30);
launch('second', 5);
const before = adapter.snapshot();
assert.equal(before.loss, 0);
assert.equal(before.pending, 0);
assert.equal(before.events.filter(e => e.kind === 'ROOT_INTENT').length, 2);
assert.equal(before.events.filter(e => e.kind === 'REQUEST_INTENT').length, 2);
const roots = before.events.filter(e => e.kind === 'ROOT_INTENT').map(e => e.root);
assert.notEqual(roots[0], roots[1]);
setTimeout(() => {
    assert.deepEqual(completed, ['second', 'first']);
    const after = adapter.snapshot();
    assert(after.registryIntact);
    assert(after.loss > before.loss);
    assert.equal(after.pending, 0);
    assert.deepEqual(after.events, before.events);
    let forwarded = false;
    hooks.trigger('onReceive', {destination:{id:'catch'}, msg:{_msgid:'same',
        _apicontour:{root:roots[0]}, error:{source:{id:'request'}}}}, () => { forwarded = true; });
    const unowned = adapter.snapshot();
    assert(forwarded);
    assert(unowned.loss > after.loss);
    assert.deepEqual(unowned.events, before.events);
    process.stdout.write('PASS: concurrent reversed direct Catch dispatch remains explicitly unowned\n');
}, 70);
