'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { install } = require('../../../collectors/nodered/runtime');
const source = fs.readFileSync(process.argv[2], 'utf8');
function hooks() {
    const module = { exports:{} };
    vm.runInNewContext(source, {module, exports:module.exports, require() { return {debug(){}}; }, Error, Promise});
    return module.exports;
}
const config = {inbound:['in'], requests:['request'], maxPending:1, maxEvents:2, maxBytes:256, ttlMs:30};
for (const action of ['add', 'remove', 'clear', 'replacement']) {
    const h = hooks(), a = install(h, config);
    if (action === 'add') h.add('onReceive.other', (_e, done) => done());
    if (action === 'remove') h.remove('onReceive.apicontour');
    if (action === 'clear') h.clear();
    if (action === 'replacement') h.trigger = h.trigger;
    assert.equal(a.snapshot().registryIntact, false);
    assert(a.snapshot().loss > 0);
}
{
    const h = hooks(), a = install(h, config);
    const event = {source:{id:'in'}, destination:{id:'request'}, msg:{req:{headers:{}}}};
    h.trigger('onSend', [event], () => h.trigger('preDeliver', event, () => {}));
    assert.equal(a.snapshot().pending, 1);
    h.add('onReceive.other', (_e, done) => done());
    assert.equal(a.snapshot().pending, 0);
    assert.equal(a.snapshot().registryIntact, false);
    assert(a.snapshot().loss >= 2);
    let forwarded = false;
    h.trigger('onReceive', event, () => { forwarded = true; });
    assert(forwarded);
}
{
    const h = hooks(); Object.defineProperty(h, 'add', { configurable:false });
    const a = install(h, config);
    assert.equal(a.snapshot().registryIntact, false);
    let forwarded = false; h.trigger('onReceive', {}, () => { forwarded = true; });
    assert(forwarded);
}
{
    const h = hooks(); h.add('onReceive.existing', (_e, done) => done());
    const a = install(h, config);
    assert.equal(a.snapshot().registryIntact, false);
}
{
    const h = hooks(), a = install(h, config);
    const event = {source:{id:'in'}, destination:{id:'request'}, msg:{req:{headers:{}}}};
    h.trigger('onSend', [event], () => {
        h.trigger('preDeliver', event, () => {});
        h.trigger('preDeliver', event, () => {});
    });
    const before = a.snapshot();
    assert(before.loss > 0);
    assert.equal(before.pending, 1);
    setTimeout(() => {
        const after = a.snapshot();
        assert.equal(after.pending, 0);
        assert(after.loss > before.loss);
        process.stdout.write('PASS: mutation, existing hooks, overload and expiry fail closed\n');
    }, 60);
}
