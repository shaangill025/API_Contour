'use strict';
// Run against the unmodified 5.0.9 dispatcher, with its logger replaced by a stub.
// This demonstrates an observation that the public API cannot distinguish.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { AsyncLocalStorage, AsyncResource } = require('node:async_hooks');

const source = fs.readFileSync(process.argv[2], 'utf8');
function dispatcher() {
    const module = { exports: {} };
    vm.runInNewContext(source, {
        module, exports: module.exports,
        require(name) {
            assert.equal(name, './log.js');
            return { debug() {} };
        },
        Error, Promise,
    }, { filename: 'hooks.js' });
    return module.exports;
}
function scenario(laterHook) {
    const hooks = dispatcher();
    const context = new AsyncLocalStorage();
    hooks.add('onReceive.contour', function (_event, done) {
        context.run('intended-owner', done);
    });
    if (laterHook) {
        // A resource created while another delivery is active captures its context.
        // The later hook has no access to the adapter's private store.
        const resource = context.run('other-owner', () => new AsyncResource('independent-hook'));
        hooks.add('onReceive.later', function (_event, done) {
            resource.runInAsyncScope(done);
        });
    }
    // An adapter can inspect its own label, but cannot discover arbitrary labels.
    const visible = [hooks.has('onReceive'), hooks.has('onReceive.contour')];
    let observed;
    hooks.trigger('onReceive', {}, function () { observed = context.getStore(); });
    return { visible, observed };
}
const sole = scenario(false);
const later = scenario(true);
assert.deepEqual(sole.visible, later.visible);
assert.equal(sole.observed, 'intended-owner');
assert.equal(later.observed, 'other-owner');
process.stdout.write('PASS: public hook observations match while continuation ownership differs\n');
