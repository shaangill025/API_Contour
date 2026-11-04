'use strict';
// Review-only counterexample: entry consumption plus a per-receive async frame
// is insufficient if a message getter directly invokes _emitInput in that frame.
const assert = require('node:assert/strict');
const { AsyncLocalStorage } = require('node:async_hooks');
const storage = new AsyncLocalStorage();
let capability;
const seen = [];
function emitInput(node, msg) {
    const frame = storage.getStore();
    if (frame && frame.token && !frame.used && frame.target === node) {
        frame.used = true;
        seen.push({owned:true, msg});
    } else seen.push({owned:false, msg});
}
function receive(node, msg) {
    const incoming = capability && capability.target === node ? capability : undefined;
    if (incoming) capability = undefined; // consume before reading msg
    storage.run(incoming ? {...incoming, used:false} : undefined, () => {
        // Pinned Node.receive accesses msg._msgid before emit("input", msg).
        if (!msg._msgid) msg._msgid = 'synthetic';
        emitInput(node, msg);
    });
}
const target = {}, other = {};
const genuine = {};
const injected = {};
Object.defineProperty(genuine, '_msgid', { configurable:true, get() {
    emitInput(target, injected); // direct call to public Node._emitInput
    return 'same';
}});
capability = {target, parent:'opaque-parent', token:{}};
receive(other, {});
assert.equal(seen[0].owned, false);
receive(target, genuine);
assert.equal(seen[1].msg, injected);
assert.equal(seen[1].owned, true); // decisive misattribution in this model
assert.equal(seen[2].msg, genuine);
assert.equal(seen[2].owned, false);
assert.equal(capability, undefined);
process.stdout.write('PASS: entry-only capability model exposes reentrant _emitInput theft\n');
