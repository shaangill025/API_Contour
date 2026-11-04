'use strict';
// Extract and execute public literals from the exact original and transformed
// source. The bridge below is a test model, not the production private runtime.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {transform} = require('../../../collectors/nodered/error-integration/node-source-transform');
const bytes = fs.readFileSync(process.argv[2]);
const transformed = transform(bytes);
assert.throws(() => transform(Buffer.from('unsupported')), /unsupported/);
function literals(data) {
    const s = data.toString();
    return ['receive', 'emit', '_emitInput'].map(name => {
        const pattern = new RegExp('Node\\.prototype\\.' + name + ' = function\\([^\\n]*\\) \\{[\\s\\S]*?\\n\\}' + (name === 'receive' ? ';' : ''));
        const match = s.match(pattern);
        assert(match, name);
        return match[0];
    }).join('\n');
}
function setup(data, instrumented) {
    const Node = {prototype:{}};
    let pending, owned = [], expected;
    const bridge = {
        trustedHook() { return true; },
        apply: Reflect.apply,
        take(kind, target) { const p = pending; pending = undefined; return p && p.kind === kind && p.target === target ? p.cap : undefined; },
        arm(kind, target, method, apply, cap) {
            if (!cap || method !== expected[kind] || (kind === 'input' && apply !== Function.prototype.apply)) return undefined;
            assert.equal(pending, undefined);
            return pending = {kind, target, cap};
        },
        finish(arm) { if (pending === arm) pending = undefined; },
        drop() {},
        bind(cap, target, event, invoke) { if (cap) owned.push({cap, target, event}); return invoke(); }
    };
    const hooks = {trigger(_kind, _event, cb) { cb(); }};
    Function('Node', 'redUtil', 'hooks', '__apicontourNodeBridge', literals(data))(Node, {generateId:()=>'id'}, hooks, bridge);
    expected = {receive:Node.prototype.receive, emit:Node.prototype.emit, input:Node.prototype._emitInput};
    const node = Object.create(Node.prototype);
    node.id = 'n'; node.metric = () => {}; node._inputCallback = () => {};
    return {node, expected, owned, dispatch(msg) {
        if (instrumented) pending = {kind:'receive', target:node, cap:'root'};
        try { node.receive(msg); } finally { pending = undefined; }
    }};
}
for (const [data, instrumented] of [[bytes,false], [transformed,true]]) {
    const s = setup(data, instrumented), trace = [];
    const msg = {};
    Object.defineProperty(msg, '_msgid', {get: Function('s','trace', `return function() {
        trace.push(arguments.callee.caller === s.expected.receive);
        s.node._emitInput({}); s.node.receive({_msgid:'nested'}); return 'id';
    }`)(s,trace)});
    s.dispatch(msg);
    assert.deepEqual(trace, [true]);
    assert.equal(s.owned.length, instrumented ? 1 : 0);
    if (instrumented) assert.equal(s.owned[0].cap, 'root');
    const input = s.node._emitInput;
    Object.defineProperty(input, 'apply', {configurable:true, get() {
        trace.push('get'); return function(receiver, args) { trace.push(['override', this === input, receiver === s.node, args[0]._msgid]); };
    }});
    s.dispatch({_msgid:'apply'});
    assert.deepEqual(trace.slice(-2), ['get',['override',true,true,'apply']]);
    delete input.apply;
    let calls = 0;
    s.node.emit = function() { calls++; };
    s.dispatch({_msgid:'changed'});
    assert.equal(calls, 1);
    assert.equal(s.owned.length, instrumented ? 1 : 0);
}
process.stdout.write('PASS: exact-source public literals; reentry, caller, own apply and mutation; bridge is a model\n');
