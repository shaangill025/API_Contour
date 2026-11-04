'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const flow = JSON.parse(fs.readFileSync(path.join(__dirname, 'flows.json'), 'utf8'));
const fanout = flow.find(node => node.id === 'fanout');
const request = flow.find(node => node.id === 'request');
const chain = flow.find(node => node.id === 'chain');
assert.deepEqual(request.wires, [['chain']]);
assert.deepEqual(chain.wires, [['request']]);
assert.equal(request.senderr, true);
assert.deepEqual(request.headers, []);
const begin = new Function('msg', 'node', 'setTimeout', fanout.func);
const next = new Function('msg', chain.func);
for (const [label, status] of [['serial', 200], ['retry', 503]]) {
    const timers = [], sends = [];
    const msg = { payload:label };
    const response = begin(msg, {send: value => sends.push(value)}, (fn, delay) => timers.push({fn, delay}));
    assert.strictEqual(response[2], msg);
    assert.equal(timers.length, 1);
    timers[0].fn();
    assert.strictEqual(sends[0][0], msg);
    assert.equal(msg.payload, label + ':1');
    const headers = {'x-node-red-request-node':'synthetic-hash', 'content-type':'text/plain'};
    msg.headers = headers;
    msg.statusCode = status;
    assert.strictEqual(next(msg), msg);
    assert.equal(msg.payload, label + ':2');
    assert.strictEqual(msg.headers, headers);
    assert.equal(next(msg), null);
}
for (const [label, status] of [['serial', 503], ['retry', 200]]) {
    assert.equal(next({fixtureLabel:label, fixtureStep:1, statusCode:status}), null);
}
for (const label of ['first', 'second', 'third']) {
    const timers = [], sends = [];
    const msg = { payload:label };
    begin(msg, {send: value => sends.push(value)}, (fn, delay) => timers.push({fn, delay}));
    timers[0].fn();
    assert.strictEqual(sends[0][0], msg);
    assert.strictEqual(sends[0][1], msg);
}
process.stdout.write('PASS: fixed flow branches, serial continuation, explicit retry and header preservation\n');
