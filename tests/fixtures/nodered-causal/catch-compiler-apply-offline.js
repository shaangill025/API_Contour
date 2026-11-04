'use strict';
// Execute the exact pinned stock emit literal. This is a source-execution
// regression, not an integrated compiler or Node-RED runtime qualification.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const bytes = fs.readFileSync(process.argv[2]);
assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),
    '4931ee2e41d4246d51b42c55bb9d7d020ac84601a9e70dff6e70946c23fdf4be');
const literals = bytes.toString('utf8').match(/Node\.prototype\.emit = function\(event, \.\.\.args\) \{[\s\S]*?\n\}/g);
assert.equal(literals && literals.length, 1);
const Node = {prototype:{}};
Function('Node', literals[0])(Node);
const observed = [];
const input = function() { observed.push('input'); };
Object.defineProperty(input, 'apply', {get() {
    observed.push('apply-get');
    return function(receiver, args) {
        observed.push(['custom-apply', this === input, receiver === node, args]);
    };
}});
const node = {_emitInput: input};
Node.prototype.emit.call(node, 'input', 'message');
assert.deepEqual(observed, ['apply-get', ['custom-apply', true, true, ['message']]]);
// A naive qualification that invokes the original function directly drops
// the getter and the application's apply override entirely.
observed.length = 0;
Reflect.apply(input, node, ['message']);
assert.deepEqual(observed, ['input']);
process.stdout.write('PASS: pinned stock emit honors an own apply getter and override; direct invocation changes behavior\n');
