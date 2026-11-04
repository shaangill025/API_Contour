'use strict';
// Execute the exact pinned receive body in its original sloppy mode, then a
// proposed strict private copy. This is not a whole-runtime execution.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const source = fs.readFileSync(process.argv[2]);
assert.equal(crypto.createHash('sha256').update(source).digest('hex'),
    '4931ee2e41d4246d51b42c55bb9d7d020ac84601a9e70dff6e70946c23fdf4be');
const match = source.toString('utf8').match(/Node\.prototype\.receive = function\(msg\) \{[\s\S]*?\n\};/g);
assert.equal(match && match.length, 1);
const statement = match[0];
const make = body => Function('Node', 'redUtil', body);
const stock = {prototype:{}};
make(statement)(stock, {generateId(){return 'generated';}});
const candidate = {prototype:{}};
make(statement.replace('function(msg) {', "function(msg) { 'use strict';"))(candidate, {generateId(){return 'generated';}});
// Function constructor is intentional: the synthetic getter is sloppy like a
// permitted JS getter and can observe its caller without exposing arguments.
// Record while inside receive rather than rereading from emit.
function outcome(receive) {
    const captured = [];
    const observe = Function('stock', 'captured', 'return function getter(){var caller=arguments.callee.caller; captured.push(caller === stock); return "existing";}')(stock.prototype.receive, captured);
    const msg = {}; Object.defineProperty(msg, '_msgid', {get:observe});
    receive.call({emit(){}}, msg);
    return captured;
}
assert.deepEqual(outcome(stock.prototype.receive), [true]);
assert.deepEqual(outcome(candidate.prototype.receive), [false]);
process.stdout.write('PASS: pinned receive getter observes strict private-copy caller change\n');
