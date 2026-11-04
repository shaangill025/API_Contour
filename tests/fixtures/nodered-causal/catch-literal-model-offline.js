'use strict';
// Executable control-plane model only. It does not transform or run Node-RED.
const assert = require('node:assert/strict');
const build = Function(`
  // Functions below deliberately retain sloppy public literal semantics.
  let pending;
  const events = [];
  let loss = 0;
  const apply = Reflect.apply;
  function take(kind, target) {
    const p = pending; pending = undefined;
    return p && p.kind === kind && p.target === target ? p.cap : undefined;
  }
  function handoff(kind, target, fn, args, cap) {
    'use strict';
    if (pending) throw Error('nested handoff');
    pending = {kind, target, cap};
    try { return apply(fn, target, args); } finally { pending = undefined; }
  }
  function method(target, name, expected) {
    const descriptor = Object.getOwnPropertyDescriptor(target, name) ||
      Object.getOwnPropertyDescriptor(Object.getPrototypeOf(target), name);
    return descriptor && 'value' in descriptor && descriptor.value === expected;
  }
  const node = {
    receive(msg) {
      const cap = take('receive', this);
      if (!msg) msg = {};
      if (!msg._msgid) msg._msgid = 'generated';
      const fn = this.emit;
      if (cap && method(this, 'emit', stockEmit) && fn === stockEmit)
        return handoff('emit', this, fn, ['input', msg], cap);
      if (cap) loss++;
      return apply(fn, this, ['input', msg]);
    },
    emit(event, ...args) {
      const cap = take('emit', this);
      if (event === 'input') {
        const fn = this._emitInput;
        if (cap && method(this, '_emitInput', stockInput) && fn === stockInput)
          return handoff('input', this, fn, args, cap);
        if (cap) loss++;
        return apply(fn, this, args);
      }
    },
    _emitInput(msg) {
      const cap = take('input', this);
      this.metric(msg);
      const event = {msg, destination:{node:this}};
      // In the real design the first guarded adapter hook consumes the one-use
      // event binding synchronously; no user callback runs while it is armed.
      if (cap) events.push({kind:'owned', root:cap.root, event});
      else { loss++; events.push({kind:'unowned', event}); }
      this.input(msg);
    },
    metric() {}, input() {}
  };
  const stockReceive = node.receive, stockEmit = node.emit, stockInput = node._emitInput;
  function dispatch(target, msg, cap) {
    const fn = target.receive;
    if (cap && method(target, 'receive', stockReceive) && fn === stockReceive)
      return handoff('receive', target, fn, [msg], cap);
    if (cap) loss++;
    return apply(fn, target, [msg]);
  }
  return {node, dispatch, events, getLoss:()=>loss, stockReceive};
`);
const model = build();
const root = Object.freeze({root:'root-a'});
let seenCaller;
const msg = {};
const getter = Function('model', 'setCaller', `return function() {
  setCaller(arguments.callee.caller);
  model.node._emitInput({});
  model.node.receive({_msgid:'nested'});
  return 'existing';
}`)(model, value => {seenCaller = value;});
Object.defineProperty(msg, '_msgid', {get:getter});
model.dispatch(model.node, msg, root);
assert.equal(seenCaller, model.stockReceive);
assert.deepEqual(model.events.map(e => e.kind), ['unowned', 'unowned', 'owned']);
assert.equal(model.events[2].root, 'root-a');
assert(model.getLoss() >= 2);
const before = model.events.length;
let forwarded = false;
const orig = model.node.emit;
model.node.emit = function(...args) { forwarded = true; return orig.apply(this, args); };
model.dispatch(model.node, {_msgid:'x'}, {root:'root-b'});
assert(forwarded);
assert.deepEqual(model.events.slice(before).map(e => e.kind), ['unowned']);
process.stdout.write('PASS: literal-handoff model rejects reentry and forwards mutation without ownership\n');
