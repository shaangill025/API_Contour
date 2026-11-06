'use strict';
// Exercise the same independently calculated one-to-one fixture assertion.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'image-wire-v2-fixture.js'),'utf8');
const start=source.indexOf('function assertAttempts('),end=source.indexOf('\nasync function composition(',start);
assert(start>=0&&end>start);
const check=vm.runInNewContext(`(${source.slice(start,end)})`,{assert,crypto});
const observed=[{root:'r',activity:'a',attempt:'1',marker:'wire-1'},{root:'r',activity:'b',attempt:'2',marker:'wire-2'}];
const event=a=>({kind:'attempt',root:a.root,activity:a.activity,attempt:a.attempt,marker_digest:crypto.createHash('sha256').update('apicontour/causal-marker-wire/1\n').update(a.marker).digest('hex')});
const events=observed.map(event);check(events,observed);
assert.throws(()=>check([events[0]],observed));
assert.throws(()=>check([events[0],events[0]],observed));
assert.throws(()=>check([{...events[0],marker_digest:'0'.repeat(64)},events[1]],observed));
assert.throws(()=>check([{...events[0],root:'wrong'},events[1]],observed));
process.stdout.write('PASS: composition marker digest and exact attempt matching\n');
