'use strict';
const assert=require('node:assert/strict');
const vectors=require('../../../docs/specification/fixtures/causal-evidence-v1.json');
const codec=require('../../../collectors/nodered/causal-evidence-codec.js');
for(const v of vectors){const result=codec.decode(v.kind,Buffer.from(JSON.stringify(v.body)));assert.equal(result.canonical,v.canonical);assert.equal(result.sha256,v.sha256);}
const wire=v=>JSON.stringify(v.body), binding=wire(vectors[0]), observer=wire(vectors[1]), receiver=wire(vectors[2]);
for(const bad of [binding.replace('"retry_of":null','"retry_of":null,"retry_of":null'),binding.replace(',"retry_of":null',''),binding.replace('9007199254740993','09007199254740993'),binding.replace('18446744073709551615','18446744073709551616'),binding.replace('123e4567','123E4567'),binding.replace('"wire_version":1','"wire_version":1.0')]) assert.throws(()=>codec.decode('binding',Buffer.from(bad)));
for(const bad of [observer.replace('"retry_of":null','"retry_of":null,"retry_of":null'),observer.replace('"binding":{','"binding":{'+' '.repeat(2049)),observer.replace('ac1.fixture.signature','ac1.é'),observer.replace('"batch_id":','"extra":1,"batch_id":')]) assert.throws(()=>codec.decode('observer',Buffer.from(bad)));
for(const bad of [receiver.replace('"wire_version":1','"wire_version":true'),receiver.replace('18446744073709551615','0'),receiver.replace('"local_root":','"extra":1,"local_root":')]) assert.throws(()=>codec.decode('receiver',Buffer.from(bad)));
assert.throws(()=>codec.decode('binding',Buffer.alloc(2049,32)));
assert.throws(()=>codec.decode('observer',Buffer.alloc(4097,32)));
assert.throws(()=>codec.decode('receiver',Buffer.from([0xff])));
console.log('causal evidence codec offline: passed');
// Escaped duplicate names must be rejected after JSON string decoding.
assert.throws(()=>codec.decode('binding',Buffer.from(binding.replace('"retry_of":null','"retry_of":null,"retry_\\u006ff":null'))));
assert.throws(()=>codec.decode('binding',Buffer.from(binding.replace('9007199254740993','9007199254740993\\n'))));
assert.throws(()=>codec.decode('observer',Buffer.from(observer.replace('ac1.fixture.signature','ac1.fixture.signature\\n'))));
assert.throws(()=>codec.decode('binding',Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),Buffer.from(binding)])));
assert.throws(()=>codec.decode('binding',Buffer.from(binding.replace('"retry_of":null','"retry_of":{}'))));
assert.throws(()=>codec.decode('receiver',Buffer.from(receiver.replace('"wire_version":1','"wire_version":1,"wire_version":1'))));
assert.throws(()=>codec.decode('observer',Buffer.from(observer.replace('"binding":{','"binding":{'+' '.repeat(2049)))));
const retry=JSON.parse(binding);retry.retry_of='a'.repeat(32);
assert.equal(codec.decode('binding',Buffer.from(JSON.stringify(retry))).value.retry_of,retry.retry_of);
const exactBinding=' '.repeat(2048-Buffer.byteLength(binding))+binding;
assert.equal(codec.decode('binding',Buffer.from(exactBinding)).sha256,vectors[0].sha256);
assert.throws(()=>codec.decode('binding',Buffer.from(' '+exactBinding)));
const rawNested=JSON.stringify(vectors[1].body.binding);
const paddedObserver=observer.replace(rawNested,'{'+' '.repeat(2048-Buffer.byteLength(rawNested))+rawNested.slice(1));
assert.equal(codec.decode('observer',Buffer.from(paddedObserver)).sha256,vectors[1].sha256);
assert.throws(()=>codec.decode('observer',Buffer.from(paddedObserver.replace('"binding":{','"binding":{ '))));
for(const field of Object.keys(vectors[2].body)){const missing={...vectors[2].body};delete missing[field];assert.throws(()=>codec.decode('receiver',Buffer.from(JSON.stringify(missing))));}
for(const field of Object.keys(vectors[0].body)){const missing={...vectors[0].body};delete missing[field];assert.throws(()=>codec.decode('binding',Buffer.from(JSON.stringify(missing))));}
// Caller-controlled properties must never set or weaken actual byte bounds.
const oversized=Buffer.from(binding+' '.repeat(3000));Object.defineProperty(oversized,'byteLength',{value:1});
assert.throws(()=>codec.decode('binding',oversized));
let getterCalls=0;
class Forged extends Uint8Array { get byteLength(){getterCalls++;return 1;} }
const forged=new Forged(Buffer.from(binding+' '.repeat(3000)));
assert.throws(()=>codec.decode('binding',forged));assert.equal(getterCalls,0);
assert.throws(()=>codec.decode('binding',new Proxy(Buffer.from(binding),{})));
const wrapped=Buffer.from('junk'+binding+'tail');
assert.equal(codec.decode('binding',wrapped.subarray(4,4+Buffer.byteLength(binding))).sha256,vectors[0].sha256);
const shared=new Uint8Array(new SharedArrayBuffer(Buffer.byteLength(binding)));shared.set(Buffer.from(binding));
assert.throws(()=>codec.decode('binding',shared));
const growable=new ArrayBuffer(2048,{maxByteLength:4096});
assert.throws(()=>codec.decode('binding',new Uint8Array(growable)));
const decoded=codec.decode('observer',Buffer.from(observer));
assert.ok(Object.isFrozen(decoded)&&Object.isFrozen(decoded.value)&&Object.isFrozen(decoded.value.binding));
assert.throws(()=>{decoded.value.binding.retry_of='a'.repeat(32);});
const ownGetter=Buffer.from(binding+' '.repeat(3000));Object.defineProperty(ownGetter,'byteLength',{get(){getterCalls++;return 1;}});
assert.throws(()=>codec.decode('binding',ownGetter));assert.equal(getterCalls,0);
const validGetter=new Forged(Buffer.from(binding));assert.equal(codec.decode('binding',validGetter).sha256,vectors[0].sha256);assert.equal(getterCalls,0);
const exactEvidence=Buffer.from(' '.repeat(4096-Buffer.byteLength(receiver))+receiver);
assert.equal(codec.decode('receiver',exactEvidence).sha256,vectors[2].sha256);
assert.throws(()=>codec.decode('receiver',Buffer.concat([Buffer.from(' '),exactEvidence])));
