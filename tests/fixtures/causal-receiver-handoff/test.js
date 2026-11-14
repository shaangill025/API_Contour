'use strict';
const assert=require('node:assert/strict');
const fixture=require('../../../docs/specification/fixtures/causal-evidence-v1.json');
const baseApi=require('../../../collectors/nodered/error-integration/private-handoff');
const api=require('../../../collectors/nodered/receiver-integration/private-root-handoff');
const binding=fixture[0].body, wire=()=>Buffer.from(JSON.stringify(binding));
const tenantId=binding.tenant_id,runtimeId=binding.receiver_runtime_id,epoch=BigInt(binding.receiver_session_epoch);
let t=0;const authority=()=>({allowed:true,epoch,deadline:1e9});
function setup(options={}){
 const base=baseApi.create({tenantId,runtimeId,epoch,authority,maxBatchEvents:options.maxBatchEvents||8,maxBatchBytes:4096,queueBytes:8192,queueTtlMs:10000});
 return {base,wrap:api.create({base,authority,tenantId,runtimeId,epoch,queueTtlMs:10000,clock:()=>t})};
}
const a='a'.repeat(32),b='b'.repeat(32);
function offer(w){const r=w.producer.prepare(wire());assert.ok(r);const root=w.producer.root(r);const ticket=w.producer.offerRoot(r);return {r,root,ticket};}
{
 const {wrap}=setup();const one=offer(wrap),ta=one.ticket;assert.ok(ta&&Object.isFrozen(ta));assert.equal(wrap.outbox.drain(ta),undefined);
 const first=wrap.exporter.freeze();const two=offer(wrap),tb=two.ticket;assert.ok(tb);assert.strictEqual(wrap.exporter.freeze(),first);
 assert.equal(wrap.exporter.ack(first.batchId,'0'.repeat(64),epoch,()=>true),false);assert.equal(wrap.exporter.ack(first.batchId,first.sha256,epoch,()=>false),false);
 assert.equal(wrap.exporter.ack(first.batchId,first.sha256,epoch,()=>true),true);
 const fact=wrap.outbox.drain(ta);assert.equal(fact.value.local_root,one.root);assert.equal(fact.value.binding_digest,fixture[0].sha256);assert.equal(fact.value.delivery_handle,binding.delivery_handle);
 assert.equal(wrap.outbox.drain(ta),undefined);assert.equal(wrap.outbox.drain(tb),undefined);assert.equal(wrap.exporter.ack(first.batchId,first.sha256,epoch,()=>true),false);
 const second=wrap.exporter.freeze();assert.notEqual(second.batchId,first.batchId);assert.equal(wrap.exporter.ack(second.batchId,second.sha256,epoch,()=>true),true);assert.equal(wrap.outbox.drain(tb).value.local_root,two.root);
}
{
 const {wrap}=setup({maxBatchEvents:1});const ta=offer(wrap).ticket;assert.ok(ta);const reg=wrap.producer.prepare(wire());assert.ok(reg);assert.equal(wrap.producer.offerRoot(reg),undefined);
 const batch=wrap.exporter.freeze();assert.equal(wrap.exporter.ack(batch.batchId,batch.sha256,epoch,()=>true),true);assert.ok(wrap.outbox.drain(ta));
}
{
 t=0;const {wrap}=setup();const one=offer(wrap),ta=one.ticket;const f=wrap.exporter.freeze();assert.equal(wrap.producer.cancel(ta),true);assert.equal(wrap.producer.offerRoot(one.r),undefined);
 assert.equal(wrap.exporter.ack(f.batchId,f.sha256,epoch,()=>true),true);assert.equal(wrap.outbox.drain(ta),undefined);
}
{
 t=0;const {wrap}=setup();const ta=offer(wrap).ticket;const f=wrap.exporter.freeze();t=5000;assert.equal(wrap.exporter.ack(f.batchId,f.sha256,epoch,()=>true),true);assert.equal(wrap.outbox.drain(ta),undefined);
}
{
 t=0;const {wrap}=setup();const ta=offer(wrap).ticket;const f=wrap.exporter.freeze();assert.equal(wrap.exporter.ack(f.batchId,f.sha256,epoch,()=>{assert.equal(wrap.producer.cancel(ta),false);return true;}),true);assert.ok(wrap.outbox.drain(ta));wrap.close();assert.equal(wrap.producer.offerRoot(b),undefined);
}
console.log('private receiver root handoff: passed');
{
 t=0;const crypto=require('node:crypto'),path=require.resolve('../../../collectors/nodered/receiver-integration/private-root-handoff'),original=crypto.randomBytes;
 try {
  crypto.randomBytes=n=>Buffer.alloc(n,7);delete require.cache[path];const controlled=require(path);
  const base=baseApi.create({tenantId,runtimeId,epoch,authority,maxBatchEvents:8,maxBatchBytes:4096,queueBytes:8192,queueTtlMs:10000});
  const wrap=controlled.create({base,authority,tenantId,runtimeId,epoch,queueTtlMs:10000,clock:()=>t});
  const reg=wrap.producer.prepare(wire()),ticket=wrap.producer.offerRoot(reg),batch=wrap.exporter.freeze();
  assert.equal(wrap.exporter.ack(batch.batchId,batch.sha256,epoch,()=>{t=5000;return true;}),true);
  assert.equal(wrap.outbox.drain(ticket),undefined);
  assert.ok(wrap.producer.prepare(wire()),'expired acknowledged root and capacity must be reclaimed');
 } finally {crypto.randomBytes=original;delete require.cache[path];}
}
(async()=>{
 const https=require('node:https'),{EventEmitter}=require('node:events');const original=https.request;
 const exporterApi=require('../../../collectors/nodered/error-integration/private-causal-exporter');
 try {
  for(const mode of ['accepted','duplicate','wrong','unknown']){
   t=0;const {wrap}=setup();const ticket=offer(wrap).ticket;
   https.request=(_options,callback)=>{
    const request=new EventEmitter();request.destroy=()=>{};request.end=body=>{
     if(mode==='unknown'){queueMicrotask(()=>request.emit('error',new Error('lost')));return;}
     const f=wrap.exporter.freeze();const receipt={batch_id:f.batchId,runtime_id:runtimeId,session_epoch:epoch.toString(),batch_digest:mode==='wrong'?'0'.repeat(64):f.sha256,receipt_id:'123e4567-e89b-12d3-a456-426614174000',accepted_at:'2026-11-12T00:00:00Z',status:mode};
     // SQL20 receipt epoch is a JSON integer, not a JS Number.
     const raw=JSON.stringify(receipt).replace('"'+epoch.toString()+'"',epoch.toString());
     queueMicrotask(()=>{const response=new EventEmitter();response.statusCode=200;response.socket={authorized:true};response.destroy=()=>{};callback(response);response.emit('data',Buffer.from(raw));response.emit('end');});
    };return request;
   };
   const exporter=exporterApi.create({endpoint:'https://example.test/v1/causal-events',ca:Buffer.from('x'),cert:Buffer.from('x'),key:Buffer.from('x'),runtimeId,epoch,handoff:wrap.exporter,timeoutMs:1000,maxBodyBytes:4096});
   const sent=await exporter.sendOnce();assert.equal(sent,mode==='accepted'||mode==='duplicate');assert.equal(Boolean(wrap.outbox.drain(ticket)),sent);exporter.close();wrap.close();
  }
 } finally {https.request=original;}
 console.log('private receiver exporter receipt: passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
{
 t=0;const {wrap}=setup();const wrong={...binding,receiver_runtime_id:'123e4567-e89b-12d3-a456-426614174001'};
 assert.equal(wrap.producer.prepare(Buffer.from(JSON.stringify(wrong))),undefined);
 assert.equal(wrap.producer.prepare(Buffer.from('{}')),undefined);
}
{
 t=0;const {wrap}=setup();const ticket=offer(wrap).ticket,batch=wrap.exporter.freeze();
 assert.equal(wrap.exporter.ack(batch.batchId,batch.sha256,epoch,()=>{t=5000;return true;}),true);
 assert.equal(wrap.outbox.drain(ticket),undefined);
}
{
 t=0;let wrap,attempted=false;const base=baseApi.create({tenantId,runtimeId,epoch,authority,maxBatchEvents:2,maxBatchBytes:4096,queueBytes:8192,queueTtlMs:10000});
 const reentrant=()=>{if(wrap&&!attempted){attempted=true;assert.equal(wrap.producer.offerRoot(b),undefined);}return authority();};
 wrap=api.create({base,authority:reentrant,tenantId,runtimeId,epoch,queueTtlMs:10000,clock:()=>t});assert.ok(offer(wrap).ticket);
}
{
 t=0;const {wrap}=setup();const first=offer(wrap);assert.equal(wrap.producer.offerRoot(first.r),undefined);assert.equal(wrap.producer.offerRoot({}),undefined);assert.equal(wrap.producer.offerRoot(first.root),undefined);
 const batch=wrap.exporter.freeze();assert.equal(wrap.exporter.ack(batch.batchId,batch.sha256,epoch,()=>true),true);
 const different={...binding,delivery_handle:'9'.repeat(32)},reg=wrap.producer.prepare(Buffer.from(JSON.stringify(different)));
 assert.ok(reg);assert.notEqual(wrap.producer.root(reg),first.root);assert.equal(wrap.producer.offerRoot(first.r),undefined);
 const ticket=wrap.producer.offerRoot(reg);assert.ok(ticket);assert.equal(wrap.outbox.drain(first.ticket).value.local_root,first.root);
 const batch2=wrap.exporter.freeze();assert.equal(wrap.exporter.ack(batch2.batchId,batch2.sha256,epoch,()=>true),true);assert.notEqual(wrap.outbox.drain(ticket).value.local_root,first.root);
 assert.equal(wrap.producer.root(first.r),undefined);assert.equal(wrap.producer.offerRoot(first.r),undefined);
}
{
 t=0;const crypto=require('node:crypto'),path=require.resolve('../../../collectors/nodered/receiver-integration/private-root-handoff'),original=crypto.randomBytes;let calls=0;
 try {
  crypto.randomBytes=n=>{calls++;return Buffer.alloc(n);};delete require.cache[path];const controlled=require(path);
  const base=baseApi.create({tenantId,runtimeId,epoch,authority,maxBatchEvents:8,maxBatchBytes:4096,queueBytes:8192,queueTtlMs:10000});
  const wrap=controlled.create({base,authority,tenantId,runtimeId,epoch,queueTtlMs:10000,clock:()=>t});assert.ok(wrap.producer.prepare(wire()));assert.equal(wrap.producer.prepare(wire()),undefined);assert.equal(calls,5);
 } finally {crypto.randomBytes=original;delete require.cache[path];}
}
