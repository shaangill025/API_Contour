'use strict';
// Private capability model; no TLS, SQL, deployment or delivery claim.
const assert=require('node:assert/strict');
const baseApi=require('../../../collectors/nodered/error-integration/private-handoff');
const api=require('../../../collectors/nodered/receiver-integration/private-root-handoff');
const binding=require('../../../docs/specification/fixtures/causal-evidence-v1.json')[0].body;
const tenantId=binding.tenant_id,runtimeId=binding.receiver_runtime_id,epoch=BigInt(binding.receiver_session_epoch);
let time=100,deadline=2100;const authority=()=>({allowed:true,epoch,deadline});
function setup(){const base=baseApi.create({tenantId,runtimeId,epoch,authority,maxBatchEvents:8,maxBatchBytes:4096,queueBytes:8192,queueTtlMs:10000});return api.create({base,authority,tenantId,runtimeId,epoch,queueTtlMs:10000,clock:()=>time});}
function offer(w){const registration=w.producer.prepare(Buffer.from(JSON.stringify(binding)));assert(registration);const ticket=w.producer.offerRoot(registration);assert(ticket);return ticket;}
{
 const w=setup(),ticket=offer(w);assert.equal(w.outbox.peek(),undefined);const b=w.exporter.freeze();assert.equal(w.exporter.ack(b.batchId,'0'.repeat(64),epoch,()=>true),false);assert.equal(w.outbox.peek(),undefined);
 assert.equal(w.exporter.ack(b.batchId,b.sha256,epoch,()=>true),true);deadline=10000;const item=w.outbox.peek();assert.equal(item.deadline,2100);assert.equal(item.fact.value.delivery_handle,binding.delivery_handle);assert.equal(w.outbox.peek().ticket,ticket);assert.equal(w.outbox.cancel(ticket),true);assert.equal(w.outbox.peek(),undefined);assert.equal(w.outbox.drain(ticket),undefined);w.close();
}
{
 time=100;deadline=2100;const w=setup();offer(w);const b=w.exporter.freeze();assert.equal(w.exporter.ack(b.batchId,b.sha256,epoch,()=>true),true);time=2100;deadline=10000;assert.equal(w.outbox.peek(),undefined);w.close();
}
{
 time=100;deadline=2100;const w=setup(),first=offer(w),batch=w.exporter.freeze(),later=offer(w);
 assert.equal(w.exporter.ack(batch.batchId,batch.sha256,epoch,()=>false),false);assert.equal(w.outbox.peek(),undefined);
 assert.equal(w.exporter.ack(batch.batchId,batch.sha256,epoch,()=>true),true);assert.equal(w.outbox.peek().ticket,first);
 assert.equal(w.outbox.cancel(first),true);assert.equal(w.outbox.peek(),undefined);
 const second=w.exporter.freeze();assert.equal(w.exporter.ack(second.batchId,second.sha256,epoch,()=>true),true);assert.equal(w.outbox.peek().ticket,later);w.close();assert.equal(w.outbox.peek(),undefined);
}
{
 time=100;deadline=2100;const w=setup(),ticket=offer(w);assert.equal(w.producer.cancel(ticket),true);const batch=w.exporter.freeze();assert.equal(w.exporter.ack(batch.batchId,batch.sha256,epoch,()=>true),true);assert.equal(w.outbox.peek(),undefined);w.close();
}
console.log('receiver 504 local outbox deadline model passed');
