'use strict';
const assert=require('node:assert/strict'),{performance}=require('node:perf_hooks');
const {create}=require('./private-handoff');
const q=create({tenantId:'123e4567-e89b-12d3-a456-426614174001',runtimeId:'123e4567-e89b-12d3-a456-426614174002',epoch:1n,initialSequence:(1n<<64n)-1n,authority:()=>({allowed:true,epoch:1n,deadline:performance.now()+10000}),maxBatchEvents:2,maxBatchBytes:2048,queueBytes:4096,queueTtlMs:10000});
assert(q.offer({kind:'ROOT_INTENT',root:'a'.repeat(32)}));const batch=q.freeze();assert(batch);
assert.equal(q.offer({kind:'ROOT_INTENT',root:'b'.repeat(32)}),false);
assert.strictEqual(q.freeze(),batch,'MAX u64 in-flight batch must remain retryable');
assert(q.ack(batch.batchId,batch.sha256,1n),'MAX u64 batch must remain acknowledgeable');
assert.equal(q.offer({kind:'ROOT_INTENT',root:'c'.repeat(32)}),false);
// A lost final sequence cannot be represented by a later LOSS event; keep the
// pending gap unexported rather than fabricate or resequence it.
const pending=create({tenantId:'123e4567-e89b-12d3-a456-426614174001',runtimeId:'123e4567-e89b-12d3-a456-426614174002',epoch:1n,initialSequence:(1n<<64n)-2n,authority:()=>({allowed:true,epoch:1n,deadline:performance.now()+10000}),maxBatchEvents:1,maxBatchBytes:2048,queueBytes:4096,queueTtlMs:10000});
assert(pending.offer({kind:'ROOT_INTENT',root:'c'.repeat(32)}));
assert.equal(pending.offer({kind:'ROOT_INTENT',root:'d'.repeat(32)}),false);
const preceding=pending.freeze();assert(preceding);assert(pending.ack(preceding.batchId,preceding.sha256,1n));
assert.equal(pending.freeze(),undefined);assert.equal(pending.admit(),false);
let authority={allowed:true,epoch:1n,deadline:performance.now()+10000};
const expiring=create({tenantId:'123e4567-e89b-12d3-a456-426614174001',runtimeId:'123e4567-e89b-12d3-a456-426614174002',epoch:1n,initialSequence:(1n<<64n)-1n,authority:()=>authority,maxBatchEvents:2,maxBatchBytes:2048,queueBytes:4096,queueTtlMs:10000});
assert(expiring.offer({kind:'ROOT_INTENT',root:'e'.repeat(32)}));const expired=expiring.freeze();
authority={allowed:false,epoch:1n,deadline:performance.now()+10000};
assert.equal(expiring.freeze(),undefined);assert.equal(expiring.ack(expired.batchId,expired.sha256,1n),false);
process.stdout.write('PASS: sequence exhaustion retains frozen in-flight batch and never invents final loss\n');
