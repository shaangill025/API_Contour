'use strict';
// New producer runtime + handoff with a hook model. No loader, verifier or transport.
const assert=require('node:assert/strict'),{performance}=require('node:perf_hooks');
const fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto');
const {install}=require('./private-producer-runtime'),{create}=require('./private-handoff');
const tenant='123e4567-e89b-12d3-a456-426614174001',runtime='123e4567-e89b-12d3-a456-426614174002';
function newHooks() {
    if(process.argv[2]) {
        const bytes=fs.readFileSync(process.argv[2]);
        assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),'e7d1e0496b5399458de55bc9b8ea59e6741869db33cdced0f03ec798c6fa6fcf');
        const mod={exports:{}};vm.runInNewContext(bytes.toString(),{module:mod,exports:mod.exports,require(){return {debug(){}}},Error,Promise});return mod.exports;
    }
    const callbacks={};return {add(k,f){callbacks[k.split('.')[0]]=f;},remove(){},clear(){},has(k){return !!callbacks[k.split('.')[0]];},trigger(k,e,done){const f=callbacks[k];if(f)f(e,done);else done();}};
}
function setup(options={}) {
    let state={allowed:true,epoch:1n,deadline:performance.now()+10000}, control;
    const handoff=create({tenantId:tenant,runtimeId:runtime,epoch:1n,authority:()=>state,maxBatchEvents:2,maxBatchBytes:2048,queueBytes:4096,queueTtlMs:10000,...options});
    const hooks=newHooks();
    const adapter=install(hooks,{inbound:['in'],requests:['worker'],maxPending:8,maxEvents:128,maxBytes:16384,ttlMs:1000,ingressPoint:{node:'in',method:'POST',url:'/run'}},c=>{control=c;c.attachProducer(handoff);});
    const send=(msg,next=()=>{})=>hooks.trigger('onSend',[{source:{id:'in'},msg}],next);
    const good=()=>({req:{method:'POST',url:'/run',headers:{}}});
    function deliver(target,done=()=>{}) {const e={destination:{node:target,id:'worker'}};hooks.trigger('preDeliver',e,()=>{const f=control.claimDelivery(e);control.bind(f,target,e,()=>hooks.trigger('onReceive',e,done));});}
    return {handoff,hooks,adapter,control,send,good,deliver,setState(v){state=v;}};
}
{
    const hooks=newHooks();const authority=()=>({allowed:true,epoch:1n,deadline:performance.now()+10000});
    const handoff=create({tenantId:tenant,runtimeId:runtime,epoch:1n,authority,maxBatchEvents:1,maxBatchBytes:512,queueBytes:1024,queueTtlMs:1000});
    const adapter=install(hooks,{inbound:['in'],requests:[],maxPending:8,maxEvents:8,maxBytes:8192,ttlMs:1000},c=>c.attachProducer(handoff));
    assert.equal(adapter.snapshot().registryIntact,false,'producer must not attach to unscoped mode');
}
{
    const t=setup();let reads=0,forwarded=false;
    t.setState({allowed:false,epoch:1n,deadline:performance.now()+10000});
    const batch=new Proxy([], {get(){reads++;throw Error('read');},getOwnPropertyDescriptor(){reads++;throw Error('descriptor');}});
    t.hooks.trigger('onSend',batch,()=>forwarded=true);
    assert(forwarded);assert.equal(reads,0);assert.equal(t.adapter.snapshot().registryIntact,false);assert.equal(t.handoff.freeze(),undefined);
}
{
    const t=setup();let headersRead=0,rawRead=0,forwarded=false;
    const req={method:'POST',url:'/run'};
    Object.defineProperty(req,'rawHeaders',{get(){rawRead++;t.setState({allowed:false,epoch:1n,deadline:performance.now()+10000});return undefined;}});
    Object.defineProperty(req,'headers',{get(){headersRead++;return {};}});
    t.send({req},()=>forwarded=true);
    assert(forwarded);assert.equal(rawRead,0);assert.equal(headersRead,0);assert(t.adapter.snapshot().loss>0);
}
{
    const t=setup();let delivered=false;
    t.send(t.good(),()=>t.deliver({},()=>delivered=true));assert(delivered);
    const batch=t.handoff.freeze();assert(batch);assert(Object.isFrozen(batch));
    const doc=JSON.parse(batch.canonical);assert.deepEqual(doc.events.map(e=>e.kind),['root','delivery']);
    assert.deepEqual(t.adapter.snapshot().events,[],'producer mode snapshot is diagnostic-only');
    assert(!doc.events.some(e=>e.kind==='attempt'));
    assert.throws(()=>{batch.canonical='modified';});assert.strictEqual(t.handoff.freeze(),batch);
    assert(!t.handoff.ack(batch.batchId,batch.sha256,2n));
    assert(!t.handoff.ack(batch.batchId,'0'.repeat(64),1n));assert.strictEqual(t.handoff.freeze(),batch);
    assert(t.handoff.ack(batch.batchId,batch.sha256,1n));assert.equal(t.handoff.freeze(),undefined);
    assert.throws(()=>t.control.attachProducer(t.handoff));
}
{
    const t=setup();t.send({req:{method:'POST',url:'/run?x=1',headers:{}}});assert.equal(t.handoff.freeze(),undefined);
    t.send(t.good());t.send(t.good());t.send(t.good());t.send(t.good());
    assert(t.adapter.snapshot().loss>=2,'overflow appears in diagnostics');
    const first=t.handoff.freeze();const a=JSON.parse(first.canonical);assert.deepEqual(a.events.map(e=>e.seq),[1,2]);
    assert(t.handoff.ack(first.batchId,first.sha256,1n));
    const loss=t.handoff.freeze(),b=JSON.parse(loss.canonical);assert.equal(b.events.length,1);assert.equal(b.events[0].kind,'loss');
    assert.deepEqual([b.events[0].first_missing_seq,b.events[0].last_missing_seq,b.events[0].seq],[3,4,5]);
    assert(t.handoff.ack(loss.batchId,loss.sha256,1n));assert.equal(t.handoff.freeze(),undefined);
}
{
    const t=setup();t.send(t.good());let reads=0, continued=0;
    const opaque=new Proxy({}, {get(){reads++;throw Error('get');},getOwnPropertyDescriptor(){reads++;throw Error('descriptor');}});
    t.setState({allowed:false,epoch:1n,deadline:performance.now()+10000});
    t.hooks.trigger('preDeliver',opaque,()=>continued++);t.hooks.trigger('onReceive',opaque,()=>continued++);
    assert.equal(t.control.capture(opaque),undefined);assert.equal(t.control.claimDelivery(opaque),undefined);
    t.control.bind(undefined,{},opaque,()=>continued++);
    assert.equal(continued,3);assert.equal(reads,0);assert.equal(t.handoff.freeze(),undefined);
}
{
    const t=setup();const frame={kind:'ROOT_INTENT',root:'a'.repeat(32)};
    assert(t.handoff.offer(frame));frame.root='b'.repeat(32);
    assert.equal(JSON.parse(t.handoff.freeze().canonical).events[0].root,'a'.repeat(32));
}
{
    const t=setup({maxBatchEvents:3});t.send(t.good());const frozen=t.handoff.freeze();
    t.send(t.good());assert.strictEqual(t.handoff.freeze(),frozen);
    assert(t.handoff.ack(frozen.batchId,frozen.sha256,1n));
    const next=t.handoff.freeze();assert.deepEqual(JSON.parse(next.canonical).events.map(x=>x.seq),[2]);
    assert(!t.handoff.ack(frozen.batchId,frozen.sha256,1n));assert(t.handoff.ack(next.batchId,next.sha256,1n));
}
{
    const t=setup({maxBatchEvents:100,maxBatchBytes:512,queueBytes:1024});
    for(let i=0;i<10;i++)t.send(t.good());
    const first=t.handoff.freeze(), body=JSON.parse(first.canonical), count=body.events.length;
    assert(count>0 && count<10);assert(Buffer.byteLength(first.canonical)<=512);
    assert(t.handoff.ack(first.batchId,first.sha256,1n));
    const second=t.handoff.freeze(), item=JSON.parse(second.canonical).events[0];
    assert.equal(item.kind,'loss');assert.equal(item.first_missing_seq,count+1);assert.equal(item.last_missing_seq,10);assert.equal(item.seq,11);
}
{
    const t=setup();t.send(t.good());const batch=t.handoff.freeze();
    t.setState({allowed:true,epoch:2n,deadline:performance.now()+10000});assert.equal(t.handoff.freeze(),undefined);assert(!t.handoff.ack(batch.batchId,batch.sha256,1n));
    assert.equal(t.handoff.gate(),false);
}
{
    const t=setup();t.send(t.good());t.hooks.add('onReceive.mutation',()=>{});assert.equal(t.adapter.snapshot().registryIntact,false);assert.equal(t.handoff.freeze(),undefined);
}
{
    const t=setup({initialSequence:(1n<<64n)-1n});t.send(t.good());const last=t.handoff.freeze();assert(last.canonical.includes('18446744073709551615'));
    t.send(t.good());assert.strictEqual(t.handoff.freeze(),last);
    assert(t.handoff.ack(last.batchId,last.sha256,1n));
}
{
    const t=setup();t.setState({allowed:true,epoch:1n,deadline:performance.now()-1});let read=0;
    const msg={};Object.defineProperty(msg,'req',{get(){read++;throw Error();}});t.send(msg);assert.equal(read,0);assert.equal(t.handoff.freeze(),undefined);
}
process.stdout.write('PASS: new producer runtime and dormant handoff; '+(process.argv[2]?'pinned hooks':'hook model')+'\n');
