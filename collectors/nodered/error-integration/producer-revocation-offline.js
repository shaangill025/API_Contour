'use strict';
// Actual new runtime with a hook model; no loader or verified authority.
const assert=require('node:assert/strict'),{performance}=require('node:perf_hooks');
const {install}=require('./private-producer-runtime'),{create}=require('./private-handoff');
const which=process.argv[2];let state={allowed:true,epoch:1n,deadline:performance.now()+10000},control,reads=0,forwarded=0;
const callbacks={};const hooks={add(k,f){callbacks[k.split('.')[0]]=f;},remove(){},clear(){},has(k){return !!callbacks[k.split('.')[0]];},trigger(k,e,done){const f=callbacks[k];if(f)f(e,done);else done();}};
const handoff=create({tenantId:'123e4567-e89b-12d3-a456-426614174001',runtimeId:'123e4567-e89b-12d3-a456-426614174002',epoch:1n,authority:()=>state,maxBatchEvents:4,maxBatchBytes:2048,queueBytes:4096,queueTtlMs:10000});
const adapter=install(hooks,{inbound:['in'],requests:[],maxPending:8,maxEvents:16,maxBytes:8192,ttlMs:1000,ingressPoint:{node:'in',method:'POST',url:'/run'}},c=>{control=c;if(which!=='no-attach')c.attachProducer(handoff);});
function revoke(){state={allowed:false,epoch:1n,deadline:performance.now()+10000};}
function good(){return {req:{method:'POST',url:'/run',headers:{}}};}
function root(next){hooks.trigger('onSend',[{source:{id:'in'},msg:good()}],next);}
function dest(target){return new Proxy({node:target},{getOwnPropertyDescriptor(t,k){reads++;return Reflect.getOwnPropertyDescriptor(t,k);}});}
function trappingEvent(target,stage){let active=false;const d=dest(target);const event=new Proxy({destination:d},{getOwnPropertyDescriptor(t,k){if(active)revoke();return Reflect.getOwnPropertyDescriptor(t,k);}});return {event,activate(){active=true;}};}
if(which==='no-attach') {
    const msg=new Proxy(good(),{get(){reads++;return undefined;},getOwnPropertyDescriptor(){reads++;return undefined;}});
    hooks.trigger('onSend',[{source:{id:'in'},msg}],()=>forwarded++);
    assert.equal(reads,0,'no attachment must deny before message reads');assert.equal(adapter.snapshot().events.length,0);assert.equal(forwarded,1);
} else if(which==='onSend') {
    const source=new Proxy({id:'in'},{getOwnPropertyDescriptor(t,k){revoke();return Reflect.getOwnPropertyDescriptor(t,k);}});
    const item=new Proxy({source,msg:good()},{getOwnPropertyDescriptor(t,k){if(k==='msg')reads++;return Reflect.getOwnPropertyDescriptor(t,k);}});
    hooks.trigger('onSend',[item],()=>forwarded++);
    assert.equal(reads,0,'revoked source descriptor must prevent message descriptor');assert.equal(forwarded,1);
} else if(which==='preDeliver') {
    const e=trappingEvent({},'pre');e.activate();root(()=>hooks.trigger('preDeliver',e.event,()=>forwarded++));
    assert.equal(reads,0,'revoked destination descriptor must prevent node descriptor');assert.equal(forwarded,1);
} else if(which==='claimDelivery') {
    const e=trappingEvent({},'claim');root(()=>hooks.trigger('preDeliver',e.event,()=>{reads=0;e.activate();assert.equal(control.claimDelivery(e.event),undefined);forwarded++;}));
    assert.equal(reads,0,'revoked claim destination must prevent node descriptor');assert.equal(forwarded,1);
} else if(which==='onReceive') {
    const target={}, delivery={destination:{node:target}};
    root(()=>hooks.trigger('preDeliver',delivery,()=>{
        const f=control.claimDelivery(delivery),e=trappingEvent(target,'receive');e.activate();
        control.bind(f,target,e.event,()=>hooks.trigger('onReceive',e.event,()=>forwarded++));
    }));
    assert.equal(reads,0,'revoked receive destination must prevent node descriptor');assert.equal(forwarded,1);
} else throw Error('unknown case');
process.stdout.write('PASS: '+which+' revocation read barrier\n');
