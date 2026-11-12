'use strict';
// Hook model only; this does not execute the pinned Node-RED runtime or TLS.
const assert=require('node:assert/strict'),http=require('node:http'),tls=require('node:tls'),crypto=require('node:crypto'),{performance}=require('node:perf_hooks');
const {install}=require('../../../collectors/nodered/receiver-integration/private-producer-runtime');
const baseApi=require('../../../collectors/nodered/error-integration/private-handoff'),rootApi=require('../../../collectors/nodered/receiver-integration/private-root-handoff'),incoming=require('../../../collectors/nodered/receiver-integration/private-incoming');
const f=require('../../../docs/specification/fixtures/causal-evidence-v1.json'),b=f[0].body,epoch=BigInt(b.receiver_session_epoch),peer=Buffer.from('peer'),server=Buffer.from('server'),sha=x=>crypto.createHash('sha256').update(x).digest('hex');
function hooks(){const cb={};return {add(k,f){cb[k.split('.')[0]]=f;},remove(){},clear(){},has(k){return !!cb[k.split('.')[0]];},trigger(k,e,done){if(cb[k])cb[k](e,done);else done();}};}
function setup(max=8){
 const auth=()=>({allowed:true,epoch,deadline:performance.now()+10000}),scope=()=>({allowed:true,deadline:performance.now()+10000,tenant_id:b.tenant_id,gateway_id:b.gateway_id,gateway_generation:b.gateway_generation,receiver_runtime_id:b.receiver_runtime_id,receiver_session_epoch:b.receiver_session_epoch,gateway_backend_leaf:sha(peer),receiver_backend_leaf:sha(server)});
 const rawBase=baseApi.create({tenantId:b.tenant_id,runtimeId:b.receiver_runtime_id,epoch,authority:auth,maxBatchEvents:max,maxBatchBytes:4096,queueBytes:8192,queueTtlMs:10000});
 const offers=[];const base=Object.freeze({...rawBase,offer(event){if(event.kind==='ROOT_INTENT')offers.push(event.root);return rawBase.offer(event);}});
 const wrap=rootApi.create({base,authority:auth,tenantId:b.tenant_id,runtimeId:b.receiver_runtime_id,epoch,queueTtlMs:10000});let appCount=0,onApp=()=>{};
 const recv=incoming.create({producer:wrap.producer,authority:scope,app(req){appCount++;onApp(req);}}),h=hooks();let control,received;
 const adapter=install(h,{inbound:['in'],requests:['worker'],maxPending:8,maxEvents:128,maxBytes:16384,ttlMs:1000,ingressPoint:{node:'in',method:'POST',url:'/run'}},c=>{control=c;c.attachProducer(base);c.attachReceiver(Object.freeze({consume(values){received=recv.consume(values);return received;}}));});
 function request(valid=true){const socket=new tls.TLSSocket();Object.defineProperties(socket,{authorized:{value:true},destroyed:{value:false},getPeerCertificate:{value:()=>({raw:peer})},getCertificate:{value:()=>({raw:server})}});const req=new http.IncomingMessage(socket);req.httpVersionMajor=1;req.method='POST';req.url='/run';const hs=valid?['x-apicontour-causal-binding',f[0].canonical]:[];req._addHeaderLines(hs,hs.length);return req;}
 function deliver(req,inboundOnly=false,abort=false){let context,done=0;onApp=msg=>{if(abort)msg.emit('aborted');h.trigger('onSend',[{source:{id:'in'},msg:{req:msg}}],()=>{if(inboundOnly){done++;return;}const target={},event={destination:{node:target,id:'worker'}};h.trigger('preDeliver',event,()=>{const frame=control.claimDelivery(event);control.bind(frame,target,event,()=>h.trigger('onReceive',event,()=>{const handle=control.captureDispatch(target);context=control.dispatchContext(handle,target);done++;}));});});};recv.handler(req,{});assert.equal(done,1);return context;}
 return {base,wrap,recv,adapter,request,deliver,offers,hooks:h,get appCount(){return appCount;},get received(){return received;}};
}
{
 const s=setup(),ctx=s.deliver(s.request()),batch=s.wrap.exporter.freeze(),events=JSON.parse(batch.canonical).events;
 assert.equal(s.appCount,1);assert.ok(ctx);assert.deepEqual(events.map(x=>x.kind),['root','delivery']);assert.equal(events[0].root,ctx.root);assert.equal(s.received.root,ctx.root);assert.equal(s.wrap.exporter.ack(batch.batchId,batch.sha256,epoch,()=>true),true);const settled=s.wrap.outbox.peek();assert.equal(settled.ticket,s.received.ticket);assert.equal(settled.fact.value.local_root,ctx.root);assert(settled.deadline>performance.now());assert.equal(s.wrap.outbox.peek().ticket,settled.ticket);assert.equal(s.wrap.outbox.cancel(settled.ticket),true);assert.equal(s.wrap.outbox.peek(),undefined);assert.equal(events.filter(x=>x.kind==='root').length,1);assert.equal(s.adapter.snapshot().registryIntact,true);s.recv.close();
}
{
 const s=setup(),ctx=s.deliver(s.request(false)),batch=s.wrap.exporter.freeze();assert.equal(s.appCount,1);assert.ok(ctx);assert.equal(s.received,undefined);assert.equal(JSON.parse(batch.canonical).events.filter(x=>x.kind==='root').length,1);s.recv.close();
}
{
 const s=setup(1);assert.ok(s.base.offer({kind:'ROOT_INTENT',root:'f'.repeat(32)}));s.deliver(s.request(),true);assert.equal(s.appCount,1);assert.equal(s.offers.length,2,'one prefill and one receiver root offer');assert.equal(s.received.status,'dropped');assert.equal(Object.hasOwn(s.received,'ticket'),false);
 const first=s.base.freeze();assert.equal(s.base.ack(first.batchId,first.sha256,epoch),true);const loss=JSON.parse(s.base.freeze().canonical).events[0];assert.deepEqual([loss.kind,loss.first_missing_seq,loss.last_missing_seq,loss.seq],['loss',2,2,3]);assert.ok(s.adapter.snapshot().loss>0);s.recv.close();
}

{
 const s=setup(1);assert.ok(s.base.offer({kind:'ROOT_INTENT',root:'f'.repeat(32)}));const ctx=s.deliver(s.request());assert.equal(s.received.status,'dropped');assert.equal(Object.hasOwn(s.received,'ticket'),false);assert.ok(ctx);assert.equal(ctx.root,s.received.root);assert.equal(s.appCount,1);s.recv.close();
}
{
 const s=setup();const ctx=s.deliver(s.request(),false,true);assert.equal(ctx,undefined);assert.equal(s.received.status,'invalid');assert.equal(s.offers.length,0);assert.equal(s.appCount,1);s.recv.close();
}

{
 const s=setup();let reads=0,done=0;const req={method:'POST',url:'/run'};
 Object.defineProperty(req,'headers',{get(){reads++;throw Error('must not run');}});
 s.hooks.trigger('onSend',[{source:{id:'in'},msg:{req}}],()=>done++);
 assert.equal(reads,0);assert.equal(done,1);assert.equal(s.received,undefined);assert.equal(s.offers.length,0);s.recv.close();
}
{
 const s=setup();let done=0;const req=new Proxy(s.request(),{getOwnPropertyDescriptor(){throw Error('proxy');}});
 s.hooks.trigger('onSend',[{source:{id:'in'},msg:{req}}],()=>done++);
 assert.equal(done,1);assert.equal(s.received,undefined);assert.equal(s.offers.length,0);s.recv.close();
}
console.log('receiver 504 synthetic composition model: passed');
