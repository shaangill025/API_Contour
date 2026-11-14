'use strict';
// Synthetic transport and key mocks; no network, issuer or database evidence.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),https=require('node:https'),{EventEmitter}=require('node:events'),{performance}=require('node:perf_hooks');
const boot=require('../../../collectors/nodered/receiver-integration/private-bootstrap-504'),baseApi=require('../../../collectors/nodered/error-integration/private-handoff'),rootApi=require('../../../collectors/nodered/receiver-integration/private-root-handoff'),senderApi=require('../../../collectors/nodered/receiver-integration/private-receiver-exporter');
const v=require('../receiver504-bootstrap/vector.json'),seed=JSON.parse(v.canonical),binding=require('../../../docs/specification/fixtures/causal-evidence-v1.json')[0].body;
const certificate=Buffer.from('synthetic-evidence-certificate'),epoch=BigInt(seed.epoch);
function setup(committed=true,timeoutMs=3000,ca=Buffer.from('ca')){
 const d={...seed,ca_sha256:crypto.createHash('sha256').update(Buffer.from('ca')).digest('hex'),receiver_evidence_leaf:crypto.createHash('sha256').update(certificate).digest('hex')};d.identity=boot.commitment(d);Object.freeze(d);
 let allowed=true,currentEpoch=epoch;const authority=()=>({allowed,epoch:currentEpoch,deadline:performance.now()+10000,tenant_id:d.tenant,gateway_id:d.gateway_id,gateway_generation:d.gateway_generation,gateway_backend_leaf:d.gateway_backend_leaf,receiver_runtime_id:d.runtime,receiver_session_epoch:d.epoch,receiver_backend_leaf:d.receiver_backend_leaf});
 const base=baseApi.create({tenantId:d.tenant,runtimeId:d.runtime,epoch,authority,maxBatchEvents:8,maxBatchBytes:4096,queueBytes:8192,queueTtlMs:10000});
 const root=rootApi.create({base,authority,tenantId:d.tenant,runtimeId:d.runtime,epoch,queueTtlMs:10000});
 const b={...binding,tenant_id:d.tenant,gateway_id:d.gateway_id,gateway_generation:d.gateway_generation,receiver_runtime_id:d.runtime,receiver_session_epoch:d.epoch};
 const registration=root.producer.prepare(Buffer.from(JSON.stringify(b))),ticket=root.producer.offerRoot(registration);assert(ticket);
 if(committed){const batch=root.exporter.freeze();assert(root.exporter.ack(batch.batchId,batch.sha256,epoch,()=>true));}
 let drains=0,override,onRelease;const outbox={reserveFlight(){return root.outbox.reserveFlight();},readFlight(token){const item=root.outbox.readFlight(token);return override?override(item):item;},releaseFlight(token){if(onRelease)onRelease();return root.outbox.releaseFlight(token);},settleFlight(...args){const result=root.outbox.settleFlight(...args);if(result)drains++;return result;}};
 const old={X509Certificate:crypto.X509Certificate,createPrivateKey:crypto.createPrivateKey,createPublicKey:crypto.createPublicKey};let sender;
 try{crypto.X509Certificate=class{constructor(raw){this.raw=raw;this.publicKey={export:()=>Buffer.from('same-key')};}};crypto.createPrivateKey=()=>({});crypto.createPublicKey=()=>({export:()=>Buffer.from('same-key')});sender=senderApi.create({descriptor:d,authority,outbox,ca,evidenceCert:certificate,evidenceKey:Buffer.from('key'),timeoutMs});}
 finally{Object.assign(crypto,old);}
 return {d,root,ticket,sender,setAllowed(v){allowed=v;},setEpoch(v){currentEpoch=v;},setRelease(fn){onRelease=fn;},setOverride(fn){override=fn;},drains:()=>drains};
}
function reply(digest,changes={}){return Buffer.from(JSON.stringify({fact_digest:digest,kind:'receiver',receipt_id:'00000000-0000-4000-8000-000000000001',status:'stored',wire_version:1,...changes}));}
function transport(handler){const old=https.request;https.request=(opts,callback)=>{const req=new EventEmitter();req.destroy=()=>{req.closed=true;req.emit('close');};req.end=body=>handler({opts,body,callback,req});return req;};return()=>{https.request=old;};}
function response(callback,body,{status=200,authorized=true,content='application/json'}={}){const res=new EventEmitter();res.statusCode=status;res.socket={authorized};res.headers={'content-type':content};res.destroy=()=>{res.closed=true;res.emit('close');};callback(res);res.emit('data',body);res.emit('end');}
(async()=>{
 assert.throws(()=>setup(true,3000,Buffer.from('different-ca')),/unsupported receiver sender/);

 {
  const x=setup(false);let calls=0;const restore=transport(()=>calls++);try{assert.equal(await x.sender.sendOnce(),false);assert.equal(calls,0);assert.equal(x.drains(),0);}finally{restore();x.sender.close();x.root.close();}
 }
 for(const status of ['stored','resolved']){
  const x=setup(),fact=x.root.outbox.peek().fact,restore=transport(({opts,body,callback})=>{assert.equal(opts.hostname,'causal-ingress');assert.equal(opts.path,'/v1/causal-evidence/receiver');assert.equal(opts.rejectUnauthorized,true);assert.equal(body.toString(),fact.canonical);queueMicrotask(()=>response(callback,reply(fact.sha256,{status})));});
  try{assert.equal(await x.sender.sendOnce(),true);assert.equal(x.drains(),1);assert.equal(x.root.outbox.peek(),undefined);assert.equal(await x.sender.sendOnce(),false);}finally{restore();x.sender.close();x.root.close();}
 }
 for(const kind of ['digest','uuid','kind','status','extra','duplicate','noncanonical','version','size','http','tls','content','network','scope']){
  const x=setup(),fact=x.root.outbox.peek().fact;const restore=transport(({callback,req})=>{let body=reply(fact.sha256),options={};
   if(kind==='digest')body=reply('0'.repeat(64));if(kind==='uuid')body=reply(fact.sha256,{receipt_id:'bad'});if(kind==='kind')body=reply(fact.sha256,{kind:'observer'});if(kind==='status')body=reply(fact.sha256,{status:'duplicate'});if(kind==='extra')body=reply(fact.sha256,{extra:'x'});if(kind==='duplicate')body=Buffer.from(body.toString().replace('"kind":"receiver"','"kind":"receiver","kind":"receiver"'));if(kind==='noncanonical')body=Buffer.from(body.toString()+' ');if(kind==='version')body=Buffer.from(body.toString().replace('\"wire_version\":1','\"wire_version\":1.0'));if(kind==='size')body=Buffer.alloc(1025,65);if(kind==='http')options.status=409;if(kind==='tls')options.authorized=false;if(kind==='content')options.content='text/plain';
   queueMicrotask(()=>{if(kind==='network')req.emit('error',Error('unavailable'));else if(kind==='scope'){x.setAllowed(false);response(callback,body,options);}else response(callback,body,options);});});
  try{assert.equal(await x.sender.sendOnce(),false,kind);assert.equal(x.drains(),0,kind);if(kind!=='scope')assert(x.root.outbox.peek(),kind);}finally{restore();x.sender.close();x.root.close();}
 }
 {
  const x=setup(),fact=x.root.outbox.peek().fact;let callback,body,calls=0;const restore=transport(v=>{calls++;callback=v.callback;body=Buffer.from(v.body);});
  try{const first=x.sender.sendOnce();assert.equal(await x.sender.sendOnce(),false);assert.equal(calls,1);x.setOverride(item=>item&&({...item,ticket:Object.freeze({})}));response(callback,reply(fact.sha256));assert.equal(await first,false);assert.equal(x.drains(),0);x.setOverride(undefined);const retry=x.sender.sendOnce();assert.equal(calls,2);assert.equal(body.toString(),fact.canonical);response(callback,reply(fact.sha256));assert.equal(await retry,true);}finally{restore();x.sender.close();x.root.close();}
 }
 {
  const x=setup(),fact=x.root.outbox.peek().fact;let callback;const restore=transport(v=>callback=v.callback);try{const pending=x.sender.sendOnce();x.sender.close();response(callback,reply(fact.sha256));assert.equal(await pending,false);assert.equal(x.drains(),0);assert(x.root.outbox.peek());}finally{restore();x.root.close();}
 }
 for(const scenario of ['cancel','epoch','expired','changed-fact','changed-deadline','throwing-peek']){
  const x=setup(true,scenario==='expired'?20:3000),fact=x.root.outbox.peek().fact;let callback;const restore=transport(v=>callback=v.callback);
  try{const pending=x.sender.sendOnce();
   if(scenario==='cancel')assert(x.root.outbox.cancel(x.ticket));
   if(scenario==='epoch')x.setEpoch(1n);
   if(scenario==='expired')await new Promise(resolve=>setTimeout(resolve,30));
   if(scenario==='changed-fact')x.setOverride(item=>item&&({...item,fact:{...item.fact,sha256:'0'.repeat(64)}}));
   if(scenario==='changed-deadline')x.setOverride(item=>item&&({...item,deadline:item.deadline+1}));
   if(scenario==='throwing-peek')x.setOverride(()=>{throw Error('synthetic');});
   response(callback,reply(fact.sha256));assert.equal(await pending,false,scenario);assert.equal(x.drains(),0,scenario);
  }finally{restore();x.sender.close();x.root.close();}
 }
 {
  const x=setup(),fact=x.root.outbox.peek().fact,receiptBytes=reply(fact.sha256);let sendBuffer,callback,released=false;const temporary=[];const concat=Buffer.concat;
  const restore=transport(v=>{sendBuffer=v.body;callback=v.callback;});
  try{
   x.setRelease(()=>{released=true;assert(sendBuffer.every(byte=>byte===0));assert(temporary.length>0);assert(temporary.every(buf=>buf.every(byte=>byte===0)));});
   const pending=x.sender.sendOnce();Buffer.concat=function(...args){const value=concat.apply(Buffer,args);temporary.push(value);return value;};
   response(callback,receiptBytes);assert.equal(await pending,true);assert(released);
  }finally{Buffer.concat=concat;restore();x.sender.close();x.root.close();}
 }
 // Late responses are destroyed directly after a confirmed request close.
 {
  const x=setup();let callback,destroyed=0,released=0;const restore=transport(v=>{callback=v.callback;});
  try{x.setRelease(()=>released++);const pending=x.sender.sendOnce();x.sender.close();assert.equal(await pending,false);const late=new EventEmitter();late.destroy=()=>destroyed++;callback(late);assert.equal(destroyed,1);assert.equal(released,1);const token=x.root.outbox.reserveFlight();assert(token);assert(x.root.outbox.releaseFlight(token));}finally{restore();x.root.close();}
 }
 // A pre-response failure with confirmed request close permits an exact retry.
 {
  const x=setup(),fact=x.root.outbox.peek().fact,bodies=[];let count=0;const restore=transport(({body,callback,req})=>{bodies.push(Buffer.from(body));if(count++===0)queueMicrotask(()=>req.emit('error',Error('lost')));else queueMicrotask(()=>response(callback,reply(fact.sha256)));});
  try{assert.equal(await x.sender.sendOnce(),false);assert.equal(x.drains(),0);assert.equal(await x.sender.sendOnce(),true);assert.equal(x.drains(),1);assert.equal(bodies.length,2);assert(bodies[0].equals(bodies[1]));assert.equal(x.root.outbox.peek(),undefined);}finally{restore();x.sender.close();x.root.close();}
 }
 // A valid settlement followed by unconfirmed close returns false and holds
 // the reservation; the already settled ticket is no longer queued.
 {
  const x=setup(),fact=x.root.outbox.peek().fact;let released=0;const old=https.request;
  https.request=(opts,callback)=>{const req=new EventEmitter();req.destroy=()=>{};req.end=()=>{const res=new EventEmitter();res.statusCode=200;res.socket={authorized:true};res.headers={'content-type':'application/json'};res.destroy=()=>{};callback(res);res.emit('data',reply(fact.sha256));res.emit('end');};return req;};
  try{x.setRelease(()=>released++);assert.equal(await x.sender.sendOnce(),false);assert.equal(released,0);assert.equal(x.root.outbox.peek(),undefined,'valid settlement is not queued after cleanup failure');assert.equal(x.root.outbox.reserveFlight(),undefined);}finally{https.request=old;x.sender.close();x.root.close();}
 }
 // Settlement checks authority and the original deadline after fact encoding.
 for(const failure of ['authority','deadline','wrong-ticket','wrong-fact']){
  const d=seed,clock={now:0};let allowed=true;const a=()=>({allowed,epoch,deadline:100000});
  const base=baseApi.create({tenantId:d.tenant,runtimeId:d.runtime,epoch,authority:a,maxBatchEvents:8,maxBatchBytes:4096,queueBytes:8192,queueTtlMs:10000});
  const root=rootApi.create({base,authority:a,tenantId:d.tenant,runtimeId:d.runtime,epoch,queueTtlMs:10000,clock:()=>clock.now});
  const b={...binding,tenant_id:d.tenant,gateway_id:d.gateway_id,gateway_generation:d.gateway_generation,receiver_runtime_id:d.runtime,receiver_session_epoch:d.epoch};
  const r=root.producer.prepare(Buffer.from(JSON.stringify(b))),ticket=root.producer.offerRoot(r),batch=root.exporter.freeze();assert(root.exporter.ack(batch.batchId,batch.sha256,epoch,()=>true));const token=root.outbox.reserveFlight(),item=root.outbox.readFlight(token);
  const live=()=>{if(failure==='authority')allowed=false;if(failure==='deadline')clock.now=item.deadline;return failure!=='authority';};
  assert.equal(root.outbox.settleFlight(token,failure==='wrong-ticket'?Object.freeze({}):ticket,failure==='wrong-fact'?'bad':item.fact.canonical,item.fact.sha256,live),false,failure);
  allowed=true;clock.now=0;assert(root.outbox.peek(),failure);assert(root.outbox.releaseFlight(token));root.close();
 }
 // The flight is charged to the root's existing aggregate budget, not a
 // separate sender queue; cancellation, expiry and close do not release it.
 {
  const d=seed,clock={now:0};const a=()=>({allowed:true,epoch,deadline:100000});
  const rawBase=baseApi.create({tenantId:d.tenant,runtimeId:d.runtime,epoch,authority:a,maxBatchEvents:64,maxBatchBytes:65536,queueBytes:131072,queueTtlMs:10000});
  const root=rootApi.create({base:rawBase,authority:a,tenantId:d.tenant,runtimeId:d.runtime,epoch,queueTtlMs:10000,clock:()=>clock.now});
  const b={...binding,tenant_id:d.tenant,gateway_id:d.gateway_id,gateway_generation:d.gateway_generation,receiver_runtime_id:d.runtime,receiver_session_epoch:d.epoch},tickets=[];
  for(let i=0;i<32;i++){const r=root.producer.prepare(Buffer.from(JSON.stringify(b)));if(!r)break;const t=root.producer.offerRoot(r);if(!t)break;tickets.push(t);}
  const batch=root.exporter.freeze();assert(root.exporter.ack(batch.batchId,batch.sha256,epoch,()=>true));assert.equal(root.outbox.reserveFlight(),undefined,'full aggregate must reject reservation');
  let token;while(tickets.length>1){token=root.outbox.reserveFlight();if(token)break;root.outbox.cancel(tickets.pop());}
  assert(token);root.close();assert.equal(root.outbox.releaseFlight(token),true);
 }
 {
  const x=setup(),token=x.root.outbox.reserveFlight();assert(token);
  const d=x.d,b={...binding,tenant_id:d.tenant,gateway_id:d.gateway_id,gateway_generation:d.gateway_generation,receiver_runtime_id:d.runtime,receiver_session_epoch:d.epoch};
  let admitted=0;while(admitted<32&&x.root.producer.prepare(Buffer.from(JSON.stringify(b))))admitted++;
  assert(admitted>0&&admitted<30,'flight budget must limit new roots');
  assert.equal(x.root.outbox.releaseFlight(token),true);
  assert(x.root.producer.prepare(Buffer.from(JSON.stringify(b))),'released flight budget admits another root');
  x.sender.close();x.root.close();
 }
 {
  const x=setup();const token=x.root.outbox.reserveFlight();assert(token&&Object.isFrozen(token));assert.equal(x.root.outbox.reserveFlight(),undefined);assert.equal(x.root.outbox.readFlight(Object.freeze({})),undefined);assert.equal(x.root.outbox.releaseFlight(Object.freeze({})),false);
  assert.equal(x.root.outbox.readFlight(token).ticket,x.ticket);assert(x.root.outbox.cancel(x.ticket));assert.equal(x.root.outbox.readFlight(token),undefined);assert.equal(x.root.outbox.reserveFlight(),undefined);x.root.close();assert.equal(x.root.outbox.releaseFlight(token),true);assert.equal(x.root.outbox.releaseFlight(token),false);x.sender.close();
 }
 {
  const d=seed,clock={now:0};const a=()=>({allowed:true,epoch,deadline:100000}),base=baseApi.create({tenantId:d.tenant,runtimeId:d.runtime,epoch,authority:a,maxBatchEvents:8,maxBatchBytes:4096,queueBytes:8192,queueTtlMs:10000}),root=rootApi.create({base,authority:a,tenantId:d.tenant,runtimeId:d.runtime,epoch,queueTtlMs:10000,clock:()=>clock.now});
  const b={...binding,tenant_id:d.tenant,gateway_id:d.gateway_id,gateway_generation:d.gateway_generation,receiver_runtime_id:d.runtime,receiver_session_epoch:d.epoch},r=root.producer.prepare(Buffer.from(JSON.stringify(b))),ticket=root.producer.offerRoot(r),batch=root.exporter.freeze();assert(ticket);assert(root.exporter.ack(batch.batchId,batch.sha256,epoch,()=>true));const flight=root.outbox.reserveFlight();assert(flight);clock.now=5000;assert.equal(root.outbox.readFlight(flight),undefined);assert.equal(root.outbox.reserveFlight(),undefined);assert.equal(root.outbox.releaseFlight(flight),true);root.close();
 }
 console.log('receiver 504 sender offline synthetic tests passed');
})().catch(()=>{console.error('receiver 504 sender offline tests failed');process.exitCode=1;});
