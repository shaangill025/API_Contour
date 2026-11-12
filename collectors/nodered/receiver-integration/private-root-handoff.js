'use strict';
// Dormant initializer building block. Public require can create an isolated
// object; it cannot mint deployment, session, TLS or global authority.
const {performance}=require('node:perf_hooks');
const {randomBytes}=require('node:crypto');
const {decode}=require('../causal-evidence-codec');
const MAX_U64=(1n<<64n)-1n;
function create({base,authority,tenantId,runtimeId,epoch,queueTtlMs,clock=()=>performance.now()}) {
 if(typeof tenantId!=='string'||typeof runtimeId!=='string'||!base||!['offer','gate','freeze','ack','close'].every(k=>typeof base[k]==='function')||typeof authority!=='function'||typeof clock!=='function'||typeof epoch!=='bigint'||epoch<1n||epoch>MAX_U64||!Number.isSafeInteger(queueTtlMs)||queueTtlMs<1||queueTtlMs>86400000)throw Error('unsupported root handoff');
 let closed=false,busy=false,bytes=0,frozen;const entries=new Map(),roots=new Map(),tombstones=new Map();
 function close(){closed=true;entries.clear();roots.clear();tombstones.clear();bytes=0;frozen=undefined;try{base.close();}catch(_){}}
 function current(){
  if(closed)return false;
  try {const now=clock(),a=authority();return Number.isFinite(now)&&a&&a.allowed===true&&a.epoch===epoch&&Number.isFinite(a.deadline)&&now<a.deadline&&base.gate()===true;}catch(_){return false;}
 }
 function remove(key,e){
  entries.delete(key);
  if(e.state==='queued')tombstones.set(key,e.charge);
  else {if(roots.get(e.root)===key)roots.delete(e.root);bytes-=e.charge;}
 }
 function sweep(){const t=clock();for(const [key,e] of entries)if(t>=e.deadline)remove(key,e);}
 function run(fn,fallback){if(closed||busy)return fallback;busy=true;try{if(!current()){close();return fallback;}sweep();return fn();}catch(_){close();return fallback;}finally{busy=false;}}
 function prepare(bindingBytes){return run(()=>{
  if(roots.size>=32||entries.size>=32)return undefined;
  const checked=decode('binding',bindingBytes),b=checked.value;
  if(b.tenant_id!==tenantId||b.receiver_runtime_id!==runtimeId||BigInt(b.receiver_session_epoch)!==epoch)return undefined;
  const charge=Buffer.byteLength(checked.canonical)+256;if(bytes+charge>32768)return undefined;
  const now=clock(),a=authority();if(!a||a.allowed!==true||a.epoch!==epoch||!Number.isFinite(a.deadline))return undefined;
  const deadline=Math.min(now+5000,now+queueTtlMs,a.deadline);if(!(now<deadline))return undefined;
  let root;for(let i=0;i<4;i++){const candidate=randomBytes(16).toString('hex');if(!roots.has(candidate)){root=candidate;break;}}
  if(!root)return undefined;
  const registration=Object.freeze({});entries.set(registration,{root,binding:b,digest:checked.sha256,deadline,charge,state:'prepared'});
  roots.set(root,registration);bytes+=charge;return registration;
 },undefined);}
 function root(key){return run(()=>entries.get(key)?.root,undefined);}
 function offerRoot(registration){return run(()=>{
  const e=entries.get(registration);if(!e||e.state!=='prepared')return undefined;
  entries.delete(registration);roots.delete(e.root);
  if(base.offer(Object.freeze({kind:'ROOT_INTENT',root:e.root}))!==true){bytes-=e.charge;return undefined;}
  if(!current()||clock()>=e.deadline){close();return undefined;}
  const ticket=Object.freeze({});e.state='queued';entries.set(ticket,e);roots.set(e.root,ticket);return ticket;
 },undefined);}
 function cancel(key){return run(()=>{const e=entries.get(key);if(!e)return false;remove(key,e);return true;},false);}
 function freeze(){return run(()=>{
  const batch=base.freeze();if(!batch)return undefined;
  if(batch.epoch!==epoch||typeof batch.canonical!=='string'||typeof batch.batchId!=='string'||typeof batch.sha256!=='string')throw Error('invalid frozen batch');
  if(frozen){if(frozen.batch!==batch)throw Error('changed frozen batch');return batch;}
  // Never use JSON-parsed numeric sequence/epoch values for identity or encoding.
  const parsed=JSON.parse(batch.canonical);if(!parsed||!Array.isArray(parsed.events))throw Error('invalid frozen batch');
  const members=[], frozenRoots=[];for(const event of parsed.events)if(event&&event.kind==='root'&&typeof event.root==='string'){
   const ticket=roots.get(event.root),entry=entries.get(ticket);if(ticket){frozenRoots.push([event.root,ticket]);if(entry&&entry.state==='queued')members.push(ticket);}
  }
  frozen={batch,members,frozenRoots};return batch;
 },undefined);}
 function ack(id,digest,receiptEpoch,commitIf){return run(()=>{
  if(!frozen||id!==frozen.batch.batchId||digest!==frozen.batch.sha256||receiptEpoch!==epoch||typeof commitIf!=='function')return false;
  const selected=frozen;
  const ok=base.ack(id,digest,receiptEpoch,()=>{try{return commitIf()===true&&current();}catch(_){return false;}});
  if(ok!==true)return false;
  frozen=undefined;
  if(!current()) {close();return false;}
  sweep();
  for(const [root,ticket] of selected.frozenRoots)if(roots.get(root)===ticket&&tombstones.has(ticket)){roots.delete(root);bytes-=tombstones.get(ticket);tombstones.delete(ticket);}
  for(const ticket of selected.members){const e=entries.get(ticket);if(e&&e.state==='queued')e.state='committed';}
  return true;
 },false);}
 function drain(ticket){return run(()=>{
  const e=entries.get(ticket);if(!e||e.state!=='committed')return undefined;
  const b=e.binding,raw={wire_version:1,tenant_id:b.tenant_id,gateway_id:b.gateway_id,gateway_generation:b.gateway_generation,delivery_handle:b.delivery_handle,receiver_runtime_id:b.receiver_runtime_id,receiver_session_epoch:b.receiver_session_epoch,local_root:e.root,binding_digest:e.digest};
  const result=decode('receiver',Buffer.from(JSON.stringify(raw)));
  entries.delete(ticket);if(roots.get(e.root)===ticket)roots.delete(e.root);bytes-=e.charge;return result;
 },undefined);}
 const producer=Object.freeze({prepare,root,offerRoot,cancel});
 const exporter=Object.freeze({gate:()=>run(()=>true,false),freeze,ack});
 const outbox=Object.freeze({drain,cancel});
 return Object.freeze({producer,exporter,outbox,close});
}
module.exports=Object.freeze({create});
