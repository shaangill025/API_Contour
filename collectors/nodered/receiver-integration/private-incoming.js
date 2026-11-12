'use strict';
// Dormant trusted-initializer building block. Direct require/create does not
// establish TLS, enrollment, deployment or global causal authority.
const http=require('node:http'),tls=require('node:tls'),crypto=require('node:crypto');
const {performance}=require('node:perf_hooks'),{types}=require('node:util');
const {decode}=require('../causal-evidence-codec');
const CARRIER='x-apicontour-causal-binding';
const fields=['tenant_id','gateway_id','gateway_generation','receiver_runtime_id','receiver_session_epoch','gateway_backend_leaf','receiver_backend_leaf'];
const data=(o,k)=>{if(!o||typeof o!=='object'||types.isProxy(o))return undefined;const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d?d.value:undefined;};
const digest=buf=>Buffer.isBuffer(buf)&&!types.isProxy(buf)&&buf.length>0&&buf.length<=65536?crypto.createHash('sha256').update(buf).digest('hex'):undefined;
function create({app,producer,authority,clock=()=>performance.now()}){
 if(typeof app!=='function'||!producer||!['prepare','root','offerRoot','cancel'].every(k=>typeof producer[k]==='function')||typeof authority!=='function'||typeof clock!=='function')throw Error('unsupported incoming handler');
 const registrations=new WeakMap(),seen=new WeakSet(),active=new Map(),invalid=Object.freeze({status:'invalid'});let closed=false,busy=false,bytes=0;
 function remove(e){if(!e.live)return;e.live=false;active.delete(e.registration);bytes-=e.charge;try{producer.cancel(e.registration);}catch(_){}}
 function sweep(){const now=clock();for(const e of active.values())if(now>=e.deadline)remove(e);}
 function scope(){const a=authority(),now=clock();if(!a||data(a,'allowed')!==true||!Number.isFinite(data(a,'deadline'))||!Number.isFinite(now)||now>=data(a,'deadline'))return undefined;const result={};for(const k of fields){const v=data(a,k);if(typeof v!=='string')return undefined;result[k]=v;}result.deadline=data(a,'deadline');return result;}
 function matches(a,b){return !!a&&fields.every(k=>a[k]===b[k])&&clock()<Math.min(a.deadline,b.deadline);}
 function scrub(req){
  const raw=req.rawHeaders;if(!Array.isArray(raw)||types.isProxy(raw)||raw.length%2)throw Error('invalid headers');
  const oversized=raw.length>256;let carrier, count=0, nominated=false;const kept=[];
  const views=[req.headers,req.headersDistinct];
  for(let i=0;i<raw.length;i+=2){const name=raw[i],value=raw[i+1];if(typeof name!=='string'||typeof value!=='string')throw Error('invalid headers');const key=name.toLowerCase();
   if(key==='connection'&&value.split(',').some(v=>v.trim().toLowerCase()===CARRIER))nominated=true;
   if(key===CARRIER){count++;carrier=value;}if(!key.startsWith('x-apicontour-'))kept.push(name,value);
  }
  raw.length=0;for(const value of kept)raw.push(value);
  for(const headers of views)if(headers&&typeof headers==='object'&&!types.isProxy(headers))for(const key of Object.keys(headers))if(key.toLowerCase().startsWith('x-apicontour-'))delete headers[key];
  return count===1&&!nominated&&!oversized?carrier:undefined;
 }
 function handler(req,res){
  try{
   const carrier=scrub(req);
   const eligible=req instanceof http.IncomingMessage&&!types.isProxy(req)&&!seen.has(req);
   if(eligible)seen.add(req);
   if(!closed&&!busy&&carrier!==undefined&&eligible&&req.httpVersionMajor===1){
    busy=true;try{
     sweep();const a=scope(),socket=req.socket;
     if(a&&socket instanceof tls.TLSSocket&&!types.isProxy(socket)&&socket.authorized===true&&active.size<32&&typeof carrier==='string'&&carrier.length<=2048&&!/[^\x20-\x7e]/.test(carrier)){
      const peer=digest(socket.getPeerCertificate(true)?.raw),local=digest(socket.getCertificate()?.raw);
      const input=Buffer.from(carrier,'ascii'),checked=decode('binding',input),b=checked.value;
      if(checked.canonical===carrier&&peer===a.gateway_backend_leaf&&local===a.receiver_backend_leaf&&b.tenant_id===a.tenant_id&&b.gateway_id===a.gateway_id&&b.gateway_generation===a.gateway_generation&&b.receiver_runtime_id===a.receiver_runtime_id&&b.receiver_session_epoch===a.receiver_session_epoch&&matches(scope(),a)){
       const charge=input.length+256;if(bytes+charge<=32768){const registration=producer.prepare(input);if(registration&&matches(scope(),a)){
        const deadline=Math.min(clock()+5000,a.deadline);const e={registration,deadline,charge,scope:a,socket:new WeakRef(socket),live:true};
        const aborted=()=>remove(e);e.aborted=aborted;active.set(registration,e);registrations.set(req,e);bytes+=charge;req.once('aborted',aborted);
       }else if(registration)producer.cancel(registration);}
      }
     }
    }finally{busy=false;}
   }
  }catch(_){ /* Evidence is optional; ordinary forwarding still runs. */ }
  return app(req,res);
 }
 function consume(values){
  if(closed||busy)return invalid;busy=true;let claimed=false;
  try{
   sweep();if(!Array.isArray(values)||types.isProxy(values)||values.length<1||values.length>4096)return undefined;
   let req;for(let i=0;i<values.length;i++){const d=Object.getOwnPropertyDescriptor(values,String(i));if(!d||!('value' in d))return undefined;const current=data(d.value,'req');if(!(current instanceof http.IncomingMessage)||types.isProxy(current)||(req&&req!==current))return undefined;req=current;}
   const e=registrations.get(req);if(!e)return undefined;claimed=true;if(!e.live){registrations.delete(req);return invalid;}
   if(req.aborted||req.socket!==e.socket.deref()||req.socket.destroyed||req.socket.authorized!==true||digest(req.socket.getPeerCertificate(true)?.raw)!==e.scope.gateway_backend_leaf||digest(req.socket.getCertificate()?.raw)!==e.scope.receiver_backend_leaf||clock()>=e.deadline||!matches(scope(),e.scope)){remove(e);registrations.delete(req);req.removeListener('aborted',e.aborted);return invalid;}
   e.live=false;active.delete(e.registration);bytes-=e.charge;registrations.delete(req);req.removeListener('aborted',e.aborted);
   const root=producer.root(e.registration);
   if(typeof root!=='string'||root.length!==32||/[^0-9a-f]/.test(root)){producer.cancel(e.registration);return invalid;}
   const ticket=producer.offerRoot(e.registration);
   if(!ticket)return matches(scope(),e.scope)?Object.freeze({status:'dropped',root}):invalid;
   if(producer.root(ticket)!==root||!matches(scope(),e.scope)){producer.cancel(ticket);return invalid;}
   return Object.freeze({status:'queued',root,ticket});
  }catch(_){return claimed?invalid:undefined;}finally{busy=false;}
 }
 function close(){if(closed)return;closed=true;for(const e of active.values())remove(e);}
 return Object.freeze({handler,consume,close});
}
module.exports=Object.freeze({create});
