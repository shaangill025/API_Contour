'use strict';
// Dormant private sender. Local receipt validation does not establish a server
// commit, enrollment, trusted deployment, TLS issuance, or a causal edge.
const https=require('node:https'),crypto=require('node:crypto'),{performance}=require('node:perf_hooks'),{types,TextDecoder}=require('node:util');
const {decode}=require('../causal-evidence-codec');
const bootstrap=require('./private-bootstrap-504');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![\s\S])/;
const HEX=/^[0-9a-f]{64}(?![\s\S])/;
function receipt(raw,digest){
 if(!Buffer.isBuffer(raw)||raw.length<1||raw.length>1024)throw Error('receipt');
 let text,value;try{text=new TextDecoder('utf-8',{fatal:true}).decode(raw);value=JSON.parse(text);}catch(_){throw Error('receipt');}
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).join(',')!=='fact_digest,kind,receipt_id,status,wire_version'||JSON.stringify(value)!==text||value.fact_digest!==digest||!HEX.test(value.fact_digest)||value.kind!=='receiver'||!UUID.test(value.receipt_id)||!['stored','resolved'].includes(value.status)||value.wire_version!==1)throw Error('receipt');
 return true;
}
function create({descriptor,authority,outbox,ca,evidenceCert,evidenceKey,timeoutMs=3000}){
 if(!descriptor||typeof descriptor!=='object'||types.isProxy(descriptor)||!Object.isFrozen(descriptor)||typeof authority!=='function'||!outbox||typeof outbox.reserveFlight!=='function'||typeof outbox.readFlight!=='function'||typeof outbox.releaseFlight!=='function'||typeof outbox.settleFlight!=='function'||![ca,evidenceCert,evidenceKey].every(x=>Buffer.isBuffer(x)&&!types.isProxy(x)&&x.length>0&&x.length<=65536)||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>3000)throw Error('unsupported receiver sender');
 let d;try{d=bootstrap.parse(Buffer.from(JSON.stringify(descriptor)));const cert=new crypto.X509Certificate(evidenceCert),pub=cert.publicKey.export({type:'spki',format:'der'}),key=crypto.createPublicKey(crypto.createPrivateKey(evidenceKey)).export({type:'spki',format:'der'});if(!pub.equals(key)||crypto.createHash('sha256').update(cert.raw).digest('hex')!==d.receiver_evidence_leaf||crypto.createHash('sha256').update(ca).digest('hex')!==d.ca_sha256)throw Error('material');}catch(_){throw Error('unsupported receiver sender');}
 const tls={ca:Buffer.from(ca),cert:Buffer.from(evidenceCert),key:Buffer.from(evidenceKey)},epoch=BigInt(d.epoch);let closed=false,active;
 function close(){if(closed)return;closed=true;if(active)active.finish(false);tls.key.fill(0);}
 function permit(){try{const a=authority(),now=performance.now();if(!a||a.allowed!==true||a.epoch!==epoch||!Number.isFinite(now)||!Number.isFinite(a.deadline)||now>=a.deadline||a.tenant_id!==d.tenant||a.gateway_id!==d.gateway_id||a.gateway_generation!==d.gateway_generation||a.gateway_backend_leaf!==d.gateway_backend_leaf||a.receiver_runtime_id!==d.runtime||a.receiver_session_epoch!==d.epoch||a.receiver_backend_leaf!==d.receiver_backend_leaf)return undefined;return a;}catch(_){return undefined;}}
 function selected(token){
  const a=permit();if(!a)return undefined;const item=outbox.readFlight(token);if(!item||!item.ticket||typeof item.ticket!=='object'||types.isProxy(item.ticket)||!Object.isFrozen(item.ticket)||!Number.isFinite(item.deadline)||performance.now()>=item.deadline||!item.fact||typeof item.fact.canonical!=='string'||typeof item.fact.sha256!=='string')return undefined;
  const raw=Buffer.from(item.fact.canonical,'utf8');let keep=false;
  try{if(raw.length<1||raw.length>4096)return undefined;const check=decode('receiver',raw),f=check.value;
   if(check.canonical!==item.fact.canonical||check.sha256!==item.fact.sha256||f.tenant_id!==d.tenant||f.gateway_id!==d.gateway_id||f.gateway_generation!==d.gateway_generation||f.receiver_runtime_id!==d.runtime||f.receiver_session_epoch!==d.epoch||!permit())return undefined;
   keep=true;return {ticket:item.ticket,deadline:item.deadline,canonical:check.canonical,digest:check.sha256,raw,permitDeadline:a.deadline};
  }finally{if(!keep)raw.fill(0);}
 }
 function sendOnce(){
  if(closed||active)return Promise.resolve(false);const op={done:false};active=op;
  return new Promise(resolve=>{let req,res,timer,poll,original,token,chunks=[];
   function finish(ok){
    if(op.done)return;op.done=true;clearTimeout(timer);clearInterval(poll);
    for(const chunk of chunks)chunk.fill(0);chunks=[];if(original){original.raw.fill(0);original=undefined;}
    let waiting=0,cleaned=false,watchdog;
    function completed(){if(cleaned||waiting!==0)return;cleaned=true;clearTimeout(watchdog);if(token){try{if(outbox.releaseFlight(token)!==true)ok=false;}catch(_){ok=false;}token=undefined;}if(active===op)active=undefined;resolve(ok);}
    const streams=[res,req].filter(stream=>stream&&!stream.closed);waiting=streams.length;
    for(const stream of streams)stream.once('close',()=>{waiting--;completed();});
    for(const stream of streams)try{stream.destroy();}catch(_){}
    req=undefined;res=undefined;
    if(waiting){watchdog=setTimeout(()=>{if(cleaned)return;cleaned=true;if(active===op)active=undefined;resolve(false);},1000);}else completed();
   }
   op.finish=finish;
   function alive(){return active===op&&!op.done&&!closed&&Number.isFinite(performance.now())&&performance.now()<op.deadline;}
   function same(){try{if(!alive())return false;const current=selected(token);if(!current)return false;try{return alive()&&current.ticket===original.ticket&&current.deadline===original.deadline&&current.canonical===original.canonical&&current.digest===original.digest;}finally{current.raw.fill(0);}}catch(_){return false;}}
   try{
    token=outbox.reserveFlight();if(!token)return finish(false);original=selected(token);if(!original)return finish(false);op.deadline=Math.min(performance.now()+timeoutMs,original.deadline,original.permitDeadline);if(!same())return finish(false);
    timer=setTimeout(()=>finish(false),Math.max(0,op.deadline-performance.now()));poll=setInterval(()=>{try{if(!same())finish(false);}catch(_){finish(false);}},Math.min(50,timeoutMs));
    req=https.request({protocol:'https:',hostname:'causal-ingress',port:8443,path:'/v1/causal-evidence/receiver',method:'POST',ca:tls.ca,cert:tls.cert,key:tls.key,servername:'causal-ingress',rejectUnauthorized:true,agent:false,headers:{'content-type':'application/json','content-length':original.raw.length}},response=>{
     if(op.done){try{response.destroy();}catch(_){}return;}res=response;if(!same()||response.statusCode!==200||!response.socket||response.socket.authorized!==true||response.headers?.['content-type']!=='application/json')return finish(false);
     let size=0;response.on('data',chunk=>{if(!alive()||!Buffer.isBuffer(chunk)||chunk.length>1024-size)return finish(false);size+=chunk.length;chunks.push(Buffer.from(chunk));});
     response.on('error',()=>finish(false));response.on('aborted',()=>finish(false));response.on('close',()=>{if(!op.done)finish(false);});
     response.on('end',()=>{let receiptBytes,success=false;try{if(same()){receiptBytes=Buffer.concat(chunks,size);if(receipt(receiptBytes,original.digest)&&same()){success=outbox.settleFlight(token,original.ticket,original.canonical,original.digest,()=>alive()&&!!permit())===true;}}}catch(_){}finally{if(receiptBytes)receiptBytes.fill(0);}finish(success);});
    });
    req.on('error',()=>finish(false));if(!same())return finish(false);req.end(original.raw);if(!same())finish(false);
   }catch(_){finish(false);}
  });
 }
 return Object.freeze({sendOnce,close});
}
module.exports=Object.freeze({create});
