'use strict';
// Dormant private building block; no enrollment, durable queue, or retry scheduler.
const https=require('node:https'),crypto=require('node:crypto'),{performance}=require('node:perf_hooks');
const {parse}=require('./private-causal-receipt');
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const max=(1n<<64n)-1n;
function validTime(value){
 const m=/^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$/.exec(value);
 if(!m)return false;const [,y,month,day,hour,minute,second,zone]=m;const year=Number(y),mo=Number(month),d=Number(day);const leap=year%4===0&&(year%100!==0||year%400===0);const days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
 return mo>=1&&mo<=12&&d>=1&&d<=days[mo-1]&&Number(hour)<=23&&Number(minute)<=59&&Number(second)<=59&&(zone==='Z'||(Number(zone.slice(1,3))<=23&&Number(zone.slice(4,6))<=59))&&Number.isFinite(Date.parse(value));
}
function create({endpoint,ca,cert,key,runtimeId,epoch,handoff,timeoutMs=5000,maxBodyBytes=1048576}){
 let url;try{url=new URL(endpoint);}catch(_){throw Error('unsupported exporter');}
 if(typeof endpoint!=='string'||url.protocol!=='https:'||!url.hostname||url.username||url.password||url.hash||url.search||url.pathname!=='/v1/causal-events'||!uuid.test(runtimeId)||typeof epoch!=='bigint'||epoch<1n||epoch>max||![ca,cert,key].every(x=>Buffer.isBuffer(x)&&x.length>0&&x.length<=65536)||!handoff||!['gate','freeze','ack'].every(k=>typeof handoff[k]==='function')||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>30000||!Number.isSafeInteger(maxBodyBytes)||maxBodyBytes<512||maxBodyBytes>1048576)throw Error('unsupported exporter');
 const tls={ca:Buffer.from(ca),cert:Buffer.from(cert),key:Buffer.from(key)},host=url.hostname.startsWith('[')?url.hostname.slice(1,-1):url.hostname,port=url.port||443,path=url.pathname;let closed=false,active;
 function close(){closed=true;if(active)active.finish(false);}
 function sendOnce(){
  if(closed||active)return Promise.resolve(false);
  const op={done:false,deadline:performance.now()+timeoutMs};active=op;
  return new Promise(resolve=>{let req,res,timer,poll;
   const alive=()=>active===op&&!op.done&&!closed&&performance.now()<op.deadline;
   function finish(success){if(op.done)return;op.done=true;clearTimeout(timer);clearInterval(poll);if(active===op)active=undefined;if(res)res.destroy();if(req)req.destroy();resolve(success);}
   op.finish=finish;
   function gated(){if(!alive())return false;const ok=handoff.gate();return ok===true&&alive();}
   try{
    if(!gated())return finish(false);const batch=handoff.freeze();if(!alive()||!batch||!gated()||batch.epoch!==epoch||!uuid.test(batch.batchId)||typeof batch.canonical!=='string'||!/^[0-9a-f]{64}$/.test(batch.sha256))return finish(false);
    const body=Buffer.from(batch.canonical,'utf8');if(body.length>maxBodyBytes||crypto.createHash('sha256').update('apicontour/causal-events/1\n').update(body).digest('hex')!==batch.sha256||!alive())return finish(false);
    timer=setTimeout(()=>finish(false),Math.max(0,op.deadline-performance.now()));poll=setInterval(()=>{try{if(!gated())finish(false);}catch(_){finish(false);}},Math.min(50,timeoutMs));
    if(!alive())return finish(false);
    req=https.request({protocol:'https:',hostname:host,port,path,method:'POST',ca:tls.ca,cert:tls.cert,key:tls.key,rejectUnauthorized:true,agent:false,headers:{'content-type':'application/json','content-length':body.length}},response=>{
     res=response;if(!alive()){response.destroy();return finish(false);}if(response.statusCode!==200||!response.socket||response.socket.authorized!==true){finish(false);return;}let size=0,chunks=[];
     response.on('data',chunk=>{if(!alive())return finish(false);size+=chunk.length;if(size>4096){finish(false);return;}chunks.push(Buffer.from(chunk));});response.on('error',()=>finish(false));response.on('aborted',()=>finish(false));response.on('end',()=>{if(!alive())return finish(false);try{const r=parse(Buffer.concat(chunks,size));const valid=r.batch_id===batch.batchId&&r.runtime_id===runtimeId&&r.session_epoch===epoch&&r.batch_digest===batch.sha256&&uuid.test(r.receipt_id)&&validTime(r.accepted_at)&&['accepted','duplicate'].includes(r.status);if(valid&&gated()&&handoff.ack(batch.batchId,batch.sha256,epoch,alive)===true)return finish(true);}catch(_){}finish(false);});response.on('close',()=>{if(!op.done)finish(false);});
    });
    req.on('error',()=>finish(false));if(!alive()){req.destroy();return finish(false);}req.end(body);if(!alive())finish(false);
   }catch(_){finish(false);}
  });
 }

 return Object.freeze({sendOnce,close});
}
module.exports=Object.freeze({create});
