'use strict';
// Dormant private channel: a parent response is not independently verified here.
// Only a future trusted parent may issue positive permits after its own checks.
const net=require('node:net'),crypto=require('node:crypto'),{performance}=require('node:perf_hooks');
const {types}=require('node:util');
const bootstrap=require('./private-bootstrap-504');
function create({fd,descriptor,signal}){
 if(!Number.isInteger(fd)||fd<3||!descriptor||typeof descriptor!=='object'||types.isProxy(descriptor)||!Object.isFrozen(descriptor)||(signal!==undefined&&!(signal instanceof AbortSignal)))throw Error('invalid owner channel');
 let checked;try{checked=bootstrap.parse(Buffer.from(JSON.stringify(descriptor),'utf8'));}catch(_){throw Error('invalid owner channel');}
 const gen=Buffer.from(checked.generation,'hex'),identity=Buffer.from(checked.identity,'hex'),commitment=Buffer.from(checked.receiver_enrollment_commitment,'hex'),expectedEpoch=BigInt(checked.epoch);
 const scope=Object.freeze({tenant_id:checked.tenant,gateway_id:checked.gateway_id,gateway_generation:checked.gateway_generation,gateway_backend_leaf:checked.gateway_backend_leaf,receiver_runtime_id:checked.runtime,receiver_session_epoch:checked.epoch,receiver_backend_leaf:checked.receiver_backend_leaf});
 let socket;try{socket=new net.Socket({fd,readable:true,writable:true});}catch(_){throw Error('invalid owner channel');}
 let closed=false,counter=0n,deadline=0,pending,buffer=Buffer.alloc(0),timer,refresh,startup,resources;
 let readyResolve,readyReject;const ready=new Promise((resolve,reject)=>{readyResolve=resolve;readyReject=reject;});
 function close(){if(closed)return;closed=true;clearTimeout(timer);clearTimeout(refresh);clearTimeout(startup);if(signal)signal.removeEventListener('abort',close);buffer.fill(0);buffer=Buffer.alloc(0);if(pending){pending.frame.fill(0);pending=undefined;}socket.destroy();if(resources)for(const x of [resources.producer,resources.exporter,resources.signer])try{if(x&&typeof x.close==='function')x.close();}catch(_){}readyReject(Error('owner unavailable'));}
 function gate(){const now=performance.now();if(closed||!Number.isFinite(now)||!deadline||now>=deadline){close();return false;}return true;}
 function authority(){return gate()?Object.freeze({...scope,epoch:expectedEpoch,allowed:true,deadline}):undefined;}
 function request(){
  if(closed||pending)return close();const start=performance.now();if(!Number.isFinite(start)||(deadline&&start>=deadline))return close();
  counter++;if(counter>(1n<<64n)-1n)return close();let frame;
  try{const challenge=crypto.randomBytes(32);if(!Buffer.isBuffer(challenge)||challenge.length!==32)throw Error('random');frame=Buffer.alloc(140);frame.write('CQP2');gen.copy(frame,4);identity.copy(frame,36);frame.writeBigUInt64BE(counter,68);challenge.copy(frame,76);challenge.fill(0);commitment.copy(frame,108);pending={start,frame};
   timer=setTimeout(close,Math.max(0,(deadline?Math.min(deadline,start+2000):start+2000)-performance.now()));
   socket.write(frame,e=>{if(e)close();});
  }catch(_){if(frame&&!pending)frame.fill(0);close();}
 }
 socket.on('data',data=>{if(closed)return;if(!pending||!Buffer.isBuffer(data)||data.length>152-buffer.length)return close();const previous=buffer;buffer=Buffer.concat([previous,data]);previous.fill(0);if(buffer.length<152)return;
  const received=performance.now(),p=pending,r=buffer;buffer=Buffer.alloc(0);pending=undefined;clearTimeout(timer);
  try{const epoch=r.readBigUInt64BE(140),ms=r.readUInt32BE(148),end=p.start+ms;
   if(r.subarray(0,4).toString()!=='CRP2'||!r.subarray(4,140).equals(p.frame.subarray(4))||epoch!==expectedEpoch||ms<1||ms>1000||!Number.isFinite(received)||!Number.isFinite(end)||received>=end||(deadline&&received>=deadline))return close();
   deadline=end;clearTimeout(startup);readyResolve();refresh=setTimeout(request,Math.max(0,Math.min(250,deadline-performance.now()-1)));
  }catch(_){close();}finally{p.frame.fill(0);r.fill(0);}
 });
 socket.on('error',close);socket.on('end',close);socket.on('close',close);
 function bind({producer,exporter,signer}){
  if(resources||closed||!producer||!exporter||!signer||typeof producer.close!=='function'||typeof exporter.close!=='function'||typeof signer.sign!=='function')throw Error('invalid resources');
  resources={producer,exporter,signer};return Object.freeze({sign(input){if(!gate())throw Error('owner unavailable');const value=signer.sign(input);if(!gate())throw Error('owner unavailable');return value;}});
 }
 startup=setTimeout(close,5000);if(signal){signal.addEventListener('abort',close,{once:true});if(signal.aborted)close();}
 if(!closed)request();return Object.freeze({ready,authority,bind,close});
}
module.exports=Object.freeze({create});
