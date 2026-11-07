'use strict';
// Dormant trusted-launcher primitive: the fd is an inherited private Unix socket.
// Never hand the raw signer to application code. The wrapper blocks signing
// after invalidation; it does not erase key material. This is not source attestation.
const net=require('node:net'),crypto=require('node:crypto'),{performance}=require('node:perf_hooks');
function create({fd,generation,identity}) {
 if(!Number.isInteger(fd)||fd<3||!Buffer.isBuffer(generation)||generation.length!==32||!generation.some(Boolean)||!Buffer.isBuffer(identity)||identity.length!==32||!identity.some(Boolean))throw Error('invalid owner channel');
 const gen=Buffer.from(generation),config=Buffer.from(identity),socket=new net.Socket({fd,readable:true,writable:true});
 let closed=false,counter=0n,epoch,deadline=0,pending,buffer=Buffer.alloc(0),timer,refresh,resources;
 let readyResolve,readyReject;const ready=new Promise((resolve,reject)=>{readyResolve=resolve;readyReject=reject;});
 function close(){if(closed)return;closed=true;clearTimeout(timer);clearTimeout(refresh);socket.destroy();if(resources)for(const x of [resources.producer,resources.exporter,resources.signer])try{if(x&&typeof x.close==='function')x.close();}catch(_){}readyReject(Error('owner unavailable'));}
 function gate(){if(closed||!epoch||performance.now()>=deadline){close();return false;}return true;}
 function authority(){return gate()?Object.freeze({epoch,allowed:true,deadline}):undefined;}
 function request(){
  if(closed||pending)return close();const start=performance.now();if(epoch&&start>=deadline)return close();
  counter++;if(counter>(1n<<64n)-1n)return close();const challenge=crypto.randomBytes(32),frame=Buffer.alloc(108);frame.write('CQP1');gen.copy(frame,4);config.copy(frame,36);frame.writeBigUInt64BE(counter,68);challenge.copy(frame,76);pending={start,frame};
  timer=setTimeout(close,Math.max(0,(epoch?Math.min(deadline,start+2000):start+2000)-performance.now()));
  socket.write(frame,e=>{if(e)close();});
 }
 socket.on('data',data=>{if(closed)return;if(!pending||data.length>120-buffer.length)return close();buffer=Buffer.concat([buffer,data]);if(buffer.length<120)return;
  const received=performance.now(),p=pending,r=buffer;buffer=Buffer.alloc(0);pending=undefined;clearTimeout(timer);
  const value=r.readBigUInt64BE(108),ms=r.readUInt32BE(116),end=p.start+ms;
  if(r.subarray(0,4).toString()!=='CRP1'||!r.subarray(4,108).equals(p.frame.subarray(4))||!value||ms<1||ms>1000||received>=end||(epoch&&value!==epoch)||(epoch&&received>=deadline))return close();
  epoch=value;deadline=end;readyResolve();refresh=setTimeout(request,Math.max(0,Math.min(250,deadline-performance.now()-1)));
 });
 socket.on('error',close);socket.on('end',close);socket.on('close',close);
 function bind({producer,exporter,signer}){
  if(resources||closed||!producer||!exporter||!signer||typeof producer.close!=='function'||typeof exporter.close!=='function'||typeof signer.sign!=='function')throw Error('invalid resources');
  resources={producer,exporter,signer};return Object.freeze({sign(input){if(!gate())throw Error('owner unavailable');const value=signer.sign(input);if(!gate())throw Error('owner unavailable');return value;}});
 }
 request();return Object.freeze({ready,authority,bind,close});
}
module.exports=Object.freeze({create});
