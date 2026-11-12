'use strict';
// One-shot in-container attach bridge. Child business streams are never control.
// The parent must inspect this container before sending the private bootstrap.
const fs=require('node:fs'),{spawn}=require('node:child_process');
const bootstrap=require('./private-bootstrap-504');
const MAX=16424, MAGIC=Buffer.from('CBP2');
class Decoder {
 constructor(deliver,fail){this.deliver=deliver;this.fail=fail;this.pending=Buffer.alloc(0);this.failed=false;}
 push(data){if(this.failed)return;try{if(!Buffer.isBuffer(data)||data.length>MAX+9-this.pending.length)throw Error('size');this.pending=Buffer.concat([this.pending,data]);while(this.pending.length>=9){if(!this.pending.subarray(0,4).equals(MAGIC))throw Error('magic');const n=this.pending.readUInt32BE(5);if(n>MAX)throw Error('size');if(this.pending.length<9+n)return;const type=this.pending[4],body=Buffer.from(this.pending.subarray(9,9+n));const old=this.pending;this.pending=Buffer.from(old.subarray(9+n));old.fill(0);try{this.deliver(type,body);}finally{body.fill(0);}if(this.failed)return;}}catch(_){this.stop();this.fail();}}
 stop(){this.failed=true;this.pending.fill(0);this.pending=Buffer.alloc(0);}
 end(){if(this.pending.length){this.stop();this.fail();}}
}
function frame(type,payload){if(!Number.isInteger(type)||type<0||type>255||!Buffer.isBuffer(payload)||payload.length>MAX)throw Error('frame');const head=Buffer.alloc(9);MAGIC.copy(head);head[4]=type;head.writeUInt32BE(payload.length,5);return Buffer.concat([head,payload]);}
function procStart(pid){const value=fs.readFileSync('/proc/'+pid+'/stat','utf8'),end=value.lastIndexOf(') ');if(end<0)throw Error('stat');const part=value.slice(end+2).split(' ')[19];if(!/^[0-9]{1,20}$/.test(part))throw Error('stat');const n=BigInt(part);if(n<1n||n>18446744073709551615n)throw Error('stat');return n;}
function pidFrame(pid){if(!Number.isSafeInteger(pid)||pid<1||pid>0xffffffff)throw Error('pid');const out=Buffer.alloc(12);out.writeUInt32BE(pid);out.writeBigUInt64BE(procStart(pid),4);return out;}
function inspectBootstrap(body){if(body.length<41||body.length>MAX||!body.subarray(0,4).equals(Buffer.from('CLB2')))throw Error('bootstrap');const n=body.readUInt32BE(4);if(n<1||n>16384||body.length!==8+n+32)throw Error('bootstrap');return bootstrap.parse(body.subarray(8,8+n));}
function run(){
 const allowed=['FLOWS','HOME','HOSTNAME','LANG','NODE_PATH','NODE_RED_VERSION','NODE_VERSION','PATH','TZ','YARN_VERSION'];
 if(Object.keys(process.env).sort().join(',')!==allowed.join(',')||process.stdin.isTTY||process.stdout.isTTY||process.stderr.isTTY||process.execPath!=='/usr/local/bin/node'||JSON.stringify(process.argv)!=='["/usr/local/bin/node","/adapter/receiver-integration/private-launch-proxy-504.js"]'||process.execArgv.length){process.exitCode=1;return;}
 let phase='hello',child,attached=true,request,childBuffer=Buffer.alloc(0),status=Buffer.alloc(0),statusEnded=false,readyTimer,responseTimer,outputBlocked=false,responseCount=0,replyWriting=false,privateFrame,pendingReady;
 const input=process.stdin,output=process.stdout;
 function captureOff(){if(!attached)return;attached=false;clearTimeout(readyTimer);clearTimeout(responseTimer);decoder.stop();childBuffer.fill(0);childBuffer=Buffer.alloc(0);status.fill(0);status=Buffer.alloc(0);if(pendingReady){pendingReady.fill(0);pendingReady=undefined;}if(request){request.fill(0);request=undefined;}if(privateFrame){privateFrame.fill(0);privateFrame=undefined;try{child.stdio[3].destroy();}catch(_){}}if(child){try{child.stdio[4].destroy();}catch(_){}try{child.stdio[5].destroy();}catch(_){}}else{process.exitCode=1;try{input.destroy();}catch(_){}try{output.end();}catch(_){}}}
 function emit(type,payload){if(!attached)return false;try{if(outputBlocked)return captureOff(),false;const bytes=frame(type,payload);outputBlocked=!output.write(bytes,()=>{outputBlocked=false;});if(outputBlocked){captureOff();return false;}return true;}catch(_){captureOff();return false;}}
 function deliverReady(){if(!attached)return false;if(pendingReady&&!request&&childBuffer.length===0){const ready=pendingReady;pendingReady=undefined;clearTimeout(readyTimer);const ok=emit(89,ready);ready.fill(0);return ok;}return true;}
 function onceBuffer(current,part,limit){if(!Buffer.isBuffer(part)||part.length>limit-current.length)throw Error('size');return Buffer.concat([current,part]);}
 function onFrame(type,body){
  if(phase==='hello'){if(type!==73||body.length!==32||body.every(x=>x===0))throw Error('hello');const hello=Buffer.concat([body,pidFrame(process.pid)]);phase='bootstrap';if(!emit(72,hello))throw Error('output');return;}
  if(phase==='bootstrap'){
   if(type!==66)throw Error('phase');const d=inspectBootstrap(body),gen=Buffer.from(d.generation,'hex'),identity=Buffer.from(d.identity,'hex'),enrollment=Buffer.from(d.receiver_enrollment_commitment,'hex'),epoch=BigInt(d.epoch);
   child=spawn('/usr/local/bin/node',['/adapter/receiver-integration/live-main-504.js'],{stdio:['ignore','ignore','ignore','pipe','pipe','pipe'],env:process.env});phase='running';
   child.on('error',captureOff);child.on('exit',()=>{captureOff();try{input.destroy();}catch(_){}try{output.end();}catch(_){}});
   if(!emit(83,pidFrame(child.pid)))throw Error('output');
   privateFrame=Buffer.from(body);child.stdio[3].on('error',captureOff);child.stdio[3].end(privateFrame,()=>{if(privateFrame){privateFrame.fill(0);privateFrame=undefined;}});
   const channel=child.stdio[4];channel.on('error',captureOff);channel.on('end',captureOff);channel.on('close',captureOff);
   channel.on('data',part=>{try{if(!attached||request)throw Error('pending');childBuffer=onceBuffer(childBuffer,part,140);if(childBuffer.length<140)return;const q=childBuffer;childBuffer=Buffer.alloc(0);if(!q.subarray(0,4).equals(Buffer.from('CQP2'))||!q.subarray(4,36).equals(gen)||!q.subarray(36,68).equals(identity)||!q.subarray(108,140).equals(enrollment))throw Error('request');request=q;if(!emit(81,q))throw Error('output');responseTimer=setTimeout(captureOff,responseCount===0?2000:500);}catch(_){captureOff();}});
   const signal=child.stdio[5];signal.on('error',captureOff);signal.on('data',part=>{try{if(statusEnded)throw Error('status');status=onceBuffer(status,part,76);}catch(_){captureOff();}});
   signal.on('end',()=>{statusEnded=true;signal.destroy();});
   signal.on('close',()=>{try{if(!attached||!statusEnded||status.length!==76||!status.subarray(0,4).equals(Buffer.from('CLR2'))||!status.subarray(4,36).equals(gen)||!status.subarray(36,68).equals(identity)||status.readBigUInt64BE(68)!==epoch)throw Error('status');pendingReady=Buffer.from(status);status.fill(0);status=Buffer.alloc(0);if(!deliverReady())throw Error('output');}catch(_){captureOff();}});signal.end();readyTimer=setTimeout(captureOff,15000);return;
  }
  if(phase==='running'){
   if(type!==82||body.length!==152||!request||replyWriting||!body.subarray(0,4).equals(Buffer.from('CRP2'))||!body.subarray(4,140).equals(request.subarray(4,140)))throw Error('response');
   replyWriting=true;const channel=child.stdio[4],copy=Buffer.from(body);channel.pause();channel.write(copy,err=>{copy.fill(0);if(err)return captureOff();if(!request||!replyWriting)return captureOff();clearTimeout(responseTimer);replyWriting=false;request.fill(0);request=undefined;responseCount++;if(!deliverReady())return captureOff();if(attached)channel.resume();});return;
  }
  throw Error('phase');
 }
 const decoder=new Decoder(onFrame,captureOff);input.on('data',chunk=>decoder.push(chunk));input.on('end',()=>{decoder.end();captureOff();});input.on('error',captureOff);output.on('error',captureOff);
}
if(require.main===module)run();
module.exports=Object.freeze({Decoder,frame,inspectBootstrap});
