'use strict';
// Data-only CLB2 parser. Neither parsing nor a commitment establishes authority.
const net=require('node:net'),crypto=require('node:crypto');
const DOMAIN=Buffer.from('apicontour/causal-receiver-launch/2\n','ascii');
const PROFILE='00000000-0000-4000-8000-000000000504';
const PROFILE_NAME='nodered_5_0_9_receiver_v1';
const FIELDS=Object.freeze(['artifact_sha256','batch_bytes','batch_events','ca_sha256','epoch','export_credential','export_leaf','gateway_backend_leaf','gateway_generation','gateway_id','generation','identity','launch_slot','launcher_sha256','manifest_sha256','marker_public','nonce','product_credential','product_leaf','profile_id','profile_name','queue_bytes','queue_ttl_ms','receiver_backend_leaf','receiver_enrollment_commitment','receiver_evidence_credential','receiver_evidence_leaf','runtime','server_leaf','tenant','version']);
const U64=18446744073709551615n;
const uuid=x=>typeof x==='string'&&x.length===36&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![\s\S])/.test(x);
const hex=(x,n=64)=>typeof x==='string'&&x.length===n&&/^[0-9a-f]+(?![\s\S])/.test(x);
function encode(value){
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).join(',')!==FIELDS.join(','))throw Error('bootstrap schema');
 for(const k of ['export_credential','gateway_id','nonce','product_credential','profile_id','receiver_evidence_credential','runtime','tenant'])if(!uuid(value[k]))throw Error('bootstrap schema');
 for(const k of ['artifact_sha256','ca_sha256','export_leaf','gateway_backend_leaf','generation','identity','launch_slot','launcher_sha256','manifest_sha256','marker_public','product_leaf','receiver_backend_leaf','receiver_enrollment_commitment','receiver_evidence_leaf','server_leaf'])if(!hex(value[k]))throw Error('bootstrap schema');
 if(!hex(value.gateway_generation,32)||value.gateway_generation==='0'.repeat(32)||value.profile_id!==PROFILE||value.profile_name!==PROFILE_NAME||value.version!==2)throw Error('bootstrap schema');
 if(typeof value.epoch!=='string'||!/^[1-9][0-9]{0,19}(?![\s\S])/.test(value.epoch)||BigInt(value.epoch)>U64)throw Error('bootstrap schema');
 if(!Number.isSafeInteger(value.batch_events)||value.batch_events<1||value.batch_events>500||!Number.isSafeInteger(value.batch_bytes)||value.batch_bytes<512||value.batch_bytes>1048576||!Number.isSafeInteger(value.queue_bytes)||value.queue_bytes<2*value.batch_bytes||value.queue_bytes>268435456||!Number.isSafeInteger(value.queue_ttl_ms)||value.queue_ttl_ms<1||value.queue_ttl_ms>86400000)throw Error('bootstrap schema');
 for(const k of ['artifact_sha256','generation','identity','launch_slot','launcher_sha256','manifest_sha256','receiver_enrollment_commitment'])if(value[k]==='0'.repeat(64))throw Error('bootstrap schema');
 if(value.server_leaf!==value.receiver_backend_leaf||new Set([value.product_leaf,value.export_leaf,value.server_leaf,value.receiver_evidence_leaf,value.gateway_backend_leaf]).size!==5||new Set([value.product_credential,value.export_credential,value.receiver_evidence_credential]).size!==3)throw Error('bootstrap schema');
 return Buffer.from(JSON.stringify(value),'utf8');
}
function commitment(value){const data={};for(const k of FIELDS)if(k!=='identity')data[k]=value[k];const body=Buffer.from(JSON.stringify(data),'utf8'),len=Buffer.alloc(4);len.writeUInt32BE(body.length);return crypto.createHash('sha256').update(DOMAIN).update(len).update(body).digest('hex');}
function parse(metadata){
 if(!Buffer.isBuffer(metadata)||metadata.length<1||metadata.length>16384)throw Error('bootstrap schema');
 let obj;try{obj=JSON.parse(metadata.toString('utf8'));}catch(_){throw Error('bootstrap schema');}
 const encoded=encode(obj);if(!encoded.equals(metadata)||commitment(obj)!==obj.identity)throw Error('bootstrap schema');
 return Object.freeze(obj);
}
function readStream(socket,timeout=5000,signal){
 if(!socket||!Number.isSafeInteger(timeout)||timeout<1||timeout>5000||(signal!==undefined&&!(signal instanceof AbortSignal)))return Promise.reject(Error('bootstrap configuration'));
 return new Promise((resolve,reject)=>{
  let done=false,ended=false,size=0,chunks=[],expected;const timer=setTimeout(()=>finish(Error('bootstrap deadline')),timeout);
  function finish(error){if(done)return;done=true;clearTimeout(timer);if(signal)signal.removeEventListener('abort',abort);socket.removeListener('data',data);socket.removeListener('end',end);socket.removeListener('error',failure);socket.removeListener('close',closed);
   if(error){socket.destroy();for(const x of chunks)x.fill(0);chunks=[];return reject(error);}
   const frame=Buffer.concat(chunks,size);for(const x of chunks)x.fill(0);chunks=[];let seed;
   try{const descriptor=parse(frame.subarray(8,expected-32));seed=Buffer.from(frame.subarray(expected-32));frame.fill(0);resolve({descriptor,seed});}
   catch(_){frame.fill(0);if(seed)seed.fill(0);reject(Error('bootstrap invalid'));}
  }
  function abort(){finish(Error('bootstrap cancelled'));}
  function data(chunk){if(done)return;if(!Buffer.isBuffer(chunk)||chunk.length>16424-size)return finish(Error('bootstrap size'));size+=chunk.length;chunks.push(Buffer.from(chunk));
   if(expected===undefined&&size>=8){const header=Buffer.concat(chunks,8);const valid=header.subarray(0,4).equals(Buffer.from('CLB2','ascii'));const n=header.readUInt32BE(4);header.fill(0);if(!valid)return finish(Error('bootstrap header'));if(n<1||n>16384)return finish(Error('bootstrap size'));expected=8+n+32;}
   if(expected!==undefined&&size>expected)finish(Error('bootstrap trailing'));
  }
  function end(){ended=true;if(expected===undefined||size!==expected)return finish(Error('bootstrap truncated'));socket.destroy();}
  function failure(){finish(Error('bootstrap read'));}
  function closed(){if(!ended)return finish(Error('bootstrap closed'));finish();}
  socket.on('data',data);socket.on('end',end);socket.on('error',failure);socket.on('close',closed);
  if(signal){signal.addEventListener('abort',abort,{once:true});if(signal.aborted)abort();}
 });
}
let claimed=false;
function read(fd=3,timeout=5000,signal){
 if(fd!==3||claimed||!Number.isSafeInteger(timeout)||timeout<1||timeout>5000||(signal!==undefined&&!(signal instanceof AbortSignal)))return Promise.reject(Error('bootstrap configuration'));claimed=true;
 let socket;try{socket=new net.Socket({fd,readable:true,writable:false,allowHalfOpen:true});}catch(_){try{require('node:fs').closeSync(fd);}catch(_){}return Promise.reject(Error('bootstrap socket'));}
 return readStream(socket,timeout,signal);
}
module.exports=Object.freeze({read,readStream,parse,commitment});
