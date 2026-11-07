'use strict';
// Private one-shot CLB1 parser. The caller owns the returned seed and closes it.
const net=require('node:net'),crypto=require('node:crypto');
const DOMAIN=Buffer.from('apicontour/causal-launch/1\n','ascii');
const FIELDS=Object.freeze(['batch_bytes','batch_events','ca_sha256','epoch','export_credential','export_leaf','generation','identity','manifest_sha256','marker_public','nonce','product_credential','product_leaf','profile_id','queue_bytes','queue_ttl_ms','runtime','server_leaf','tenant','version']);
const U64=18446744073709551615n;
const uuid=x=>typeof x==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(x);
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
function encode(value){
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).join(',')!==FIELDS.join(','))throw Error('bootstrap schema');
 for(const k of ['export_credential','nonce','product_credential','profile_id','runtime','tenant'])if(!uuid(value[k]))throw Error('bootstrap schema');
 for(const k of ['ca_sha256','export_leaf','generation','identity','manifest_sha256','marker_public','product_leaf','server_leaf'])if(!hex(value[k]))throw Error('bootstrap schema');
 if(typeof value.epoch!=='string'||!/^[1-9][0-9]{0,19}$/.test(value.epoch)||BigInt(value.epoch)>U64||value.version!==1)throw Error('bootstrap schema');
 if(!Number.isSafeInteger(value.batch_events)||value.batch_events<1||value.batch_events>500||!Number.isSafeInteger(value.batch_bytes)||value.batch_bytes<512||value.batch_bytes>1048576||!Number.isSafeInteger(value.queue_bytes)||value.queue_bytes<2*value.batch_bytes||value.queue_bytes>268435456||!Number.isSafeInteger(value.queue_ttl_ms)||value.queue_ttl_ms<1||value.queue_ttl_ms>86400000)throw Error('bootstrap schema');
 if(value.generation==='0'.repeat(64)||value.identity==='0'.repeat(64))throw Error('bootstrap schema');
 return Buffer.from(JSON.stringify(value),'utf8');
}
function commitment(value){const data={};for(const k of FIELDS)if(k!=='identity')data[k]=value[k];const body=Buffer.from(JSON.stringify(data),'utf8'),len=Buffer.alloc(4);len.writeUInt32BE(body.length);return crypto.createHash('sha256').update(DOMAIN).update(len).update(body).digest('hex');}
function parse(metadata){
 let obj;try{obj=JSON.parse(metadata.toString('utf8'));}catch(_){throw Error('bootstrap schema');}
 const encoded=encode(obj);if(!encoded.equals(metadata)||commitment(obj)!==obj.identity)throw Error('bootstrap schema');
 return Object.freeze(obj);
}
function readStream(socket,timeout=5000){
 if(!socket||!Number.isSafeInteger(timeout)||timeout<1||timeout>5000)return Promise.reject(Error('bootstrap configuration'));
 return new Promise((resolve,reject)=>{
  let done=false,ended=false,size=0,chunks=[],expected;const timer=setTimeout(()=>finish(Error('bootstrap deadline')),timeout);
  function finish(error){if(done)return;done=true;clearTimeout(timer);if(error){socket.destroy();for(const x of chunks)x.fill(0);return reject(error);}const frame=Buffer.concat(chunks,size);for(const x of chunks)x.fill(0);let seed;try{const meta=frame.subarray(8,expected-32);seed=Buffer.from(frame.subarray(expected-32));const descriptor=parse(meta);frame.fill(0);resolve({descriptor,seed});}catch(_){frame.fill(0);if(seed)seed.fill(0);reject(Error('bootstrap invalid'));}}
  socket.on('data',chunk=>{if(done)return;if(!Buffer.isBuffer(chunk)||chunk.length>16424-size)return finish(Error('bootstrap size'));size+=chunk.length;chunks.push(Buffer.from(chunk));
   if(expected===undefined&&size>=8){const header=Buffer.concat(chunks,8);if(!header.subarray(0,4).equals(Buffer.from('CLB1','ascii')))return finish(Error('bootstrap header'));const n=header.readUInt32BE(4);if(n<1||n>16384)return finish(Error('bootstrap size'));expected=8+n+32;}
   if(expected!==undefined&&size>expected)finish(Error('bootstrap trailing'));
  });
  socket.on('end',()=>{ended=true;if(expected===undefined||size!==expected)return finish(Error('bootstrap truncated'));socket.destroy();});
  socket.on('error',()=>finish(Error('bootstrap read')));socket.on('close',()=>{if(!ended)return finish(Error('bootstrap closed'));finish();});
 });
}
let claimed=false;
function read(fd=3,timeout=5000){
 if(fd!==3||claimed)return Promise.reject(Error('bootstrap configuration'));
 claimed=true;
 let socket;try{socket=new net.Socket({fd,readable:true,writable:false,allowHalfOpen:true});}catch(_){try{require('node:fs').closeSync(fd);}catch(_){}return Promise.reject(Error('bootstrap socket'));}
 return readStream(socket,timeout);
}
module.exports=Object.freeze({read,readStream,parse,commitment});
