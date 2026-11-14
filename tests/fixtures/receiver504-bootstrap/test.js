'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),{PassThrough}=require('node:stream');
const bootstrap=require('../../../collectors/nodered/receiver-integration/private-bootstrap-504');
const vector=JSON.parse(fs.readFileSync(__dirname+'/vector.json','utf8'));
const raw=Buffer.from(vector.canonical,'utf8'),base=JSON.parse(vector.canonical);
function signed(changes={}){const obj={...base,...changes};obj.identity=bootstrap.commitment(obj);return Buffer.from(JSON.stringify(obj));}
function frame(body=raw,magic='CLB2',seed=Buffer.alloc(32,9)){const h=Buffer.alloc(8);h.write(magic);h.writeUInt32BE(body.length,4);return Buffer.concat([h,body,seed]);}
async function stream(parts,{timeout=200,signal,finish=true}={}){const s=new PassThrough();const p=bootstrap.readStream(s,timeout,signal);for(const x of parts)s.write(x);if(finish)s.end();return p;}
(async()=>{
 assert.equal(bootstrap.commitment(base),vector.identity);assert.equal(bootstrap.parse(raw).epoch,'18446744073709551615');assert(Object.isFrozen(bootstrap.parse(raw)));
 const domain=Buffer.from('apicontour/causal-receiver-launch/2\n');const body={...base};delete body.identity;const canonical=Buffer.from(JSON.stringify(body));const n=Buffer.alloc(4);n.writeUInt32BE(canonical.length);assert.equal(crypto.createHash('sha256').update(domain).update(n).update(canonical).digest('hex'),vector.identity);
 for(const epoch of ['1','18446744073709551615'])assert.equal(bootstrap.parse(signed({epoch})).epoch,epoch);
 for(const epoch of ['0','01','18446744073709551616','-1',1])assert.throws(()=>bootstrap.parse(signed({epoch})));
 const uuidFields=['export_credential','gateway_id','nonce','product_credential','profile_id','receiver_evidence_credential','runtime','tenant'];
 const hexFields=['artifact_sha256','ca_sha256','export_leaf','gateway_backend_leaf','gateway_generation','generation','launch_slot','launcher_sha256','manifest_sha256','marker_public','product_leaf','receiver_backend_leaf','receiver_enrollment_commitment','receiver_evidence_leaf','server_leaf'];
 for(const ending of ['\n','\r','\u2028','\u2029']){
  for(const key of uuidFields)assert.throws(()=>bootstrap.parse(signed({[key]:base[key]+ending})),key);
  for(const key of hexFields){
   const bad=base[key].slice(0,-1)+ending;
   const changes=(key==='server_leaf'||key==='receiver_backend_leaf')?{server_leaf:bad,receiver_backend_leaf:bad}:{[key]:bad};
   assert.throws(()=>bootstrap.parse(signed(changes)),key);
  }
  const badIdentity={...base,identity:base.identity.slice(0,-1)+ending};
  assert.throws(()=>bootstrap.parse(Buffer.from(JSON.stringify(badIdentity))),'identity');
  assert.throws(()=>bootstrap.parse(signed({epoch:'1'+ending})),'epoch');
 }
 for(const changes of [{version:1},{profile_id:'00000000-0000-4000-8000-000000000503'},{profile_name:'other'},{gateway_generation:'a'.repeat(64)},{generation:'b'.repeat(32)},{server_leaf:'f'.repeat(64)},{receiver_evidence_leaf:base.product_leaf},{gateway_backend_leaf:base.export_leaf},{receiver_evidence_credential:base.product_credential},{batch_bytes:511},{queue_bytes:1},{queue_ttl_ms:86400001},{artifact_sha256:'0'.repeat(64)}])assert.throws(()=>bootstrap.parse(signed(changes)));
 assert.throws(()=>bootstrap.parse(Buffer.from(vector.canonical.replace('"version":2','"version":2,"version":2'))));
 assert.throws(()=>bootstrap.parse(Buffer.from(vector.canonical.replace('"version":2','"unknown":1,"version":2'))));
 assert.throws(()=>bootstrap.parse(Buffer.from(vector.canonical.replace('"version":2','"version":2 '))));
 const wrong={...base};wrong.identity=crypto.createHash('sha256').update('wrong domain').digest('hex');assert.throws(()=>bootstrap.parse(Buffer.from(JSON.stringify(wrong))));
 const framed=frame();const result=await stream([...framed].map(x=>Buffer.from([x])));assert.deepEqual(result.descriptor,base);assert.deepEqual(result.seed,Buffer.alloc(32,9));result.seed.fill(0);
 await assert.rejects(stream([frame(raw,'CLB1')]));await assert.rejects(stream([framed.subarray(0,framed.length-1)]));await assert.rejects(stream([Buffer.concat([framed,Buffer.from([1])])]));
 const bad=Buffer.alloc(8);bad.write('CLB2');bad.writeUInt32BE(16385,4);await assert.rejects(stream([bad]));
 await assert.rejects(stream([],{timeout:5,finish:false}));const controller=new AbortController();controller.abort();await assert.rejects(stream([],{signal:controller.signal,finish:false}));
 // Inspect only internally allocated copies; caller-owned input remains caller-owned.
 for(const mode of ['parse','timeout','cancel']){
  const tracked=[],from=Buffer.from,concat=Buffer.concat;const controller=new AbortController();
  const bytes=mode==='parse'?frame(Buffer.from('{}')):framed.subarray(0,12);
  try{
   Buffer.from=function(value,...args){const out=from.call(Buffer,value,...args);if(Buffer.isBuffer(value))tracked.push(out);return out;};
   Buffer.concat=function(...args){const out=concat.apply(Buffer,args);tracked.push(out);return out;};
   const s=new PassThrough(),pending=bootstrap.readStream(s,mode==='timeout'?5:200,mode==='cancel'?controller.signal:undefined);
   s.write(bytes);
   if(mode==='parse')s.end();if(mode==='cancel')controller.abort();
   await assert.rejects(pending);
  }finally{Buffer.from=from;Buffer.concat=concat;}
  assert(tracked.length>0);assert(tracked.every(buffer=>buffer.every(x=>x===0)));
 }
 console.log('receiver 504 bootstrap data-only tests passed');
})().catch(()=>{console.error('receiver 504 bootstrap tests failed');process.exitCode=1;});
