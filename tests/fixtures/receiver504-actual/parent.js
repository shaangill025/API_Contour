'use strict';
// Root-owned synthetic component parent. No database, deployment or edge proof.
const fs=require('node:fs'),crypto=require('node:crypto'),https=require('node:https'),net=require('node:net'),{spawn}=require('node:child_process');
const bootstrap=require('/adapter/receiver-integration/private-bootstrap-504');
const KEYS=['backend_cert','backend_key','gateway_cert','gateway_key','ingress_cert','ingress_key','seed'];
const STAGES=new Set(['input','material','metadata','listeners','proxy','bootstrap','readiness','request','batch','cleanup','complete']);
const diag={stage:'input',failure:undefined,hello:false,spawned:false,ready:false,refresh:0,proxy:'none'};
function diagnostic(){const stage=STAGES.has(diag.failure)?diag.failure:STAGES.has(diag.stage)?diag.stage:'input';const proxy=['none','zero','nonzero','signal','other'].includes(diag.proxy)?diag.proxy:'other';const count=Number.isSafeInteger(diag.refresh)?Math.max(0,Math.min(16,diag.refresh)):0;return `FAIL phase=${stage} hello=${diag.hello===true?1:0} spawned=${diag.spawned===true?1:0} ready=${diag.ready===true?1:0} refresh=${count} proxy=${proxy}`;}
function readPrivate(){return new Promise((resolve,reject)=>{
 let socket;try{socket=new net.Socket({fd:3,readable:true,writable:false,allowHalfOpen:true});}catch(_){return reject(Error('input'));}
 let size=0,parts=[],expected,closing=false,done=false,output={},failure,closeTimer;const timer=setTimeout(()=>finish(Error('input deadline')),5000);
 function finalize(error){if(done)return;done=true;clearTimeout(timer);clearTimeout(closeTimer);socket.removeListener('data',data);socket.removeListener('end',end);socket.removeListener('error',onerror);socket.removeListener('close',onclose);for(const p of parts)p.fill(0);parts=[];if(error||failure){for(const b of Object.values(output))b.fill(0);return reject(Error('input'));}resolve(output);}
 function finish(error){if(closing||done)return;closing=true;failure=error;let raw;try{
  if(error)throw error;raw=Buffer.concat(parts,size);if(raw.length<8||raw.subarray(0,4).toString()!=='R5I1'||raw.readUInt32BE(4)!==raw.length-8)throw Error('input');const text=raw.subarray(8).toString('utf8'),obj=JSON.parse(text);if(!obj||Array.isArray(obj)||Object.keys(obj).join(',')!==KEYS.join(',')||JSON.stringify(obj)!==text)throw Error('input');
  for(const k of KEYS){const v=obj[k];if(typeof v!=='string'||!v||!/^[A-Za-z0-9+/]*={0,2}(?![\s\S])/.test(v))throw Error('input');const b=Buffer.from(v,'base64');if(!b.length||b.length>16384||b.toString('base64')!==v)throw Error('input');output[k]=b;}if(output.seed.length!==32)throw Error('input');
 }catch(_){failure=Error('input');}finally{if(raw)raw.fill(0);for(const p of parts)p.fill(0);parts=[];}
 closeTimer=setTimeout(()=>finalize(Error('input close deadline')),1000);
 try{socket.destroy();}catch(_){finalize(Error('input'));}
 }
 function data(part){if(!Buffer.isBuffer(part)||part.length>65536-size)return finish(Error('input'));size+=part.length;parts.push(Buffer.from(part));if(expected===undefined&&size>=8){const header=Buffer.concat(parts,8);if(header.subarray(0,4).toString()!=='R5I1'){header.fill(0);return finish(Error('input'));}expected=8+header.readUInt32BE(4);header.fill(0);if(expected<9||expected>65536)return finish(Error('input'));}if(expected!==undefined){if(size>expected)return finish(Error('input'));if(size===expected)finish();}}
 function end(){finish(Error('input'));}function onerror(){if(closing)failure=Error('input');else finish(Error('input'));}function onclose(){if(!closing)finish(Error('input'));finalize();}
 socket.on('data',data);socket.on('end',end);socket.on('error',onerror);socket.on('close',onclose);
});}
function frame(kind,body){if(!Buffer.isBuffer(body)||body.length>16424)throw Error('frame');const h=Buffer.alloc(9);h.write('CBP2');h[4]=kind;h.writeUInt32BE(body.length,5);return Buffer.concat([h,body]);}
function leaf(bytes){return crypto.createHash('sha256').update(new crypto.X509Certificate(bytes).raw).digest('hex');}
function boundedFile(name){const b=fs.readFileSync('/run/apicontour/live/'+name);if(!b.length||b.length>65536)throw Error('file');return b;}
function listen(server,port){return new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});}
function shutdown(server){return new Promise(resolve=>{if(!server)return resolve();server.closeAllConnections();server.close(()=>resolve());});}
function processStart(pid){
 try{const raw=fs.readFileSync('/proc/'+pid+'/stat','utf8'),end=raw.lastIndexOf(') ');if(end<0)throw Error('process');const value=raw.slice(end+2).split(' ')[19];if(!/^[0-9]{1,20}(?![\s\S])/.test(value))throw Error('process');return BigInt(value);}
 catch(error){if(error.code==='ENOENT')return undefined;throw error;}
}
async function stopChild(child){
 if(!child)return;let start=processStart(child.pid);if(start===undefined)return;if(start!==child.start)throw Error('child identity');process.kill(child.pid,'SIGTERM');
 const until=Date.now()+3000;while(Date.now()<until){await new Promise(resolve=>setTimeout(resolve,25));start=processStart(child.pid);if(start===undefined)return;if(start!==child.start)throw Error('child identity');}
 process.kill(child.pid,'SIGKILL');const killUntil=Date.now()+2000;while(Date.now()<killUntil){await new Promise(resolve=>setTimeout(resolve,25));start=processStart(child.pid);if(start===undefined)return;if(start!==child.start)throw Error('child identity');}throw Error('child remains');
}
(async()=>{
 let privateInput,proxy,backend,ingress,child,pending=Buffer.alloc(0),held,done=false,rootSeen=false,firstId,firstDigest,duplicate=false;
 const timeout=setTimeout(()=>{if(!done){console.error(diagnostic());process.exit(1);}},60000);
 try{
  privateInput=await readPrivate();diag.stage='material';const ca=boundedFile('ca.pem'),server=boundedFile('server.pem'),product=boundedFile('product.pem'),exportCert=boundedFile('export.pem'),evidence=boundedFile('evidence.pem');
  diag.stage='metadata';const manifestBytes=fs.readFileSync('/adapter/receiver-integration/manifest-504.json'),manifest=JSON.parse(manifestBytes),vector=JSON.parse(fs.readFileSync('/work/tests/fixtures/receiver504-bootstrap/vector.json'));
  const markerDer=Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),privateInput.seed]);const marker=crypto.createPublicKey(crypto.createPrivateKey({key:markerDer,format:'der',type:'pkcs8'})).export({type:'spki',format:'der'});markerDer.fill(0);if(marker.length!==44)throw Error('marker');
  const d=JSON.parse(vector.canonical);Object.assign(d,{artifact_sha256:manifest.artifact_sha256,ca_sha256:crypto.createHash('sha256').update(ca).digest('hex'),epoch:'1',export_leaf:leaf(exportCert),gateway_backend_leaf:leaf(privateInput.gateway_cert),identity:'1'.repeat(64),manifest_sha256:crypto.createHash('sha256').update(manifestBytes).digest('hex'),marker_public:marker.subarray(12).toString('hex'),product_leaf:leaf(product),receiver_backend_leaf:leaf(server),receiver_evidence_leaf:leaf(evidence),server_leaf:leaf(server)});d.identity=bootstrap.commitment(d);const metadata=Buffer.from(JSON.stringify(d));bootstrap.parse(metadata);
  backend=https.createServer({key:privateInput.backend_key,cert:privateInput.backend_cert,ca,requestCert:true,rejectUnauthorized:true},(req,res)=>{req.resume();req.on('end',()=>{res.writeHead(200);res.end('ok');});});
  ingress=https.createServer({key:privateInput.ingress_key,cert:privateInput.ingress_cert,ca,requestCert:true,rejectUnauthorized:true},(req,res)=>{let size=0,chunks=[];req.on('data',part=>{size+=part.length;if(size>65536)req.destroy();else chunks.push(part);});req.on('end',()=>{try{const raw=Buffer.concat(chunks,size),batch=JSON.parse(raw),digest=crypto.createHash('sha256').update('apicontour/causal-events/1\n').update(raw).digest('hex');if(!Array.isArray(batch.events)||batch.runtime_id!==d.runtime)throw Error('batch');rootSeen ||= batch.events.some(x=>x.kind==='root');if(!firstId){firstId=batch.batch_id;firstDigest=digest;res.destroy();return;}if(batch.batch_id===firstId&&digest===firstDigest)duplicate=true;const result=JSON.stringify({batch_id:batch.batch_id,runtime_id:d.runtime,session_epoch:1,batch_digest:digest,receipt_id:'00000000-0000-4000-8000-000000000001',accepted_at:'2026-11-12T00:00:00Z',status:duplicate?'duplicate':'accepted'});res.writeHead(200,{'content-type':'application/json'});res.end(result);}catch(_){res.destroy();}});});
  diag.stage='listeners';await listen(backend,9443);await listen(ingress,8443);
  diag.stage='proxy';proxy=spawn('/usr/local/bin/node',['/adapter/receiver-integration/private-launch-proxy-504.js'],{env:manifest.env,stdio:['pipe','pipe','ignore']});
  let ready=false,hello=false,spawned=false,frameFailed=false,resolveReady,rejectReady,counter=0n;const helloToken=crypto.randomBytes(32);const readiness=new Promise((resolve,reject)=>{resolveReady=resolve;rejectReady=reject;});proxy.on('error',()=>rejectReady(Error('proxy')));proxy.on('exit',(code,signal)=>{diag.proxy=signal?'signal':code===0?'zero':Number.isInteger(code)?'nonzero':'other';if(!ready)rejectReady(Error('proxy'));});
  proxy.stdout.on('data',part=>{try{if(!Buffer.isBuffer(part)||part.length>16433-pending.length)throw Error('frame');pending=Buffer.concat([pending,part]);while(pending.length>=9){if(pending.subarray(0,4).toString()!=='CBP2')throw Error('frame');const n=pending.readUInt32BE(5);if(n>16424)throw Error('frame');if(pending.length<9+n)break;const kind=pending[4],body=Buffer.from(pending.subarray(9,9+n)),old=pending;pending=Buffer.from(old.subarray(9+n));old.fill(0);
   if(kind===72&&!hello){if(body.length!==44||!body.subarray(0,32).equals(helloToken))throw Error('hello');hello=true;diag.hello=true;diag.stage='bootstrap';const h=Buffer.alloc(8);h.write('CLB2');h.writeUInt32BE(metadata.length,4);held=Buffer.concat([h,metadata,privateInput.seed]);privateInput.seed.fill(0);const packet=frame(66,held);proxy.stdin.write(packet,()=>{packet.fill(0);if(held){held.fill(0);held=undefined;}});}
   else if(kind===83&&!spawned&&hello&&body.length===12){const pid=body.readUInt32BE(0),start=body.readBigUInt64BE(4);if(pid<2||!start||processStart(pid)!==start)throw Error('child');child={pid,start};spawned=true;diag.spawned=true;diag.stage='readiness';}
   else if(kind===81&&spawned&&body.length===140&&body.subarray(0,4).toString()==='CQP2'){counter++;diag.refresh=Math.min(16,diag.refresh+1);if(body.readBigUInt64BE(68)!==counter||!body.subarray(4,36).equals(Buffer.from(d.generation,'hex'))||!body.subarray(36,68).equals(Buffer.from(d.identity,'hex'))||!body.subarray(108,140).equals(Buffer.from(d.receiver_enrollment_commitment,'hex'))||!body.subarray(76,108).some(Boolean))throw Error('scope');const response=Buffer.alloc(152);response.write('CRP2');body.copy(response,4,4);response.writeBigUInt64BE(1n,140);response.writeUInt32BE(1000,148);proxy.stdin.write(frame(82,response));}
   else if(kind===89&&body.length===76&&body.subarray(0,4).toString()==='CLR2'){if(!body.subarray(4,36).equals(Buffer.from(d.generation,'hex'))||!body.subarray(36,68).equals(Buffer.from(d.identity,'hex'))||body.readBigUInt64BE(68)!==1n)throw Error('ready');ready=true;diag.ready=true;resolveReady();}else throw Error('frame');body.fill(0);
  }}catch(_){frameFailed=true;proxy.stdin.destroy();rejectReady(Error('frame'));}});proxy.stdin.write(frame(73,helloToken));await readiness;helloToken.fill(0);
  diag.stage='request';const binding={...require('/work/docs/specification/fixtures/causal-evidence-v1.json')[0].body,tenant_id:d.tenant,gateway_id:d.gateway_id,gateway_generation:d.gateway_generation,receiver_runtime_id:d.runtime,receiver_session_epoch:d.epoch};const carrier=JSON.stringify(Object.fromEntries(Object.entries(binding).sort(([a],[b])=>a<b?-1:a>b?1:0)));
  await new Promise((resolve,reject)=>{const request=https.request({host:'127.0.0.1',port:1880,path:'/run',method:'POST',ca,cert:privateInput.gateway_cert,key:privateInput.gateway_key,servername:'causal-receiver',rejectUnauthorized:true,headers:{'content-type':'text/plain','x-apicontour-causal-binding':carrier,'x-apicontour-extra':'remove'}},res=>{res.resume();res.on('end',()=>res.statusCode===200?resolve():reject(Error('response')));});request.on('error',reject);request.end('serial');});
  diag.stage='batch';const until=Date.now()+12000;while(Date.now()<until&&(!rootSeen||!duplicate))await new Promise(resolve=>setTimeout(resolve,50));if(!rootSeen||!duplicate||frameFailed)throw Error('batch');
  done=true;diag.stage='complete';
 }catch(error){diag.failure=diag.stage;throw error;}finally{
  clearTimeout(timeout);pending.fill(0);if(held)held.fill(0);if(privateInput)for(const value of Object.values(privateInput))value.fill(0);
  diag.stage='cleanup';const cleanupTimer=setTimeout(()=>{if(!diag.failure)diag.failure='cleanup';console.error(diagnostic());process.exit(1);},8000);
  let cleanupFailed=false;try{await stopChild(child);}catch(_){cleanupFailed=true;}
  try{if(proxy){proxy.stdin.destroy();if(proxy.exitCode===null&&proxy.signalCode===null){const exited=new Promise(resolve=>proxy.once('exit',resolve));proxy.kill('SIGTERM');await Promise.race([exited,new Promise(resolve=>setTimeout(resolve,3000))]);if(proxy.exitCode===null&&proxy.signalCode===null){proxy.kill('SIGKILL');await exited;}}}}catch(_){cleanupFailed=true;}
  for(const item of [backend,ingress])try{await shutdown(item);}catch(_){cleanupFailed=true;}
  clearTimeout(cleanupTimer);if(cleanupFailed){if(!diag.failure)diag.failure='cleanup';throw Error('cleanup');}
 }
 if(done)console.log('PASS phase=receiver504_component checks=1,1,1');
})().catch(()=>{console.error(diagnostic());process.exitCode=1;});
