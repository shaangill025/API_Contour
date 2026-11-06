'use strict';
// Staged synthetic fixture: root executes in the pinned owned image only.
// Local mTLS and signature verification do not prove database registration.
const assert=require('node:assert/strict'),fs=require('node:fs'),http=require('node:http'),https=require('node:https'),crypto=require('node:crypto'),os=require('node:os'),path=require('node:path');
const {createRequire}=require('node:module');const redRequire=createRequire('/usr/src/node-red/node_modules/node-red/red.js');
const adapter=require('/adapter/error-integration/wire-v2-bootstrap.js'),RED=redRequire('node-red'),express=redRequire('express');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'wire-v2-fixture-')),app=express(),server=http.createServer(app),arrivals=[];
const pin=crypto.createHash('sha256').update(new crypto.X509Certificate(fs.readFileSync('/fixture-tls/client')).raw).digest('hex');
const key=crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,7)]),format:'der',type:'pkcs8'}),pub=crypto.createPublicKey(key);
const destination=https.createServer({cert:fs.readFileSync('/fixture-tls/server'),key:fs.readFileSync('/fixture-tls/server-key'),ca:fs.readFileSync('/fixture-tls/ca'),requestCert:true,rejectUnauthorized:true},(req,res)=>{
 try{
  assert.equal(crypto.createHash('sha256').update(req.socket.getPeerCertificate(true).raw).digest('hex'),pin);
  const marker=req.headers['x-apicontour-causal-marker'];if(!marker){let payload='';req.setEncoding('utf8');req.on('data',x=>payload+=x);req.on('end',()=>{arrivals.push({payload,unmarked:true});res.end('ok');});return;}const parts=marker.split('.');assert.equal(parts.length,3);assert.equal(parts[0],'ac1');
  const bytes=Buffer.from(parts[1],'base64url');assert(crypto.verify(null,Buffer.concat([Buffer.from('apicontour/causal-marker/1\n'),bytes]),pub,Buffer.from(parts[2],'base64url')));
  const body=JSON.parse(bytes.toString('utf8'));let payload='';req.setEncoding('utf8');req.on('data',x=>payload+=x);req.on('end',()=>{arrivals.push({payload,root:body.root,activity:body.activity,attempt:body.attempt,marker});if(payload==='retry:1')res.statusCode=503;res.end('ok');});
 }catch(_){res.statusCode=400;res.end('bad');}
});
// Fixture-only mTLS receiver. Its digest and receipt are constructed independently
// from the producer/exporter; it is not a Rust or PostgreSQL authority.
let receiptMode='accepted',heldReceipt,receiptArrivals=[];
const exportPin=()=>crypto.createHash('sha256').update(new crypto.X509Certificate(fs.readFileSync('/fixture-tls/export-client')).raw).digest('hex');
const receiptServer=https.createServer({cert:fs.readFileSync('/fixture-tls/server'),key:fs.readFileSync('/fixture-tls/server-key'),ca:fs.readFileSync('/fixture-tls/ca'),requestCert:true,rejectUnauthorized:true},(req,res)=>{
 try{
  assert(req.socket.authorized);assert.notEqual(exportPin(),pin);assert.equal(crypto.createHash('sha256').update(req.socket.getPeerCertificate(true).raw).digest('hex'),exportPin());
  assert.equal(req.method,'POST');assert.equal(req.url,'/v1/causal-events');assert.equal(req.headers['content-type'],'application/json');
  let chunks=[],length=0;req.on('data',chunk=>{length+=chunk.length;if(length>65536){req.destroy();return;}chunks.push(chunk);});req.on('error',()=>{});req.on('end',()=>{try{
   const bytes=Buffer.concat(chunks,length),batch=JSON.parse(bytes.toString('utf8'));assert.equal(batch.runtime_id,'123e4567-e89b-12d3-a456-426614174002');assert.equal(batch.session_epoch,1);assert(Array.isArray(batch.events)&&batch.events.length);
   const digest=crypto.createHash('sha256').update('apicontour/causal-events/1\n').update(bytes).digest('hex');receiptArrivals.push({bytes,batch,digest});
   if(receiptMode==='503'){res.writeHead(503);res.end();return;}
   const send=()=>{if(res.destroyed)return;const receipt={batch_id:batch.batch_id,runtime_id:batch.runtime_id,session_epoch:1,batch_digest:receiptMode==='bad-digest'?'0'.repeat(64):digest,receipt_id:'123e4567-e89b-12d3-a456-426614174003',accepted_at:'2026-11-05T12:00:00Z',status:'accepted'};res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(receipt));};
   if(receiptMode==='hold'){heldReceipt=send;return;}send();
  }catch(_){res.writeHead(400);res.end();}});
 }catch(_){res.writeHead(400);res.end();}
});receiptServer.on('tlsClientError',()=>{});
for(const s of [server,destination,receiptServer]){s.requestTimeout=2000;s.headersTimeout=2000;s.setTimeout(2000,x=>x.destroy());}
const timer=setTimeout(()=>{process.stderr.write('FAIL: fixture deadline\n');process.exit(1);},20000);
function listen(s,port){return new Promise((resolve,reject)=>{s.once('error',reject);s.listen(port,'127.0.0.1',resolve);});}
function close(s){return new Promise(resolve=>{if(!s.listening)return resolve();s.close(resolve);s.closeAllConnections();});}
function request(port,body){return new Promise((resolve,reject)=>{const r=http.request({host:'127.0.0.1',port,path:'/run',method:'POST',headers:{'host':'127.0.0.1:18443','content-type':'text/plain'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});r.on('error',reject);r.setTimeout(3000,()=>r.destroy(Error('timeout')));r.end(body);});}
function qualificationMode(){
 let fd;try{fd=fs.openSync('/fixture/qualification-mode.json',fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);}catch(e){if(e.code==='ENOENT')return 'positive';throw e;}
 try{const stat=fs.fstatSync(fd);if(!stat.isFile()||stat.size>128)throw Error('invalid qualification mode');const value=JSON.parse(fs.readFileSync(fd,'utf8'));if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==1||!['hook','cache','composition','composition-hook','composition-cache'].includes(value.mode))throw Error('invalid qualification mode');return value.mode;}finally{fs.closeSync(fd);}
}
async function negative(mode){
 assert.equal(await request(server.address().port,'baseline'),200);
 let deadline=Date.now()+5000;while(arrivals.length<2&&Date.now()<deadline)await new Promise(r=>setTimeout(r,20));
 assert.equal(arrivals.length,2);assert(arrivals.every(a=>typeof a.marker==='string'));assert(adapter.snapshot().ready);assert(adapter.fixtureBatch());
 if(mode==='hook')redRequire('@node-red/util').hooks.add('onSend.qualification',(_batch,done)=>done());
 else {const target='/usr/src/node-red/node_modules/@node-red/runtime/lib/nodes/Node.js';const entry=require.cache[target];assert(entry);entry.exports=function qualificationReplacement(){};}
 assert.equal(adapter.snapshot().ready,false);assert.equal(adapter.fixtureBatch(),undefined);
 assert.equal(await request(server.address().port,'after-tamper'),200);
 deadline=Date.now()+5000;while(arrivals.length<4&&Date.now()<deadline)await new Promise(r=>setTimeout(r,20));
 assert.equal(arrivals.length,4);assert(arrivals.slice(2).every(a=>a.unmarked));assert.equal(adapter.snapshot().ready,false);assert.equal(adapter.fixtureBatch(),undefined);
 process.stdout.write(`PASS: synthetic pinned Node-RED live ${mode} invalidation; forwarding unmarked\n`);
}
function assertAttempts(events,observed){
 const attempts=events.filter(e=>e.kind==='attempt');
 assert.equal(attempts.length,observed.length);assert.equal(new Set(attempts.map(e=>e.attempt)).size,attempts.length);
 assert.equal(new Set(observed.map(a=>a.attempt)).size,observed.length);
 for(const a of observed){
  const matches=attempts.filter(e=>e.attempt===a.attempt);assert.equal(matches.length,1);const e=matches[0];
  assert.equal(e.root,a.root);assert.equal(e.activity,a.activity);
  assert.equal(e.marker_digest,crypto.createHash('sha256').update('apicontour/causal-marker-wire/1\n').update(a.marker).digest('hex'));
 }
}
async function composition(mode){
 const waitFor=async predicate=>{const until=Date.now()+5000;while(!predicate()&&Date.now()<until)await new Promise(r=>setTimeout(r,20));assert(predicate());};
 const produce=async label=>{const count=arrivals.length;assert.equal(await request(server.address().port,label),200);await waitFor(()=>arrivals.length===count+2);assert(arrivals.slice(count).every(x=>x.marker));};
 await listen(receiptServer,18444);
 await produce('compose-first');const first=adapter.fixtureBatch();assert(first);const firstEvents=JSON.parse(first.canonical).events;
 assertAttempts(firstEvents,arrivals.slice(0,2));
 if(mode!=='composition'){
  receiptMode='hold';heldReceipt=undefined;const pending=adapter.fixtureSendOnce();await waitFor(()=>heldReceipt);
  if(mode==='composition-hook')redRequire('@node-red/util').hooks.add('onSend.qualification',(_batch,done)=>done());
  else {const target='/usr/src/node-red/node_modules/@node-red/runtime/lib/nodes/Node.js';const entry=require.cache[target];assert(entry);entry.exports=function qualificationReplacement(){};}
  assert.equal(adapter.snapshot().ready,false);heldReceipt();assert.equal(await pending,false);assert.equal(adapter.fixtureBatch(),undefined);
  const before=arrivals.length;assert.equal(await request(server.address().port,'compose-after-integrity-loss'),200);await waitFor(()=>arrivals.length===before+2);assert(arrivals.slice(before).every(a=>a.unmarked));
  assert.equal(adapter.snapshot().ready,false);assert.equal(await adapter.fixtureSendOnce(),false);
  process.stdout.write(`PASS: synthetic composition ${mode.slice('composition-'.length)} held ACK invalidation; forwarding unmarked\n`);return;
 }
 receiptMode='503';assert.equal(await adapter.fixtureSendOnce(),false);assert.equal(adapter.fixtureBatch().canonical,first.canonical);
 receiptMode='bad-digest';assert.equal(await adapter.fixtureSendOnce(),false);assert.equal(adapter.fixtureBatch().canonical,first.canonical);
 receiptMode='hold';heldReceipt=undefined;const inflight=adapter.fixtureSendOnce();await waitFor(()=>heldReceipt);await produce('compose-during-flight');heldReceipt();assert.equal(await inflight,true);
 assert(receiptArrivals.slice(0,3).every(x=>x.bytes.equals(Buffer.from(first.canonical))&&x.digest===first.sha256));
 const second=adapter.fixtureBatch();assert(second);assert.notEqual(second.batchId,first.batchId);const secondEvents=JSON.parse(second.canonical).events;
 assertAttempts(secondEvents,arrivals.slice(2,4));
 receiptMode='accepted';assert.equal(await adapter.fixtureSendOnce(),true);assert.equal(adapter.fixtureBatch(),undefined);
 await produce('compose-late');const late=adapter.fixtureBatch();receiptMode='hold';heldReceipt=undefined;const pending=adapter.fixtureSendOnce();await waitFor(()=>heldReceipt);adapter.fixtureCloseExporter();heldReceipt();assert.equal(await pending,false);assert.equal(adapter.fixtureBatch().canonical,late.canonical);
 adapter.invalidate();assert.equal(adapter.snapshot().ready,false);assert.equal(adapter.fixtureBatch(),undefined);
 const before=arrivals.length;assert.equal(await request(server.address().port,'compose-after-invalidation'),200);await waitFor(()=>arrivals.length===before+2);assert(arrivals.slice(before).every(a=>a.unmarked));
 process.stdout.write('PASS: synthetic factory handoff fenced exporter mTLS composition\n');
}
async function main(){
 const mode=qualificationMode();
 await listen(destination,18443);RED.init(server,{userDir:dir,flowFile:'/fixture/flows-wire-v2.json',httpAdminRoot:false,httpNodeRoot:'/',credentialSecret:false,functionExternalModules:false,logging:{console:{level:'off',metrics:false,audit:false}}});app.use(RED.httpNode);
 const started=new Promise((resolve,reject)=>{const t=setTimeout(()=>reject(Error('flows timeout')),8000);RED.events.once('flows:started',()=>{clearTimeout(t);resolve();});});
 await RED.start();await started;assert(adapter.snapshot().ready);await listen(server,0);
 if(mode.startsWith('composition'))return composition(mode);
 if(mode!=='positive')return negative(mode);
 assert.deepEqual(await Promise.all([request(server.address().port,'first'),request(server.address().port,'second')]),[200,200]);
 const deadline=Date.now()+5000;while(arrivals.length<4&&Date.now()<deadline)await new Promise(r=>setTimeout(r,20));assert.equal(arrivals.length,4);
 assert.equal(await request(server.address().port,'retry'),200);const retryDeadline=Date.now()+5000;while(arrivals.length<6&&Date.now()<retryDeadline)await new Promise(r=>setTimeout(r,20));assert.equal(arrivals.length,6);assert.deepEqual(arrivals.slice(4).map(a=>a.payload),['retry:1','retry:2']);
 const batch=adapter.fixtureBatch(),events=JSON.parse(batch.canonical).events,attempts=events.filter(e=>e.kind==='attempt');assert.equal(attempts.length,6);
 assert.equal(new Set(arrivals.map(a=>a.marker)).size,6);assert.equal(new Set(arrivals.map(a=>a.attempt)).size,6);
 for(const label of ['first','second']){const rows=arrivals.filter(a=>a.payload===label);assert.equal(rows.length,2);assert.equal(new Set(rows.map(r=>r.root)).size,1);}
 assert.notEqual(arrivals.find(r=>r.payload==='first').root,arrivals.find(r=>r.payload==='second').root);
 for(const a of arrivals)assert(attempts.some(e=>e.root===a.root&&e.activity===a.activity&&e.attempt===a.attempt));
 adapter.invalidate();assert.equal(adapter.snapshot().ready,false);assert.equal(await request(server.address().port,'after-revoke'),200);const revokedDeadline=Date.now()+5000;while(arrivals.length<8&&Date.now()<revokedDeadline)await new Promise(r=>setTimeout(r,20));assert.equal(arrivals.length,8);assert(arrivals.slice(6).every(a=>a.unmarked));process.stdout.write('PASS: synthetic pinned Node-RED mTLS causal wire fixture\n');
}
(async()=>{let failure;try{await main();}catch(e){failure=e;}for(const op of [()=>RED.stop(),()=>close(server),()=>close(destination),()=>close(receiptServer),()=>fs.rmSync(dir,{recursive:true,force:true})])try{await op();}catch(e){failure??=e;}clearTimeout(timer);if(failure){process.stderr.write('FAIL: wire fixture assertion or runtime error\n');process.exitCode=1;}})();
