'use strict';
// Owned-image qualification only: synthetic mTLS receipt server, not a database.
const assert=require('node:assert/strict'),fs=require('node:fs'),https=require('node:https'),crypto=require('node:crypto'),{performance}=require('node:perf_hooks');
const {create:createExporter}=require('/adapter/error-integration/private-causal-exporter');
const {create:createHandoff}=require('/adapter/error-integration/private-handoff');
const read=name=>fs.readFileSync('/fixture-tls/'+name);
const ca=read('ca'),client=read('client'),key=read('client-key'),serverCert=read('server'),serverKey=read('server-key'),wrongCert=read('wrong-name-server'),wrongKey=read('wrong-name-server-key'),untrusted=read('untrusted-ca');
const trustedCert=new crypto.X509Certificate(ca),untrustedCert=new crypto.X509Certificate(untrusted);
assert(untrustedCert.ca);assert(untrustedCert.checkIssued(untrustedCert));assert(untrustedCert.verify(untrustedCert.publicKey));assert.notEqual(untrustedCert.fingerprint256,trustedCert.fingerprint256);assert(Date.parse(untrustedCert.validFrom)<=Date.now()&&Date.now()<=Date.parse(untrustedCert.validTo));
const pin=crypto.createHash('sha256').update(new crypto.X509Certificate(client).raw).digest('hex');
const tenant='123e4567-e89b-12d3-a456-426614174001',runtime='123e4567-e89b-12d3-a456-426614174002',receiptId='123e4567-e89b-12d3-a456-426614174003',epoch=(1n<<64n)-1n;
let mode='accepted',arrivals=[],held,servers=[];
const deadline=setTimeout(()=>{process.stderr.write('FAIL: fixture deadline\n');process.exit(1);},30000);
function listen(server){return new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',()=>{server.removeListener('error',reject);resolve(server.address().port);});});}
function stop(server){return new Promise((resolve,reject)=>{server.close(e=>e?reject(e):resolve());server.closeAllConnections();});}
function makeServer(cert,key){
 const server=https.createServer({cert,key,ca,requestCert:true,rejectUnauthorized:true},(req,res)=>{
  try{assert(req.socket.authorized);assert.equal(crypto.createHash('sha256').update(req.socket.getPeerCertificate(true).raw).digest('hex'),pin);assert.equal(req.method,'POST');assert.equal(req.url,'/v1/causal-events');assert.equal(req.headers['content-type'],'application/json');}catch(_){res.writeHead(400);res.end();return;}
  let length=0,chunks=[];req.on('data',chunk=>{length+=chunk.length;if(length>1048576){req.destroy();return;}chunks.push(chunk);});req.on('error',()=>{});req.on('end',()=>{
   try{const bytes=Buffer.concat(chunks,length),text=bytes.toString('utf8'),id=/"batch_id":"([0-9a-f-]{36})"/.exec(text)?.[1];assert(id);assert(text.includes('"session_epoch":18446744073709551615'));const digest=crypto.createHash('sha256').update('apicontour/causal-events/1\n').update(bytes).digest('hex');const item={bytes,id,digest};arrivals.push(item);
    if(mode==='503'){res.writeHead(503);res.end();return;}
    const send=()=>{if(res.destroyed)return;res.writeHead(200,{'content-type':'application/json'});res.end(`{"batch_id":"${id}","runtime_id":"${runtime}","session_epoch":18446744073709551615,"batch_digest":"${digest}","receipt_id":"${receiptId}","accepted_at":"2026-11-05T12:00:00Z","status":"${mode==='duplicate'?'duplicate':'accepted'}"}`);};
    if(mode==='hold'){held=send;return;}send();
   }catch(_){res.writeHead(400);res.end();}
  });
 });server.on('tlsClientError',()=>{});server.requestTimeout=3000;server.headersTimeout=3000;server.setTimeout(3000,s=>s.destroy());servers.push(server);return server;
}
function handoff(){return createHandoff({tenantId:tenant,runtimeId:runtime,epoch,authority:()=>({allowed:true,epoch,deadline:performance.now()+60000}),maxBatchEvents:10,maxBatchBytes:4096,queueBytes:8192,queueTtlMs:60000});}
function offer(h,c){assert(h.offer({kind:'ROOT_INTENT',root:c.repeat(32)}));}
function exporter(h,port,trust=ca){return createExporter({endpoint:`https://127.0.0.1:${port}/v1/causal-events`,ca:trust,cert:client,key,runtimeId:runtime,epoch,handoff:h,timeoutMs:3000,maxBodyBytes:4096});}
async function waitFor(fn){const until=performance.now()+3000;while(!fn()&&performance.now()<until)await new Promise(r=>setTimeout(r,10));assert(fn());}
async function wrongNameControl(port){
 const h=handoff();offer(h,'2');const frozen=h.freeze(),body=Buffer.from(frozen.canonical),count=arrivals.length;
 await new Promise((resolve,reject)=>{const req=https.request({hostname:'127.0.0.1',port,path:'/v1/causal-events',method:'POST',servername:'wrong.example',ca,cert:client,key,rejectUnauthorized:true,agent:false,headers:{'content-type':'application/json','content-length':body.length}},res=>{try{assert(res.socket.authorized);assert.equal(res.statusCode,200);}catch(e){res.destroy();return reject(e);}res.resume();res.on('end',resolve);res.on('error',reject);});req.on('error',reject);req.setTimeout(3000,()=>req.destroy(Error('control timeout')));req.end(body);});
 assert.equal(arrivals.length,count+1);assert.equal(arrivals[count].id,frozen.batchId);assert.equal(arrivals[count].digest,frozen.sha256);
}
async function baseline(port){const h=handoff();offer(h,'a');const e=exporter(h,port);mode='accepted';assert.equal(await e.sendOnce(),true);assert.equal(h.freeze(),undefined);e.close();}
async function main(){
 const good=makeServer(serverCert,serverKey),wrong=makeServer(wrongCert,wrongKey),port=await listen(good),wrongPort=await listen(wrong);
 await baseline(port);process.stdout.write('PASS: mTLS accepted receipt\n');
 {const h=handoff();offer(h,'b');const e=exporter(h,port);mode='duplicate';assert.equal(await e.sendOnce(),true);assert.equal(h.freeze(),undefined);e.close();}process.stdout.write('PASS: duplicate receipt\n');
 await baseline(port);{const h=handoff();offer(h,'c');const frozen=h.freeze(),e=exporter(h,port);mode='503';const start=arrivals.length;assert.equal(await e.sendOnce(),false);assert.equal(h.freeze(),frozen);mode='accepted';assert.equal(await e.sendOnce(),true);assert.equal(arrivals.length,start+2);assert(arrivals[start].bytes.equals(arrivals[start+1].bytes));assert.equal(arrivals[start].id,arrivals[start+1].id);assert.equal(arrivals[start].digest,arrivals[start+1].digest);assert.equal(h.freeze(),undefined);e.close();}process.stdout.write('PASS: explicit retry preserves batch\n');
 await baseline(port);{const h=handoff();offer(h,'d');const first=h.freeze(),e=exporter(h,port);mode='hold';held=undefined;const pending=e.sendOnce();await waitFor(()=>held);offer(h,'e');held();assert.equal(await pending,true);const next=h.freeze();assert(next);assert.notEqual(next.batchId,first.batchId);e.close();}process.stdout.write('PASS: events during flight survive\n');
 await baseline(port);{const h=handoff();offer(h,'f');const first=h.freeze(),e=exporter(h,port);mode='hold';held=undefined;const pending=e.sendOnce();await waitFor(()=>held);e.close();held();assert.equal(await pending,false);assert.equal(h.freeze(),first);}process.stdout.write('PASS: close prevents late acknowledgement\n');
 mode='accepted';await wrongNameControl(wrongPort);process.stdout.write('PASS: wrong-name certificate trusted control\n');
 for(const [label,target,trust] of [['wrong CA',port,untrusted],['wrong hostname',wrongPort,ca]]){await baseline(port);const h=handoff();offer(h,'1');const frozen=h.freeze(),e=exporter(h,target,trust),count=arrivals.length;mode='accepted';assert.equal(await e.sendOnce(),false);assert.equal(h.freeze(),frozen);assert.equal(arrivals.length,count);e.close();process.stdout.write(`PASS: ${label} rejects before HTTP\n`);}
}
(async()=>{let failure;try{await main();}catch(e){failure=e;}for(const server of servers)try{if(server.listening)await stop(server);}catch(e){failure??=e;}clearTimeout(deadline);if(failure){process.stderr.write('FAIL: mTLS fixture assertion or runtime error\n');process.exitCode=1;}})();
