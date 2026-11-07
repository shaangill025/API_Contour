'use strict';
// Synthetic-only exact forwarding checks. Diagnostics are closed labels only.
const fs=require('fs'),http=require('http'),https=require('https'),crypto=require('crypto'),zlib=require('zlib'),{performance}=require('perf_hooks');
const cases=['normal','request-malformed','response-malformed','request-compressed','response-compressed','request-oversized','response-oversized','request-chunked','response-chunked','request-progress','response-progress','request-trailer','response-trailer','response-409'];
const normal=Buffer.from('{"probe":true}'),reply=Buffer.from('{"id":1}'),malformed=Buffer.from('{"probe":'),huge=Buffer.from('{"probe":"'+'synthetic-secret-sentinel-'+'x'.repeat(65536)+'"}');
const PREFIX=3, WAIT_MS=5000;
function body(name,direction){if(name===direction+'-malformed')return malformed;if(name===direction+'-oversized')return huge;if(name===direction+'-compressed')return zlib.gzipSync(direction==='request'?normal:reply);return direction==='request'?normal:reply;}
function digest(x){return crypto.createHash('sha256').update(x).digest('hex');}
function fail(label,stream){process.stderr.write('DIAG '+label+'\n');process.exitCode=1;if(stream)stream.destroy();}
// One fresh, bounded rendezvous. Only a nonce, mode and boolean are retained.
function rendezvous(ttl=7000){let active=null,timer=null;return {
 register(nonce,mode){if(active||!(/^[0-9a-f]{32}$/.test(nonce))||!['request','response'].includes(mode))return false;active={nonce,mode,seen:false};timer=setTimeout(()=>{active=null;timer=null;},ttl);timer.unref();return true;},
 matches(nonce,mode){return !!active&&active.nonce===nonce&&active.mode===mode;},
 mark(nonce,mode){if(!this.matches(nonce,mode))return false;active.seen=true;return true;},
 seen(nonce){return active&&active.nonce===nonce?active.seen:null;},
 clear(nonce){if(!active||active.nonce!==nonce)return false;active=null;clearTimeout(timer);timer=null;return true;}
};}
// Observe the actual first bytes, including fragmented data events, before marking.
function prefixObserver(expected,onPrefix){let prefix=Buffer.alloc(0),done=false;return chunk=>{if(done)return;prefix=Buffer.concat([prefix,chunk]).subarray(0,expected.length);if(!expected.subarray(0,prefix.length).equals(prefix))throw new Error('prefix');if(prefix.length===expected.length){done=true;onPrefix();}};}
function waitUntil(check,timeout=WAIT_MS,interval=25,signal){return new Promise((resolve,reject)=>{const deadline=performance.now()+timeout;let timer,finished=false;function finish(error){if(finished)return;finished=true;clearTimeout(timer);if(signal)signal.removeEventListener('abort',abort);error?reject(error):resolve();}function abort(){finish(new Error('aborted'));}function step(){if(finished)return;Promise.resolve().then(check).then(ok=>{if(finished)return;if(performance.now()>=deadline)return finish(new Error('timeout'));if(ok)return finish();timer=setTimeout(step,interval);},finish);}if(signal){if(signal.aborted)return abort();signal.addEventListener('abort',abort,{once:true});}step();});}
function checked(stream,expected,label,done,onData,onFailure=()=>{}){let n=0,chunks=[],failed=false;function bad(){if(failed)return;failed=true;fail(label,stream);onFailure(new Error('bytes'));}stream.on('data',b=>{n+=b.length;if(n>70000)return bad();try{if(onData)onData(b);}catch(_){return bad();}chunks.push(b);});stream.on('error',()=>{fail('transport',null);onFailure(new Error('transport'));});stream.on('end',()=>{if(failed)return;if(!Buffer.concat(chunks).equals(expected))return bad();done();});}
function control(method,path,nonce){return new Promise((resolve,reject)=>{const req=http.request({host:'127.0.0.1',port:9445,method,path,headers:{'x-fixture-nonce':nonce},timeout:1000},res=>{let data='';res.setEncoding('ascii');res.on('data',c=>{data+=c;if(data.length>8)req.destroy();});res.on('end',()=>res.statusCode===200?resolve(data):reject(new Error('control')));});req.on('timeout',()=>req.destroy());req.on('error',reject);req.end();});}
function serve(){
 const state=rendezvous(),expected=process.env.EXPECTED_CLIENT_SHA256;
 const ctl=http.createServer((req,res)=>{const nonce=req.headers['x-fixture-nonce'];let result=false;if(req.method==='POST'&&(req.url==='/request'||req.url==='/response'))result=state.register(nonce,req.url.slice(1));else if(req.method==='POST'&&req.url==='/ack')result=state.mark(nonce,'response');else if(req.method==='DELETE'&&req.url==='/')result=state.clear(nonce);else if(req.method==='GET'&&req.url==='/state'){const seen=state.seen(nonce);if(seen!==null){res.writeHead(200);return res.end(seen?'1':'0');}}res.writeHead(result?200:400);res.end(result?'1':'0');});
 const server=https.createServer({cert:fs.readFileSync('/fixture/destination.crt'),key:fs.readFileSync('/fixture/destination.key'),ca:fs.readFileSync('/fixture/ca.crt'),requestCert:true,rejectUnauthorized:true},(req,res)=>{
  const peer=req.socket.getPeerCertificate(true);if(!req.socket.authorized||!peer.raw||digest(peer.raw)!==expected)return fail('server_tls',res);
  const name=req.headers['x-fixture-case'],nonce=req.headers['x-fixture-nonce'];if(req.method!=='POST'||req.url!=='/pilot'||!cases.includes(name)||req.headers['content-encoding']!==(name==='request-compressed'?'gzip':undefined)||((name==='request-progress'||name==='response-progress')&&!state.matches(nonce,name.split('-')[0])))return fail('server_request_metadata',res);
  if(name==='request-progress'||name==='response-progress')req.on('close',()=>{if(!req.complete)state.clear(nonce);});
  const observe=name==='request-progress'?prefixObserver(normal.subarray(0,PREFIX),()=>{if(!state.mark(nonce,'request'))throw new Error('state');}):null;
  checked(req,body(name,'request'),'server_request_bytes',()=>{if(req.trailers['x-fixture-end']!==(name==='request-trailer'?'done':undefined))return fail('server_request_trailers',res);
   const out=body(name,'response'),headers={'content-type':'application/json'};if(name==='response-compressed')headers['content-encoding']='gzip';if(name==='response-trailer')headers.trailer='x-fixture-end';else if(!['response-chunked','response-progress'].includes(name))headers['content-length']=out.length;res.writeHead(name==='response-409'?409:200,headers);if(name==='response-progress'){const abort=new AbortController();res.on('close',()=>abort.abort());res.write(out.subarray(0,PREFIX));waitUntil(()=>state.matches(nonce,'response')&&state.seen(nonce),WAIT_MS,25,abort.signal).then(()=>res.end(out.subarray(PREFIX)),()=>{state.clear(nonce);if(!res.destroyed)fail('transport',res);});}else if(name==='response-chunked'){res.write(out.subarray(0,3));res.end(out.subarray(3));}else if(name==='response-trailer'){res.write(out);res.addTrailers({'x-fixture-end':'done'});res.end();}else res.end(out);
  },observe);
 });server.on('tlsClientError',()=>fail('server_tls',null));ctl.listen(9445,'127.0.0.1',()=>server.listen(9444,'127.0.0.1',()=>process.stdout.write('READY 9444\n')));const stop=()=>{ctl.close();ctl.closeAllConnections();server.close(()=>process.exit(process.exitCode||0));server.closeAllConnections();};process.on('SIGTERM',stop);process.on('SIGINT',stop);
}
async function client(name){
 if(!cases.includes(name))return fail('client_setup',null);
 const progress=name==='request-progress'||name==='response-progress',nonce=progress?crypto.randomBytes(16).toString('hex'):null,mode=progress?name.split('-')[0]:null;
 let req;const abort=new AbortController();
 try{
  if(progress)await control('POST','/'+mode,nonce);
  await new Promise((resolve,reject)=>{
   const payload=body(name,'request'),headers={'content-type':'application/json','x-fixture-case':name,'te':'trailers'};if(progress)headers['x-fixture-nonce']=nonce;if(name==='request-compressed')headers['content-encoding']='gzip';if(name==='request-trailer')headers.trailer='x-fixture-end';else if(!['request-chunked','request-progress'].includes(name))headers['content-length']=payload.length;
   req=https.request({host:'127.0.0.1',port:9443,servername:'pilot-destination',path:'/pilot',method:'POST',ca:fs.readFileSync('/fixture/ca.crt'),cert:fs.readFileSync('/fixture/client.crt'),key:fs.readFileSync('/fixture/client.key'),rejectUnauthorized:true,headers},res=>{if(res.statusCode!==(name==='response-409'?409:200)){fail('client_status',res);return reject(new Error('status'));}if(res.headers['content-encoding']!==(name==='response-compressed'?'gzip':undefined)){fail('client_response_metadata',res);return reject(new Error('metadata'));}let ack=Promise.resolve();const observe=name==='response-progress'?prefixObserver(reply.subarray(0,PREFIX),()=>{ack=control('POST','/ack',nonce);ack.catch(()=>res.destroy());}):null;res.on('error',reject);res.on('close',()=>{if(!res.complete)reject(new Error('closed'));});checked(res,body(name,'response'),'client_response_bytes',()=>{if(res.trailers['x-fixture-end']!==(name==='response-trailer'?'done':undefined)){fail('client_response_trailers',res);return reject(new Error('trailers'));}ack.then(resolve,reject);},observe,reject);});req.setTimeout(10000,()=>req.destroy());req.on('error',reject);
   if(name==='request-progress'){req.write(payload.subarray(0,PREFIX));waitUntil(()=>control('GET','/state',nonce).then(x=>x==='1'),WAIT_MS,25,abort.signal).then(()=>req.end(payload.subarray(PREFIX)),reject);}else if(name==='request-chunked'){req.write(payload.subarray(0,3));req.end(payload.subarray(3));}else if(name==='request-trailer'){req.write(payload);req.addTrailers({'x-fixture-end':'done'});req.end();}else req.end(payload);
  });
  if(progress)await control('DELETE','/',nonce);
  process.stdout.write('OK\n');
 }catch(e){abort.abort();if(req)req.destroy();if(progress)try{await control('DELETE','/',nonce);}catch(_){}fail(typeof e.code==='string'&&(e.code.startsWith('ERR_TLS_')||e.code.startsWith('CERT_')||e.code==='UNABLE_TO_VERIFY_LEAF_SIGNATURE')?'client_tls':'transport',null);}
}
if(require.main===module){if(process.argv[2]==='server')serve();else if(process.argv[2]==='client')client(process.argv[3]);else fail('client_setup',null);}
module.exports={rendezvous,prefixObserver,waitUntil,checked};
