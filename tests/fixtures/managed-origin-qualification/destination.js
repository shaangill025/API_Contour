'use strict';
// Qualification-only destination. Control is fixed loopback and nonce-bound;
// it never returns request data, credentials, paths or arbitrary network I/O.
const fs=require('node:fs'),https=require('node:https'),http=require('node:http');
const prefix=Buffer.from('{"probe":'),request=Buffer.from('{"probe":true}'),response=Buffer.from('{"result":"owned-pilot-ok"}');
const responsePrefix=Buffer.from('{"result":');
let slot=null; const used=new Set();
function nonceValid(x){return typeof x==='string'&&/^[0-9a-f]{32}$/.test(x);}
function begin(nonce,mode){
 if(!nonceValid(nonce)||!['request','response'].includes(mode)||used.has(nonce)||used.size>=64||slot&&slot.state!=='DONE'&&slot.state!=='ERROR')return false;
 used.add(nonce);slot={nonce,mode,state:'PENDING',response:null,timer:null};
 slot.timer=setTimeout(()=>{if(slot&&slot.nonce===nonce&&slot.state!=='DONE'){slot.state='ERROR';if(slot.response)slot.response.destroy();}},10000);return true;
}
function status(nonce){return slot&&slot.nonce===nonce?slot.state:'UNKNOWN';}
function release(nonce){
 if(!slot||slot.nonce!==nonce||slot.mode!=='response'||slot.state!=='RESPONSE_PREFIX'||!slot.response)return false;
 const out=slot.response;slot.response=null;slot.state='DONE';clearTimeout(slot.timer);out.end('"owned-pilot-ok"}');return true;
}
function start(){
 const server=https.createServer({key:fs.readFileSync('/pilot/tls/server.key'),cert:fs.readFileSync('/pilot/tls/server.crt'),ca:fs.readFileSync('/pilot/ca.crt'),requestCert:true,rejectUnauthorized:true,minVersion:'TLSv1.2'},(req,res)=>{
  if(req.method!=='POST'||req.url!=='/pilot'||!req.socket.authorized){res.writeHead(404);res.end();req.resume();return;}
  const mode=req.headers['x-managed-qual-mode'],nonce=req.headers['x-managed-qual-nonce'];
  const controlled=mode!==undefined||nonce!==undefined;
  if(controlled&&!begin(nonce,mode)){res.writeHead(409);res.end();req.resume();return;}
  let parts=[],length=0,marked=false;
  req.on('data',chunk=>{
   length+=chunk.length;if(length>1024){if(controlled)slot.state='ERROR';req.destroy();return;}
   parts.push(chunk);const current=Buffer.concat(parts);
   if(controlled&&mode==='request'&&!marked&&current.length>=prefix.length){
    if(!current.subarray(0,prefix.length).equals(prefix)){slot.state='ERROR';req.destroy();return;}
    marked=true;slot.state='REQUEST_PREFIX';
   }
  });
  req.on('error',()=>{if(controlled&&slot&&slot.nonce===nonce)slot.state='ERROR';});
  req.on('end',()=>{
   if(controlled&&!Buffer.concat(parts).equals(request)){slot.state='ERROR';req.destroy();return;}
   res.writeHead(200,{'content-type':'application/json'});
   if(controlled&&mode==='response'){slot.response=res;res.write(responsePrefix);slot.state='RESPONSE_PREFIX';}
   else {if(controlled){slot.state='DONE';clearTimeout(slot.timer);}res.end(response);}
  });
 });
 server.headersTimeout=5000;server.requestTimeout=5000;server.keepAliveTimeout=1000;server.maxConnections=32;
 server.on('clientError',(_e,socket)=>socket.destroy());
 const control=http.createServer((req,res)=>{
  const match=typeof req.url==='string'&&/^\/v1\/(status|release)\/([0-9a-f]{32})$/.exec(req.url);
  if(!match){res.writeHead(404);res.end();req.resume();return;}
  if(req.method==='GET'&&match[1]==='status'){res.writeHead(200,{'content-type':'text/plain','cache-control':'no-store'});res.end(status(match[2]));return;}
  if(req.method==='POST'&&match[1]==='release'){
   let count=0;req.on('data',x=>{count+=x.length;if(count>0)req.destroy();});
   req.on('end',()=>{res.writeHead(count===0&&release(match[2])?204:409);res.end();});return;
  }
  res.writeHead(405);res.end();req.resume();
 });
 control.headersTimeout=2000;control.requestTimeout=2000;control.maxConnections=8;
 server.listen(9443,'0.0.0.0');control.listen(9445,'127.0.0.1');
 const stop=()=>{server.close();control.close();if(slot&&slot.timer)clearTimeout(slot.timer);setTimeout(()=>process.exit(1),3000).unref();};
 process.on('SIGTERM',stop);process.on('SIGINT',stop);
}
if(require.main===module)start();
module.exports={nonceValid,begin,status,release};
