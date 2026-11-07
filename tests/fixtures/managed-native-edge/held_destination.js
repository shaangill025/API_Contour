'use strict';
// Disposable owned destination, mTLS only, with stdout/stdin test barriers.
const fs=require('node:fs'),https=require('node:https'),readline=require('node:readline');
const requestBody=Buffer.from('{"probe":true}'),prefix=Buffer.from('{"probe":'),response=Buffer.from('{"result":"owned-pilot-ok"}');
let held;
const server=https.createServer({key:fs.readFileSync('/pilot/tls/server.key'),cert:fs.readFileSync('/pilot/tls/server.crt'),ca:fs.readFileSync('/pilot/ca.crt'),requestCert:true,rejectUnauthorized:true,minVersion:'TLSv1.2'},(req,res)=>{
 if(req.method!=='POST'||req.url!=='/pilot'||!req.socket.authorized)return req.destroy();
 let chunks=[],length=0,marked=false;
 req.on('data',b=>{length+=b.length;if(length>1024)return req.destroy();chunks.push(b);const partial=Buffer.concat(chunks);if(!marked&&partial.length>=prefix.length&&partial.subarray(0,prefix.length).equals(prefix)){marked=true;process.stdout.write('REQUEST_PREFIX\n');}});
 req.on('end',()=>{if(!Buffer.concat(chunks).equals(requestBody))return req.destroy();res.writeHead(200,{'content-type':'application/json'});
  if(req.headers['x-fixture-stream']==='response') {if(held)return res.destroy();held=res;res.write('{"result":');process.stdout.write('RESPONSE_WRITTEN\n');}
  else res.end(response);
 });
});
server.on('tlsClientError',()=>{process.stderr.write('DIAG tls\n');process.exitCode=1;});
readline.createInterface({input:process.stdin}).on('line',line=>{if(line!=='RELEASE_RESPONSE'||!held){process.stderr.write('DIAG control\n');process.exitCode=1;return;}const current=held;held=null;current.end('"owned-pilot-ok"}');});
server.listen(9443,'0.0.0.0',()=>process.stdout.write('READY\n'));
const stop=()=>{server.close(()=>process.exit(process.exitCode||0));server.closeAllConnections();};process.on('SIGTERM',stop);process.on('SIGINT',stop);
