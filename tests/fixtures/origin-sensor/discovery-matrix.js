'use strict';
// Synthetic-only exact forwarding checks. Diagnostics are closed labels only.
const fs=require('fs'),https=require('https'),crypto=require('crypto'),zlib=require('zlib');
const cases=['normal','request-malformed','response-malformed','request-compressed','response-compressed','request-oversized','response-oversized','request-chunked','response-chunked','request-trailer','response-trailer','response-409'];
const normal=Buffer.from('{"probe":true}'),reply=Buffer.from('{"id":1}'),malformed=Buffer.from('{"probe":'),huge=Buffer.from('{"probe":"'+'synthetic-secret-sentinel-'+'x'.repeat(65536)+'"}');
function body(name,direction){if(name===direction+'-malformed')return malformed;if(name===direction+'-oversized')return huge;if(name===direction+'-compressed')return zlib.gzipSync(direction==='request'?normal:reply);return direction==='request'?normal:reply;}
function digest(x){return crypto.createHash('sha256').update(x).digest('hex');}
function fail(label,stream){process.stderr.write('DIAG '+label+'\n');process.exitCode=1;if(stream)stream.destroy();}
function checked(stream,expected,label,done){let n=0,chunks=[];stream.on('data',b=>{n+=b.length;if(n>70000){fail(label,stream);return;}chunks.push(b);});stream.on('error',()=>fail('transport',null));stream.on('end',()=>{if(!Buffer.concat(chunks).equals(expected))return fail(label,stream);done();});}
if(process.argv[2]==='server'){
 const expected=process.env.EXPECTED_CLIENT_SHA256;
 const server=https.createServer({cert:fs.readFileSync('/fixture/destination.crt'),key:fs.readFileSync('/fixture/destination.key'),ca:fs.readFileSync('/fixture/ca.crt'),requestCert:true,rejectUnauthorized:true},(req,res)=>{
  const peer=req.socket.getPeerCertificate(true);if(!req.socket.authorized||!peer.raw||digest(peer.raw)!==expected)return fail('server_tls',res);
  const name=req.headers['x-fixture-case'];if(req.method!=='POST'||req.url!=='/pilot'||!cases.includes(name)||req.headers['content-encoding']!==(name==='request-compressed'?'gzip':undefined))return fail('server_request_metadata',res);
  checked(req,body(name,'request'),'server_request_bytes',()=>{if(req.trailers['x-fixture-end']!==(name==='request-trailer'?'done':undefined))return fail('server_request_trailers',res);
   const out=body(name,'response'),headers={'content-type':'application/json'};if(name==='response-compressed')headers['content-encoding']='gzip';if(name==='response-trailer')headers.trailer='x-fixture-end';else if(name!=='response-chunked')headers['content-length']=out.length;res.writeHead(name==='response-409'?409:200,headers);if(name==='response-chunked'){res.write(out.subarray(0,3));res.end(out.subarray(3));}else if(name==='response-trailer'){res.write(out);res.addTrailers({'x-fixture-end':'done'});res.end();}else res.end(out);
  });
 });server.on('tlsClientError',()=>fail('server_tls',null));server.listen(9444,'127.0.0.1',()=>process.stdout.write('READY 9444\n'));const stop=()=>{server.close(()=>process.exit(process.exitCode||0));server.closeAllConnections();};process.on('SIGTERM',stop);process.on('SIGINT',stop);
}else if(process.argv[2]==='client'){
 const name=process.argv[3];if(!cases.includes(name)){fail('client_setup',null);}else{
 const payload=body(name,'request'),headers={'content-type':'application/json','x-fixture-case':name,'te':'trailers'};if(name==='request-compressed')headers['content-encoding']='gzip';if(name==='request-trailer')headers.trailer='x-fixture-end';else if(name!=='request-chunked')headers['content-length']=payload.length;
 const req=https.request({host:'127.0.0.1',port:9443,servername:'pilot-destination',path:'/pilot',method:'POST',ca:fs.readFileSync('/fixture/ca.crt'),cert:fs.readFileSync('/fixture/client.crt'),key:fs.readFileSync('/fixture/client.key'),rejectUnauthorized:true,headers},res=>{if(res.statusCode!==(name==='response-409'?409:200))return fail('client_status',res);if(res.headers['content-encoding']!==(name==='response-compressed'?'gzip':undefined))return fail('client_response_metadata',res);checked(res,body(name,'response'),'client_response_bytes',()=>{if(res.trailers['x-fixture-end']!==(name==='response-trailer'?'done':undefined))return fail('client_response_trailers',res);process.stdout.write('OK\n');});});req.setTimeout(10000,()=>req.destroy());req.on('error',e=>fail(typeof e.code==='string'&&(e.code.startsWith('ERR_TLS_')||e.code.startsWith('CERT_')||e.code==='UNABLE_TO_VERIFY_LEAF_SIGNATURE')?'client_tls':'transport',null));if(name==='request-chunked'){req.write(payload.subarray(0,3));req.end(payload.subarray(3));}else if(name==='request-trailer'){req.write(payload);req.addTrailers({'x-fixture-end':'done'});req.end();}else req.end(payload);
 }
}else fail('client_setup',null);
