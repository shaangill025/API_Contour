'use strict';
// Synthetic fixed mTLS authority; capture attempts are deliberately rejected.
const fs=require('node:fs'),https=require('node:https'),crypto=require('node:crypto');
const config=JSON.parse(fs.readFileSync('/fixture/authority.json','utf8'));
const policy=config.policy,id=config.id,source=config.source,peer=config.peer;
const server=https.createServer({key:fs.readFileSync('/fixture/server.key'),cert:fs.readFileSync('/fixture/server.crt'),ca:fs.readFileSync('/fixture/ca.crt'),requestCert:true,rejectUnauthorized:true,ALPNProtocols:['http/1.1']},(req,res)=>{
 const c=req.socket.getPeerCertificate(true);if(!req.socket.authorized||!c.raw||crypto.createHash('sha256').update(c.raw).digest('hex')!==peer)return req.destroy();
 let parts=[],size=0;req.on('data',b=>{size+=b.length;if(size>1048576)return req.destroy();parts.push(b);});
 req.on('end',()=>{if(req.method!=='POST')return req.destroy();
  if(req.url==='/v1/batches'){process.stdout.write('BATCH_ATTEMPT\n');res.writeHead(503,{'content-type':'application/json'});return res.end('{}');}
  if(req.url!=='/v1/collector-authority'||size>32768)return req.destroy();
  let x;try{x=JSON.parse(Buffer.concat(parts));}catch(_){return req.destroy();}
  if(!x||Object.keys(x).sort().join(',')!=='challenge,source_ids,wire_version'||x.wire_version!==1||typeof x.challenge!=='string'||! /^[0-9a-f]{64}$/.test(x.challenge)||!Array.isArray(x.source_ids)||x.source_ids.length!==1||x.source_ids[0]!==source)return req.destroy();
  const out=JSON.stringify({wire_version:1,challenge:x.challenge,tenant_id:id,collector_id:id,checked_at:new Date().toISOString(),signed_policy:policy,sources:[{source_id:source,project_id:id,service_id:id,environment_id:id,deployment_id:id,technique:'gateway',parser_profiles:['http_json_v1']}]});
  res.writeHead(200,{'content-type':'application/json'});res.end(out,()=>process.stdout.write('AUTHORITY_SENT\n'));
 });
});
server.on('tlsClientError',()=>{process.stderr.write('DIAG tls\n');process.exitCode=1;});
server.listen(9445,'0.0.0.0',()=>process.stdout.write('READY\n'));
const stop=()=>{server.close(()=>process.exit(process.exitCode||0));server.closeAllConnections();};process.on('SIGTERM',stop);process.on('SIGINT',stop);
