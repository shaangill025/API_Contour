'use strict';
// Owned ephemeral loopback mTLS fixture. Execute only in the authorized host lane.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),https=require('node:https'),crypto=require('node:crypto');
const fixture=require('../../../docs/specification/fixtures/causal-evidence-v1.json');
const baseApi=require('../../../collectors/nodered/error-integration/private-handoff'),rootApi=require('../../../collectors/nodered/receiver-integration/private-root-handoff'),incoming=require('../../../collectors/nodered/receiver-integration/private-incoming');
const dir=path.join(__dirname,'../causal-container-launch/materials'),read=name=>fs.readFileSync(path.join(dir,name));
const ca=read('ca.pem'),serverCert=read('server.pem'),serverKey=read('server.key'),clientCert=read('product.pem'),clientKey=read('product.key'),otherCert=read('export.pem'),otherKey=read('export.key');
const hash=pem=>crypto.createHash('sha256').update(new crypto.X509Certificate(pem).raw).digest('hex');
const binding=fixture[0].body,epoch=BigInt(binding.receiver_session_epoch),now=require('node:perf_hooks').performance;
const permit=()=>({allowed:true,epoch,deadline:now.now()+60000});
let badScope=false,badLocal=false,phase='setup',httpStatus='none',seenDelta='none';
const authority=()=>({allowed:true,deadline:now.now()+60000,tenant_id:binding.tenant_id,gateway_id:badScope?'123e4567-e89b-12d3-a456-426614174001':binding.gateway_id,gateway_generation:binding.gateway_generation,receiver_runtime_id:binding.receiver_runtime_id,receiver_session_epoch:binding.receiver_session_epoch,gateway_backend_leaf:hash(clientCert),receiver_backend_leaf:badLocal?'0'.repeat(64):hash(serverCert)});
async function main(){
 const base=baseApi.create({tenantId:binding.tenant_id,runtimeId:binding.receiver_runtime_id,epoch,authority:permit,maxBatchEvents:8,maxBatchBytes:4096,queueBytes:8192,queueTtlMs:10000});
 const wrap=rootApi.create({base,authority:permit,tenantId:binding.tenant_id,runtimeId:binding.receiver_runtime_id,epoch,queueTtlMs:10000});let result,seen=0,action='normal';
 const receiver=incoming.create({producer:wrap.producer,authority,app(req,res){seen++;assert.equal(req.headers['x-apicontour-causal-binding'],undefined);assert.equal(req.headersDistinct['x-apicontour-causal-binding'],undefined);assert.ok(!req.rawHeaders.some((v,i)=>i%2===0&&v.toLowerCase().startsWith('x-apicontour-')));if(action==='abort')req.emit('aborted');if(action==='close')receiver.close();result=receiver.consume([{req}]);res.end('ok');}});
 const server=https.createServer({ca,cert:serverCert,key:serverKey,requestCert:true,rejectUnauthorized:true},receiver.handler);
 const deadline=setTimeout(()=>{server.closeAllConnections();server.close();process.exitCode=1;},10000);deadline.unref();
 try{
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  async function request(headers,cert=clientCert,key=clientKey){
   result=undefined;httpStatus='none';seenDelta='none';const before=seen;
   const response=await new Promise((resolve,reject)=>{const req=https.request({host:'127.0.0.1',port:server.address().port,servername:'causal-node',ca,cert,key,rejectUnauthorized:true,method:'POST',headers:['host','causal-node',...headers]},res=>{let body='';res.on('data',c=>body+=c);res.on('end',()=>resolve([res.statusCode,body]));});req.on('error',reject);req.end();});
   httpStatus=response[0]===200?'200':response[0]===400?'400':'other';seenDelta=seen-before===1?'one':seen-before===0?'zero':'other';assert.deepEqual(response,[200,'ok']);assert.equal(seen,before+1);return result;
  }
  const valid=['x-apicontour-causal-binding',fixture[0].canonical,'x-apicontour-extra','private'];
  phase='valid';const first=await request(valid);assert.ok(first);assert.equal(wrap.producer.root(first.ticket),first.root);
  phase='peer';assert.equal(await request(valid,otherCert,otherKey),undefined);
  phase='scope';badScope=true;assert.equal(await request(valid),undefined);badScope=false;
  phase='local';badLocal=true;assert.equal(await request(valid),undefined);badLocal=false;
  phase='duplicate';assert.equal(await request(['x-apicontour-causal-binding',fixture[0].canonical,'X-APIContour-Causal-Binding',fixture[0].canonical]),undefined);
  phase='connection';assert.equal(await request(['connection','x-apicontour-causal-binding','x-apicontour-causal-binding',fixture[0].canonical]),undefined);
  phase='abort';action='abort';assert.equal((await request(valid)).status,'invalid');
  phase='close';action='close';assert.equal((await request(valid)).status,'invalid');
  console.log('receiver incoming host mTLS: passed');
 }finally{clearTimeout(deadline);receiver.close();wrap.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
}
main().catch(()=>{console.error(`receiver incoming host mTLS: failed phase=${phase} status=${httpStatus} seen=${seenDelta}`);process.exitCode=1;});
