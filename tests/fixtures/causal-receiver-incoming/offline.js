'use strict';
const assert=require('node:assert/strict'),http=require('node:http'),tls=require('node:tls'),crypto=require('node:crypto');
const rootApi=require('../../../collectors/nodered/receiver-integration/private-root-handoff');
const baseApi=require('../../../collectors/nodered/error-integration/private-handoff');
const incoming=require('../../../collectors/nodered/receiver-integration/private-incoming');
const fixture=require('../../../docs/specification/fixtures/causal-evidence-v1.json');
const b=fixture[0].body,canonical=fixture[0].canonical,epoch=BigInt(b.receiver_session_epoch),peer=Buffer.from('peer'),local=Buffer.from('local'),hash=x=>crypto.createHash('sha256').update(x).digest('hex');let now=0,allowed=true,apps=0;
const authority=()=>({allowed,deadline:100000,tenant_id:b.tenant_id,gateway_id:b.gateway_id,gateway_generation:b.gateway_generation,receiver_runtime_id:b.receiver_runtime_id,receiver_session_epoch:b.receiver_session_epoch,gateway_backend_leaf:hash(peer),receiver_backend_leaf:hash(local)});
const permit=()=>({allowed,epoch,deadline:100000});
function setup(max=8){const base=baseApi.create({tenantId:b.tenant_id,runtimeId:b.receiver_runtime_id,epoch,authority:permit,maxBatchEvents:max,maxBatchBytes:4096,queueBytes:8192,queueTtlMs:10000});const wrap=rootApi.create({base,authority:permit,tenantId:b.tenant_id,runtimeId:b.receiver_runtime_id,epoch,queueTtlMs:10000,clock:()=>now});const inc=incoming.create({app(req){apps++;assert.ok(!req.rawHeaders.some((x,i)=>i%2===0&&x.toLowerCase().startsWith('x-apicontour-')));assert.equal(req.headers['x-apicontour-causal-binding'],undefined);assert.equal(req.headersDistinct['x-apicontour-causal-binding'],undefined);assert.equal(req.headers['x-apicontour-extra'],undefined);assert.equal(req.headersDistinct['x-apicontour-extra'],undefined);},producer:wrap.producer,authority,clock:()=>now});return {inc,wrap};}
function request(headers=['X-APIContour-Causal-Binding',canonical,'X-APIContour-Extra','private','X-Ordinary','kept']){const sock=new tls.TLSSocket();Object.defineProperties(sock,{authorized:{value:true,writable:true},destroyed:{value:false,writable:true},getPeerCertificate:{value:()=>({raw:peer}),configurable:true},getCertificate:{value:()=>({raw:local})}});const req=new http.IncomingMessage(sock);req._addHeaderLines(headers.slice(),headers.length);req.httpVersionMajor=1;return req;}
function msg(req){return {req};}
{
 const {inc,wrap}=setup(),req=request();inc.handler(req,{});const result=inc.consume([msg(req),msg(req)]);assert.ok(result);assert.equal(wrap.producer.root(result.ticket),result.root);assert.equal(inc.consume([msg(req)]),undefined);assert.equal(req.headers['x-ordinary'],'kept');inc.close();
}
for(const headers of [[],['X-APIContour-Causal-Binding',canonical,'x-apicontour-causal-binding',canonical],['Connection','X-APIContour-Causal-Binding','X-APIContour-Causal-Binding',canonical],['X-APIContour-Causal-Binding','{}'],['X-APIContour-Causal-Binding',JSON.stringify(b)]]){
 const {inc}=setup(),req=request(headers);inc.handler(req,{});assert.equal(inc.consume([msg(req)]),undefined);inc.close();
}
{
 const {inc}=setup(),req=request();req.socket.authorized=false;inc.handler(req,{});assert.equal(inc.consume([msg(req)]),undefined);inc.close();
}
{
 const {inc}=setup(),req=request();inc.handler(req,{});assert.equal(inc.consume([{get req(){throw Error('getter');}}]),undefined);assert.equal(inc.consume([new Proxy({req},{})]),undefined);assert.equal(inc.consume([msg({})]),undefined);assert.equal(inc.consume([msg(req),msg(request())]),undefined);assert.ok(inc.consume([msg(req)]));inc.close();
}
{
 now=0;const {inc}=setup(),req=request();inc.handler(req,{});now=5000;assert.equal(inc.consume([msg(req)]).status,'invalid');inc.close();now=0;
}
{
 const {inc}=setup(),req=request();inc.handler(req,{});req.emit('aborted');assert.equal(inc.consume([msg(req)]).status,'invalid');inc.close();
}
{
 const {inc}=setup(),req=request();inc.handler(req,{});allowed=false;assert.equal(inc.consume([msg(req)]).status,'invalid');allowed=true;assert.equal(inc.consume([msg(req)]),undefined);inc.close();
}
{
 const {inc}=setup(1),one=request(),two=request();inc.handler(one,{});inc.handler(two,{});assert.ok(inc.consume([msg(one)]));assert.equal(inc.consume([msg(two)]).status,'dropped');inc.close();
}
assert.ok(apps>0);console.log('receiver incoming offline: passed');
{
 const {inc}=setup(),req=request();Object.defineProperty(req.socket,'getPeerCertificate',{value:()=>({raw:Buffer.from('wrong')}),configurable:true});inc.handler(req,{});assert.equal(inc.consume([msg(req)]),undefined);inc.close();
}
{
 const {inc}=setup(),req=request();inc.handler(req,{});const replacement=request();req.socket=replacement.socket;assert.equal(inc.consume([msg(req)]).status,'invalid');inc.close();
}
{
 const {inc}=setup(),req=request();inc.handler(req,{});inc.close();assert.equal(inc.consume([msg(req)]).status,'invalid');
}

{
 now=0;const {inc}=setup(),requests=Array.from({length:33},()=>request());for(const req of requests)inc.handler(req,{});
 assert.equal(inc.consume([msg(requests[32])]),undefined);assert.ok(inc.consume([msg(requests[0])]));inc.close();
}
