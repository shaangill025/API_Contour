'use strict';
// Synthetic, offline component tests. No sockets, TLS or producer proof.
const assert=require('node:assert/strict'), fs=require('node:fs'),vm=require('node:vm');
const crypto=require('node:crypto'),https=require('node:https'),http=require('node:http'),tls=require('node:tls');
const {performance}=require('node:perf_hooks');
const {install}=require('./private-producer-runtime'),{create}=require('./private-handoff');
const {createMarkerSigner}=require('./causal-marker');
const source=fs.readFileSync(require.resolve('./private-wire-dispatch.js'),'utf8');
const publicSource=fs.readFileSync(require.resolve('../../../crates/contour-postgres/src/transport.rs'),'utf8');
const certificate=publicSource.match(/const CERT: &str = r#"(-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----)/)[1];
const productLeafSha256=crypto.createHash('sha256').update(new crypto.X509Certificate(certificate).raw).digest('hex');
let nativeCount=0,httpCount=0,nativeAction=()=>{};
const fakeRequest=(url,opts)=>{nativeCount++;nativeAction(url,opts);return Object.create(http.ClientRequest.prototype);};
const fakeModule={exports:{}};
const fakeHttps={...https,request:fakeRequest};
const fakeHttp={...http,request:(url,opts)=>{httpCount++;nativeAction(url,opts);return Object.create(http.ClientRequest.prototype);}};
vm.runInThisContext('(function(require,module,exports){'+source+'\n})',{filename:'private-wire-dispatch.js'})(
 name=>name==='node:https'?fakeHttps:name==='node:http'?fakeHttp:require(name),fakeModule,fakeModule.exports);
const wire=fakeModule.exports;
const tenant='123e4567-e89b-12d3-a456-426614174001',runtime='123e4567-e89b-12d3-a456-426614174002';
function setup(overrides={},wireOverrides={},bufferTLS=false){
 let state={allowed:true,epoch:1n,deadline:performance.now()+10000},control;
 const q=create({tenantId:tenant,runtimeId:runtime,epoch:1n,authority:()=>state,maxBatchEvents:8,maxBatchBytes:4096,queueBytes:8192,queueTtlMs:10000,...overrides});
 const callbacks={};const hooks={add(k,f){callbacks[k.split('.')[0]]=f;},remove(){},clear(){},has(k){return !!callbacks[k.split('.')[0]];},trigger(k,e,done){const f=callbacks[k];if(f)f(e,done);else done();}};
 const adapter=install(hooks,{inbound:['in'],requests:['worker'],maxPending:8,maxEvents:128,maxBytes:16384,ttlMs:1000,ingressPoint:{node:'in',method:'POST',url:'/run'}},c=>{control=c;c.attachProducer(q);});
 const node={},agent=new https.Agent({keepAlive:true});
 const tlsOptions={certificateAuthority:'synthetic-ca',certificate,key:'synthetic-key',serverName:'example.test',rejectUnauthorized:true};
 if(bufferTLS)for(const key of ['certificateAuthority','certificate','key'])tlsOptions[key]=Buffer.from(tlsOptions[key]);
 const signer=createMarkerSigner(Buffer.alloc(32,7));
 const dispatcher=wire.create({control,handoff:q,signer,tenantId:tenant,runtimeId:runtime,epoch:1n,productLeafSha256,destination:'https://example.test/run',method:'POST',agent,tlsOptions,...wireOverrides});
 const opts={headers:{'X-ApiContour-Forged':'spoof','content-type':'text/plain'},hooks:{beforeRequest:[]}};
 function context(fn){const msg={req:{method:'POST',url:'/run',headers:{}}};hooks.trigger('onSend',[{source:{id:'in'},msg}],()=>{
    const e={destination:{node,id:'worker'}};hooks.trigger('preDeliver',e,()=>{const frame=control.claimDelivery(e);control.bind(frame,node,e,()=>hooks.trigger('onReceive',e,fn));});});}
 function normalized(){return {_unixOptions:undefined,_internals:{url:new URL('https://example.test/run'),method:'POST',request:undefined,http2:false,cache:undefined,dnsLookup:undefined,dnsCache:undefined,createConnection:undefined,enableUnixSockets:false,agent:{https:agent,http2:undefined},https:{...tlsOptions},headers:opts.headers}};}
 function nativeOpts(o){return {agent,method:'POST',setHost:true,headers:o._internals.headers,ca:tlsOptions.certificateAuthority,cert:tlsOptions.certificate,key:tlsOptions.key,servername:tlsOptions.serverName,rejectUnauthorized:true,checkServerIdentity:tls.checkServerIdentity,createConnection:undefined,lookup:undefined};}
 return {q,adapter,control,node,agent,opts,dispatcher,context,normalized,nativeOpts,set(v){state=v;}};
}
function events(q){const b=q.freeze();return b&&JSON.parse(b.canonical).events;}
{
 const t=setup();let scope;t.context(()=>{assert.equal(t.control.captureDispatch({}),undefined);scope=t.dispatcher.begin(t.node,t.opts);});
 assert(scope);assert.equal(t.opts.headers['X-ApiContour-Forged'],undefined);assert.equal(t.opts.headers['content-type'],'text/plain');
 const o=t.normalized();t.opts.hooks.beforeRequest[0](o);const factory=o._internals.request;assert.equal(typeof factory,'function');
 let marker,calls=0;assert.equal(t.opts.headers['x-apicontour-causal-marker'],undefined);
 nativeAction=()=>{marker=t.opts.headers['x-apicontour-causal-marker'];assert(marker.startsWith('ac1.'));calls++;assert.equal(o._internals.request,undefined,'factory must restore before constructor');};
 const result=factory(o._internals.url,t.nativeOpts(o));assert(result instanceof http.ClientRequest);assert.equal(calls,1);
 const list=events(t.q);assert.deepEqual(list.map(x=>x.kind),['root','delivery','attempt']);
 const digest=crypto.createHash('sha256').update('apicontour/causal-marker-wire/1\n').update(marker).digest('hex');
 assert.equal(list[2].marker_digest,digest);assert.equal(list[2].root,list[1].root);assert.equal(list[2].activity,list[1].activity);
 scope.close();assert.equal(t.control.dispatchContext({},t.node),undefined);nativeAction=()=>{};
}
{
 const t=setup();let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));const o=t.normalized();t.opts.hooks.beforeRequest[0](o);
 nativeAction=()=>{throw Error('constructor failed');};assert.throws(()=>o._internals.request(o._internals.url,t.nativeOpts(o)),/constructor failed/);nativeAction=()=>{};
 const list=events(t.q);assert.deepEqual(list.map(x=>x.kind),['root','delivery','loss']);assert.deepEqual([list[2].first_missing_seq,list[2].last_missing_seq,list[2].seq],[3,3,4]);scope.close();
}
{
 const t=setup();let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));const o=t.normalized();t.opts.hooks.beforeRequest[0](o);
 nativeAction=()=>{assert.equal(events(t.q),undefined,'unsettled reservation must not export a prefix');assert.equal(t.q.offer(Object.freeze({kind:'ROOT_INTENT',root:'f'.repeat(32)})),false);};
 o._internals.request(o._internals.url,t.nativeOpts(o));nativeAction=()=>{};const list=events(t.q);
 assert.deepEqual(list.map(x=>x.kind),['root','delivery','attempt','loss']);assert.deepEqual([list[3].first_missing_seq,list[3].last_missing_seq,list[3].seq],[4,4,5]);scope.close();
}
{
 const t=setup();let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));const o=t.normalized();t.opts.hooks.beforeRequest[0](o);
 t.dispatcher.closeNode({});assert.equal(typeof o._internals.request,'function');t.dispatcher.closeNode(t.node);
 assert.equal(o._internals.request,undefined);assert.equal(t.opts.headers['x-apicontour-causal-marker'],undefined);
 assert.deepEqual(events(t.q).map(x=>x.kind),['root','delivery']);scope.close();
}
{
 const t=setup();let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));t.agent.options.path='/tmp/untrusted.sock';
 const o=t.normalized();t.opts.hooks.beforeRequest[0](o);assert.equal(o._internals.request,undefined);
 assert.equal(t.opts.headers['x-apicontour-causal-marker'],undefined);scope.close();
}
{
 const t=setup();let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));const o=t.normalized();t.opts.hooks.beforeRequest[0](o);scope.close();
 assert.equal(o._internals.request,undefined);assert.equal(t.opts.headers['x-apicontour-causal-marker'],undefined);
 assert.deepEqual(events(t.q).map(x=>x.kind),['root','delivery']);
}
{
 const t=setup();let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));const o=t.normalized();t.opts.hooks.beforeRequest[0](o);
 nativeAction=()=>t.set({allowed:false,epoch:1n,deadline:performance.now()+10000});o._internals.request(o._internals.url,t.nativeOpts(o));nativeAction=()=>{};
 assert.equal(t.q.freeze(),undefined);assert(t.adapter.snapshot().loss>0);scope.close();
}
{
 const t=setup();let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));
 for(const mutate of [o=>o._internals.url=new URL('http://example.test/run'),o=>o._internals.url=new URL('https://other.test/run'),
  o=>o._internals.http2=true,o=>o._internals.request=()=>{},o=>o._internals.agent.https={},o=>o._internals.https.rejectUnauthorized=false,
  o=>o._internals.https.checkServerIdentity=()=>{},o=>o._internals.createConnection=()=>{},o=>o._internals.cache={},o=>o._internals.dnsLookup=()=>{}]){
  const o=t.normalized();o._internals.headers['X-ApiContour-Spoof']='bad';mutate(o);t.opts.hooks.beforeRequest[0](o);
  assert.equal(o._internals.headers['X-ApiContour-Spoof'],undefined);assert.equal(o._internals.headers['x-apicontour-causal-marker'],undefined);
 }
 assert.deepEqual(events(t.q).map(x=>x.kind),['root','delivery']);scope.close();
}
{
 const t=setup();let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));t.set({allowed:false,epoch:1n,deadline:performance.now()+10000});
 let reads=0;const o=new Proxy({}, {get(){reads++;throw Error('read');},getOwnPropertyDescriptor(){reads++;throw Error('descriptor');}});
 t.opts.hooks.beforeRequest[0](o);assert.equal(reads,0);assert.equal(t.q.freeze(),undefined);scope.close();
}
{
 // No capacity means no marker, no reserved attempt, and ordinary request can continue.
 const t=setup({maxBatchEvents:2});let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));
 const o=t.normalized();t.opts.hooks.beforeRequest[0](o);o._internals.request(o._internals.url,t.nativeOpts(o));
 assert.equal(t.opts.headers['x-apicontour-causal-marker'],undefined);assert(t.adapter.snapshot().loss>0);assert.deepEqual(events(t.q).map(x=>x.kind),['root','delivery']);scope.close();
}
{
 const t=setup({}, {maxAttempts:2});let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));const markers=[];
 nativeAction=()=>markers.push(t.opts.headers['x-apicontour-causal-marker']);for(let i=0;i<2;i++){const o=t.normalized();t.opts.hooks.beforeRequest[0](o);o._internals.request(o._internals.url,t.nativeOpts(o));}nativeAction=()=>{};
 assert.notEqual(markers[0],markers[1]);const o=t.normalized();t.opts.hooks.beforeRequest[0](o);
 assert.equal(o._internals.request,undefined);assert.equal(t.opts.headers['x-apicontour-causal-marker'],undefined);
 assert.deepEqual(events(t.q).map(x=>x.kind),['root','delivery','attempt','attempt']);scope.close();
}
{
 const t=setup();let scope;t.context(()=>scope=t.dispatcher.begin({},t.opts));const o=t.normalized();t.opts.hooks.beforeRequest[0](o);
 assert.equal(o._internals.request,undefined);assert.equal(t.opts.headers['x-apicontour-causal-marker'],undefined);scope.close();
}
{
 let t;const revokeSigner=Object.freeze({sign(){t.set({allowed:false,epoch:1n,deadline:performance.now()+10000});return Object.freeze({header:'forged',markerDigest:'a'.repeat(64)});}});
 t=setup({}, {signer:revokeSigner});let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));const o=t.normalized();
 t.opts.hooks.beforeRequest[0](o);o._internals.request(o._internals.url,t.nativeOpts(o));assert.equal(t.opts.headers['x-apicontour-causal-marker'],undefined);assert.equal(t.q.freeze(),undefined);scope.close();
}
{
 const t=setup();let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));const o=t.normalized();t.opts.hooks.beforeRequest[0](o);
 const factory=o._internals.request;factory(o._internals.url,t.nativeOpts(o));let unmarked=false;
 nativeAction=(_url,opts)=>{unmarked=!Object.keys(opts.headers).some(x=>x.toLowerCase().startsWith('x-apicontour-'));};
 factory(o._internals.url,t.nativeOpts(o));nativeAction=()=>{};assert(unmarked);assert.deepEqual(events(t.q).map(x=>x.kind),['root','delivery','attempt']);scope.close();
}
{
 // A destination changed after beforeRequest must be scrubbed and use the
 // corresponding native fallback, never send the stale marked headers.
 const t=setup();let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));const o=t.normalized();t.opts.hooks.beforeRequest[0](o);
 const factory=o._internals.request,opts=t.nativeOpts(o);let seen=false;const before=httpCount;
 nativeAction=(_url,value)=>{seen=!Object.keys(value.headers).some(x=>x.toLowerCase().startsWith('x-apicontour-'));};
 factory(new URL('http://other.test/run'),opts);nativeAction=()=>{};assert(seen);assert.equal(httpCount,before+1);
 assert.deepEqual(events(t.q).map(x=>x.kind),['root','delivery']);scope.close();
}
{
 const t=setup();let reads=0,scope;const badHeaders=new Proxy({}, {get(){reads++;throw Error('get');},getOwnPropertyDescriptor(){reads++;throw Error('descriptor');},ownKeys(){reads++;throw Error('keys');}});
 const bad={headers:badHeaders,hooks:{beforeRequest:[]}}, before=t.adapter.snapshot().loss;
 t.context(()=>scope=t.dispatcher.begin(t.node,bad));assert.equal(reads,0);assert.equal(bad.hooks.beforeRequest.length,0);
 assert(t.adapter.snapshot().loss>before);assert.deepEqual(events(t.q).map(e=>e.kind),['root','delivery']);scope.close();
}
{
 let reads=0;const t=setup();const bad={headers:{}};Object.defineProperty(bad,'hooks',{get(){reads++;throw Error('getter');}});
 let scope;t.context(()=>scope=t.dispatcher.begin(t.node,bad));assert.equal(reads,0);scope.close();
}
{
 // Both Got hooks run before either factory, as happens across await.
 const t=setup(), second={headers:{},hooks:{beforeRequest:[]}};let a,b;
 t.context(()=>{a=t.dispatcher.begin(t.node,t.opts);b=t.dispatcher.begin(t.node,second);});
 const x=t.normalized(),y=t.normalized();y._internals.headers=second.headers;
 t.opts.hooks.beforeRequest[0](x);second.hooks.beforeRequest[0](y);
 assert.equal(t.opts.headers['x-apicontour-causal-marker'],undefined);assert.equal(second.headers['x-apicontour-causal-marker'],undefined);
 const markers=[];nativeAction=(_url,opts)=>markers.push(opts.headers['x-apicontour-causal-marker']);
 x._internals.request(x._internals.url,t.nativeOpts(x));y._internals.request(y._internals.url,t.nativeOpts(y));nativeAction=()=>{};
 assert.equal(markers.length,2);assert(markers[0]&&markers[1]);assert.notEqual(markers[0],markers[1]);
 assert.deepEqual(events(t.q).map(e=>e.kind),['root','delivery','attempt','attempt']);a.close();b.close();
}
{
 for(const [name,value] of [['hostname','evil.test'],['port',444],['path','/other'],['method','GET'],['socketPath','/tmp/evil'],['secureContext',{}]]){
  const t=setup();let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));const o=t.normalized();t.opts.hooks.beforeRequest[0](o);
  const opts=t.nativeOpts(o);opts[name]=value;let unmarked=false;nativeAction=(_url,v)=>{unmarked=!v.headers['x-apicontour-causal-marker'];};
  o._internals.request(o._internals.url,opts);nativeAction=()=>{};assert(unmarked,name);assert.deepEqual(events(t.q).map(e=>e.kind),['root','delivery']);scope.close();
 }
}
{
 const t=setup({}, {}, true);let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));const o=t.normalized();t.opts.hooks.beforeRequest[0](o);
 o._internals.request(o._internals.url,t.nativeOpts(o));assert.deepEqual(events(t.q).map(e=>e.kind),['root','delivery','attempt']);scope.close();
 const u=setup({}, {}, true);let other;u.context(()=>other=u.dispatcher.begin(u.node,u.opts));const x=u.normalized();u.opts.hooks.beforeRequest[0](x);
 x._internals.https.key[0]^=1;let unmarked=false;nativeAction=(_url,v)=>{unmarked=!v.headers['x-apicontour-causal-marker'];};
 x._internals.request(x._internals.url,u.nativeOpts(x));nativeAction=()=>{};assert(unmarked);assert.deepEqual(events(u.q).map(e=>e.kind),['root','delivery']);other.close();
}
{
 const max=(1n<<64n)-1n;const q=create({tenantId:tenant,runtimeId:runtime,epoch:1n,initialSequence:max-1n,authority:()=>({allowed:true,epoch:1n,deadline:performance.now()+10000}),maxBatchEvents:1,maxBatchBytes:2048,queueBytes:4096,queueTtlMs:10000});
 assert(q.offer({kind:'ROOT_INTENT',root:'a'.repeat(32)}));assert.equal(q.offer({kind:'ROOT_INTENT',root:'b'.repeat(32)}),false);
 const first=q.freeze();assert(first);assert.strictEqual(q.freeze(),first);assert(q.ack(first.batchId,first.sha256,1n));assert.equal(q.freeze(),undefined);assert.equal(q.admit(),false);
}
{
 for(const headers of [{host:'other.test'},{Host:'example.test',host:'example.test'},{Host:'EXAMPLE.TEST'}]){
  const t=setup();Object.assign(t.opts.headers,headers);let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));const o=t.normalized();t.opts.hooks.beforeRequest[0](o);
  let observed;const before=t.adapter.snapshot().loss;nativeAction=(_url,opts)=>{observed={...opts.headers};};o._internals.request(o._internals.url,t.nativeOpts(o));nativeAction=()=>{};
  assert.deepEqual(Object.fromEntries(Object.entries(observed).filter(([k])=>k.toLowerCase()==='host')),headers);assert.equal(observed['x-apicontour-causal-marker'],undefined);
  assert(t.adapter.snapshot().loss>before);assert.deepEqual(events(t.q).map(e=>e.kind),['root','delivery']);scope.close();
 }
 for(const headers of [{},{Host:'example.test'}]){
  const t=setup();Object.assign(t.opts.headers,headers);let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));const o=t.normalized();t.opts.hooks.beforeRequest[0](o);
  let marked=false;nativeAction=(_url,opts)=>{marked=!!opts.headers['x-apicontour-causal-marker'];};o._internals.request(o._internals.url,t.nativeOpts(o));nativeAction=()=>{};assert(marked);
  assert.deepEqual(events(t.q).map(e=>e.kind),['root','delivery','attempt']);scope.close();
 }
}
{
 // URL instances can carry own Node request overrides even when href matches.
 const t=setup();let scope;t.context(()=>scope=t.dispatcher.begin(t.node,t.opts));const o=t.normalized();
 o._internals.url.socketPath='/tmp/evil';o._internals.url.secureContext={};t.opts.hooks.beforeRequest[0](o);
 let received;nativeAction=(url)=>{received=url;};o._internals.request(o._internals.url,t.nativeOpts(o));nativeAction=()=>{};
 assert.notStrictEqual(received,o._internals.url);assert.equal(received.href,o._internals.url.href);
 assert.equal(Object.hasOwn(received,'socketPath'),false);assert.equal(Object.hasOwn(received,'secureContext'),false);
 assert.deepEqual(events(t.q).map(e=>e.kind),['root','delivery','attempt']);scope.close();
 const u=setup();let other;u.context(()=>other=u.dispatcher.begin(u.node,u.opts));const x=u.normalized();x._internals.url.socketPath='/tmp/keep';u.opts.hooks.beforeRequest[0](x);
 const options=u.nativeOpts(x);options.socketPath='/tmp/fallback';let passed;nativeAction=(url)=>{passed=url;};x._internals.request(x._internals.url,options);nativeAction=()=>{};
 assert.strictEqual(passed,x._internals.url);assert.equal(passed.socketPath,'/tmp/keep');assert.deepEqual(events(u.q).map(e=>e.kind),['root','delivery']);other.close();
}
{
 const max=(1n<<64n)-1n,common={tenantId:tenant,runtimeId:runtime,epoch:1n,authority:()=>({allowed:true,epoch:1n,deadline:performance.now()+10000}),maxBatchEvents:2,maxBatchBytes:2048,queueBytes:4096,queueTtlMs:10000};
 const frame=Object.freeze({root:'a'.repeat(32),activity:'b'.repeat(32),attempt:'c'.repeat(32),marker_digest:'d'.repeat(64)});
 const q=create({...common,initialSequence:max-4n});assert(q.offer({kind:'ROOT_INTENT',root:'a'.repeat(32)}));assert(q.offer({kind:'ROOT_INTENT',root:'b'.repeat(32)}));
 assert.equal(q.offer({kind:'ROOT_INTENT',root:'e'.repeat(32)}),false);const frozen=q.freeze();assert(frozen);assert.strictEqual(q.freeze(),frozen);assert(q.ack(frozen.batchId,frozen.sha256,1n));
 assert.equal(q.reserveAttempt(frame),undefined);const loss=q.freeze();assert(loss);assert.strictEqual(q.freeze(),loss);assert(loss.canonical.includes('18446744073709551614'));
 for(const commit of [false,true]){
  const r=create({...common,initialSequence:max-2n});const ticket=r.reserveAttempt(frame);assert(ticket);
  assert.equal(r.offer({kind:'ROOT_INTENT',root:'f'.repeat(32)}),false);assert.equal(r.freeze(),undefined);
  assert(commit?r.commitAttempt(ticket):r.cancelAttempt(ticket));const batch=r.freeze();assert(batch);assert.strictEqual(r.freeze(),batch);
  assert(batch.canonical.includes('18446744073709551615'));const kinds=JSON.parse(batch.canonical).events.map(e=>e.kind);
  assert.deepEqual(kinds,commit?['attempt','loss']:['loss']);assert(r.ack(batch.batchId,batch.sha256,1n));assert.equal(r.freeze(),undefined);
 }
}
{
 const max=(1n<<64n)-1n;const common={tenantId:tenant,runtimeId:runtime,epoch:1n,authority:()=>({allowed:true,epoch:1n,deadline:performance.now()+10000}),maxBatchEvents:8,maxBatchBytes:4096,queueBytes:8192,queueTtlMs:10000};
 const frame=Object.freeze({root:'a'.repeat(32),activity:'b'.repeat(32),attempt:'c'.repeat(32),marker_digest:'d'.repeat(64)});
 const end=create({...common,initialSequence:max});assert.equal(end.reserveAttempt(frame),undefined);assert(end.offer({kind:'ROOT_INTENT',root:'a'.repeat(32)}));
 const almost=create({...common,initialSequence:max-1n});const ticket=almost.reserveAttempt(frame);assert(ticket);assert(almost.cancelAttempt(ticket));
 const loss=almost.freeze();assert(loss.canonical.includes('18446744073709551615'));assert(loss.canonical.includes('18446744073709551614'));
}
{
 const sourcePath=process.argv[2];const transform=require('./private-wire-transform').transform;
 assert.throws(()=>transform(Buffer.from('invalid')),/unsupported source/);
 if(sourcePath){const sourceBytes=fs.readFileSync(sourcePath);const transformed=transform(sourceBytes);
  assert(transformed.includes('__privateWire.begin(node,opts)'));assert(transformed.includes('__wireScope.close()'));assert(transformed.includes('__privateWire.closeNode(node)'));
  assert.throws(()=>transform(Buffer.concat([sourceBytes,Buffer.from(' ')])),/unsupported source/);
 }
}
process.stdout.write('PASS: private dispatch component only; no transport or authority proof\n');
