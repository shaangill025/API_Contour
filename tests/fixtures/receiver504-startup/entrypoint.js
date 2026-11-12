'use strict';
// Executes actual startup source in a VM with synthetic modules/private parent.
// This is not Node-RED, real TLS, a real socket or an authority/deployment test.
const assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs'),crypto=require('node:crypto'),{EventEmitter}=require('node:events');
const source=fs.readFileSync(__dirname+'/../../../collectors/nodered/receiver-integration/live-main-504.js','utf8');
const vector=JSON.parse(fs.readFileSync(__dirname+'/../receiver504-bootstrap/vector.json','utf8'));
const d={...JSON.parse(vector.canonical)},q={};for(const name of ['ca','product_cert','product_key','export_cert','export_key','server_cert','server_key','evidence_cert','evidence_key'])q[name]=Buffer.from(name.replace('_key','_cert'));
d.server_leaf=d.receiver_backend_leaf=crypto.createHash('sha256').update(q.server_cert).digest('hex');d.receiver_evidence_leaf=crypto.createHash('sha256').update(q.evidence_cert).digest('hex');
const original=Buffer.from('source'),srcHash=crypto.createHash('sha256').update(original).digest('hex');
const targets=['@node-red/runtime/lib/nodes/Node.js','@node-red/runtime/lib/flows/Flow.js','@node-red/nodes/core/network/21-httprequest.js'];const treeManifest={files:Object.fromEntries(targets.map(x=>[x,{bytes:original.length,sha256:srcHash}]))};
const events=new EventEmitter();function Node(){}Node.prototype.receive=function(){};Node.prototype.emit=function(){};Node.prototype._emitInput=function(){};
const nodes=[['in','http in'],['request','http request']].map(([id,type])=>Object.assign(Object.create(Node.prototype),{id,type}));
let handler,attached,registrationCalled=0,init=0,listened=0,status,failed=false;
const hooks={trigger(){}};const red={events,nodes:{getNode(id){return nodes.find(x=>x.id===id);}},httpNode:()=>{},init(){init++;},async start(){events.emit('flows:started');},stop(){}};
const app=()=>{};app.use=()=>{};const server=new EventEmitter();server.listen=(_port,_host,cb)=>{listened++;cb();};server.close=()=>{};
const auth=Object.freeze({allowed:true,epoch:BigInt(d.epoch),deadline:1e20});
const control={attachProducer(){},attachReceiver(value){attached=value;},noteDispatchLoss(){}};
const snapshot=()=>({registryIntact:true,loss:0,pending:0,frames:0,events:[]});
const targetPath='/usr/src/node-red/node_modules/@node-red/runtime/lib/nodes/Node.js';const fakeRequire=name=>name==='@node-red/util'?{hooks}:name==='node-red'?red:name==='express'?()=>app:assert.fail('unexpected red module');
const fakeModule={createRequire:()=>fakeRequire};
const realCrypto={...crypto,X509Certificate:class {constructor(bytes){this.raw=bytes;this.publicKey={export:()=>bytes};}checkHost(){return true;}},createPrivateKey:key=>({key}),createPublicKey:key=>({export:()=>key.key})};
const mocks={
 'node:fs':{closeSync(){},createWriteStream(){return {on(){},end(bytes,done){status=Buffer.from(bytes);done();},destroy(){}};}},'node:crypto':realCrypto,'node:module':fakeModule,'node:util':require('node:util'),'node:https':{createServer(_options,fn){handler=fn;return server;}},
 './private-bootstrap-504':{read:async()=>({descriptor:d,seed:Buffer.alloc(32,7)})},
 './private-profile-504':{load:()=>({manifest:{capture:{node:'in',method:'POST',url:'/run'},product_endpoint:'https://pilot-gateway:9443/pilot',export_endpoint:'https://causal-ingress:8443/v1/causal-events',nodes:[['in','http in'],['request','http request']]},material:q,treeManifest}),read:()=>original},
 '../live-integration/credential-check':{check(){},checkServer(){}},'../live-integration/lifecycle':{create:()=>({add(){},close(){failed=true;}}),awaitFirst:async()=>{},requireEpoch(){}},
 '../error-integration/causal-marker':{createMarkerSigner:()=>({sign(){}})},'./private-owner-permit-504':{create:()=>({authority:()=>auth,bind:()=>({}),close(){}})},
 '../error-integration/wire-v2-loader':{boundedTransform:x=>x,install:()=>({finish:()=>true,intact:()=>true,cancel(){}}),makeLiveGate:({ready,gate,integrity})=>()=>ready()&&gate()&&integrity(),scrubHeaders:()=>true},
 '../error-integration/node-source-transform':{transform:x=>x},'../error-integration/flow-source-transform':{transform:x=>x},'../error-integration/private-wire-transform':{transform:x=>x},
 '../error-integration/private-handoff':{create:()=>({gate:()=>true,close(){}})},'./private-root-handoff':{create:()=>({producer:{},exporter:{gate:()=>true,freeze(){},ack(){}},close(){}})},
 './private-producer-runtime':{install(_hooks,_options,callback){callback(control);return {snapshot,invalidate(){}};}},'../error-integration/private-causal-exporter':{create:()=>({sendOnce:async()=>true,close(){}})},
 './private-incoming':{create({app:actual}){registrationCalled++;assert.equal(actual,app);return {handler(){},consume(){return 'registered';},close(){}};}},
 '../error-integration/lexical-bridge':{initialize:()=>({node:{},flow:{}})}
};
function mockedRequire(name){if(!Object.hasOwn(mocks,name))throw Error('unexpected import');return mocks[name];}mockedRequire.cache={[targetPath]:{exports:Node}};
const processFake={exitCode:0,once(){},exit(){}};const timer=()=>({unref(){}});
const context={require:mockedRequire,module:{exports:{}},Buffer,URL,process:processFake,setTimeout:timer,clearTimeout(){},setInterval:timer,clearInterval(){},Promise};
vm.runInNewContext(source,context,{filename:'live-main-504.js'});
setImmediate(()=>{try{assert.equal(failed,false);assert.equal(registrationCalled,1);assert.equal(typeof handler,'function');assert.equal(init,1);assert.equal(listened,1);assert.equal(status.subarray(0,4).toString(),'CLR2');assert.equal(attached.consume([]),'registered');assert.deepEqual(Object.keys(context.module.exports),[]);console.log('504 entrypoint mocked startup readiness passed');}catch(_){console.error('504 entrypoint mocked startup readiness failed',JSON.stringify({failed,registrationCalled,init,listened,status:!!status}));process.exitCode=1;}});
