'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs'),path=require('node:path'),{performance}=require('node:perf_hooks');
const root=path.resolve(__dirname,'../../../collectors/nodered/live-integration');
const source=fs.readFileSync(path.join(root,'live-main.js'),'utf8');
const life=require(path.join(root,'lifecycle'));
async function failStartup(permit){
 const seed=Buffer.alloc(32,7),seen=[],d={epoch:'1',generation:'11'.repeat(32),identity:'22'.repeat(32)};
 const descriptor={read:()=>Promise.resolve({descriptor:d,seed})};
 const profile={load:()=>({manifest:{},material:{product_cert:Buffer.from('a'),product_key:Buffer.from('b'),export_cert:Buffer.from('c'),export_key:Buffer.from('d')},treeManifest:{}}),read:()=>{seen.push('source read');throw Error('controlled');}};
 const modules={'node:fs':{closeSync:fd=>seen.push('close fd '+fd)},'node:crypto':require('node:crypto'),'node:module':{createRequire:()=>{seen.push('application loaded');throw Error('not expected');}},'node:util':require('node:util'),'./private-bootstrap':descriptor,'./live-profile':profile,'./credential-check':{check:()=>true,checkServer:()=>true},'./lifecycle':life,'../error-integration/causal-marker':{createMarkerSigner:()=>({sign(){}})},'../error-integration/private-owner-permit':{create:()=>permit}};
 const sandbox={require:name=>{if(!Object.hasOwn(modules,name))throw Error('unexpected import');return modules[name];},module:{exports:{}},Buffer,process:{exitCode:0},setTimeout,clearTimeout,setInterval,clearInterval};
 vm.runInNewContext(source,sandbox,{filename:'live-main.js'});await new Promise(resolve=>setImmediate(resolve));
 assert.deepEqual(Object.keys(sandbox.module.exports),[]);assert.equal(sandbox.process.exitCode,1);assert(seed.equals(Buffer.alloc(32)));assert(!seen.includes('application loaded'));return seen;
}
test('permit loss before first response closes resources before any app load',async()=>{let closed=0;const seen=await failStartup({ready:Promise.reject(Error('closed')),authority:()=>undefined,close:()=>closed++});assert.equal(closed,1);assert(!seen.includes('source read'));});
test('first permit epoch mismatch refuses application load',async()=>{let closed=0;const seen=await failStartup({ready:Promise.resolve(),authority:()=>({epoch:2n,allowed:true,deadline:performance.now()+1000}),close:()=>closed++});assert.equal(closed,1);assert(!seen.includes('source read'));});
test('source drift after first permit closes the permit',async()=>{let closed=0;const seen=await failStartup({ready:Promise.resolve(),authority:()=>({epoch:1n,allowed:true,deadline:performance.now()+1000}),close:()=>closed++});assert.equal(closed,1);assert(seen.includes('source read'));});
async function embedded(badNodes=false,expireDuringScan=false,expireBeforeNode=false,expireBeforeListen=false,expireDuringNode=false){
 const hash=bytes=>require('node:crypto').createHash('sha256').update(bytes).digest('hex'),bytes=Buffer.from('synthetic-source'),seen=[],timers=[];
 const pfx='/usr/src/node-red/node_modules/',paths=['@node-red/runtime/lib/nodes/Node.js','@node-red/runtime/lib/flows/Flow.js','@node-red/nodes/core/network/21-httprequest.js'];
 const tree={files:Object.fromEntries(paths.map(x=>[x,{bytes:bytes.length,sha256:hash(bytes)}]))};
 const d={epoch:'1',generation:'11'.repeat(32),identity:'22'.repeat(32),tenant:'00000000-0000-4000-8000-000000000001',runtime:'00000000-0000-4000-8000-000000000002',batch_events:1,batch_bytes:512,queue_bytes:1024,queue_ttl_ms:1000,product_leaf:'33'.repeat(32),server_leaf:'44'.repeat(32)};
 const material=Object.fromEntries(['ca','product_cert','product_key','export_cert','export_key','server_cert','server_key'].map(x=>[x,Buffer.from(x)]));
 const m={capture:{node:'in',method:'POST',url:'/run'},nodes:[['in','http in'],['request','http request']],product_endpoint:'https://pilot-gateway:9443/pilot',export_endpoint:'https://causal-ingress:8443/v1/causal-events'};
 const app={use:()=>seen.push('attach route')};let livePermit=true,flowCallback,options,settings;
 const permit={ready:Promise.resolve(),authority:()=>livePermit?{epoch:1n,allowed:true,deadline:performance.now()+10000}:undefined,bind:({signer})=>signer,close:()=>seen.push('permit close')};
 function Node(){}Node.prototype.receive=function(){};Node.prototype.emit=function(){};Node.prototype._emitInput=function(){};
 const nodes=Object.fromEntries(m.nodes.map(([id,type])=>{const n=new Node();n.id=id;n.type=badNodes&&id==='request'?'wrong':type;return[id,n];}));
 const server={once(){},listen(port,host,done){seen.push(`listen ${host}:${port}`);done();},close(){seen.push('server close');}};
 const RED={events:{once:(_name,fn)=>{flowCallback=fn;}},nodes:{getNode:id=>nodes[id]},init:(_server,s)=>{settings=s;seen.push('init');},httpNode:()=>{},start:async()=>{seen.push('start');flowCallback();if(expireBeforeListen)livePermit=false;},stop:async()=>{seen.push('RED stop');}};
 const redRequire=name=>{seen.push('import '+name);if(name==='node-red'){if(expireDuringNode)livePermit=false;return RED;}return name==='express'?()=>app:name==='@node-red/util'?{hooks:{trigger(){}}}:(()=>{throw Error('unexpected RED module');})();};
 let authority;const handoff={gate:()=>!!authority(),close:()=>seen.push('handoff close')};
 const loader={finish:()=>true,intact:()=>true,cancel:()=>seen.push('loader cancel')};
 const loaderApi={boundedTransform:x=>x,install:()=>loader,scrubHeaders:()=>true,makeLiveGate:cfg=>()=>{if(cfg.ready()&&cfg.gate()&&cfg.integrity())return true;cfg.invalidate();return false;}};
 const adapter={snapshot:()=>({registryIntact:true,loss:0,pending:0,frames:0,events:[]}),invalidate:()=>seen.push('adapter invalidate')};
 const modules={'node:fs':{closeSync:()=>{}},'node:crypto':require('node:crypto'),'node:module':{createRequire:()=>redRequire},'node:util':require('node:util'),'node:https':{createServer:(o)=>{options=o;return server;}},'./private-bootstrap':{read:()=>Promise.resolve({descriptor:d,seed:Buffer.alloc(32,7)})},'./live-profile':{load:()=>({manifest:m,material,treeManifest:tree}),read:()=>bytes},'./credential-check':{check:()=>true,checkServer:()=>true},'./lifecycle':life,'../error-integration/causal-marker':{createMarkerSigner:()=>({sign(){}})},'../error-integration/private-owner-permit':{create:()=>permit},'../error-integration/wire-v2-loader':loaderApi,'../error-integration/node-source-transform':{transform:x=>{if(expireDuringScan)livePermit=false;return x;}},'../error-integration/flow-source-transform':{transform:x=>x},'../error-integration/private-wire-transform':{transform:x=>x},'../error-integration/private-handoff':{create:c=>{authority=c.authority;return handoff;}},'../error-integration/private-producer-runtime':{install:(_h,_o,cb)=>{cb({attachProducer(){},noteDispatchLoss(){}});return adapter;}},'../error-integration/private-causal-exporter':{create:()=>{if(expireBeforeNode)livePermit=false;return {sendOnce:async()=>true,close:()=>seen.push('exporter close')};}},'../error-integration/lexical-bridge':{initialize:()=>({node:{},flow:{}})}};
 function req(name){if(!Object.hasOwn(modules,name))throw Error('unexpected import '+name);return modules[name];}req.cache={[pfx+paths[0]]:{exports:Node}};
 const sandbox={require:req,module:{exports:{}},Buffer,URL,process:{exitCode:0,once(){},exit(){}},setTimeout:()=>({unref(){}}),clearTimeout(){},setInterval:(fn,ms)=>{timers.push({fn,ms});return {};},clearInterval(){}};
 vm.runInNewContext(source,sandbox,{filename:'live-main.js'});await new Promise(resolve=>setImmediate(resolve));
 return {seen,options,settings,proc:sandbox.process,losePermit(){livePermit=false;timers.find(x=>x.ms===50).fn();}};
}
test('embedded TLS startup waits for permit and capture loss preserves listener',async()=>{
 const {seen,options,settings,proc,losePermit}=await embedded();
 assert(seen.includes('init'));assert(seen.includes('attach route'));assert(seen.includes('start'));assert(seen.includes('listen 0.0.0.0:1880'));
 assert.equal(options.requestCert,true);assert.equal(options.rejectUnauthorized,true);assert.equal(options.cert.toString(),'server_cert');assert.equal(options.key.toString(),'server_key');assert.equal(options.ca.toString(),'ca');assert.equal(settings.credentialSecret,false);assert.equal(settings.httpAdminRoot,false);assert.equal(settings.flowFile,'/data/flows.json');assert.equal(settings.externalModules.autoInstall,false);assert.equal(settings.externalModules.palette.allowInstall,false);
 losePermit();assert(seen.includes('adapter invalidate'));assert(seen.includes('handoff close'));assert(seen.includes('exporter close'));assert(seen.includes('permit close'));assert(!seen.includes('server close'));assert(!seen.includes('RED stop'));assert.equal(proc.exitCode,0);
});
test('failed flow identity closes startup without opening listener',async()=>{
 const {seen}=await embedded(true);assert(!seen.some(x=>x.startsWith('listen ')));assert(seen.includes('server close'));assert(seen.includes('RED stop'));assert(seen.includes('permit close'));
});

test('permit expiry during synchronous transform prevents first RED import',async()=>{const {seen,proc}=await embedded(false,true);assert(!seen.includes('import @node-red/util'));assert(!seen.includes('import node-red'));assert(!seen.some(x=>x.startsWith('listen ')));assert(seen.includes('permit close'));assert.equal(proc.exitCode,1);});

test('permit expiry before Node-RED import prevents application load',async()=>{const {seen,proc}=await embedded(false,false,true);assert(seen.includes('import @node-red/util'));assert(!seen.includes('import node-red'));assert(!seen.some(x=>x.startsWith('listen ')));assert.equal(proc.exitCode,1);});
test('permit expiry during RED startup prevents listener exposure',async()=>{const {seen,proc}=await embedded(false,false,false,true);assert(seen.includes('start'));assert(!seen.some(x=>x.startsWith('listen ')));assert(seen.includes('server close'));assert.equal(proc.exitCode,1);});

test('permit expiry during Node-RED import prevents Express and listener',async()=>{const {seen,proc}=await embedded(false,false,false,false,true);assert(seen.includes('import node-red'));assert(!seen.includes('import express'));assert(!seen.some(x=>x.startsWith('listen ')));assert(seen.includes('permit close'));assert.equal(proc.exitCode,1);});
