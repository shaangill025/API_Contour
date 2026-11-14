'use strict';
// Fixed private entry point. No application module is loaded before the checked
// parent channel, source policy, credentials and first matching permit succeed.
const fs=require('node:fs'),crypto=require('node:crypto'),Module=require('node:module');
const {types}=require('node:util');
const bootstrap=require('./private-bootstrap'),profile=require('./live-profile'),credentials=require('./credential-check'),lifecycle=require('./lifecycle');
const closer=lifecycle.create();
module.exports=Object.freeze({});
let permit,handoff,adapter,loader,dispatcher,exporter,requestNode,server,RED,rejectStartup,fd3=true,fd4=true,fd5=true,statusStream,ended=false,businessStarted=false,timer,poller,sender,ready=false,installed,control,live=()=>false;
closer.add(()=>{clearTimeout(timer);clearInterval(poller);clearInterval(sender);});
closer.add(()=>dispatcher?.closeNode(requestNode));closer.add(()=>exporter?.close());closer.add(()=>adapter?.invalidate());
closer.add(()=>handoff?.close());closer.add(()=>loader?.cancel());closer.add(()=>permit?.close());
closer.add(()=>{if(!businessStarted){try{server?.close();}catch(_){}try{Promise.resolve(RED?.stop()).catch(()=>{});}catch(_){}}});
closer.add(()=>{if(fd3)fs.closeSync(3);fd3=false;});closer.add(()=>{if(fd4&&!permit)fs.closeSync(4);fd4=false;});closer.add(()=>{if(statusStream)statusStream.destroy();else if(fd5)fs.closeSync(5);fd5=false;});
function close(){if(ended)return;ended=true;if(!businessStarted)process.exitCode=1;ready=false;if(rejectStartup)rejectStartup(Error('startup closed'));closer.close();}
function data(x,k){if(!x||typeof x!=='object'||types.isProxy(x))return;const d=Object.getOwnPropertyDescriptor(x,k);return d&&'value'in d?d.value:undefined;}
(async()=>{
 let seed;
 try{
  const incoming=bootstrap.read();fd3=false;const result=await incoming;const d=result.descriptor;seed=result.seed;
  const {manifest:m,material:q,treeManifest}=profile.load(d);
  credentials.check(seed,{cert:q.product_cert,key:q.product_key},{cert:q.export_cert,key:q.export_key},d);
  credentials.checkServer(q.server_cert,q.server_key,q.ca,d.server_leaf);
  const signer=require('../error-integration/causal-marker').createMarkerSigner(seed);seed.fill(0);seed=undefined;
  permit=require('../error-integration/private-owner-permit').create({fd:4,generation:Buffer.from(d.generation,'hex'),identity:Buffer.from(d.identity,'hex')});fd4=false;
  await lifecycle.awaitFirst(permit,d.epoch);
  const npath='/usr/src/node-red/node_modules/@node-red/runtime/lib/nodes/Node.js',fpath='/usr/src/node-red/node_modules/@node-red/runtime/lib/flows/Flow.js',wpath='/usr/src/node-red/node_modules/@node-red/nodes/core/network/21-httprequest.js';
  const originals=new Map([npath,fpath,wpath].map(p=>{const bytes=profile.read(p,4194304),key=p.slice('/usr/src/node-red/node_modules/'.length),expected=treeManifest.files[key];if(!expected||bytes.length!==expected.bytes||crypto.createHash('sha256').update(bytes).digest('hex')!==expected.sha256)throw Error('source drift');return[p,bytes];}));
  const loaderApi=require('../error-integration/wire-v2-loader');
  const transformed=new Map([[npath,loaderApi.boundedTransform(require('../error-integration/node-source-transform').transform(originals.get(npath)))],[fpath,loaderApi.boundedTransform(require('../error-integration/flow-source-transform').transform(originals.get(fpath)))],[wpath,loaderApi.boundedTransform(require('../error-integration/private-wire-transform').transform(originals.get(wpath)))]]);
  lifecycle.requireEpoch(permit.authority(),d.epoch);
  const redRequire=Module.createRequire('/usr/src/node-red/node_modules/node-red/red.js'),hooks=redRequire('@node-red/util').hooks;
  const epoch=BigInt(d.epoch),tenantId=d.tenant,runtimeId=d.runtime;
  handoff=require('../error-integration/private-handoff').create({tenantId,runtimeId,epoch,authority:()=>permit.authority(),maxBatchEvents:d.batch_events,maxBatchBytes:d.batch_bytes,queueBytes:d.queue_bytes,queueTtlMs:d.queue_ttl_ms});
  adapter=require('../error-integration/private-producer-runtime').install(hooks,{inbound:['in'],requests:['request'],maxPending:32,maxEvents:128,maxBytes:32768,ttlMs:5000,ingressPoint:m.capture},c=>{control=c;c.attachProducer(handoff);});
  if(!control||!adapter.snapshot().registryIntact)throw Error('hooks');
  const product=new URL(m.product_endpoint),tlsOptions=Object.freeze({certificateAuthority:q.ca,certificate:q.product_cert,key:q.product_key,serverName:product.hostname,rejectUnauthorized:true});
  const fenced=Object.freeze({gate:()=>live()&&handoff.gate(),freeze:()=>live()?handoff.freeze():undefined,ack:(id,digest,ep,commitIf)=>live()&&handoff.ack(id,digest,ep,()=>live()&&commitIf())});
  exporter=require('../error-integration/private-causal-exporter').create({endpoint:m.export_endpoint,ca:q.ca,cert:q.export_cert,key:q.export_key,runtimeId,epoch,handoff:fenced,timeoutMs:3000,maxBodyBytes:d.batch_bytes});
  const gatedSigner=permit.bind({producer:handoff,exporter,signer});
  function tlsMatches(opts){const tls=data(opts,'https');if(!tls||types.isProxy(tls)||Object.getPrototypeOf(tls)!==Object.prototype)return false;const keys=['certificateAuthority','certificate','key','serverName','rejectUnauthorized'];if(Reflect.ownKeys(tls).some(k=>typeof k!=='string'||!keys.includes(k)))return false;return keys.every(k=>{const v=data(tls,k),x=tlsOptions[k];return Buffer.isBuffer(x)?!types.isProxy(v)&&Buffer.isBuffer(v)&&Buffer.prototype.equals.call(v,x):v===x;});}
  const wire=Object.freeze({begin(node,opts){if(!loaderApi.scrubHeaders(opts)){control.noteDispatchLoss();return Object.freeze({close(){}});}if(!ready||!live()||node!==requestNode)return Object.freeze({close(){}});const agents=data(opts,'agent'),agent=data(agents,'https');if(!dispatcher){if(!tlsMatches(opts)){control.noteDispatchLoss();return Object.freeze({close(){}});}try{dispatcher=require('../error-integration/private-wire-dispatch').create({control,handoff,signer:gatedSigner,tenantId,runtimeId,epoch,productLeafSha256:d.product_leaf,destination:m.product_endpoint,method:'POST',agent,tlsOptions});}catch(_){control.noteDispatchLoss();return Object.freeze({close(){}});}}return dispatcher.begin(node,opts);},closeNode(node){if(node===requestNode&&dispatcher)dispatcher.closeNode(node);}});
  const nodeBridge=Object.freeze({apply:Reflect.apply,take(...a){return installed?.node.take(...a);},arm(...a){return installed?.node.arm(...a);},finish(...a){installed?.node.finish(...a);},drop(...a){installed?.node.drop(...a);},trustedHook(...a){return installed?installed.node.trustedHook(...a):false;},bind(...a){return installed.node.bind(...a);}});
  const flowBridge=Object.freeze({apply:Reflect.apply,claim(...a){return installed?.flow.claim(...a);},capture(...a){return installed?.flow.capture(...a);},arm(...a){return installed?.flow.arm(...a);},finish(...a){installed?.flow.finish(...a);},drop(...a){installed?.flow.drop(...a);}});
  const targets=new Map([[npath,{binding:'__apicontourNodeBridge',facade:nodeBridge}],[fpath,{binding:'__apicontourFlowBridge',facade:flowBridge}],[wpath,{binding:'__unused',facade:undefined}]].map(([p,x])=>[p,{...x,original:originals.get(p),transformed:transformed.get(p)}]));
  loader=loaderApi.install({targets,wirePath:wpath,wireFacade:wire,invalidate:close});
  live=loaderApi.makeLiveGate({ready:()=>ready,gate:()=>handoff.gate()&&adapter.snapshot().registryIntact,integrity:()=>loader.intact(),invalidate:close});
  timer=setTimeout(close,10000);poller=setInterval(()=>{if(ready)live();else if(!permit.authority())close();},50);
  // The fixed Node-RED module is loaded only after the checked first permit.
  lifecycle.requireEpoch(permit.authority(),d.epoch);
  RED=redRequire('node-red');const Node=require.cache[npath]?.exports;if(typeof Node!=='function')throw Error('node');
  const stock={receive:Node.prototype.receive,emit:Node.prototype.emit,input:Node.prototype._emitInput};if(Object.values(stock).some(x=>typeof x!=='function'))throw Error('methods');
  let acceptStarted,rejectStarted;const started=new Promise((resolve,reject)=>{acceptStarted=resolve;rejectStarted=reject;rejectStartup=reject;});started.catch(()=>{});
  RED.events.once('flows:started',()=>{try{if(!permit.authority()||!loader.finish())throw Error('loader');const state=adapter.snapshot();if(!state.registryIntact||state.loss||state.pending||state.frames||state.events.length)throw Error('startup');const nodes=m.nodes.map(([id,type])=>{const n=RED.nodes.getNode(id);if(!n||n.id!==id||n.type!==type)throw Error('node');for(const [name,fn] of [['receive',stock.receive],['emit',stock.emit],['_emitInput',stock.input]]){let o=n,v;while(o&&!(v=Object.getOwnPropertyDescriptor(o,name)))o=Object.getPrototypeOf(o);if(!v||!('value'in v)||v.value!==fn)throw Error('methods');}return n;});if(new Set(nodes).size!==nodes.length)throw Error('nodes');requestNode=nodes[m.nodes.findIndex(x=>x[0]==='request')];installed=require('../error-integration/lexical-bridge').initialize(control,stock,hooks,hooks.trigger,nodes);ready=true;sender=setInterval(()=>{if(live())exporter.sendOnce().catch(close);},250);acceptStarted();}catch(_){close();rejectStarted(Error('flow startup'));}});
  lifecycle.requireEpoch(permit.authority(),d.epoch);
  const app=redRequire('express')(),https=require('node:https');
  server=https.createServer({cert:q.server_cert,key:q.server_key,ca:q.ca,requestCert:true,rejectUnauthorized:true},app);
  RED.init(server,{userDir:'/data',flowFile:'/data/flows.json',httpAdminRoot:false,httpNodeRoot:'/',credentialSecret:false,externalModules:{autoInstall:false,palette:{allowInstall:false}},logging:{console:{level:'off',metrics:false,audit:false}}});
  app.use(RED.httpNode);
  const shutdown=()=>{close();try{server.close();}catch(_){}const deadline=setTimeout(()=>process.exit(1),5000);deadline.unref();Promise.resolve(RED.stop()).then(()=>process.exit(0),()=>process.exit(1));};
  process.once('SIGTERM',shutdown);process.once('SIGINT',shutdown);
  await RED.start();await started;if(ended||!live())throw Error('permit unavailable');
  lifecycle.requireEpoch(permit.authority(),d.epoch);
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(1880,'0.0.0.0',resolve);});
  if(ended||!live())throw Error('permit unavailable');businessStarted=true;rejectStartup=undefined;clearTimeout(timer);
  const status=Buffer.alloc(76);status.write('CLR1');Buffer.from(d.generation,'hex').copy(status,4);Buffer.from(d.identity,'hex').copy(status,36);status.writeBigUInt64BE(epoch,68);
  statusStream=fs.createWriteStream(null,{fd:5,autoClose:true});fd5=false;statusStream.on('error',close);if(!live())throw Error('permit unavailable');statusStream.end(status,()=>{status.fill(0);statusStream=undefined;});

 }catch(_){if(seed)seed.fill(0);close();}
})();
