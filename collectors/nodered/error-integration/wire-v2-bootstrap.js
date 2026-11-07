'use strict';
// INACTIVE synthetic fixture preload. No database grant, deployment registration,
// production signing key, or producer attestation is established here.
const fs=require('node:fs'),Module=require('node:module'),crypto=require('node:crypto');
const {performance}=require('node:perf_hooks'),{types}=require('node:util');
const profile=require('./wire-v2-profile');
let adapter,handoff,fixtureExporter,makeFixtureExporter,ready=false,phase='launch',loader,requestNode,dispatcher,live=()=>false;
const fail=()=>{if(fixtureExporter)fixtureExporter.close();ready=false;phase='invalidated';if(dispatcher&&requestNode)dispatcher.closeNode(requestNode);if(adapter)adapter.invalidate();};
module.exports=Object.freeze({
    snapshot(){if(ready)live();const s=adapter?.snapshot();return Object.freeze({ready:!!(ready&&s?.registryIntact),phase,registryIntact:!!s?.registryIntact,loss:s?.loss??1,pending:s?.pending??0,frames:s?.frames??0});},
    // Synthetic fixture only: data-only batch, not a transport or authority API.
    fixtureBatch(){return ready&&live()?handoff.freeze():undefined;},
    // Synthetic qualification transport only. This is not session authority.
    fixtureSendOnce(){if(!ready||!live())return Promise.resolve(false);try{fixtureExporter??=makeFixtureExporter();return fixtureExporter.sendOnce();}catch(_){return Promise.resolve(false);}},
    fixtureCloseExporter(){if(fixtureExporter)fixtureExporter.close();},
    invalidate:fail
});
try{
    if(!profile.validateLaunch({version:process.versions.node,executable:process.execPath,argv:process.argv,execArgv:process.execArgv,env:process.env,cached:Object.keys(require.cache)}))throw Error('launch');
    phase='sources';if(!profile.verifySources())throw Error('sources');
    const nodePath='/usr/src/node-red/node_modules/@node-red/runtime/lib/nodes/Node.js';
    const flowPath='/usr/src/node-red/node_modules/@node-red/runtime/lib/flows/Flow.js';
    const wirePath='/usr/src/node-red/node_modules/@node-red/nodes/core/network/21-httprequest.js';
    const original=new Map([nodePath,flowPath,wirePath].map(p=>[p,fs.readFileSync(p)]));
    const {boundedTransform,makeLiveGate}=require('./wire-v2-loader');
    const transformed=new Map([[nodePath,boundedTransform(require('./node-source-transform').transform(original.get(nodePath)))],
        [flowPath,boundedTransform(require('./flow-source-transform').transform(original.get(flowPath)))],
        [wirePath,boundedTransform(require('./private-wire-transform').transform(original.get(wirePath)))]]);
    const redRequire=Module.createRequire('/usr/src/node-red/node_modules/node-red/red.js');
    const hooks=redRequire('@node-red/util').hooks;
    let control,installed;
    let allowed=true;const epoch=1n,tenantId='123e4567-e89b-12d3-a456-426614174001',runtimeId='123e4567-e89b-12d3-a456-426614174002';
    const deadline=performance.now()+120000;
    handoff=require('./private-handoff').create({tenantId,runtimeId,epoch,authority:()=>({allowed,epoch,deadline}),maxBatchEvents:128,maxBatchBytes:65536,queueBytes:131072,queueTtlMs:60000});
    adapter=require('./private-producer-runtime').install(hooks,{inbound:['in'],requests:['request'],maxPending:32,maxEvents:128,maxBytes:32768,ttlMs:5000,ingressPoint:profile.INGRESS_POINT},c=>{control=c;c.attachProducer(handoff);});
    if(!control||!adapter.snapshot().registryIntact)throw Error('hooks');
    const tlsOptions=Object.freeze({certificateAuthority:fs.readFileSync('/fixture-tls/ca'),certificate:fs.readFileSync('/fixture-tls/client'),key:fs.readFileSync('/fixture-tls/client-key'),serverName:'pilot-destination',rejectUnauthorized:true});
    const productLeafSha256=crypto.createHash('sha256').update(new crypto.X509Certificate(tlsOptions.certificate).raw).digest('hex');
    const signer=require('./causal-marker').createMarkerSigner(Buffer.alloc(32,7));
    const get=(x,k)=>{if(!x||typeof x!=='object'||types.isProxy(x))return;const d=Object.getOwnPropertyDescriptor(x,k);return d&&'value'in d?d.value:undefined;};
    function fixtureTlsMatches(opts){
        const tls=get(opts,'https');if(!tls||types.isProxy(tls)||Object.getPrototypeOf(tls)!==Object.prototype)return false;
        const keys=['certificateAuthority','certificate','key','serverName','rejectUnauthorized'];
        if(Reflect.ownKeys(tls).some(k=>typeof k!=='string'||!keys.includes(k)))return false;
        return keys.every(k=>{const value=get(tls,k),expected=tlsOptions[k];return Buffer.isBuffer(expected)?!types.isProxy(value)&&Buffer.isBuffer(value)&&Buffer.prototype.equals.call(value,expected):value===expected;});
    }
    const wire=Object.freeze({
        begin(node,opts){
            if(!require('./wire-v2-loader').scrubHeaders(opts)){control.noteDispatchLoss();return Object.freeze({close(){}});}
            if(!ready||!live()||node!==requestNode)return Object.freeze({close(){}});
            const agents=get(opts,'agent'),agent=get(agents,'https');
            if(!dispatcher){
                if(!fixtureTlsMatches(opts)){control.noteDispatchLoss();return Object.freeze({close(){}});}
                try{dispatcher=require('./private-wire-dispatch').create({control,handoff,signer,tenantId,runtimeId,epoch,productLeafSha256,destination:'https://127.0.0.1:18443/',method:'POST',agent,tlsOptions});}
                catch(_){control.noteDispatchLoss();return Object.freeze({close(){}});}
            }
            return dispatcher.begin(node,opts);
        },
        closeNode(node){if(node===requestNode&&dispatcher)dispatcher.closeNode(node);}
    });
    const nodeBridge=Object.freeze({apply:Reflect.apply,take(...a){return installed?.node.take(...a);},arm(...a){return installed?.node.arm(...a);},finish(...a){installed?.node.finish(...a);},drop(...a){installed?.node.drop(...a);},trustedHook(...a){return installed?installed.node.trustedHook(...a):false;},bind(...a){return installed.node.bind(...a);}});
    const flowBridge=Object.freeze({apply:Reflect.apply,claim(...a){return installed?.flow.claim(...a);},capture(...a){return installed?.flow.capture(...a);},arm(...a){return installed?.flow.arm(...a);},finish(...a){installed?.flow.finish(...a);},drop(...a){installed?.flow.drop(...a);}});
    const targets=new Map([[nodePath,{binding:'__apicontourNodeBridge',facade:nodeBridge}],[flowPath,{binding:'__apicontourFlowBridge',facade:flowBridge}],[wirePath,{binding:'__unused',facade:undefined}]].map(([p,x])=>[p,{...x,original:original.get(p),transformed:transformed.get(p)}]));
    loader=require('./wire-v2-loader').install({targets,wirePath,wireFacade:wire,invalidate:fail});
    live=makeLiveGate({ready:()=>ready,gate:()=>handoff.gate()&&adapter.snapshot().registryIntact,integrity:()=>loader.intact(),invalidate:fail});
    // Explicitly synthetic test authority; no registry or production initializer.
    const fenced=Object.freeze({gate:()=>live()&&handoff.gate(),freeze:()=>live()?handoff.freeze():undefined,
        ack:(id,digest,ep,commitIf)=>live()&&handoff.ack(id,digest,ep,()=>live()&&commitIf())});
    makeFixtureExporter=()=>require('./private-causal-exporter').create({endpoint:'https://127.0.0.1:18444/v1/causal-events',
        ca:tlsOptions.certificateAuthority,cert:fs.readFileSync('/fixture-tls/export-client'),key:fs.readFileSync('/fixture-tls/export-client-key'),runtimeId,epoch,handoff:fenced,timeoutMs:3000,maxBodyBytes:65536});
    const timer=setTimeout(()=>{if(!ready){loader.cancel();fail();}},10000);timer.unref();
    phase='loader';const RED=redRequire('node-red');
    const Node=require.cache[nodePath]?.exports;if(typeof Node!=='function')throw Error('node');
    const stock={receive:Node.prototype.receive,emit:Node.prototype.emit,input:Node.prototype._emitInput};
    if(Object.values(stock).some(f=>typeof f!=='function'))throw Error('methods');
    const expected=[['in','http in'],['fanout','function'],['request','http request'],['response','http response'],['chain','function'],['tls-catch','catch'],['tls-count','function']];
    RED.events.once('flows:started',()=>{try{
        if(!loader.finish())throw Error('loader');const state=adapter.snapshot();
        if(!state.registryIntact||state.loss||state.pending||state.frames||state.events.length)throw Error('startup');
        const nodes=expected.map(([id,type])=>{const n=RED.nodes.getNode(id);if(!n||n.id!==id||n.type!==type)throw Error('node profile');
            for(const [name,fn] of [['receive',stock.receive],['emit',stock.emit],['_emitInput',stock.input]]){let o=n,d;while(o&&!(d=Object.getOwnPropertyDescriptor(o,name)))o=Object.getPrototypeOf(o);if(!d||!('value'in d)||d.value!==fn)throw Error('methods');}return n;});
        if(new Set(nodes).size!==nodes.length)throw Error('identities');requestNode=nodes[2];installed=require('./lexical-bridge').initialize(control,stock,hooks,hooks.trigger,nodes);
        ready=true;phase='ready';clearTimeout(timer);
    }catch(_){allowed=false;loader.cancel();fail();}});
}catch(_){if(loader)loader.cancel();fail();}
