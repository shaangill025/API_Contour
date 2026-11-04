'use strict';
// Experimental, owned-image preload only. Bootstrap and profile are trusted
// roots supplied by an owner who verifies image, mounts and both files outside
// this process. This module exports observation, never loader/control handles.
const fs=require('node:fs');
const {createHash}=require('node:crypto');
const Module=require('node:module');
const vm=require('node:vm');
const reflectApply=Reflect.apply;
// BEGIN offline-tested CommonJS helpers
function moduleRequire(parent) {
    function localRequire(request) { return parent.require(request); }
    localRequire.resolve=function(request,options) { return Module._resolveFilename(request,parent,false,options); };
    localRequire.resolve.paths=function(request) { return Module._resolveLookupPaths(request,parent); };
    localRequire.main=process.mainModule;
    localRequire.extensions=Module._extensions;
    localRequire.cache=Module._cache;
    return localRequire;
}
function passthrough(original,receiver,args) { return reflectApply(original,receiver,args); }
// END offline-tested CommonJS helpers
const profile=require('./profile.js');
let adapter, ready=false, phase='launch';
const blocked=Object.freeze({registryIntact:false,loss:1,pending:0,frames:0,events:Object.freeze([]),ready:false,phase:'launch'});
module.exports=Object.freeze({
    snapshot() { if(!adapter)return phase==='launch'?blocked:Object.freeze({...blocked,phase}); const state=adapter.snapshot(); return Object.freeze({...state,ready:ready && state.registryIntact,phase:ready && !state.registryIntact ? 'invalidated' : phase}); },
    invalidate() { ready=false; phase='invalidated'; if(adapter)adapter.invalidate(); }
});
try {
    const launch={version:process.versions.node,executable:process.execPath,argv:process.argv,execArgv:process.execArgv,env:process.env,cached:Object.keys(require.cache)};
    if (!profile.validateLaunch(launch)) throw Error('launch');
    phase='sources';
    const hashes={};
    for(const file of Object.keys(profile.FILES)) hashes[file]=createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    if(!profile.validateFiles(hashes)) throw Error('sources');
    const nodePath='/usr/src/node-red/node_modules/@node-red/runtime/lib/nodes/Node.js';
    const flowPath='/usr/src/node-red/node_modules/@node-red/runtime/lib/flows/Flow.js';
    if(require.cache[nodePath] || require.cache[flowPath]) throw Error('cached targets');
    const originals=new Map([[nodePath,fs.readFileSync(nodePath)],[flowPath,fs.readFileSync(flowPath)]]);
    const transformNode=require('./node-source-transform.js').transform;
    const transformFlow=require('./flow-source-transform.js').transform;
    // Both source pins and all sites are checked before interception starts.
    const transformed=new Map([[nodePath,transformNode(originals.get(nodePath))],[flowPath,transformFlow(originals.get(flowPath))]]);
    const redRequire=Module.createRequire('/usr/src/node-red/node_modules/node-red/red.js');
    phase='hooks';
    const hooks=redRequire('@node-red/util').hooks;
    let control;
    adapter=require('./private-runtime.js').install(hooks,{inbound:['in'],requests:['request'],maxPending:32,maxEvents:128,maxBytes:32768,ttlMs:5000},c=>{control=c;});
    if(!control || !adapter.snapshot().registryIntact) throw Error('hooks');
    // Stable lexical facades forward without ownership until the fixed fixture
    // has started and the private bridge has been constructed.
    let installed;
    const nodeBridge=Object.freeze({apply:reflectApply,
        take(...a){return installed?.node.take(...a);},arm(...a){return installed?.node.arm(...a);},
        finish(...a){installed?.node.finish(...a);},drop(...a){installed?.node.drop(...a);},
        trustedHook(...a){return installed ? installed.node.trustedHook(...a) : false;},
        bind(...a){return installed.node.bind(...a);}
    });
    const flowBridge=Object.freeze({apply:reflectApply,
        claim(...a){return installed?.flow.claim(...a);},capture(...a){return installed?.flow.capture(...a);},
        arm(...a){return installed?.flow.arm(...a);},finish(...a){installed?.flow.finish(...a);},drop(...a){installed?.flow.drop(...a);}
    });
    phase='loader';
    const oldCompile=Module.prototype._compile, seen=new Set();
    let RED;
    try {
        Module.prototype._compile=function(content,filename) {
            if(!transformed.has(filename))return passthrough(oldCompile,this,arguments);
            if(seen.has(filename) || !Buffer.from(content,'utf8').equals(originals.get(filename))) throw Error('target mismatch');
            seen.add(filename);
            const binding=filename===nodePath ? '__apicontourNodeBridge' : '__apicontourFlowBridge';
            const compiled=vm.compileFunction(transformed.get(filename).toString('utf8'),['exports','require','module','__filename','__dirname',binding],{filename});
            return reflectApply(compiled,this.exports,[this.exports,moduleRequire(this),this,filename,require('node:path').dirname(filename),filename===nodePath?nodeBridge:flowBridge]);
        };
        RED=redRequire('node-red');
        if(seen.size!==2)throw Error('missing pinned target');
    } finally { Module.prototype._compile=oldCompile; }
    phase='identities';
    const Node=require.cache[nodePath]?.exports;
    if(typeof Node!=='function')throw Error('node constructor');
    const stock={receive:Node.prototype.receive,emit:Node.prototype.emit,input:Node.prototype._emitInput};
    if(Object.values(stock).some(fn=>typeof fn!=='function'))throw Error('methods');
    const expected=[['in','http in'],['fanout','function'],['request','http request'],['response','http response'],['chain','function'],['tls-catch','catch'],['tls-count','function']];
    RED.events.once('flows:started',()=>{
        try {
            const state=adapter.snapshot();
            if(!state.registryIntact || state.loss!==0 || state.pending!==0 || state.frames!==0 || state.events.length!==0)throw Error('startup traffic or mutation');
            const actual=expected.map(([id,type])=>{
                const n=RED.nodes.getNode(id);
                if(!n || n.id!==id || n.type!==type)throw Error('node profile');
                for(const [name,fn] of [['receive',stock.receive],['emit',stock.emit],['_emitInput',stock.input]]){
                    let object=n, descriptor;
                    while(object && !(descriptor=Object.getOwnPropertyDescriptor(object,name)))object=Object.getPrototypeOf(object);
                    if(!descriptor || !('value' in descriptor) || descriptor.value!==fn)throw Error('method profile');
                }
                return n;
            });
            if(new Set(actual).size!==expected.length)throw Error('node identity');
            installed=require('./lexical-bridge.js').initialize(control,stock,hooks,hooks.trigger,actual);
            ready=true; phase='ready';
        } catch (_) { adapter.invalidate(); }
    });
} catch (_) { if(adapter)adapter.invalidate(); }
