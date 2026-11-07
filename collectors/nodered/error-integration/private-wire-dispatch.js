'use strict';
// Unactivated building block for the pinned source transform. This records
// only native request construction; no TLS, wire, receipt or edge is proven.
// Qualified deployment excludes hostile same-process hooks/diagnostics.
const {randomBytes,createHash,X509Certificate}=require('node:crypto');
const {performance}=require('node:perf_hooks');
const {types}=require('node:util');
const {URL}=require('node:url');
const https=require('node:https');
const http=require('node:http');
const {ClientRequest}=http;
const tls=require('node:tls');
const request=https.request;
const push=Array.prototype.push, apply=Reflect.apply;
const href=Object.getOwnPropertyDescriptor(URL.prototype,'href').get;
const protocol=Object.getOwnPropertyDescriptor(URL.prototype,'protocol').get;
const MARKER='x-apicontour-causal-marker';
function object(x){return !!x&&typeof x==='object'&&!types.isProxy(x);}
function data(x,name){if(!object(x))return undefined;const d=Object.getOwnPropertyDescriptor(x,name);return d&&'value' in d?d.value:undefined;}
function plain(x){if(!object(x))return false;const p=Object.getPrototypeOf(x);return p===Object.prototype||p===null;}
function scrub(headers){
    if(!plain(headers))return false;
    for(const name of Reflect.ownKeys(headers)){
        if(typeof name!=='string')return false;
        const own=Object.getOwnPropertyDescriptor(headers,name);if(!own||!('value' in own))return false;
        if(name.toLowerCase().startsWith('x-apicontour-')){
            const d=Object.getOwnPropertyDescriptor(headers,name);
            if(!d||!d.configurable||!('value' in d)||!delete headers[name])return false;
        }
    }
    return Object.isExtensible(headers);
}
function create(config){
    const {control,handoff,signer,tenantId,runtimeId,epoch,productLeafSha256,destination,method,agent,tlsOptions,maxAttempts=8}=config;
    if(!control||!handoff||!signer||typeof destination!=='string'||typeof method!=='string'||
       typeof epoch!=='bigint'||epoch<1n||typeof productLeafSha256!=='string'||!/^[0-9a-f]{64}$/.test(productLeafSha256)||
       !Number.isSafeInteger(maxAttempts)||maxAttempts<1||maxAttempts>32||
       !object(agent)||Object.getPrototypeOf(agent)!==https.Agent.prototype||!plain(tlsOptions))throw Error('unsupported dispatch configuration');
    const url=new URL(destination);
    if(url.protocol!=='https:'||url.username||url.password||url.hash||url.href!==destination||method!==method.toUpperCase())throw Error('unsupported dispatch configuration');
    const expected={};
    for(const key of ['certificateAuthority','certificate','key','serverName','rejectUnauthorized']){
        const descriptor=Object.getOwnPropertyDescriptor(tlsOptions,key);
        if(!descriptor||!('value' in descriptor))throw Error('unsupported dispatch configuration');
        expected[key]=descriptor.value;
    }
    const materials=['certificateAuthority','certificate','key'], snapshots={};
    for(const k of materials){const v=expected[k];if(types.isProxy(v)||!(typeof v==='string'||Buffer.isBuffer(v))||v.length<1||v.length>1048576)throw Error('unsupported dispatch configuration');snapshots[k]=typeof v==='string'?v:Buffer.from(v);}
    if(typeof expected.serverName!=='string'||!/^(?=.{1,253}$)[a-zA-Z0-9.-]+$/.test(expected.serverName)||expected.rejectUnauthorized!==true)throw Error('unsupported dispatch configuration');
    function materialMatches(k,v){const snap=snapshots[k];return typeof snap==='string'?v===snap:!types.isProxy(v)&&Buffer.isBuffer(v)&&Buffer.prototype.equals.call(v,snap);}
    let certificate;
    try{certificate=new X509Certificate(expected.certificate);}catch(_){throw Error('unsupported dispatch configuration');}
    if(createHash('sha256').update(certificate.raw).digest('hex')!==productLeafSha256)throw Error('unsupported dispatch configuration');
    const agentAllowed=new Set(['keepAlive','defaultPort','protocol','noDelay','path','maxSockets','maxFreeSockets','scheduling','timeout','keepAliveMsecs','maxTotalSockets']);
    function agentSafe(){
        if(types.isProxy(agent)||Object.getPrototypeOf(agent)!==https.Agent.prototype)return false;
        for(const key of ['createConnection','addRequest','getName'])if(Object.getOwnPropertyDescriptor(agent,key))return false;
        const options=data(agent,'options');if(!plain(options))return false;
        for(const key of Reflect.ownKeys(options)){const d=Object.getOwnPropertyDescriptor(options,key);if(typeof key!=='string'||!agentAllowed.has(key)||!d||!('value' in d))return false;}
        return data(options,'defaultPort')===443&&data(options,'protocol')==='https:'&&(data(options,'path')===null||data(options,'path')===undefined);
    }
    const tlsKeys=['certificateAuthority','certificate','key','serverName','rejectUnauthorized'];
    const allowed=new Set(tlsKeys);
    function active(handle,node){
        try{const value=control.dispatchContext(handle,node);return value&&value.deadline>performance.now()?value:undefined;}catch(_){return undefined;}
    }
    function sameUrl(value){try{return object(value)&&apply(href,value,[])===destination;}catch(_){return false;}}
    function withoutMarker(headers,nativeOptions){
        const other=data(nativeOptions,'headers');
        if(!scrub(headers)||(other!==headers&&!scrub(other)))throw Error('reserved headers unavailable');
    }
    function fallback(nativeUrl,nativeOptions){
        let scheme;try{if(object(nativeUrl))scheme=apply(protocol,nativeUrl,[]);}catch(_){}
        return scheme==='http:'?http.request(nativeUrl,nativeOptions):request(nativeUrl,nativeOptions);
    }
    function tlsMatch(value){
        if(!plain(value))return false;
        for(const key of Reflect.ownKeys(value)){
            if(typeof key!=='string')return false;
            const d=Object.getOwnPropertyDescriptor(value,key);if(!d||!('value' in d))return false;
            if(allowed.has(key)){if(materials.includes(key)?!materialMatches(key,d.value):d.value!==expected[key])return false;}else if(d.value!==undefined)return false;
        }
        return tlsKeys.every(k=>materials.includes(k)?materialMatches(k,data(value,k)):data(value,k)===expected[k]);
    }
    function hostMatches(headers){
        if(!plain(headers))return false;let seen=false;
        for(const name of Reflect.ownKeys(headers)){
            if(typeof name!=='string')return false;
            if(name.toLowerCase()==='host'){
                if(seen)return false;seen=true;const d=Object.getOwnPropertyDescriptor(headers,name);
                if(!d||!('value' in d)||typeof d.value!=='string'||d.value!==url.host)return false;
            }
        }
        return true;
    }
    function eligible(internals,options){
        if(!agentSafe()||!plain(internals)||!sameUrl(data(internals,'url'))||data(internals,'method')!==method||data(internals,'request')!==undefined||
           data(internals,'http2')!==false||data(internals,'cache')!==undefined||data(internals,'dnsLookup')!==undefined||
           data(internals,'dnsCache')!==undefined||data(internals,'createConnection')!==undefined||data(internals,'enableUnixSockets')!==false||
           data(options,'_unixOptions')!==undefined)return false;
        const agents=data(internals,'agent');
        if(!plain(agents)||data(agents,'https')!==agent||data(agents,'http2')!==undefined)return false;
        return tlsMatch(data(internals,'https'));
    }
    const scopes=new Set();
    function closeNode(node){for(const scope of scopes){if(scope.node.deref()===node)scope.close();}}
    // Exact closed shape emitted by pinned Got createNativeRequestOptions.
    const nativeUndefined=new Set(['shared','cacheHeuristic','immutableMinTimeToLive','ignoreCargoCult','ALPNProtocols','passphrase','pfx','ciphers','honorCipherOrder','minVersion','maxVersion','sigalgs','sessionTimeout','dhparam','ecdhCurve','crl','secureOptions','lookup','family','maxHeaderSize','localAddress','createConnection','timeout','h2session']);
    function nativeSafe(options,headers){
        if(!plain(options))return false;
        const expectedNative={ca:'certificateAuthority',cert:'certificate',key:'key',rejectUnauthorized:true,checkServerIdentity:tls.checkServerIdentity,servername:expected.serverName,agent,method,headers,setHost:true};
        for(const key of Reflect.ownKeys(options)){
            if(typeof key!=='string')return false;const d=Object.getOwnPropertyDescriptor(options,key);
            if(!d||!('value' in d))return false;
            if(Object.hasOwn(expectedNative,key)){if(['ca','cert','key'].includes(key)?!materialMatches(expectedNative[key],d.value):d.value!==expectedNative[key])return false;}
            else if(!nativeUndefined.has(key)||d.value!==undefined)return false;
        }
        return Object.keys(expectedNative).every(key=>['ca','cert','key'].includes(key)?materialMatches(expectedNative[key],data(options,key)):data(options,key)===expectedNative[key]);
    }
    function begin(node,opts){
        for(const scope of scopes){const target=scope.node.deref();if(!target||!active(scope.handle,target))scope.close();}
        let handle,open=true,attempts=0,outstanding,entry;
        try{handle=control.captureDispatch(node);}catch(_){}
        const abandon=()=>{if(!outstanding)return;const item=outstanding;outstanding=undefined;
            try{Object.defineProperty(item.internals,'request',item.original);scrub(item.headers);}catch(_){} };
        const close=()=>{if(!open)return;open=false;abandon();if(entry)scopes.delete(entry);try{if(handle)control.closeDispatch(handle);}catch(_){}};
        if(handle){entry={node:new WeakRef(node),handle,close};scopes.add(entry);}
        try{
            if(!plain(opts))return Object.freeze({close});
            const initial=data(opts,'headers');
            if(!scrub(initial)){try{control.noteDispatchLoss();}catch(_){}close();return Object.freeze({close});}
            const hooks=data(opts,'hooks'), before=data(hooks,'beforeRequest');
            if(!plain(hooks)||!Array.isArray(before)||types.isProxy(before)||Object.getPrototypeOf(before)!==Array.prototype)return Object.freeze({close});
            const hook=function(options){
                const internals=data(options,'_internals'), headers=data(internals,'headers');
                if(!scrub(headers)){try{control.noteDispatchLoss();}catch(_){}return;}
                if(outstanding){abandon();try{control.noteDispatchLoss();}catch(_){}return;}
                if(!open||!handle)return;
                if(attempts>=maxAttempts){try{control.noteDispatchLoss();}catch(_){}return;}
                if(!active(handle,node)||!eligible(internals,options)||!active(handle,node))return;
                const original=Object.getOwnPropertyDescriptor(internals,'request');
                if(!original||!original.configurable||!('value' in original)||original.value!==undefined)return;
                let used=false;
                const wrapper=function(nativeUrl,nativeOptions){
                    if(used){withoutMarker(headers,nativeOptions);return fallback(nativeUrl,nativeOptions);}
                    used=true;outstanding=undefined;
                    try{Object.defineProperty(internals,'request',original);}catch(error){control.noteDispatchLoss();withoutMarker(headers,nativeOptions);throw error;}
                    let context=active(handle,node);
                    if(!hostMatches(headers)){control.noteDispatchLoss();withoutMarker(headers,nativeOptions);return fallback(nativeUrl,nativeOptions);}
                    if(!context||!sameUrl(nativeUrl)||!nativeSafe(nativeOptions,headers)||!agentSafe()||!active(handle,node)){
                        withoutMarker(headers,nativeOptions);return fallback(nativeUrl,nativeOptions);
                    }
                    attempts++;
                    let marker,ticket;const attempt=randomBytes(16).toString('hex');
                    try{marker=signer.sign(Object.freeze({tenant_id:tenantId,runtime_id:runtimeId,session_epoch:epoch,product_leaf_sha256:productLeafSha256,root:context.root,activity:context.activity,attempt}));}catch(_){control.noteDispatchLoss();withoutMarker(headers,nativeOptions);return fallback(nativeUrl,nativeOptions);}
                    context=active(handle,node);
                    if(!context||!nativeSafe(nativeOptions,headers)||!agentSafe()||!hostMatches(headers)||!marker||typeof marker.header!=='string'||typeof marker.markerDigest!=='string'){
                        control.noteDispatchLoss();withoutMarker(headers,nativeOptions);return fallback(nativeUrl,nativeOptions);
                    }
                    try{ticket=handoff.reserveAttempt(Object.freeze({root:context.root,activity:context.activity,attempt,marker_digest:marker.markerDigest}));}catch(_){}
                    if(!ticket){control.noteDispatchLoss();withoutMarker(headers,nativeOptions);return fallback(nativeUrl,nativeOptions);}
                    if(!active(handle,node)||!nativeSafe(nativeOptions,headers)||!agentSafe()||!hostMatches(headers)){handoff.cancelAttempt(ticket);control.noteDispatchLoss();withoutMarker(headers,nativeOptions);return fallback(nativeUrl,nativeOptions);}
                    try{Object.defineProperty(headers,MARKER,{value:marker.header,writable:true,configurable:true,enumerable:true});}
                    catch(_){handoff.cancelAttempt(ticket);control.noteDispatchLoss();withoutMarker(headers,nativeOptions);return fallback(nativeUrl,nativeOptions);}
                    if(!active(handle,node)||!nativeSafe(nativeOptions,headers)||!agentSafe()||!hostMatches(headers)||data(headers,MARKER)!==marker.header){handoff.cancelAttempt(ticket);control.noteDispatchLoss();withoutMarker(headers,nativeOptions);return fallback(nativeUrl,nativeOptions);}
                    let result;
                    try{result=request(new URL(destination),nativeOptions);}catch(error){handoff.cancelAttempt(ticket);control.noteDispatchLoss();throw error;}
                    if(!active(handle,node)||!result||types.isProxy(result)||!(result instanceof ClientRequest)){
                        handoff.cancelAttempt(ticket);control.noteDispatchLoss();return result;
                    }
                    if(!handoff.commitAttempt(ticket))control.noteDispatchLoss();
                    return result;
                };
                try{Object.defineProperty(internals,'request',{...original,value:wrapper});outstanding={headers,internals,original};}
                catch(_){scrub(headers);control.noteDispatchLoss();}
            };
            apply(push,before,[hook]);
        }catch(_){close();}
        return Object.freeze({close});
    }
    return Object.freeze({begin,closeNode});
}
module.exports=Object.freeze({create});
