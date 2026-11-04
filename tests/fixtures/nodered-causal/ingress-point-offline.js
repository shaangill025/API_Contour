'use strict';
// With an argument uses exact pinned hooks; without one uses a tiny hook model.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto');
const {install}=require('../../../collectors/nodered/error-integration/private-runtime');
let hooks;
if(process.argv[2]) {
    const data=fs.readFileSync(process.argv[2]);
    assert.equal(crypto.createHash('sha256').update(data).digest('hex'),'e7d1e0496b5399458de55bc9b8ea59e6741869db33cdced0f03ec798c6fa6fcf');
    const mod={exports:{}};vm.runInNewContext(data.toString(),{module:mod,exports:mod.exports,require(){return {debug(){}}},Error,Promise});hooks=mod.exports;
} else {
    const callbacks={};hooks={add(k,f){callbacks[k.split('.')[0]]=f;},remove(){},clear(){},has(k){return !!callbacks[k.split('.')[0]];},trigger(k,e,done){const f=callbacks[k];if(f)f(e,done);else done();}};
}
let control;
const adapter=install(hooks,{inbound:['in'],requests:[],maxPending:8,maxEvents:64,maxBytes:8192,ttlMs:1000,ingressPoint:{node:'in',method:'POST',url:'/run'}},c=>{control=c;});
const roots=()=>adapter.snapshot().events.filter(e=>e.kind==='ROOT_INTENT');
function send(msg){let called=false;hooks.trigger('onSend',[{source:{id:'in'},msg}],()=>called=true);assert(called,'forwarding');}
function req(method,url){return {method,url,headers:{}};}
function reject(msg){const before=adapter.snapshot();send(msg);const after=adapter.snapshot();assert(after.loss>before.loss,'each rejected point records loss');assert.equal(roots().length,0);}
const initial=adapter.snapshot();
for (const [method,url] of [['GET','/run'],['POST','/run?query=1'],['POST','/run/'],['POST','/Run'],['POST','/%72un'],['POST','/run#x'],['POST','http://example/run'],['POST',''],['POST',null]]) {
    const msg={req:req(method,url),_apicontour:'untouched'};reject(msg);
    assert.equal(msg._apicontour,'untouched','reject before scrub');
}
reject({req:{headers:{}}});reject({});reject({req:null});
let getterCalls=0;
for(const name of ['method','url']) {
    const r=req('POST','/run');Object.defineProperty(r,name,{get(){getterCalls++;return name==='method'?'POST':'/run';}});reject({req:r});
}
const msg={};Object.defineProperty(msg,'req',{get(){getterCalls++;return req('POST','/run');}});reject(msg);
const inherited=Object.create({method:'POST',url:'/run'});inherited.headers={};reject({req:inherited});
assert.equal(getterCalls,0);assert.equal(roots().length,0);assert(adapter.snapshot().loss>initial.loss);
const accepted={req:req('POST','/run'),_apicontour:'remove'};send(accepted);assert.equal(roots().length,1);assert(!('_apicontour' in accepted));
// Overlapping continuations deliver in reverse and retain their own roots.
const expected = [], actual = [], targetA = {}, targetB = {};
for(const [index,target,delay] of [[0,targetA,20],[1,targetB,0]]) {
    hooks.trigger('onSend',[{source:{id:'in'},msg:{req:req('POST','/run')}}],()=>{
        expected[index]=roots().at(-1).root;
        setTimeout(()=>{
            const event={destination:{node:target,id:'worker'}};
            hooks.trigger('preDeliver',event,()=>{
                const frame=control.claimDelivery(event);
                control.bind(frame,target,event,()=>hooks.trigger('onReceive',event,()=>{
                    actual.push([index,adapter.snapshot().events.filter(e=>e.kind==='DELIVERY_INTENT').at(-1).root]);
                }));
            });
        },delay);
    });
}
setTimeout(()=>{
    assert.deepEqual(actual,[[1,expected[1]],[0,expected[0]]]);
    assert.equal(roots().length,3);assert.equal(new Set(roots().map(x=>x.root)).size,3);
    const snap=adapter.snapshot();assert(snap.registryIntact);const serialized=JSON.stringify(snap);
    for(const raw of ['/run','query','example','POST','untouched'])assert(!serialized.includes(raw),'raw point or message leaked');
    process.stdout.write('PASS: exact ingress point, malformed/accessor rejection, loss and forwarding'+(process.argv[2]?' with pinned hooks':' with hook model')+'\n');
},50);
