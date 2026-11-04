'use strict';
// Pinned extracted Flow/Node literals composed with the actual private lexical bridge; no loader.
const assert=require('node:assert/strict'), fs=require('node:fs'), vm=require('node:vm'), crypto=require('node:crypto');
const {install}=require('../../../collectors/nodered/error-integration/private-runtime');
const {initialize}=require('../../../collectors/nodered/error-integration/lexical-bridge');
const flowTransform=require('../../../collectors/nodered/error-integration/flow-source-transform').transform;
const nodeTransform=require('../../../collectors/nodered/error-integration/node-source-transform').transform;
const hooksBytes=fs.readFileSync(process.argv[2]), nodeBytes=fs.readFileSync(process.argv[3]), flowBytes=fs.readFileSync(process.argv[4]);
assert.equal(crypto.createHash('sha256').update(hooksBytes).digest('hex'),'e7d1e0496b5399458de55bc9b8ea59e6741869db33cdced0f03ec798c6fa6fcf');
assert.throws(()=>flowTransform(Buffer.from('bad')),/unsupported/);
function run(instrumented, accessor, throws) {
    const moduleStub={exports:{}};
    vm.runInNewContext(hooksBytes.toString(),{module:moduleStub,exports:moduleStub.exports,require(){return {debug(){}}},Error,Promise});
    const hooks=moduleStub.exports; let control;
    const adapter=install(hooks,{inbound:['in'],requests:[],maxPending:8,maxEvents:64,maxBytes:8192,ttlMs:1000},c=>control=c);
    const trace=[], observed=[];
    const Node={prototype:{}}, ns=(instrumented?nodeTransform(nodeBytes):nodeBytes).toString();
    const literals=['receive','emit','_emitInput'].map(name=>{const m=ns.match(new RegExp('Node\\.prototype\\.'+name+' = function\\([^\\n]*\\) \\{[\\s\\S]*?\\n\\}'+(name==='receive'?';':'')));assert(m);return m[0];}).join('\n');
    const setBridge=Function('Node','redUtil','hooks','let __apicontourNodeBridge;'+literals+';return x=>__apicontourNodeBridge=x;')(Node,{generateId:()=> 'id'},hooks);
    const expected={receive:Node.prototype.receive,emit:Node.prototype.emit,input:Node.prototype._emitInput};
    function node(id){const n=Object.create(Node.prototype);n.id=id;n.metric=()=>{};n._inputCallback=msg=>{trace.push('callback:'+id+':'+msg.label);observed.push([id,msg.label,adapter.snapshot().events.filter(e=>e.kind==='DELIVERY_INTENT').length]);};return n;}
    const a=node('A'), b=node('B');
    const bridge=initialize(control,expected,hooks,hooks.trigger,[a,b]); setBridge(bridge.node);
    let hookCaller=false, hookCalls=0, applyCalls=0, methodCalls=0;
    const originalTrigger=hooks.trigger;
    const nested=()=>{expected.receive.call(a,{_msgid:'id',label:'nested-A'});b._emitInput({label:'nested-B'});};
    Object.defineProperty(a,'receive',{get(){trace.push('get:receive');if(accessor==='receive')nested();return expected.receive;}});
    const event={destination:{node:a}};
    Object.defineProperty(event,'msg',{get(){trace.push('get:msg');if(accessor==='msg')nested();
        if(accessor==='hook') hooks.trigger=Function('original','expected','record',`return function() { if (arguments[0] === "onReceive") record(arguments.callee.caller === expected.input); return Reflect.apply(original,this,arguments); }`)(originalTrigger,expected,value=>{hookCaller=value;hookCalls++;});
        if(accessor==='apply') Object.defineProperty(expected.input,'apply',{configurable:true,get(){applyCalls++;return function(receiver,args){return Reflect.apply(expected.input,receiver,args);};}});
        if(accessor==='method') a.emit=function(...args){methodCalls++;return Reflect.apply(expected.emit,this,args);};
        if(throws)throw Error('message getter');return {_msgid:'id',label:'intended'};}});
    const ftext=(instrumented?flowTransform(flowBytes):flowBytes).toString();
    const match=ftext.match(/function deliverMessageToDestination\(sendEvent\) \{[\s\S]*?\n\}/);assert(match);
    const deliver=Function('Log','__apicontourFlowBridge',match[0]+';return deliverMessageToDestination;')({error(){trace.push('log');}},bridge.flow);
    hooks.trigger('onSend',[{source:{id:'in'},msg:{req:{headers:{}}}}],()=>hooks.trigger('preDeliver',event,()=>deliver(event)));
    return {trace,observed,state:adapter.snapshot(),adapter,control,hooks,event,hookCaller,hookCalls,applyCalls,methodCalls,bridge,a,b,expected};
}
for(const accessor of ['receive','msg']) {
    const stock=run(false,accessor,false), candidate=run(true,accessor,false);
    assert.deepEqual(candidate.trace,stock.trace,'stock property lookup order and callback behavior');
    const delivery=candidate.state.events.filter(e=>e.kind==='DELIVERY_INTENT');
    assert.deepEqual(candidate.observed,[['A','nested-A',0],['B','nested-B',0],['A','intended',1]]);
    assert.equal(delivery.length,1);const root=candidate.state.events.find(e=>e.kind==='ROOT_INTENT');
    assert.equal(delivery[0].root,root.root);assert.equal(delivery[0].parent,root.root);
    assert.equal(candidate.state.pending,0);assert.equal(candidate.state.frames,0);
    assert(candidate.state.loss>=2);
}
for (const mutation of ['hook','apply','method']) {
    const result=run(true,mutation,false);
    assert.equal(result.state.events.filter(e=>e.kind==='DELIVERY_INTENT').length,0,mutation+' must not own delivery');
    assert.equal(result.state.frames,0); assert.equal(result.state.pending,0);
    assert.deepEqual(result.trace.slice(-1),['callback:A:intended']);
    if(mutation==='hook') { assert.equal(result.hookCalls,1); assert.equal(result.hookCaller,true); }
    if(mutation==='apply') assert.equal(result.applyCalls,1);
    if(mutation==='method') assert.equal(result.methodCalls,1);
}
const stockThrow=run(false,'none',true), changedThrow=run(true,'none',true);
assert.deepEqual(changedThrow.trace,stockThrow.trace); assert.equal(changedThrow.state.frames,0);assert.equal(changedThrow.state.pending,0);
const stateCheck=run(true,'none',false), inbound={source:{id:'in'},msg:{req:{headers:{}}}};
const target={}, event={destination:{node:target}};
const guarded={destination:{node:stateCheck.a}};
stateCheck.hooks.trigger('onSend',[inbound],()=>stateCheck.hooks.trigger('preDeliver',guarded,()=>{
    const frame=stateCheck.bridge.flow.claim(guarded); assert(frame);
    const armed=stateCheck.bridge.flow.arm(stateCheck.a,stateCheck.expected.receive,frame); assert(armed);
    assert.equal(stateCheck.bridge.flow.arm(stateCheck.a,stateCheck.expected.receive,frame),undefined,'overlap must fail closed');
    assert.equal(stateCheck.bridge.node.take('receive',stateCheck.b),undefined,'wrong target consumes handoff');
    assert.equal(stateCheck.bridge.node.take('receive',stateCheck.a),undefined,'handoff replay rejected');
    stateCheck.bridge.flow.finish(armed); stateCheck.bridge.flow.drop(frame); stateCheck.bridge.flow.drop(frame);
}));
stateCheck.hooks.trigger('onSend',[inbound],()=>stateCheck.hooks.trigger('preDeliver',event,()=>{
    const frame=stateCheck.control.claimDelivery(event); assert(frame);
    assert.equal(stateCheck.control.claimDelivery(event),undefined);
    stateCheck.control.cancel(frame);
}));
const wrong={destination:{node:target}};
stateCheck.hooks.trigger('onSend',[inbound],()=>stateCheck.hooks.trigger('preDeliver',wrong,()=>{
    wrong.destination.node={}; assert.equal(stateCheck.control.claimDelivery(wrong),undefined);
}));
stateCheck.hooks.trigger('onSend',[inbound],()=>stateCheck.hooks.trigger('preDeliver',{},()=>assert.equal(stateCheck.control.claimDelivery({}),undefined)));
assert.equal(stateCheck.adapter.snapshot().frames,0); assert.equal(stateCheck.adapter.snapshot().pending,0);
process.stdout.write('PASS: pinned Flow getter order/reentry and exception cleanup with actual bridge\n');
