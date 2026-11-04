'use strict';
// Pinned stock/transformed Flow and Node literals; bridge is test-only.
const assert=require('node:assert/strict'), fs=require('node:fs'), vm=require('node:vm'), crypto=require('node:crypto');
const {install}=require('../../../collectors/nodered/error-integration/private-runtime');
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
    let handoff; const active=new Set(); const trace=[], observed=[];
    const Node={prototype:{}}, ns=(instrumented?nodeTransform(nodeBytes):nodeBytes).toString();
    const literals=['receive','emit','_emitInput'].map(name=>{const m=ns.match(new RegExp('Node\\.prototype\\.'+name+' = function\\([^\\n]*\\) \\{[\\s\\S]*?\\n\\}'+(name==='receive'?';':'')));assert(m);return m[0];}).join('\n');
    let expected;
    const bridge={trustedHook(){return true;},apply:Reflect.apply,
        claim(event){const frame=control.claimDelivery(event);if(frame)active.add(frame);return frame;},
        take(kind,target){const p=handoff;handoff=undefined;return p && p.kind===kind && p.target===target?p.frame:undefined;},
        arm(...args){let kind,target,method,apply,frame;
            if(args.length===3){[target,method,frame]=args;kind='receive';}
            else [kind,target,method,apply,frame]=args;
            if(!frame || method!==expected[kind] || (kind==='input' && apply!==Function.prototype.apply))return undefined;
            return handoff={kind,target,frame};},
        finish(handle){if(handoff===handle)handoff=undefined;},
        drop(frame){if(active.delete(frame))control.cancel(frame);},
        bind(frame,target,event,invoke){active.delete(frame);return control.bind(frame,target,event,invoke);}
    };
    Function('Node','redUtil','hooks','__apicontourNodeBridge',literals)(Node,{generateId:()=> 'id'},hooks,bridge);
    expected={receive:Node.prototype.receive,emit:Node.prototype.emit,input:Node.prototype._emitInput};
    function node(id){const n=Object.create(Node.prototype);n.id=id;n.metric=()=>{};n._inputCallback=msg=>{trace.push('callback:'+id+':'+msg.label);observed.push([id,msg.label,adapter.snapshot().events.filter(e=>e.kind==='DELIVERY_INTENT').length]);};return n;}
    const a=node('A'), b=node('B');
    const nested=()=>{expected.receive.call(a,{_msgid:'id',label:'nested-A'});b._emitInput({label:'nested-B'});};
    Object.defineProperty(a,'receive',{get(){trace.push('get:receive');if(accessor==='receive')nested();return expected.receive;}});
    const event={destination:{node:a}};
    Object.defineProperty(event,'msg',{get(){trace.push('get:msg');if(accessor==='msg')nested();if(throws)throw Error('message getter');return {_msgid:'id',label:'intended'};}});
    const ftext=(instrumented?flowTransform(flowBytes):flowBytes).toString();
    const match=ftext.match(/function deliverMessageToDestination\(sendEvent\) \{[\s\S]*?\n\}/);assert(match);
    const deliver=Function('Log','__apicontourFlowBridge',match[0]+';return deliverMessageToDestination;')({error(){trace.push('log');}},bridge);
    hooks.trigger('onSend',[{source:{id:'in'},msg:{req:{headers:{}}}}],()=>hooks.trigger('preDeliver',event,()=>deliver(event)));
    return {trace,observed,state:adapter.snapshot(),adapter,control,hooks,event};
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
const stockThrow=run(false,'none',true), changedThrow=run(true,'none',true);
assert.deepEqual(changedThrow.trace,stockThrow.trace); assert.equal(changedThrow.state.frames,0);assert.equal(changedThrow.state.pending,0);
const stateCheck=run(true,'none',false), inbound={source:{id:'in'},msg:{req:{headers:{}}}};
const target={}, event={destination:{node:target}};
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
process.stdout.write('PASS: pinned Flow getter order/reentry and exception cleanup with test bridge\n');
