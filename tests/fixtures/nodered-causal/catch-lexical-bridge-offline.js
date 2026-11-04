'use strict';
// Actual pinned Flow.handleError method and transformed Node literals, with
// real private runtime and lexical bridge; stubbed dependencies, no loader.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto');
const {install}=require('../../../collectors/nodered/error-integration/private-runtime');
const {initialize}=require('../../../collectors/nodered/error-integration/lexical-bridge');
const transformNode=require('../../../collectors/nodered/error-integration/node-source-transform').transform;
const transformFlow=require('../../../collectors/nodered/error-integration/flow-source-transform').transform;
const hooksBytes=fs.readFileSync(process.argv[2]), nodeBytes=fs.readFileSync(process.argv[3]), flowBytes=fs.readFileSync(process.argv[4]);
assert.equal(crypto.createHash('sha256').update(hooksBytes).digest('hex'),'e7d1e0496b5399458de55bc9b8ea59e6741869db33cdced0f03ec798c6fa6fcf');
const mod={exports:{}};vm.runInNewContext(hooksBytes.toString(),{module:mod,exports:mod.exports,require(){return {debug(){}}},Error,Promise});
const hooks=mod.exports;let control;
const adapter=install(hooks,{inbound:['in'],requests:[],maxPending:16,maxEvents:256,maxBytes:32768,ttlMs:5000},c=>control=c);
const Node={prototype:{}}, ns=transformNode(nodeBytes).toString();
const literals=['receive','emit','_emitInput'].map(name=>{const m=ns.match(new RegExp('Node\\.prototype\\.'+name+' = function\\([^\\n]*\\) \\{[\\s\\S]*?\\n\\}'+(name==='receive'?';':'')));assert(m);return m[0];}).join('\n');
const setBridge=Function('Node','redUtil','hooks','let __apicontourNodeBridge;'+literals+';return x=>__apicontourNodeBridge=x;')(Node,{generateId:()=> 'id'},hooks);
const stock={receive:Node.prototype.receive,emit:Node.prototype.emit,input:Node.prototype._emitInput};
const deliveries=()=>adapter.snapshot().events.filter(e=>e.kind==='DELIVERY_INTENT');
const seen=[], parents={};let bridge, flow, warnings=0, getterCalls=0, mutation=false, nested=false, throwGetter=false;
function node(id){const n=Object.create(Node.prototype);n.id=id;n.type='test';n.metric=()=>{};n.warn=()=>warnings++;return n;}
const a=node('A'),b=node('B'),c=node('C'),d=node('D');
bridge=initialize(control,stock,hooks,hooks.trigger,[a,b,c,d]);setBridge(bridge.node);
const ftext=transformFlow(flowBytes).toString();
const match=ftext.match(/    handleError\(node,logMessage,msg,reportingNode\) \{[\s\S]*?\n    \}\n\n    handleComplete\(node,msg\)/);assert(match);
const method=match[0].replace(/\n\n    handleComplete\(node,msg\)$/,'');
const Flow=Function('redUtil','Log','__apicontourFlowBridge','return class Flow { '+method+' }')({cloneMessage:msg=>({...msg})},{_:x=>x},bridge.flow);
flow=new Flow();flow.id='flow';flow.groups={};flow.catchNodes=[c,d];
Object.defineProperty(c,'receive',{get(){
    getterCalls++;
    if(throwGetter) throw Error('receive getter');
    const before=deliveries().length;
    c._emitInput({label:'direct-C'}); b._emitInput({label:'direct-B'});
    assert.equal(deliveries().length,before,'reentrant direct input must not own a delivery');
    if(mutation)return function(msg){return Reflect.apply(stock.receive,this,[msg]);};
    return stock.receive;
}});
for(const n of [c,d,b])n._inputCallback=msg=>{
    if(msg.label && msg.label.startsWith('direct-')) {seen.push([n.id,msg.label,deliveries().length]);return;}
    const item=deliveries().at(-1);seen.push([n.id,msg.label,item]);
    if(n===c && msg.label==='nested-root' && !nested){nested=true;flow.handleError(c,Error('nested'),{label:'nested-child'});}
};
function start(id, delay) {
    const worker=id==='A'?a:b;
    return new Promise(resolve=>{
        worker._inputCallback=msg=>{if (msg.label === 'direct-B') { seen.push(['B',msg.label,deliveries().length]); return; } parents[id]=deliveries().at(-1);setTimeout(()=>{flow.handleError(worker,Error('failure'),{label:id});resolve();},delay);};
        const e={destination:{node:worker},msg:{_msgid:'id',label:id}};
        hooks.trigger('onSend',[{source:{id:'in'},msg:{req:{headers:{}}}}],()=>hooks.trigger('preDeliver',e,()=>{
            const frame=bridge.flow.claim(e), armed=bridge.flow.arm(worker,stock.receive,frame);
            try {Reflect.apply(stock.receive,worker,[e.msg]);} finally {bridge.flow.finish(armed);bridge.flow.drop(frame);}
        }));
    });
}
(async()=>{
    await Promise.all([start('A',20),start('B',0)]);
    const owned=seen.filter(x=>x[1]==='A'||x[1]==='B');
    assert.deepEqual(owned.map(x=>[x[0],x[1]]),[['C','B'],['D','B'],['C','A'],['D','A']]);
    for(const [_,id,event] of owned){assert.equal(event.parent,parents[id].activity);assert.equal(event.root,parents[id].root);}
    assert.notEqual(parents.A.root,parents.B.root);
    // Outside an owned activity, forwarding continues but no parent is invented.
    let before=deliveries().length;flow.handleError(a,Error('unowned'),{label:'unowned'});assert.equal(deliveries().length,before);
    // Exercise nested catches from an owned worker activity, then verify the
    // nested child is parented to C's freshly bound delivery.
    await new Promise(resolve=>{a._inputCallback=()=>{parents.N=deliveries().at(-1);flow.handleError(a,Error('outer'),{label:'nested-root'});resolve();};
        const e={destination:{node:a},msg:{_msgid:'id'}};
        hooks.trigger('onSend',[{source:{id:'in'},msg:{req:{headers:{}}}}],()=>hooks.trigger('preDeliver',e,()=>{const f=bridge.flow.claim(e),h=bridge.flow.arm(a,stock.receive,f);try{stock.receive.call(a,e.msg);}finally{bridge.flow.finish(h);bridge.flow.drop(f);}}));});
    const outer=seen.find(x=>x[0]==='C'&&x[1]==='nested-root')[2];
    for(const x of seen.filter(x=>x[1]==='nested-child'))assert.equal(x[2].parent,outer.activity);
    before=deliveries().length;const loops=flow.handleError(a,Error('loop'),{error:{source:{id:'A',count:9}}});assert.equal(loops,false);assert.equal(warnings,1);assert.equal(deliveries().length,before);
    // One mutated Catch method forwards without proof; sibling remains owned.
    mutation=true;
    await new Promise(resolve=>{a._inputCallback=()=>{parents.M=deliveries().at(-1);flow.handleError(a,Error('mutated'),{label:'mutated'});resolve();};
        const e={destination:{node:a},msg:{_msgid:'id'}};
        hooks.trigger('onSend',[{source:{id:'in'},msg:{req:{headers:{}}}}],()=>hooks.trigger('preDeliver',e,()=>{const f=bridge.flow.claim(e),h=bridge.flow.arm(a,stock.receive,f);try{stock.receive.call(a,e.msg);}finally{bridge.flow.finish(h);bridge.flow.drop(f);}}));});
    const changed=seen.filter(x=>x[1]==='mutated');assert.equal(changed.length,2);
    assert.equal(changed[0][2].activity,parents.M.activity,'mutated C forwarded without ownership');
    assert.equal(changed[1][2].parent,parents.M.activity);
    throwGetter=true;
    await new Promise(resolve=>{a._inputCallback=()=>{assert.throws(()=>flow.handleError(a,Error('throw'),{label:'throws'}),/receive getter/);resolve();};
        const e={destination:{node:a},msg:{_msgid:'id'}};
        hooks.trigger('onSend',[{source:{id:'in'},msg:{req:{headers:{}}}}],()=>hooks.trigger('preDeliver',e,()=>{const f=bridge.flow.claim(e),h=bridge.flow.arm(a,stock.receive,f);try{stock.receive.call(a,e.msg);}finally{bridge.flow.finish(h);bridge.flow.drop(f);}}));});
    const snap=adapter.snapshot();assert.equal(snap.pending,0);assert.equal(snap.frames,0);assert(getterCalls>=5);assert(snap.loss>0);
    process.stdout.write('PASS: actual pinned Catch method with private bridge, reversed roots, nested and loss paths\n');
})().catch(err=>{console.error(err);process.exitCode=1;});
