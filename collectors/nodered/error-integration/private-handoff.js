'use strict';
// Dormant trusted-initializer building block. Not grant verification, session
// issuance, authentication, durable delivery, or an application-facing API.
const {randomBytes,randomUUID}=require('node:crypto');
const {performance}=require('node:perf_hooks');
const {types}=require('node:util');
const {encodeBatch}=require('../causal-codec');
const MAX_U64=(1n<<64n)-1n;
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const id=()=>randomBytes(16).toString('hex');
function create(config) {
    const {tenantId,runtimeId,epoch,authority,maxBatchEvents,maxBatchBytes,queueBytes,queueTtlMs,initialSequence=1n}=config;
    if(![tenantId,runtimeId].every(x=>typeof x==='string'&&x.length===36&&uuid.test(x)) ||
        typeof epoch!=='bigint'||epoch<1n||epoch>MAX_U64||typeof initialSequence!=='bigint'||initialSequence<1n||initialSequence>MAX_U64||typeof authority!=='function'||
        ![maxBatchEvents,maxBatchBytes,queueBytes,queueTtlMs].every(Number.isSafeInteger)||
        maxBatchEvents<1||maxBatchEvents>500||maxBatchBytes<512||maxBatchBytes>1048576||
        queueBytes<2*maxBatchBytes||queueBytes>268435456||queueTtlMs<1||queueTtlMs>86400000) throw Error('unsupported handoff bounds');
    let closed=false, nextSeq=initialSequence, events=[], pending, frozen, reserved, exhausted=false;
    function close(){closed=true;events=[];pending=undefined;frozen=undefined;reserved=undefined;}
    function gate(){
        if(closed)return false;
        try {
            const current=authority();
            if(!current || current.epoch!==epoch || current.allowed!==true ||
                !Number.isFinite(current.deadline) || performance.now()>=current.deadline ||
                (events.length && performance.now()-events[0].at>=queueTtlMs) ||
                (pending && performance.now()-pending.at>=queueTtlMs) ||
                (reserved && performance.now()-reserved.at>=queueTtlMs)) {close();return false;}
            return true;
        } catch (_) {close();return false;}
    }
    function admit(){return gate() && !exhausted && nextSeq<=MAX_U64;}
    function sequence(){if(nextSeq>MAX_U64)return undefined;return nextSeq++;}
    function body(batchId,items){return {wire_version:1,batch_id:batchId,tenant_id:tenantId,runtime_id:runtimeId,session_epoch:epoch,
        first_seq:items[0].seq,last_seq:items.at(-1).seq,events:items};}
    function fits(items){
        if(items.length>maxBatchEvents)return false;
        try{return Buffer.byteLength(encodeBatch(body('00000000-0000-4000-8000-000000000000',items)).canonical)<=maxBatchBytes;}catch(_){close();return false;}
    }
    function materialize(){
        if(!pending)return true;
        if(events.length>=maxBatchEvents)return false;
        if(nextSeq>MAX_U64)return false;
        const event={kind:'loss',event_id:id(),seq:nextSeq,first_missing_seq:pending.first,last_missing_seq:pending.last,reason:'overflow'};
        if(!fits([...events.map(x=>x.event),event]))return false;
        nextSeq++;events.push({event,at:pending.at});pending=undefined;return true;
    }
    function offer(frame){
        if(!gate())return false;
        if(!frame||typeof frame!=='object'||!['ROOT_INTENT','DELIVERY_INTENT'].includes(frame.kind))return false;
        if(reserved){
            // Reserve the last sequence for an explicit LOSS record. Interleaved
            // facts are dropped into a contiguous range until settlement.
            if(nextSeq>=MAX_U64)return false;
            const dropped=sequence();
            if(reserved.firstDropped===undefined)reserved.firstDropped=dropped;
            reserved.lastDropped=dropped;
            return false;
        }
        if(pending)materialize();
        if(closed)return false;
        if(exhausted||nextSeq>MAX_U64)return false;
        if(pending && nextSeq===MAX_U64){exhausted=true;return false;}
        const seq=nextSeq;
        if(pending){nextSeq++;pending.last=seq;return false;}
        const event=frame.kind==='ROOT_INTENT'?{kind:'root',event_id:id(),seq,root:frame.root}:
            {kind:'delivery',event_id:id(),seq,root:frame.root,activity:frame.activity,parent:frame.parent};
        if(!fits([...events.map(x=>x.event),event])){if(!closed){if(seq===MAX_U64)exhausted=true;else{nextSeq++;pending={first:seq,last:seq,at:performance.now()};}}return false;}
        nextSeq++;events.push({event:Object.freeze(event),at:performance.now()});return true;
    }
    function reserveAttempt(frame){
        if(!gate()||exhausted||reserved||nextSeq>=MAX_U64)return undefined;
        if(pending){materialize();if(pending||closed||nextSeq>=MAX_U64)return undefined;}
        if(!frame||typeof frame!=='object'||types.isProxy(frame)||Array.isArray(frame))return undefined;
        const names=['root','activity','attempt','marker_digest'], values={};
        if(Reflect.ownKeys(frame).length!==names.length)return undefined;
        for(const name of names){const d=Object.getOwnPropertyDescriptor(frame,name);if(!d||!('value' in d))return undefined;values[name]=d.value;}
        if(![values.root,values.activity,values.attempt].every(x=>typeof x==='string'&&/^[0-9a-f]{32}$/.test(x)) ||
           typeof values.marker_digest!=='string'||!/^[0-9a-f]{64}$/.test(values.marker_digest))return undefined;
        const event=Object.freeze({kind:'attempt',event_id:id(),seq:nextSeq,root:values.root,activity:values.activity,attempt:values.attempt,marker_digest:values.marker_digest});
        if(!fits([...events.map(x=>x.event),event])||!gate())return undefined;
        const ticket=Object.freeze({});nextSeq++;
        reserved={ticket,event,at:performance.now(),firstDropped:undefined,lastDropped:undefined};
        return ticket;
    }
    function settleAttempt(ticket,commit){
        if(!gate()||!reserved||reserved.ticket!==ticket)return false;
        const item=reserved;reserved=undefined;
        if(commit)events.push({event:item.event,at:item.at});
        const first=commit?item.firstDropped:item.event.seq;
        const last=item.lastDropped===undefined?item.event.seq:item.lastDropped;
        if(first!==undefined)pending={first,last,at:item.at};
        return true;
    }
    function commitAttempt(ticket){return settleAttempt(ticket,true);}
    function cancelAttempt(ticket){return settleAttempt(ticket,false);}
    function freeze(){
        if(!gate())return undefined;
        if(frozen)return frozen.view;
        if(reserved)return undefined;
        materialize();if(closed||!events.length)return undefined;
        const batchId=randomUUID(), items=events.map(x=>x.event), encoded=encodeBatch(body(batchId,items));
        const view=Object.freeze({batchId,epoch,canonical:encoded.canonical,sha256:encoded.sha256});
        frozen={view,count:events.length};return view;
    }
    function ack(batchId,sha256,receiptEpoch,commitIf){
        if(!gate()||!frozen||receiptEpoch!==epoch||batchId!==frozen.view.batchId||sha256!==frozen.view.sha256)return false;
        if(commitIf!==undefined){try{if(typeof commitIf!=='function'||commitIf()!==true)return false;}catch(_){return false;}}
        events.splice(0,frozen.count);frozen=undefined;return true;
    }
    return Object.freeze({gate,admit,offer,freeze,ack,close,reserveAttempt,commitAttempt,cancelAttempt});
}
module.exports={create};
