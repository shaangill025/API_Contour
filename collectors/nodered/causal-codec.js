'use strict';
// Data-only untrusted claims. Encoding never establishes capture authority,
// session enrollment, delivery, an attempt witness, or a verified causal edge.
const {createHash}=require('node:crypto');
const {types}=require('node:util');
const MAX_U64=(1n<<64n)-1n, MAX_EVENTS=500, MAX_BYTES=1048576;
const EVENT_DOMAIN='apicontour/causal-event/1\n', BATCH_DOMAIN='apicontour/causal-events/1\n';
const fields={
    root:['kind','event_id','seq','root'],
    delivery:['kind','event_id','seq','root','activity','parent'],
    attempt:['kind','event_id','seq','root','activity','attempt','marker_digest'],
    loss:['kind','event_id','seq','first_missing_seq','last_missing_seq','reason']
};
const reasons=new Set(['overflow','expired','canceled','guard_invalidated','dispatch_missing','restart','unsupported']);
function fail(){throw new TypeError('invalid causal batch');}
function record(value, names) {
    if(!value || typeof value!=='object' || types.isProxy(value) || Array.isArray(value))fail();
    const proto=Object.getPrototypeOf(value);
    if(proto!==Object.prototype && proto!==null)fail();
    const keys=Reflect.ownKeys(value);
    if(keys.length!==names.length || keys.some(k=>typeof k!=='string'||!names.includes(k)))fail();
    const out=Object.create(null);
    for(const name of names){const d=Object.getOwnPropertyDescriptor(value,name);if(!d || !('value' in d))fail();out[name]=d.value;}
    return out;
}
function eventArray(value) {
    if(!Array.isArray(value)||types.isProxy(value)||Object.getPrototypeOf(value)!==Array.prototype)fail();
    const length=Object.getOwnPropertyDescriptor(value,'length');
    if(!length || !('value' in length) || !Number.isSafeInteger(length.value) || length.value<1 || length.value>MAX_EVENTS)fail();
    const keys=Reflect.ownKeys(value);
    if(keys.length!==length.value+1)fail();
    const result=[];
    for(let i=0;i<length.value;i++){const d=Object.getOwnPropertyDescriptor(value,String(i));if(!d||!('value' in d))fail();result.push(d.value);}
    return result;
}
function u64(value) {
    if(typeof value==='number') {if(!Number.isSafeInteger(value)||value<0)fail();value=BigInt(value);}
    if(typeof value!=='bigint'||value<0n||value>MAX_U64)fail();return value;
}
function hex(value,n){return typeof value==='string'&&value.length===n&&!/[^0-9a-f]/.test(value);}
function uuid(value){return typeof value==='string'&&value.length===36&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);}
function sameMap(map,key,value) {if(map.has(key)&&map.get(key)!==value)fail();map.set(key,value);}
function canonical(value) {
    if(typeof value==='bigint')return value.toString();
    if(typeof value==='string')return JSON.stringify(value);
    if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
    return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
}
function digest(domain,text){return createHash('sha256').update(domain,'utf8').update(text,'utf8').digest('hex');}
function encodeBatch(input) {
    const e=record(input,['wire_version','batch_id','tenant_id','runtime_id','session_epoch','first_seq','last_seq','events']);
    e.wire_version=u64(e.wire_version);e.session_epoch=u64(e.session_epoch);e.first_seq=u64(e.first_seq);e.last_seq=u64(e.last_seq);
    if(e.wire_version!==1n||e.session_epoch===0n||![e.batch_id,e.tenant_id,e.runtime_id].every(uuid))fail();
    const raw=eventArray(e.events), events=[], ids=new Set(), roots=new Set(), activities=new Map(), activityRoots=new Map(), attempts=new Map();
    let previous=0n;
    for(const value of raw){
        if(!value||typeof value!=='object'||types.isProxy(value)||Array.isArray(value))fail();
        const kindDescriptor=Object.getOwnPropertyDescriptor(value,'kind');
        if(!kindDescriptor||!('value' in kindDescriptor)||typeof kindDescriptor.value!=='string'||!Object.hasOwn(fields,kindDescriptor.value))fail();
        const kind=kindDescriptor.value, item=record(value,fields[kind]); item.seq=u64(item.seq);
        if(item.seq<=previous||!hex(item.event_id,32)||ids.has(item.event_id))fail();
        previous=item.seq;ids.add(item.event_id);
        if(kind==='root') {if(!hex(item.root,32)||roots.has(item.root))fail();roots.add(item.root);}
        else if(kind==='delivery') {
            if(![item.root,item.activity,item.parent].every(x=>hex(x,32)))fail();
            sameMap(activityRoots,item.activity,item.root);sameMap(activities,item.activity,item.root+item.parent);
        } else if(kind==='attempt') {
            if(![item.root,item.activity,item.attempt].every(x=>hex(x,32))||!hex(item.marker_digest,64))fail();
            sameMap(activityRoots,item.activity,item.root);sameMap(attempts,item.attempt,item.root+item.activity+item.marker_digest);
        } else {
            item.first_missing_seq=u64(item.first_missing_seq);item.last_missing_seq=u64(item.last_missing_seq);
            if(!reasons.has(item.reason)||item.first_missing_seq===0n||item.first_missing_seq>item.last_missing_seq||item.last_missing_seq>=item.seq)fail();
        }
        events.push(item);
    }
    if(e.first_seq!==events[0].seq||e.last_seq!==events.at(-1).seq)fail();
    for(const item of events){
        if(item.kind==='loss'&&events.some(other=>other.seq>=item.first_missing_seq&&other.seq<=item.last_missing_seq))fail();
        if(item.kind==='delivery'&&(item.activity===item.parent||roots.has(item.activity)))fail();
        if(item.kind==='attempt'&&roots.has(item.activity)&&item.activity!==item.root)fail();
    }
    e.events=events;
    const text=canonical(e);if(Buffer.byteLength(text,'utf8')>MAX_BYTES)fail();
    return {canonical:text,sha256:digest(BATCH_DOMAIN,text),events:events.map(item=>{const text=canonical(item);return {canonical:text,sha256:digest(EVENT_DOMAIN,text)};})};
}
module.exports={encodeBatch};
