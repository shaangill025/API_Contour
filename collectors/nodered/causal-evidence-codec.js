'use strict';
// Data-only untrusted claims: decoding and hashing do not authenticate, verify a
// signature, enroll a receiver, grant access, or create a causal edge.
const {createHash}=require('node:crypto');
const {TextDecoder,types}=require('node:util');
const typedPrototype=Object.getPrototypeOf(Uint8Array.prototype);
const typedLength=Object.getOwnPropertyDescriptor(typedPrototype,'byteLength').get;
const typedOffset=Object.getOwnPropertyDescriptor(typedPrototype,'byteOffset').get;
const typedBuffer=Object.getOwnPropertyDescriptor(typedPrototype,'buffer').get;
const arrayBufferLength=Object.getOwnPropertyDescriptor(ArrayBuffer.prototype,'byteLength').get;
const arrayBufferResizable=Object.getOwnPropertyDescriptor(ArrayBuffer.prototype,'resizable').get;
const copyBytes=Uint8Array.prototype.set;
const bindingFields=['wire_version','tenant_id','gateway_id','gateway_generation','collector_id','record_id','producer_runtime_id','producer_session_epoch','producer_attempt_id','marker_digest','receiver_runtime_id','receiver_session_epoch','delivery_handle','retry_of'];
const receiverFields=['wire_version','tenant_id','gateway_id','gateway_generation','delivery_handle','receiver_runtime_id','receiver_session_epoch','local_root','binding_digest'];
function fail(){throw new TypeError('invalid causal evidence');}
// This bounded parser keeps duplicate keys visible and records the exact raw
// nested binding span, including internal whitespace, before typed validation.
function parse(bytes,limit){
    let snapshot;
    try {
        if(!types.isUint8Array(bytes))fail();
        const length=Reflect.apply(typedLength,bytes,[]);
        const offset=Reflect.apply(typedOffset,bytes,[]);
        const buffer=Reflect.apply(typedBuffer,bytes,[]);
        // The ArrayBuffer intrinsic rejects SharedArrayBuffer, including growable shared storage.
        Reflect.apply(arrayBufferLength,buffer,[]);
        if(Reflect.apply(arrayBufferResizable,buffer,[])||length>limit)fail();
        snapshot=new Uint8Array(length);
        Reflect.apply(copyBytes,snapshot,[new Uint8Array(buffer,offset,length)]);
    } catch { fail(); }
    let text;try{text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(snapshot);}catch{fail();}
    let i=0, nestedBytes=0;
    function ws(){while(i<text.length&&' \t\r\n'.includes(text[i]))i++;}
    function string(){
        if(text[i]!== '"')fail();const start=i++;
        while(i<text.length){const c=text.charCodeAt(i++);if(c===34){try{return JSON.parse(text.slice(start,i));}catch{fail();}}if(c<32)fail();if(c===92){if(i>=text.length)fail();i++;}}
        fail();
    }
    function value(depth){
        ws();if(text[i]==='{')return object(depth);
        if(text[i]==='"')return string();
        if(text.slice(i,i+4)==='null'){i+=4;return null;}
        // The only permitted numeric value is the integer wire version 1.
        if(text[i]==='1'){i++;return 1;}
        fail();
    }
    function object(depth){
        if(depth>1)fail();
        if(depth===1){
            let j=i, level=0, quoted=false, escaped=false, end=-1;
            for(;j<text.length;j++){
                const c=text[j];
                if(quoted){if(escaped)escaped=false;else if(c==='\\')escaped=true;else if(c==='"')quoted=false;}
                else if(c==='"')quoted=true;
                else if(c==='{')level++;
                else if(c==='}'&&--level===0){end=j+1;break;}
            }
            if(end<0||Buffer.byteLength(text.slice(i,end),'utf8')>2048)fail();
        }
        const start=i++;const out=Object.create(null);ws();
        if(text[i]==='}'){i++;return out;}
        while(true){ws();const key=string();if(Object.hasOwn(out,key))fail();ws();if(text[i++]!==':')fail();out[key]=value(depth+1);ws();
            if(text[i]==='}'){i++;break;}if(text[i++]!==',')fail();}
        if(depth===1)nestedBytes=Buffer.byteLength(text.slice(start,i),'utf8');
        return out;
    }
    ws();const result=value(0);ws();if(i!==text.length)fail();return {result,nestedBytes};
}
function exact(o,keys){if(!o||typeof o!=='object'||Array.isArray(o)||Object.keys(o).length!==keys.length||keys.some(k=>!Object.hasOwn(o,k)))fail();}
function uuid(s){return typeof s==='string'&&s.length===36&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s);}
function hex(s,n){return typeof s==='string'&&s.length===n&&!/[^0-9a-f]/.test(s);}
function epoch(s){return typeof s==='string'&&/^[1-9][0-9]{0,19}(?![\s\S])/.test(s)&&BigInt(s)<=18446744073709551615n;}
function binding(o){
    exact(o,bindingFields);
    if(o.wire_version!==1||![o.tenant_id,o.gateway_id,o.collector_id,o.record_id,o.producer_runtime_id,o.receiver_runtime_id].every(uuid)||
       ![o.gateway_generation,o.producer_attempt_id,o.delivery_handle].every(x=>hex(x,32))||!hex(o.marker_digest,64)||
       !epoch(o.producer_session_epoch)||!epoch(o.receiver_session_epoch)||(o.retry_of!==null&&!hex(o.retry_of,32)))fail();
}
function canonical(value){
    if(value===null||typeof value==='string'||typeof value==='number')return JSON.stringify(value);
    return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
}
function decode(kind,bytes){
    if(!['binding','observer','receiver'].includes(kind))fail();
    const {result:o,nestedBytes}=parse(bytes,kind==='binding'?2048:4096);
    if(kind==='binding')binding(o);
    else if(kind==='observer'){
        exact(o,['wire_version','binding','batch_id','signed_marker']);
        if(nestedBytes>2048)fail();binding(o.binding);
        if(o.wire_version!==1||!uuid(o.batch_id)||typeof o.signed_marker!=='string'||o.signed_marker.length>1024||(!o.signed_marker.startsWith('ac1.')||/[^\x21-\x7e]/.test(o.signed_marker)))fail();
    } else {
        exact(o,receiverFields);
        if(o.wire_version!==1||![o.tenant_id,o.gateway_id,o.receiver_runtime_id].every(uuid)||
           ![o.gateway_generation,o.delivery_handle,o.local_root].every(x=>hex(x,32))||!hex(o.binding_digest,64)||!epoch(o.receiver_session_epoch))fail();
    }
    const text=canonical(o);
    if(kind==='observer')Object.freeze(o.binding);
    Object.freeze(o);
    return Object.freeze({value:o,canonical:text,sha256:createHash('sha256').update(`apicontour/causal-evidence/${kind}/1\n`).update(text).digest('hex')});
}
module.exports={decode};
