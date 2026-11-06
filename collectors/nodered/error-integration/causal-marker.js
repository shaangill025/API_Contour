'use strict';
// Data-only signer for a future trusted initializer. A signature is not an
// original-peer witness, live authorization, replay defense, or an actual edge.
const {createHash,createPrivateKey,sign}=require('node:crypto');
const {types}=require('node:util');
const MAX_U64=(1n<<64n)-1n;
const SIGN_DOMAIN=Buffer.from('apicontour/causal-marker/1\n','utf8');
const WIRE_DOMAIN='apicontour/causal-marker-wire/1\n';
const FIELDS=Object.freeze(['tenant_id','runtime_id','session_epoch','product_leaf_sha256','root','activity','attempt']);
const PKCS8_PREFIX=Buffer.from('302e020100300506032b657004220420','hex');
const typedLength=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype),'length').get;
function fail(){throw new TypeError('invalid causal marker');}
function readRecord(value){
    if(!value || typeof value!=='object' || types.isProxy(value) || Array.isArray(value))fail();
    const proto=Object.getPrototypeOf(value);if(proto!==Object.prototype && proto!==null)fail();
    const keys=Reflect.ownKeys(value);if(keys.length!==FIELDS.length || keys.some(k=>typeof k!=='string'||!FIELDS.includes(k)))fail();
    const output=Object.create(null);
    for(const name of FIELDS){const descriptor=Object.getOwnPropertyDescriptor(value,name);if(!descriptor||!('value' in descriptor))fail();output[name]=descriptor.value;}
    return output;
}
function hex(value,n){return typeof value==='string'&&value.length===n&&!/[^0-9a-f]/.test(value);}
function uuid(value){return typeof value==='string'&&value.length===36&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);}
function epoch(value){
    if(typeof value==='number'){if(!Number.isSafeInteger(value)||value<=0)fail();value=BigInt(value);}
    if(typeof value!=='bigint'||value<=0n||value>MAX_U64)fail();return value;
}
function payload(value){
    const p=readRecord(value);p.session_epoch=epoch(p.session_epoch);
    if(!uuid(p.tenant_id)||!uuid(p.runtime_id)||!hex(p.product_leaf_sha256,64)||!hex(p.root,32)||!hex(p.activity,32)||!hex(p.attempt,32))fail();
    // All text fields are ASCII fixed-format values, so their JSON spellings
    // cannot contain escapes. Key order is fixed canonical ASCII order.
    return '{"activity":"'+p.activity+'","attempt":"'+p.attempt+'","product_leaf_sha256":"'+p.product_leaf_sha256+'","root":"'+p.root+'","runtime_id":"'+p.runtime_id+'","session_epoch":'+p.session_epoch.toString()+',"tenant_id":"'+p.tenant_id+'","wire_version":1}';
}
/// Only a trusted initializer should hold this key. The closure never returns it;
/// the Node runtime does not guarantee key-memory erasure.
function createMarkerSigner(seed){
    if(types.isProxy(seed)||!Buffer.isBuffer(seed)||Object.getPrototypeOf(seed)!==Buffer.prototype)fail();
    if(Reflect.apply(typedLength,seed,[])!==32)fail();
    const keys=Reflect.ownKeys(seed);if(keys.length!==32||keys.some((key,index)=>key!==String(index)))fail();
    const copy=Buffer.from(seed),der=Buffer.concat([PKCS8_PREFIX,copy]);let key;
    try {key=createPrivateKey({key:der,format:'der',type:'pkcs8'});} catch {fail();} finally {copy.fill(0);der.fill(0);}
    function signMarker(input){
        const bytes=Buffer.from(payload(input),'utf8');let signature;
        try {signature=sign(null,Buffer.concat([SIGN_DOMAIN,bytes]),key);} catch {fail();}
        const header='ac1.'+bytes.toString('base64url')+'.'+signature.toString('base64url');
        if(Buffer.byteLength(header,'ascii')>1024)fail();
        const markerDigest=createHash('sha256').update(WIRE_DOMAIN,'utf8').update(header,'ascii').digest('hex');
        return Object.freeze({header,markerDigest});
    }
    return Object.freeze({sign:signMarker});
}
module.exports=Object.freeze({createMarkerSigner});
