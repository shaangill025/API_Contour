'use strict';
const assert=require('node:assert/strict');
const {createPublicKey,verify}=require('node:crypto');
const {inspect,types}=require('node:util');
const fixture=require('../../../crates/contour-core/tests/fixtures/signed-causal-marker-openssl.json');
const {createMarkerSigner}=require('../../../collectors/nodered/error-integration/causal-marker');
const seed=Buffer.from(fixture.seed_hex,'hex');
const signer=createMarkerSigner(seed);
const claim=()=>({tenant_id:'f0000000-0000-4000-8000-000000000001',runtime_id:'fc000000-0000-4000-8000-000000000001',session_epoch:18446744073709551615n,product_leaf_sha256:'44'.repeat(32),root:'11'.repeat(16),activity:'22'.repeat(16),attempt:'33'.repeat(16)});
const signed=signer.sign(claim());
assert.equal(signed.header,fixture.header);assert.equal(signed.markerDigest,fixture.marker_digest);
assert(Object.isFrozen(signer));assert(Object.isFrozen(signed));assert.throws(()=>{signed.header='changed';},TypeError);
const [prefix,payload,signature]=signed.header.split('.');assert.equal(prefix,'ac1');
assert.equal(Buffer.from(payload,'base64url').toString('utf8'),fixture.payload);
const publicKey=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(fixture.public_key_hex,'hex')]),format:'der',type:'spki'});
assert(verify(null,Buffer.concat([Buffer.from('apicontour/causal-marker/1\n'),Buffer.from(payload,'base64url')]),publicKey,Buffer.from(signature,'base64url')));
const badSignature=Buffer.from(signature,'base64url');badSignature[0]^=1;
assert(!verify(null,Buffer.concat([Buffer.from('apicontour/causal-marker/1\n'),Buffer.from(payload,'base64url')]),publicKey,badSignature));
seed.fill(0);assert.equal(signer.sign(claim()).header,fixture.header); // signer captured a copy
for(const bad of [0,0n,-1n,2n**64n,Number.MAX_SAFE_INTEGER+1,1.5,NaN,'1',null]){
    const value=claim();value.session_epoch=bad;assert.throws(()=>signer.sign(value),/invalid causal marker/);
}
for(const good of [1,Number.MAX_SAFE_INTEGER,1n,18446744073709551615n]){
    const value=claim();value.session_epoch=good;const p=Buffer.from(signer.sign(value).header.split('.')[1],'base64url').toString('utf8');
    assert(p.includes('"session_epoch":'+BigInt(good).toString()+','));
}
for(const [field,value] of [['tenant_id','BAD'],['runtime_id','FC000000-0000-4000-8000-000000000001'],['product_leaf_sha256','A'.repeat(64)],['root','é'.repeat(32)],['activity','1'.repeat(31)],['attempt','0'.repeat(33)]]){
    const record=claim();record[field]=value;assert.throws(()=>signer.sign(record),/invalid causal marker/);
}
assert.throws(()=>signer.sign({...claim(),extra:'secret'}),/invalid causal marker/);
assert.throws(()=>signer.sign({...claim(),wire_version:1}),/invalid causal marker/);
let invocations=0;const accessor=claim();Object.defineProperty(accessor,'root',{get(){invocations++;throw Error('SECRET');},enumerable:true});
assert.throws(()=>signer.sign(accessor),/invalid causal marker/);assert.equal(invocations,0);
const symbolRecord=claim();Object.defineProperty(symbolRecord,Symbol('SECRET'),{get(){invocations++;throw Error('SECRET');}});assert.throws(()=>signer.sign(symbolRecord),/invalid causal marker/);assert.equal(invocations,0);
const handler={getPrototypeOf(){invocations++;throw Error('SECRET');},ownKeys(){invocations++;throw Error('SECRET');},get(){invocations++;throw Error('SECRET');}};
assert(types.isProxy(new Proxy({},handler)));assert.throws(()=>signer.sign(new Proxy(claim(),handler)),/invalid causal marker/);assert.equal(invocations,0);
const revoked=Proxy.revocable(claim(),handler);revoked.revoke();assert.throws(()=>signer.sign(revoked.proxy),/invalid causal marker/);assert.equal(invocations,0);
const poisonedSeed=Buffer.alloc(32);Object.defineProperty(poisonedSeed,'length',{get(){invocations++;throw Error('SECRET');}});
assert.throws(()=>createMarkerSigner(poisonedSeed),/invalid causal marker/);assert.equal(invocations,0);
for(const bad of [null,Buffer.alloc(31),'SECRET',new Uint8Array(32),new Proxy(Buffer.alloc(32),handler)])assert.throws(()=>createMarkerSigner(bad),/invalid causal marker/);
assert(!inspect(signer).includes(fixture.seed_hex));assert(!inspect(signer).includes(fixture.header));
console.log('PASS: synthetic OpenSSL/Node marker encoding and fail-closed data-only signing');
