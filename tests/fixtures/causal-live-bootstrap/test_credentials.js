'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const check=require('../../../collectors/nodered/live-integration/credential-check').check;
const seed=Buffer.alloc(32,7),prefix=Buffer.from('302e020100300506032b657004220420','hex');
function pair(){return crypto.generateKeyPairSync('ed25519');}
function pem(pair){return pair.privateKey.export({type:'pkcs8',format:'pem'});}
function markerPair(){const privateKey=crypto.createPrivateKey({key:Buffer.concat([prefix,seed]),format:'der',type:'pkcs8'});return {privateKey,publicKey:crypto.createPublicKey(privateKey)};}
function digest(bytes){return crypto.createHash('sha256').update(bytes).digest('hex');}
function fixture(product,exporter){const pc=Buffer.from('synthetic-product-certificate'),ec=Buffer.from('synthetic-export-certificate');const marker=markerPair().publicKey.export({type:'spki',format:'der'}).subarray(12).toString('hex');return {product:{cert:pc,key:Buffer.from(pem(product))},exporter:{cert:ec,key:Buffer.from(pem(exporter))},expected:{marker_public:marker,product_leaf:digest(pc),export_leaf:digest(ec)},map:new Map([[pc.toString(),product.publicKey],[ec.toString(),exporter.publicKey]])};}
function fake(t,f){t.mock.method(crypto,'X509Certificate',function(bytes){const key=f.map.get(bytes.toString());if(!key)throw Error('bad certificate');return {publicKey:key,raw:bytes};});}
test('independent matching synthetic SPKIs pass; cert key mismatch fails',t=>{const p=pair(),e=pair(),f=fixture(p,e);fake(t,f);assert.equal(check(seed,f.product,f.exporter,f.expected),true);f.product.key=Buffer.from(pem(e));assert.throws(()=>check(seed,f.product,f.exporter,f.expected));});
test('every pairwise key equality is refused',async t=>{const m=markerPair();for(const [p,e] of [[m,pair()],[pair(),m],(()=>{const k=pair();return [k,k];})()])await t.test('equal pair',t=>{const f=fixture(p,e);fake(t,f);assert.throws(()=>check(seed,f.product,f.exporter,f.expected));});});
test('reported marker and leaf bytes must equal inspected material',t=>{const f=fixture(pair(),pair());fake(t,f);for(const field of ['marker_public','product_leaf','export_leaf'])assert.throws(()=>check(seed,f.product,f.exporter,{...f.expected,[field]:'00'.repeat(32)}));});
test('server certificate matches private key, selected leaf and configured CA',t=>{
 const p=pair(),other=pair(),cert=Buffer.from('synthetic-server-certificate'),ca=Buffer.from('synthetic-ca-certificate');let validSignature=true;
 const issuer={ca:true,publicKey:other.publicKey};
 t.mock.method(crypto,'X509Certificate',function(bytes){if(bytes.equals(ca))return issuer;if(bytes.equals(cert))return {publicKey:p.publicKey,raw:cert,checkIssued:x=>x===issuer,verify:x=>validSignature&&x===issuer.publicKey};throw Error('invalid certificate');});
 const server=require('../../../collectors/nodered/live-integration/credential-check');
 assert.equal(server.checkServer(cert,Buffer.from(pem(p)),ca,digest(cert)),true);
 assert.throws(()=>server.checkServer(cert,Buffer.from(pem(other)),ca,digest(cert)));
 assert.throws(()=>server.checkServer(cert,Buffer.from(pem(p)),ca,'00'.repeat(32)));
 validSignature=false;assert.throws(()=>server.checkServer(cert,Buffer.from(pem(p)),ca,digest(cert)));
});
