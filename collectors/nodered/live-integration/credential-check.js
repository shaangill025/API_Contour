'use strict';
const crypto=require('node:crypto');
const ED25519_PREFIX=Buffer.from('302e020100300506032b657004220420','hex');
function spki(key){return crypto.createPublicKey(key).export({type:'spki',format:'der'});}
function check(seed,product,exporter,expected){
 if(!Buffer.isBuffer(seed)||seed.length!==32||![product.cert,product.key,exporter.cert,exporter.key].every(x=>Buffer.isBuffer(x)&&x.length>0&&x.length<=65536))throw Error('credential input');
 let der,key;try{
  der=Buffer.concat([ED25519_PREFIX,seed]);key=crypto.createPrivateKey({key:der,format:'der',type:'pkcs8'});
  const marker=spki(key),pc=new crypto.X509Certificate(product.cert),ec=new crypto.X509Certificate(exporter.cert);
  const ps=pc.publicKey.export({type:'spki',format:'der'}),es=ec.publicKey.export({type:'spki',format:'der'});
  if(!ps.equals(spki(crypto.createPrivateKey(product.key)))||!es.equals(spki(crypto.createPrivateKey(exporter.key)))||marker.equals(ps)||marker.equals(es)||ps.equals(es))throw Error('credential mismatch');
  if(marker.length!==44||!marker.subarray(0,12).equals(Buffer.from('302a300506032b6570032100','hex'))||marker.subarray(12).toString('hex')!==expected.marker_public||crypto.createHash('sha256').update(pc.raw).digest('hex')!==expected.product_leaf||crypto.createHash('sha256').update(ec.raw).digest('hex')!==expected.export_leaf)throw Error('credential mismatch');
  return true;
 }catch(_){throw Error('credential mismatch');}finally{if(der)der.fill(0);}
}
function checkServer(cert,key,ca,expectedLeaf){
 try{const server=new crypto.X509Certificate(cert),issuer=new crypto.X509Certificate(ca),actual=server.publicKey.export({type:'spki',format:'der'});if(!actual.equals(spki(crypto.createPrivateKey(key)))||!issuer.ca||!server.checkIssued(issuer)||!server.verify(issuer.publicKey)||crypto.createHash('sha256').update(server.raw).digest('hex')!==expectedLeaf)throw Error('server credential');return true;}catch(_){throw Error('server credential');}
}
module.exports=Object.freeze({check,checkServer});
