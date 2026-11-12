'use strict';
// Offline data validation only; no real runtime/tree hash or deployment proof.
const assert=require('node:assert/strict'),fs=require('node:fs');
const profile=require('../../../collectors/nodered/receiver-integration/private-profile-504');
const bytes=fs.readFileSync(__dirname+'/../../../collectors/nodered/receiver-integration/artifact-504.json');
assert.equal(profile.validateArtifact(bytes),true);
const artifact=JSON.parse(bytes);
for(const mutate of [x=>x.base_index='0'.repeat(64),x=>x.donor_index='0'.repeat(64),x=>x.recipe_sha256='0'.repeat(64),x=>x.binary.arm64.sha256='0'.repeat(64),x=>x.binary.x64.size++,x=>x.binary.x64.mode=384,x=>x.binary.x64.uid=1,x=>x.binary.x64.gid=1,x=>x.binary.x64.path='/tmp/node',x=>x.node='24.22.1',x=>x.node_red='5.0.8',x=>x.binary.riscv64={}]){
 const v=structuredClone(artifact);mutate(v);assert.throws(()=>profile.validateArtifact(Buffer.from(JSON.stringify(v))));
}
assert.throws(()=>profile.validateArtifact(Buffer.from(bytes.toString()+'\n')));
assert.throws(()=>profile.validateArtifact(Buffer.from(bytes.toString().replace('"artifact_version":1','"artifact_version":1,"artifact_version":1'))));
assert.throws(()=>profile.validateArtifact('{}'));assert.throws(()=>profile.binarySpec('riscv64'));
assert.deepEqual(profile.binarySpec('arm64'),{size:128247648,sha256:'f6a453bcbfd0d866cabbc7b02fa5b173931ca08ddbfdca866fe71253b8b583d5'});
assert.deepEqual(profile.binarySpec('x64'),{size:132502712,sha256:'7e027679034844bb06f53bead732673553cf5bb0de424bbbd257b35c989d34b0'});
assert(Object.isFrozen(profile.binarySpec('x64')));
assert.throws(()=>profile.verifyRuntime());
// Synthetic metadata and bounded empty reads exercise failure/cleanup only.
const saved={arch:Object.getOwnPropertyDescriptor(process,'arch'),execPath:Object.getOwnPropertyDescriptor(process,'execPath'),node:Object.getOwnPropertyDescriptor(process.versions,'node')};
const methods=['realpathSync','lstatSync','openSync','fstatSync','readSync','closeSync'];const old=Object.fromEntries(methods.map(k=>[k,fs[k]]));
try{
 Object.defineProperty(process,'arch',{...saved.arch,value:'x64'});Object.defineProperty(process,'execPath',{...saved.execPath,value:'/usr/local/bin/node'});Object.defineProperty(process.versions,'node',{...saved.node,value:'24.22.3'});
 const good={isFile:()=>true,uid:0,gid:0,mode:0o100755,nlink:1,size:132502712,dev:1,ino:2,mtimeMs:3,ctimeMs:4};
 for(const mutation of ['owner','mode','size','drift','short']){
  let closed=0,calls=0;const path={...good};if(mutation==='owner')path.uid=1;if(mutation==='mode')path.mode=0o100700;if(mutation==='size')path.size--;
  fs.realpathSync=()=>'/usr/local/bin/node';fs.lstatSync=()=>path;fs.openSync=()=>9;
  fs.fstatSync=()=>{calls++;return mutation==='drift'&&calls===2?{...good,ino:3}:good;};fs.readSync=()=>0;fs.closeSync=()=>{closed++;};
  assert.throws(()=>profile.verifyRuntime());assert.equal(closed,['drift','short'].includes(mutation)?1:0);
 }
}finally{
 Object.defineProperty(process,'arch',saved.arch);Object.defineProperty(process,'execPath',saved.execPath);Object.defineProperty(process.versions,'node',saved.node);for(const k of methods)fs[k]=old[k];
}
console.log('receiver 504 partial artifact data tests passed');
