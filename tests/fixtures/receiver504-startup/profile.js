'use strict';
// Offline source/data checks only: no pinned Node-RED runtime or issuer.
const assert=require('node:assert/strict'),fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');
const profile=require('../../../collectors/nodered/receiver-integration/private-profile-504');
const file=path.join(__dirname,'../../../collectors/nodered/receiver-integration/manifest-504.json'),raw=fs.readFileSync(file),m=JSON.parse(raw);
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
const descriptor={profile_id:'00000000-0000-4000-8000-000000000504',artifact_sha256:m.artifact_sha256,manifest_sha256:digest(raw)};
assert.equal(profile.validateManifest(raw,descriptor).version,2);
for(const [name,expected] of Object.entries(m.files)){const relative=name.slice('/adapter/'.length);const local=path.join(__dirname,'../../../collectors/nodered',relative);assert.equal(digest(fs.readFileSync(local)),expected);}
for(const mutate of [x=>x.version=1,x=>x.profile_id='00000000-0000-4000-8000-000000000503',x=>x.node='24.22.1',x=>delete x.files[Object.keys(x.files)[0]],x=>x.files['/adapter/foreign.js']='0'.repeat(64),x=>x.mounts.evidence_key='/tmp/key',x=>x.arch_trees.x64.sha256='0'.repeat(64),x=>x.artifact_sha256='0'.repeat(64)]){
 const copy=structuredClone(m);mutate(copy);const body=Buffer.from(JSON.stringify(copy)),d={...descriptor,manifest_sha256:digest(body)};assert.throws(()=>profile.validateManifest(body,d));
}
const duplicate=Buffer.from(raw.toString().replace('"version":2','"version":2,"version":2'));assert.throws(()=>profile.validateManifest(duplicate,{...descriptor,manifest_sha256:digest(duplicate)}));
assert.throws(()=>profile.validateManifest(raw,{...descriptor,manifest_sha256:'0'.repeat(64)}));
assert.throws(()=>profile.binarySpec('other'));
assert.match(fs.readFileSync(path.join(__dirname,'../../../collectors/nodered/receiver-integration/live-main-504.js'),'utf8'),/module\.exports=Object\.freeze\(\{\}\)/);
console.log('receiver 504 source profile offline tests passed');
