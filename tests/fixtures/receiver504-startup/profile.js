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
// Exercise the actual closed environment predicates, with synthetic process state.
{
 const vm=require('node:vm'),dir=path.join(__dirname,'../../../collectors/nodered/receiver-integration');
 const profileSource=fs.readFileSync(path.join(dir,'private-profile-504.js'),'utf8');
 const profileGuard=profileSource.match(/const allowed=\[[^\n]+\];\n if\([^\n]+throw Error\('launch mismatch'\);/)[0];
 const proxySource=fs.readFileSync(path.join(dir,'private-launch-proxy-504.js'),'utf8');
 const proxyGuard=proxySource.match(/const allowed=\[[^\n]+\];\n if\([^\n]+\{process.exitCode=1;return;\}/)[0];
 function checks(env){const process={env,stdin:{},stdout:{},stderr:{},execPath:'/usr/local/bin/node',argv:['/usr/local/bin/node','/adapter/receiver-integration/private-launch-proxy-504.js'],execArgv:[]};let profileOk=true;try{vm.runInNewContext(`(function(){${profileGuard}})()`,{process,m,record:(x,keys)=>Object.keys(x).join(',')===keys.join(',')});}catch(_){profileOk=false;}vm.runInNewContext(`(function(){${proxyGuard}})()`,{process});return [profileOk,process.exitCode!==1];}
 const env={...m.env};assert.deepEqual(checks(env),[true,true]);
 const oldKeys=Object.keys(env).filter(k=>k!=='UV_USE_IO_URING');assert.notEqual(Object.keys(env).sort().join(','),oldKeys.sort().join(','));
 for(const bad of [{...env,UV_USE_IO_URING:'1'},Object.fromEntries(Object.entries(env).filter(([k])=>k!=='UV_USE_IO_URING')),{...env,UNKNOWN_EXTRA:'0'}])assert.deepEqual(checks(bad),[false,false]);
}
