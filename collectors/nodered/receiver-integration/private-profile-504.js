'use strict';
// Partial source-only artifact checker: no manifest, deployment or authority.
const fs=require('node:fs'),crypto=require('node:crypto');
const ARTIFACT_SHA='707e7b359fb757c668d8a22c999e067556b5f2a785f9c3333c12fca7debfa660';
const NODE='/usr/local/bin/node';
const BINARIES=Object.freeze({
 arm64:Object.freeze({size:128247648,sha256:'f6a453bcbfd0d866cabbc7b02fa5b173931ca08ddbfdca866fe71253b8b583d5'}),
 x64:Object.freeze({size:132502712,sha256:'7e027679034844bb06f53bead732673553cf5bb0de424bbbd257b35c989d34b0'})
});
function validateArtifact(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>4096||crypto.createHash('sha256').update(bytes).digest('hex')!==ARTIFACT_SHA)throw Error('artifact mismatch');
 let artifact;try{artifact=JSON.parse(bytes.toString('utf8'));}catch(_){throw Error('artifact mismatch');}
 if(!Buffer.from(JSON.stringify(artifact)).equals(bytes))throw Error('artifact mismatch');
 return true;
}
function binarySpec(arch){if(!Object.hasOwn(BINARIES,arch))throw Error('unsupported architecture');return BINARIES[arch];}
function same(a,b){return a.dev===b.dev&&a.ino===b.ino&&a.mode===b.mode&&a.uid===b.uid&&a.gid===b.gid&&a.nlink===b.nlink&&a.size===b.size&&a.mtimeMs===b.mtimeMs&&a.ctimeMs===b.ctimeMs;}
function validStat(s,expected){return s.isFile()&&s.uid===0&&s.gid===0&&(s.mode&0o7777)===0o755&&s.nlink===1&&s.size===expected.size;}
function verifyRuntime(){
 const expected=binarySpec(process.arch);
 if(process.versions.node!=='24.22.3'||process.execPath!==NODE||process.execArgv.length!==0||fs.realpathSync(NODE)!==NODE)throw Error('runtime mismatch');
 let fd;try{
  const pathBefore=fs.lstatSync(NODE);if(!validStat(pathBefore,expected))throw Error('runtime mismatch');
  fd=fs.openSync(NODE,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  const before=fs.fstatSync(fd);if(!validStat(before,expected)||!same(pathBefore,before))throw Error('runtime mismatch');
  const hash=crypto.createHash('sha256'),buffer=Buffer.alloc(65536);let total=0;
  for(;;){const n=fs.readSync(fd,buffer,0,Math.min(buffer.length,expected.size-total+1),null);if(!n)break;total+=n;if(total>expected.size)throw Error('runtime mismatch');hash.update(buffer.subarray(0,n));}
  const after=fs.fstatSync(fd),pathAfter=fs.lstatSync(NODE);
  if(total!==expected.size||!same(before,after)||!same(before,pathAfter)||fs.realpathSync(NODE)!==NODE||hash.digest('hex')!==expected.sha256)throw Error('runtime mismatch');
  return true;
 }finally{if(fd!==undefined)fs.closeSync(fd);}
}
const shared=require('../live-integration/live-profile');
const SOURCES=Object.freeze([
 '/adapter/causal-codec.js','/adapter/causal-evidence-codec.js',
 ...['causal-marker.js','flow-source-transform.js','lexical-bridge.js','node-source-transform.js','private-causal-exporter.js','private-causal-receipt.js','private-handoff.js','private-wire-dispatch.js','private-wire-transform.js','wire-v2-loader.js'].map(x=>'/adapter/error-integration/'+x),
 ...['credential-check.js','lifecycle.js','live-profile.js'].map(x=>'/adapter/live-integration/'+x),
 ...['live-main-504.js','private-bootstrap-504.js','private-incoming.js','private-launch-proxy-504.js','private-owner-permit-504.js','private-producer-runtime.js','private-profile-504.js','private-root-handoff.js'].map(x=>'/adapter/receiver-integration/'+x)
].sort());
const MOUNTS=Object.freeze({ca:'/run/apicontour/live/ca.pem',evidence_cert:'/run/apicontour/live/evidence.pem',evidence_key:'/run/apicontour/live/evidence.key',export_cert:'/run/apicontour/live/export.pem',export_key:'/run/apicontour/live/export.key',product_cert:'/run/apicontour/live/product.pem',product_key:'/run/apicontour/live/product.key',server_cert:'/run/apicontour/live/server.pem',server_key:'/run/apicontour/live/server.key'});
const TREES=Object.freeze({arm64:Object.freeze({sha256:'63560c3dbe43d22c9391d0ac2e46dbad1d428f5b8ea8418b2a9038322da2ad0b',files:8520,bytes:94313030,links:27}),x64:Object.freeze({sha256:'5f1c14c5e6a6cdbe9d841b5ee749058b05183fc9bee02e27f50ab0bd9a432e96',files:8520,bytes:94371739,links:27})});
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
function record(x,keys){return !!x&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype&&Object.keys(x).join(',')===keys.join(',');}
function validateManifest(bytes,d){
 if(!Buffer.isBuffer(bytes)||hash(bytes)!==d.manifest_sha256)throw Error('manifest mismatch');
 let m;try{m=JSON.parse(bytes.toString('utf8'));}catch(_){throw Error('manifest mismatch');}
 if(!record(m,['arch_trees','artifact_sha256','capture','env','export_endpoint','files','flow_sha256','mounts','node','nodes','product_endpoint','profile_id','profile_name','version'])||!Buffer.from(JSON.stringify(m)).equals(bytes)||m.version!==2||m.profile_id!=='00000000-0000-4000-8000-000000000504'||m.profile_id!==d.profile_id||m.profile_name!=='nodered_5_0_9_receiver_v1'||m.node!=='24.22.3'||m.artifact_sha256!==ARTIFACT_SHA||m.artifact_sha256!==d.artifact_sha256)throw Error('manifest mismatch');
 if(!record(m.mounts,Object.keys(MOUNTS))||JSON.stringify(m.mounts)!==JSON.stringify(MOUNTS)||!record(m.capture,['method','node','url'])||JSON.stringify(m.capture)!=='{"method":"POST","node":"in","url":"/run"}'||m.export_endpoint!=='https://causal-ingress:8443/v1/causal-events'||m.product_endpoint!=='https://pilot-gateway:9443/pilot'||!(/^[0-9a-f]{64}(?![\s\S])/.test(m.flow_sha256)))throw Error('manifest policy');
 if(!Array.isArray(m.nodes)||m.nodes.length<2||m.nodes.length>64||m.nodes.some(x=>!Array.isArray(x)||x.length!==2||x.some(y=>typeof y!=='string'||!y||y.length>64))||new Set(m.nodes.map(x=>x[0])).size!==m.nodes.length||!m.nodes.some(x=>x[0]==='in'&&x[1]==='http in')||!m.nodes.some(x=>x[0]==='request'&&x[1]==='http request'))throw Error('node policy');
 if(!record(m.files,SOURCES)||SOURCES.some(p=>typeof m.files[p]!=='string'||!/^[0-9a-f]{64}(?![\s\S])/.test(m.files[p])))throw Error('source inventory');
 if(!record(m.arch_trees,['arm64','x64']))throw Error('architecture');
 for(const arch of ['arm64','x64']){const t=m.arch_trees[arch];if(!record(t,['path','sha256'])||t.path!=='/adapter/live-integration/tree-'+arch+'.json'||t.sha256!==TREES[arch].sha256)throw Error('tree policy');}
 return m;
}
function load(d){
 verifyRuntime();
 const read=shared.read,m=validateManifest(read('/adapter/receiver-integration/manifest-504.json',1048576),d);
 validateArtifact(read('/adapter/receiver-integration/artifact-504.json',4096));
 if(SOURCES.some(p=>hash(read(p,4194304))!==m.files[p]))throw Error('source mismatch');
 const tree=m.arch_trees[process.arch],limits=TREES[process.arch];if(!tree||!limits)throw Error('architecture');
 const treeBytes=read(tree.path,8388608);if(hash(treeBytes)!==tree.sha256)throw Error('tree mismatch');let treeManifest;try{treeManifest=JSON.parse(treeBytes.toString('utf8'));}catch(_){throw Error('tree');}
 shared.validateTree('/usr/src/node-red/node_modules',treeManifest,limits);
 if(process.execPath!==NODE||JSON.stringify(process.argv)!=='["/usr/local/bin/node","/adapter/receiver-integration/live-main-504.js"]'||process.execArgv.length)throw Error('launch mismatch');
 const allowed=['FLOWS','HOME','HOSTNAME','LANG','NODE_PATH','NODE_RED_VERSION','NODE_VERSION','PATH','TZ','YARN_VERSION'];
 if(!record(m.env,allowed)||Object.keys(process.env).sort().join(',')!==allowed.join(',')||allowed.some(k=>typeof m.env[k]!=='string'||process.env[k]!==m.env[k])||process.env.FLOWS!=='flows.json'||process.env.HOME!=='/data'||process.env.NODE_PATH!=='/usr/src/node-red/node_modules'||process.env.NODE_VERSION!==m.node||process.env.NODE_RED_VERSION!=='v5.0.9')throw Error('launch mismatch');
 const material={};for(const [name,path] of Object.entries(MOUNTS))material[name]=read(path,65536,name.endsWith('_key'));
 if(hash(material.ca)!==d.ca_sha256||hash(read('/data/flows.json',4194304))!==m.flow_sha256)throw Error('material mismatch');
 return {manifest:m,material,treeManifest};
}
module.exports=Object.freeze({validateArtifact,binarySpec,verifyRuntime,validateManifest,load,read:shared.read});
