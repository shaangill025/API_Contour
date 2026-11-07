'use strict';
// Manifest is authenticated by the checked parent's signed/DB-bound profile;
// parsing local bytes alone never establishes a qualified deployment.
const fs=require('node:fs'),crypto=require('node:crypto');
const SOURCES=Object.freeze([
 '/adapter/causal-codec.js',
 ...['causal-marker.js','flow-source-transform.js','lexical-bridge.js','node-source-transform.js','private-causal-exporter.js','private-causal-receipt.js','private-handoff.js','private-owner-permit.js','private-producer-runtime.js','private-wire-dispatch.js','private-wire-transform.js','wire-v2-loader.js'].map(x=>'/adapter/error-integration/'+x),
 ...['credential-check.js','lifecycle.js','live-main.js','live-profile.js','private-bootstrap.js','private-launch-proxy.js'].map(x=>'/adapter/live-integration/'+x)
].sort());
const MOUNTS=Object.freeze({ca:'/run/apicontour/live/ca.pem',export_cert:'/run/apicontour/live/export.pem',export_key:'/run/apicontour/live/export.key',product_cert:'/run/apicontour/live/product.pem',product_key:'/run/apicontour/live/product.key',server_cert:'/run/apicontour/live/server.pem',server_key:'/run/apicontour/live/server.key'});
const MANIFEST='/adapter/live-integration/manifest.json';
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
function read(file,max,privateFile=false){let fd;try{if(fs.realpathSync(file)!==file)throw Error('file path');fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);const s=fs.fstatSync(fd);if(!s.isFile()||s.nlink!==1||s.size<1||s.size>max||(privateFile&&(typeof process.getuid!=='function'||s.uid!==process.getuid()||(s.mode&0o777)!==0o600)))throw Error('file');const b=Buffer.alloc(s.size+1);let n=0;while(n<b.length){const count=fs.readSync(fd,b,n,b.length-n,null);if(!count)break;n+=count;}const after=fs.fstatSync(fd);if(n!==s.size||s.dev!==after.dev||s.ino!==after.ino||s.size!==after.size||s.mtimeMs!==after.mtimeMs||s.ctimeMs!==after.ctimeMs||fs.realpathSync(file)!==file)throw Error('file');return b.subarray(0,n);}finally{if(fd!==undefined)fs.closeSync(fd);}}
function record(x,keys){return !!x&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype&&Object.keys(x).join(',')===keys.join(',');}
function endpoint(x,path){try{const u=new URL(x);return u.protocol==='https:'&&!!u.hostname&&!u.username&&!u.password&&!u.search&&!u.hash&&u.pathname===path&&u.href===x;}catch(_){return false;}}
const TREES=Object.freeze({
 arm64:Object.freeze({sha256:'63560c3dbe43d22c9391d0ac2e46dbad1d428f5b8ea8418b2a9038322da2ad0b',files:8520,bytes:94313030,links:27}),
 x64:Object.freeze({sha256:'5f1c14c5e6a6cdbe9d841b5ee749058b05183fc9bee02e27f50ab0bd9a432e96',files:8520,bytes:94371739,links:27})
});
function relative(name){return typeof name==='string'&&name.length>0&&name.length<=4096&&!name.startsWith('/')&&!name.includes('\\')&&!name.includes('\0')&&name.split('/').every(x=>x&&x!=='.'&&x!=='..');}
function hashTreeFile(file,expected){
 let fd;try{fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);const before=fs.fstatSync(fd);if(!before.isFile()||before.size!==expected.bytes)throw Error('tree file');
 const digest=crypto.createHash('sha256'),buffer=Buffer.alloc(65536);let total=0;
 while(true){const n=fs.readSync(fd,buffer,0,Math.min(buffer.length,expected.bytes-total+1),null);if(!n)break;total+=n;if(total>expected.bytes)throw Error('tree growth');digest.update(buffer.subarray(0,n));}
 const after=fs.fstatSync(fd);if(total!==expected.bytes||before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs||digest.digest('hex')!==expected.sha256)throw Error('tree file');return total;
 }finally{if(fd!==undefined)fs.closeSync(fd);}
}
function validateTree(root,m,limits){
 if(!m||m.root!==root||m.node!=='24.22.1'||!m.files||!m.symlinks||Array.isArray(m.files)||Array.isArray(m.symlinks)||Object.getPrototypeOf(m.files)!==Object.prototype||Object.getPrototypeOf(m.symlinks)!==Object.prototype||m.file_count!==limits.files||m.total_bytes!==limits.bytes||Object.keys(m.files).length!==limits.files||Object.keys(m.symlinks).length!==limits.links||fs.realpathSync(root)!==root)throw Error('tree manifest');
 const dirs=new Map([['',new Map()]]);
 function insert(name,kind){if(!relative(name))throw Error('tree path');const parts=name.split('/');let parent='';for(let i=0;i<parts.length;i++){const child=parts[i],last=i===parts.length-1,entry=dirs.get(parent),type=last?kind:'dir',prior=entry.get(child);if(prior&&prior!==type)throw Error('tree path');entry.set(child,type);if(!last){parent=parent?parent+'/'+child:child;if(!dirs.has(parent))dirs.set(parent,new Map());}}}
 for(const [name,e] of Object.entries(m.files)){if(!e||!Number.isSafeInteger(e.bytes)||e.bytes<0||e.bytes>limits.bytes||!/^([0-9a-f]{64})$/.test(e.sha256)||Object.keys(e).sort().join(',')!=='bytes,sha256')throw Error('tree entry');insert(name,'file');}
 for(const [name,target] of Object.entries(m.symlinks)){if(typeof target!=='string'||target.length>4096||!target||target.includes('\0'))throw Error('tree link');insert(name,'link');}
 let total=0,files=0,links=0;
 for(const [relativeDir,children] of dirs){const dir=root+(relativeDir?'/'+relativeDir:''),stream=fs.opendirSync(dir);let count=0;try{let item;while((item=stream.readSync())!==null){count++;if(count>children.size||!children.has(item.name))throw Error('tree unexpected entry');const type=children.get(item.name),rel=relativeDir?relativeDir+'/'+item.name:item.name,file=root+'/'+rel;
  if(type==='dir'){if(!item.isDirectory()||item.isSymbolicLink())throw Error('tree directory');}
  else if(type==='file'){if(!item.isFile()||item.isSymbolicLink())throw Error('tree file');total+=hashTreeFile(file,m.files[rel]);files++;if(total>limits.bytes)throw Error('tree size');}
  else {if(!item.isSymbolicLink()||fs.readlinkSync(file)!==m.symlinks[rel])throw Error('tree link');const resolved=fs.realpathSync(file);if(!resolved.startsWith(root+'/')||!Object.hasOwn(m.files,resolved.slice(root.length+1)))throw Error('tree link');links++;}
 }if(count!==children.size)throw Error('tree missing entry');}finally{stream.closeSync();}}
 if(files!==limits.files||links!==limits.links||total!==limits.bytes)throw Error('tree mismatch');return true;
}
function validateManifest(manifestBytes,descriptor){
 if(hash(manifestBytes)!==descriptor.manifest_sha256)throw Error('manifest digest');
 let m;try{m=JSON.parse(manifestBytes.toString('utf8'));}catch(_){throw Error('manifest');}
 if(!record(m,['arch_trees','capture','env','export_endpoint','files','flow_sha256','image','mounts','node','nodes','product_endpoint','profile_id','profile_name','version'])||!Buffer.from(JSON.stringify(m)).equals(manifestBytes)||m.version!==1||m.profile_id!=='00000000-0000-4000-8000-000000000503'||m.profile_id!==descriptor.profile_id||m.profile_name!=='nodered_5_0_9_wire_v1'||m.node!=='24.22.1'||typeof m.image!=='string'||m.image!=='docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963')throw Error('manifest');
 if(!record(m.mounts,Object.keys(MOUNTS))||JSON.stringify(m.mounts)!==JSON.stringify(MOUNTS)||!record(m.capture,['method','node','url'])||JSON.stringify(m.capture)!=='{"method":"POST","node":"in","url":"/run"}'||!endpoint(m.export_endpoint,'/v1/causal-events')||new URL(m.export_endpoint).hostname!=='causal-ingress'||m.product_endpoint!=='https://pilot-gateway:9443/pilot'||!/^[0-9a-f]{64}$/.test(m.flow_sha256))throw Error('manifest policy');
 if(!Array.isArray(m.nodes)||m.nodes.length<2||m.nodes.length>64||m.nodes.some(x=>!Array.isArray(x)||x.length!==2||x.some(y=>typeof y!=='string'||!y||y.length>64))||new Set(m.nodes.map(x=>x[0])).size!==m.nodes.length||!m.nodes.some(x=>x[0]==='in'&&x[1]==='http in')||!m.nodes.some(x=>x[0]==='request'&&x[1]==='http request'))throw Error('node policy');
 return m;
}
function load(descriptor){
 const m=validateManifest(read(MANIFEST,1048576),descriptor);
 if(!record(m.files,SOURCES)||SOURCES.some(p=>!/^[0-9a-f]{64}$/.test(m.files[p])||hash(read(p,4194304))!==m.files[p]))throw Error('source mismatch');
 if(!record(m.arch_trees,['arm64','x64'])||!['arm64','x64'].includes(process.arch))throw Error('architecture');
 for(const arch of ['arm64','x64']){const entry=m.arch_trees[arch];if(!record(entry,['path','sha256'])||entry.path!=='/adapter/live-integration/tree-'+arch+'.json'||entry.sha256!==TREES[arch].sha256)throw Error('tree policy');}
 const tree=m.arch_trees[process.arch],limits=TREES[process.arch];
 const bytes=read(tree.path,8388608);if(hash(bytes)!==tree.sha256)throw Error('tree mismatch');let treeManifest;try{treeManifest=JSON.parse(bytes.toString('utf8'));}catch(_){throw Error('tree');}
 validateTree('/usr/src/node-red/node_modules',treeManifest,limits);
 if(process.versions.node!==m.node||process.execPath!=='/usr/local/bin/node'||JSON.stringify(process.argv)!=='["/usr/local/bin/node","/adapter/live-integration/live-main.js"]'||process.execArgv.length)throw Error('launch mismatch');
 const allowed=['FLOWS','HOME','HOSTNAME','LANG','NODE_PATH','NODE_RED_VERSION','NODE_VERSION','PATH','TZ','YARN_VERSION'];
 if(!record(m.env,allowed)||Object.keys(process.env).sort().join(',')!==allowed.join(',')||allowed.some(k=>typeof m.env[k]!=='string'||process.env[k]!==m.env[k])||process.env.FLOWS!=='flows.json'||process.env.HOME!=='/data'||process.env.NODE_PATH!=='/usr/src/node-red/node_modules'||process.env.NODE_VERSION!==m.node||process.env.NODE_RED_VERSION!=='v5.0.9')throw Error('launch mismatch');
 const material={};for(const [name,path] of Object.entries(MOUNTS))material[name]=read(path,65536,name.endsWith('_key'));
 if(hash(material.ca)!==descriptor.ca_sha256)throw Error('CA mismatch');
 if(hash(read('/data/flows.json',4194304))!==m.flow_sha256)throw Error('flow mismatch');
 return {manifest:m,material,treeManifest};
}
module.exports=Object.freeze({load,read,validateManifest,validateTree});
