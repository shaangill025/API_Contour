'use strict';
// INACTIVE v2 synthetic fixture profile. Owner verifies the image, mounts,
// this profile and manifest independently. No registry enrollment is implied.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const ID='apicontour/nodered-causal-wire-v2-inactive-0502';
const IMAGE='docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963';
const MANIFESTS=Object.freeze({
 arm64:Object.freeze({path:'/adapter/error-integration/wire-v2-image-manifest.json',sha:'63560c3dbe43d22c9391d0ac2e46dbad1d428f5b8ea8418b2a9038322da2ad0b',count:8520,bytes:94313030,links:27}),
 x64:Object.freeze({path:'/adapter/error-integration/wire-v2-image-manifest-x64.json',sha:'5f1c14c5e6a6cdbe9d841b5ee749058b05183fc9bee02e27f50ab0bd9a432e96',count:8520,bytes:94371739,links:27})
});
function selectManifest(arch){return Object.hasOwn(MANIFESTS,arch)?MANIFESTS[arch]:null;}
const FILES=Object.freeze({
'/adapter/error-integration/wire-v2-bootstrap.js':'07a3f32e0c5fda49c301ca0f35e792da2fb4d3bbb61dbb792ae7d067ff0a1178',
'/adapter/error-integration/wire-v2-loader.js':'d8bb00e3e603d5b01cbe846eb55abb92b7cc6ad9fde2ffcf3ab5685b47f6e7ba',
'/adapter/error-integration/private-producer-runtime.js':'f8019faa36e7fd9365e9e1fc1273009fde5f343a5db5ca226f803dd78a8c60b3',
'/adapter/error-integration/private-causal-exporter.js':'eb1eb8005bf0364366543d33a7f07511739cdd0d29a830d90f4c45e06fa15f4a',
'/adapter/error-integration/private-causal-receipt.js':'8a653420a51fcb2204aef1df708669d2353de88e382713f5bab7c6a4443f5a09',
'/adapter/error-integration/private-handoff.js':'728867508798fe956ef76894965fbef7ddf64056d42154121f50d59423a74fd8',
'/adapter/error-integration/private-wire-dispatch.js':'01d1f89c26dce2f7aa96425162cb41d49edb81883443f228a6f8fcaa60c9e1d1',
'/adapter/error-integration/private-wire-transform.js':'63bda9107335a903d112c33bae600d04e5f3b0fb777d3b41d53c38ebeef7f6d9',
'/adapter/error-integration/causal-marker.js':'75bde9e2ed40ab0089775f8ba2d3ce6c532eaeb8d235370ac960d9405d205edb',
'/adapter/error-integration/node-source-transform.js':'62c41177fb9a7645627556baeae7dcd960910586e5b3cb44835427763b1fd0f6',
'/adapter/error-integration/flow-source-transform.js':'4d089d255ef44c3e296d6dff7657013db73db309c0ea5cfa728ec938e63e5819',
'/adapter/error-integration/lexical-bridge.js':'ec5d7180dd03f0502fa6ab92d2bf07cfedb7982f0d10266d741028900c427d51',
'/adapter/causal-codec.js':'60fc474e6fad91833146049d0f704519c3b9dea256730100393761f62cd94b89',
'/fixture/flows-wire-v2.json':'88bae4823fb1665bb2ca5d7fe923e6b255430bd10eacac5bbf1b8ec4829068d3',
'/fixture/image-wire-v2-fixture.js':'e5b9bb99577ccdd10a76fabb4fb44821726a0142cd52f1b78f75dda6db421748'});
const INGRESS_POINT=Object.freeze({node:'in',method:'POST',url:'/run'});
const ENV=new Set(['PATH','HOME','HOSTNAME','LANG','TZ','NODE_OPTIONS','NODE_PATH','NODE_RED_VERSION','NODE_VERSION','FLOWS','YARN_VERSION']);
function validateLaunch(e){
 if(e.version!=='24.22.1'||e.executable!=='/usr/local/bin/node'||JSON.stringify(e.argv)!==JSON.stringify(['/usr/local/bin/node','/fixture/image-wire-v2-fixture.js'])||JSON.stringify(e.execArgv)!==JSON.stringify(['--require','/adapter/error-integration/wire-v2-bootstrap.js']))return false;
 const x=e.env;if(!x||Object.keys(x).some(k=>!ENV.has(k))||x.HOME!=='/data'||x.HOSTNAME!=='causal-wire-v2'||x.LANG!=='C.UTF-8'||x.TZ!=='UTC'||x.NODE_OPTIONS!==''||x.NODE_PATH!=='/usr/src/node-red/node_modules'||x.NODE_VERSION!=='24.22.1'||x.NODE_RED_VERSION!=='v5.0.9'||x.FLOWS!=='flows.json'||x.YARN_VERSION!=='1.22.22'||x.PATH!=='/usr/src/node-red/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')return false;
 return Array.isArray(e.cached)&&e.cached.every(x=>x==='/adapter/error-integration/wire-v2-bootstrap.js'||x==='/adapter/error-integration/wire-v2-profile.js');
}
function readRegular(file,max){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const stat=fs.fstatSync(fd);if(!stat.isFile()||stat.size>max)throw Error('source');return fs.readFileSync(fd);}finally{fs.closeSync(fd);}}
function hash(bytes){return crypto.createHash('sha256').update(bytes).digest('hex');}
// One bounded startup scan of the complete immutable image module tree. No
// symlink traversal, source code output, credentials or persistent copy.
function verifyTree(root,manifest){
 try{
  if(fs.realpathSync(root)!==root||manifest.node!=='24.22.1'||manifest.file_count!==Object.keys(manifest.files).length)return false;
  const foundFiles=new Set(),foundLinks=new Set();let total=0;const todo=[''];
  while(todo.length){const relative=todo.pop(),directory=path.join(root,relative);for(const name of fs.readdirSync(directory)){
   const rel=relative?relative+'/'+name:name,file=path.join(root,rel),stat=fs.lstatSync(file);
   if(stat.isDirectory()){todo.push(rel);continue;}
   if(stat.isSymbolicLink()){
    if(!Object.hasOwn(manifest.symlinks,rel)||fs.readlinkSync(file)!==manifest.symlinks[rel])return false;
    const resolved=fs.realpathSync(file);if(!resolved.startsWith(root+'/')||!Object.hasOwn(manifest.files,resolved.slice(root.length+1)))return false;
    foundLinks.add(rel);continue;
   }
   if(!stat.isFile()||!Object.hasOwn(manifest.files,rel))return false;const expected=manifest.files[rel];
   if(stat.size!==expected.bytes||hash(readRegular(file,expected.bytes))!==expected.sha256)return false;
   total+=stat.size;if(total>manifest.total_bytes)return false;foundFiles.add(rel);
  }}
  return foundFiles.size===manifest.file_count&&foundLinks.size===Object.keys(manifest.symlinks).length&&total===manifest.total_bytes;
 }catch(_){return false;}
}
function validateManifest(bytes,arch){try{
 const pin=selectManifest(arch);if(!pin||!Buffer.isBuffer(bytes)||hash(bytes)!==pin.sha)return null;
 const m=JSON.parse(bytes);if(m.root!=='/usr/src/node-red/node_modules'||m.node!=='24.22.1'||m.file_count!==pin.count||m.total_bytes!==pin.bytes||Object.keys(m.files).length!==pin.count||Object.keys(m.symlinks).length!==pin.links)return null;
 return m;
}catch(_){return null;}}
function verifySources(){try{
 const pin=selectManifest(process.arch);if(!pin)return false;
 const m=validateManifest(readRegular(pin.path,8*1024*1024),process.arch);if(!m)return false;
 for(const [file,digest] of Object.entries(FILES))if(hash(readRegular(file,4*1024*1024))!==digest)return false;
 return verifyTree(m.root,m);
}catch(_){return false;}}
module.exports=Object.freeze({ID,IMAGE,FILES,INGRESS_POINT,validateLaunch,verifySources,verifyTree,selectManifest,validateManifest});
