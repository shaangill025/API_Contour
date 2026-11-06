'use strict';
// Synthetic filesystem/source guards only; no image or Node-RED runtime.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const profile=require('../../../collectors/nodered/error-integration/wire-v2-profile');
const base=fs.mkdtempSync(path.join(os.tmpdir(),'wire-v2-tree-')),root=fs.realpathSync(base),sha=x=>crypto.createHash('sha256').update(x).digest('hex');
try{
 fs.mkdirSync(path.join(root,'pkg'));fs.mkdirSync(path.join(root,'.bin'));fs.writeFileSync(path.join(root,'pkg/a.js'),'alpha');fs.symlinkSync('../pkg/a.js',path.join(root,'.bin/a'));
 const manifest={node:'24.22.1',file_count:1,total_bytes:5,files:{'pkg/a.js':{bytes:5,sha256:sha('alpha')}},symlinks:{'.bin/a':'../pkg/a.js'}};
 assert(profile.verifyTree(root,manifest));fs.writeFileSync(path.join(root,'pkg/a.js'),'ALPHA');assert.equal(profile.verifyTree(root,manifest),false);
 fs.writeFileSync(path.join(root,'pkg/a.js'),'alpha');fs.writeFileSync(path.join(root,'pkg/extra.js'),'x');assert.equal(profile.verifyTree(root,manifest),false);fs.unlinkSync(path.join(root,'pkg/extra.js'));
 fs.unlinkSync(path.join(root,'.bin/a'));fs.symlinkSync('/etc/passwd',path.join(root,'.bin/a'));assert.equal(profile.verifyTree(root,manifest),false);
 const good={version:'24.22.1',executable:'/usr/local/bin/node',argv:['/usr/local/bin/node','/fixture/image-wire-v2-fixture.js'],execArgv:['--require','/adapter/error-integration/wire-v2-bootstrap.js'],cached:['/adapter/error-integration/wire-v2-bootstrap.js','/adapter/error-integration/wire-v2-profile.js'],env:{HOME:'/data',HOSTNAME:'causal-wire-v2',LANG:'C.UTF-8',TZ:'UTC',NODE_OPTIONS:'',NODE_PATH:'/usr/src/node-red/node_modules',NODE_VERSION:'24.22.1',NODE_RED_VERSION:'v5.0.9',FLOWS:'flows.json',YARN_VERSION:'1.22.22',PATH:'/usr/src/node-red/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}};
 assert(profile.validateLaunch(good));assert.equal(profile.validateLaunch({...good,version:'24.22.2'}),false);assert.equal(profile.validateLaunch({...good,cached:[...good.cached,'/other.js']}),false);
 const flow=JSON.parse(fs.readFileSync(path.join(__dirname,'flows-wire-v2.json'))),request=flow.find(n=>n.id==='request'),ingress=flow.find(n=>n.id==='in');
 assert.equal(request.url,'https://127.0.0.1:18443/');assert.equal(request.persist,true);assert.equal(ingress.url,'/run');assert.equal(ingress.method,'post');
 const repo=path.resolve(__dirname,'../../..');for(const [dst,want] of Object.entries(profile.FILES)){
  const rel=dst.startsWith('/adapter/')?'collectors/nodered/'+dst.slice('/adapter/'.length):'tests/fixtures/nodered-causal/'+path.basename(dst);
  assert.equal(sha(fs.readFileSync(path.join(repo,rel))),want,dst);
 }
 assert.equal(sha(fs.readFileSync(path.join(repo,'collectors/nodered/error-integration/wire-v2-image-manifest.json'))),'63560c3dbe43d22c9391d0ac2e46dbad1d428f5b8ea8418b2a9038322da2ad0b');
 assert.notEqual(profile.ID,'apicontour/nodered-causal-v1');
}finally{fs.rmSync(base,{recursive:true,force:true});}
process.stdout.write('PASS: synthetic launch, tree, symlink and source guards only\n');
