'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'../../..'),live=path.join(root,'collectors/nodered/live-integration'),profile=require(path.join(live,'live-profile'));
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
test('candidate503 assets bind exact source, tree, flow and public pilot policy',()=>{
 const bytes=fs.readFileSync(path.join(live,'manifest.json')),m=profile.validateManifest(bytes,{profile_id:'00000000-0000-4000-8000-000000000503',manifest_sha256:hash(bytes)});
 assert.equal(Object.keys(m.files).length,19);
 for(const [name,digest] of Object.entries(m.files)){assert.match(name,/^\/adapter\/(?:error-integration\/|live-integration\/)?[a-z0-9-]+\.js$/);assert.equal(hash(fs.readFileSync(path.join(root,'collectors/nodered',name.slice('/adapter/'.length)))),digest);}
 const flows=fs.readFileSync(path.join(live,'flows.json'));assert.equal(hash(flows),m.flow_sha256);const nodes=JSON.parse(flows);
 assert.deepEqual(nodes.filter(n=>!['tab','tls-config'].includes(n.type)).map(n=>[n.id,n.type]),m.nodes);
 assert.equal(nodes.find(n=>n.id==='request').url,m.product_endpoint);
 const tls=nodes.find(n=>n.type==='tls-config');assert.equal(tls.cert,m.mounts.product_cert);assert.equal(tls.key,m.mounts.product_key);assert.equal(tls.ca,m.mounts.ca);assert.equal(tls.servername,'pilot-gateway');assert.equal(tls.verifyservercert,true);
 for(const [arch,name] of [['arm64','wire-v2-image-manifest.json'],['x64','wire-v2-image-manifest-x64.json']]){assert.equal(hash(fs.readFileSync(path.join(root,'collectors/nodered/error-integration',name))),m.arch_trees[arch].sha256);assert.equal(m.arch_trees[arch].path,'/adapter/live-integration/tree-'+arch+'.json');}
 assert.equal(m.env.HOSTNAME,'causal-live');assert.equal(m.env.NODE_PATH,'/usr/src/node-red/node_modules');assert.equal(m.env.NODE_VERSION,m.node);assert.equal(m.env.HOME,'/data');assert.deepEqual(Object.keys(m.env),Object.keys(m.env).sort());
 assert.equal(Object.hasOwn(m.files,'/adapter/live-integration/manifest.json'),false);
});
