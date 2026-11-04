'use strict';
// Offline profile and blocked-launch checks only; no pinned image execution.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),Module=require('node:module');
const base=path.join(__dirname,'../../../collectors/nodered/error-integration');
const {FILES,INGRESS_POINT,validateLaunch,validateFiles}=require(path.join(base,'profile.js'));
const valid={version:'24.22.1',executable:'/usr/local/bin/node',argv:['/usr/local/bin/node','/fixture/image-error-fixture.js'],execArgv:['--require','/adapter/error-integration/bootstrap.js'],env:{NODE_PATH:'/usr/src/node-red/node_modules',NODE_VERSION:'24.22.1',NODE_RED_VERSION:'v5.0.9',FLOWS:'flows.json',YARN_VERSION:'1.22.22',PATH:'/usr/src/node-red/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'},cached:['/adapter/error-integration/bootstrap.js','/adapter/error-integration/profile.js']};
assert(Object.isFrozen(INGRESS_POINT)); assert.deepEqual(INGRESS_POINT,{node:'in',method:'POST',url:'/run'});
assert(fs.readFileSync(path.join(base,'bootstrap.js'),'utf8').includes('ingressPoint:profile.INGRESS_POINT'));
assert(validateLaunch(valid));assert(validateLaunch({...valid,argv:[...valid.argv,'negative']}));
assert(!validateLaunch({...valid,version:'22.0.0'}));assert(!validateLaunch({...valid,cached:[...valid.cached,'/tmp/extra']}));
assert(!validateLaunch({...valid,env:{...valid.env,NODE_OPTIONS:'--require evil'}}));
assert(validateFiles({...FILES}));assert(!validateFiles({...FILES,'/fixture/flows-error.json':'invalid'}));
for(const file of ['bootstrap.js','private-runtime.js','lexical-bridge.js','node-source-transform.js','flow-source-transform.js']){
    assert.equal(crypto.createHash('sha256').update(fs.readFileSync(path.join(base,file))).digest('hex'),FILES['/adapter/error-integration/'+file]);
}
for(const file of ['flows-error.json','image-error-fixture.js']) assert.equal(crypto.createHash('sha256').update(fs.readFileSync(path.join(__dirname,file))).digest('hex'),FILES['/fixture/'+file]);
const old=Module.prototype._compile;
const preload=require(path.join(base,'bootstrap.js'));
assert.deepEqual(Object.keys(preload).sort(),['invalidate','snapshot']);
assert.equal(preload.snapshot().ready,false);assert.equal(preload.snapshot().registryIntact,false);assert.equal(preload.snapshot().phase,'launch');assert.equal(Module.prototype._compile,old);
process.stdout.write('PASS: offline profile hashes, denied launch and unchanged compiler\n');
