'use strict';
// Execute the exact helper declarations extracted from the experimental
// bootstrap; this exercises Node's CJS loader, not the pinned image wrapper.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),Module=require('node:module');
const source=fs.readFileSync(path.join(__dirname,'../../../collectors/nodered/error-integration/bootstrap.js'),'utf8');
assert(source.includes('this.exports,moduleRequire(this),this,filename'));
assert(source.includes('return passthrough(oldCompile,this,arguments)'));
const begin='// BEGIN offline-tested CommonJS helpers', end='// END offline-tested CommonJS helpers';
assert.equal(source.split(begin).length,2);assert.equal(source.split(end).length,2);
const declarations=source.slice(source.indexOf(begin)+begin.length,source.indexOf(end));
const {moduleRequire,passthrough}=Function('Module','process','reflectApply',declarations+'\nreturn {moduleRequire,passthrough};')(Module,process,Reflect.apply);
const directory=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'error-cjs-')));
const parentPath=path.join(directory,'parent.js'), childPath=path.join(directory,'child.js');
try {
    fs.writeFileSync(parentPath,'// synthetic cache parent\n');
    fs.writeFileSync(childPath,"exports.cycle=require('./parent.js'); exports.parent=module.parent; exports.parentHasChild=module.parent.children.includes(module); exports.requireCache=require.cache;\n");
    const parent=new Module(parentPath,module);parent.filename=parentPath;parent.paths=Module._nodeModulePaths(directory);parent.exports={marker:'parent'};Module._cache[parentPath]=parent;
    const req=moduleRequire(parent), child=req('./child.js');
    assert.equal(child.cycle,parent.exports);assert.equal(child.parent,parent);assert.equal(child.parentHasChild,true);
    assert(parent.children.includes(Module._cache[childPath]));assert.equal(req('./child.js'),child);
    assert.equal(child.requireCache,Module._cache);assert.equal(req.cache,Module._cache);assert.equal(req.extensions,Module._extensions);
    assert.equal(req.main,process.mainModule);assert.equal(req.resolve('./child.js'),childPath);assert(Array.isArray(req.resolve.paths('./child.js')));
    const receiver={}, args=['source','filename','format','extra'];let seen;
    assert.equal(passthrough(function(){seen=[this,...arguments];return 7;},receiver,args),7);
    assert.deepEqual(seen,[receiver,...args]);
} finally {delete Module._cache[parentPath];delete Module._cache[childPath];fs.rmSync(directory,{recursive:true,force:true});}
process.stdout.write('PASS: extracted bootstrap helpers preserve CJS parent, cycle, cache and passthrough arguments\n');
