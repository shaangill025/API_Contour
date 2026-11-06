'use strict';
// Offline mode parser checks; does not start Node-RED or open a listener.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'image-wire-v2-fixture.js'),'utf8');
const start=source.indexOf('function qualificationMode(){'),end=source.indexOf('\nasync function negative(',start);
assert(start>=0&&end>start);
function run(content,options={}){
 let closed=false;const fake={constants:fs.constants,openSync(file,flags){assert.equal(file,'/fixture/qualification-mode.json');assert(flags&fs.constants.O_NOFOLLOW);if(options.missing){const e=Error();e.code='ENOENT';throw e;}return 7;},fstatSync(){return {isFile:()=>!options.nonfile,size:options.size??Buffer.byteLength(content)};},readFileSync(){return content;},closeSync(){closed=true;}};
 const fn=vm.runInNewContext(`(${source.slice(start,end)})`,{fs:fake});
 try{return fn();}finally{if(!options.missing)assert(closed);}
}
assert.equal(run('',{missing:true}),'positive');
for(const mode of ['hook','cache','composition','composition-hook','composition-cache'])assert.equal(run(JSON.stringify({mode})),mode);
for(const value of ['{}','{"mode":"positive"}','{"mode":"hook","extra":1}','[]','null','bad'])assert.throws(()=>run(value));
assert.throws(()=>run('{}',{nonfile:true}));assert.throws(()=>run('{}',{size:129}));
process.stdout.write('PASS: offline qualification mode parser\n');
