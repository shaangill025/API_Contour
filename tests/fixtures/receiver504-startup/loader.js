'use strict';
// Synthetic modules exercise existing checked loader only, not Node-RED.
const assert=require('node:assert/strict'),Module=require('node:module');
const {install}=require('../../../collectors/nodered/error-integration/wire-v2-loader');
const paths=['/tmp/504-Node.js','/tmp/504-Flow.js','/tmp/504-wire.js'];
const originals=['module.exports={node:1};','module.exports={flow:1};','module.exports=function(RED,privateWire){ RED.ok=privateWire.ok; };'];
function run(mode){
 let invalid=0;const wire=Object.freeze({ok:true});const targets=new Map(paths.map((p,i)=>[p,{original:Buffer.from(originals[i]),transformed:Buffer.from(originals[i]),binding:'privateBridge',facade:Object.freeze({})}]));
 if(mode==='cached')require.cache[paths[0]]={exports:{}};
 let guard;try{
  if(mode==='cached'){assert.throws(()=>install({targets,wirePath:paths[2],wireFacade:wire,invalidate(){invalid++;}}));return;}
  guard=install({targets,wirePath:paths[2],wireFacade:wire,invalidate(){invalid++;}});
  for(let i=0;i<3;i++){const m=new Module(paths[i]);m.filename=paths[i];m.paths=[];require.cache[paths[i]]=m;if(mode==='source'&&i===1){assert.throws(()=>m._compile(originals[i]+' ',paths[i]));return;}m._compile(originals[i],paths[i]);}
  const red={};require.cache[paths[2]].exports(red);assert.equal(red.ok,true);assert.equal(guard.finish(),true);
  if(mode==='repeat'){assert.throws(()=>require.cache[paths[2]].exports({}));assert(invalid);}
  if(mode==='cache'){require.cache[paths[0]].exports={};assert.equal(guard.intact(),false);assert(invalid);}
 }finally{if(guard)guard.cancel();for(const p of paths)delete require.cache[p];}
}
for(const mode of ['ok','cached','source','repeat','cache'])run(mode);
console.log('receiver 504 loader synthetic lifecycle tests passed');
