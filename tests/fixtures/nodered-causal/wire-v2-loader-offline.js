'use strict';
// Synthetic CJS lifecycle; no Node-RED, network, TLS, loader qualification or activation.
const assert=require('node:assert/strict'),Module=require('node:module'),path=require('node:path');
const {install,scrubHeaders,boundedTransform,makeLiveGate}=require('../../../collectors/nodered/error-integration/wire-v2-loader');
const base='/private/tmp/apicontour-v2-offline', names=['Node.js','Flow.js','21-httprequest.js'].map(x=>path.join(base,x));
const text=['module.exports = {ok: 1};','module.exports = {ok: 2};','module.exports = async function(RED,secret) { RED.used=secret.test(); };'];
async function run(mode){
 let invalid=0,calls=0;const facade=Object.freeze({test(){calls++;return 'qualified';}}), red={};
 const sources=text.slice();if(mode==='dynamic')sources[2]="module.exports = async function(RED,secret) { const path=await import('node:path'); RED.used=secret.test()+':'+path.basename('/a/b'); };";if(mode==='bad-import')sources[2]="module.exports = async function() { await import('node:does-not-exist'); };";
 const targets=new Map(names.map((file,i)=>[file,{original:Buffer.from(sources[i]),transformed:boundedTransform(sources[i]),binding:'__unused',facade:{}}]));
 if(mode==='cached')require.cache[names[2]]={exports:()=>{}};
 let guard;
 try{
  if(mode==='cached'){assert.throws(()=>install({targets,wirePath:names[2],wireFacade:facade,invalidate(){invalid++;}}),/target unavailable/);return;}
  guard=install({targets,wirePath:names[2],wireFacade:facade,invalidate(){invalid++;}});
  for(let i=0;i<3;i++){
   if(mode==='missing'&&i===2)break;
   const m=new Module(names[i]);m.filename=names[i];m.paths=[];require.cache[names[i]]=m;
   if(mode==='changed'&&i===1){assert.throws(()=>m._compile(sources[i]+' ',names[i]),/target mismatch/);return;}
   m._compile(sources[i],names[i]);
  }
  if(mode==='missing'){assert.equal(guard.finish(),false);assert(invalid);return;}
  const exported=require.cache[names[2]].exports;
  assert.equal(Object.values(exported).includes(facade),false);assert.equal(calls,0);
  if(mode==='bad-import'){await assert.rejects(exported(red));assert(invalid);assert.equal(guard.finish(),false);return;}
  await exported(red);assert.equal(red.used,mode==='dynamic'?'qualified:b':'qualified');assert.equal(calls,1);
  assert.equal(guard.finish(),true);assert.equal(guard.intact(),true);
  if(mode==='repeat'){assert.throws(()=>exported(red),/repeated registration/);assert(invalid);}
  if(mode==='tamper'){require.cache[names[2]].exports=()=>{};assert.equal(guard.intact(),false);assert(invalid);}
  if(mode==='node-tamper'){require.cache[names[0]].exports={};assert.equal(guard.intact(),false);assert(invalid);}
 }finally{if(guard)guard.cancel();for(const name of names)delete require.cache[name];}
}
{const opts={headers:{'X-ApiContour-Id':'spoof','Content-Type':'text/plain'}};assert(scrubHeaders(opts));assert.deepEqual(opts.headers,{'Content-Type':'text/plain'});let reads=0;const proxy=new Proxy({}, {get(){reads++;throw Error('getter');},ownKeys(){reads++;throw Error('keys');}});assert.equal(scrubHeaders({headers:proxy}),false);assert.equal(reads,0);}
async function realTransform(){
 const file=process.argv[2];assert(file,'supply pinned 21 source path');const bytes=require('node:fs').readFileSync(file);
 const output=require('../../../collectors/nodered/error-integration/private-wire-transform').transform(bytes);assert.equal(typeof output,'string');
 const targets=new Map(names.map((name,i)=>[name,{original:i===2?bytes:Buffer.from(text[i]),transformed:i===2?boundedTransform(output):boundedTransform(text[i]),binding:'__unused',facade:{}}]));
 let invalid=0;const guard=install({targets,wirePath:names[2],wireFacade:{},invalidate(){invalid++;}});
 try{for(let i=0;i<3;i++){const m=new Module(names[i]);m.filename=names[i];m.paths=[];require.cache[names[i]]=m;m._compile((i===2?bytes:Buffer.from(text[i])).toString('utf8'),names[i]);}assert.equal(typeof require.cache[names[2]].exports,'function');assert.equal(invalid,0);}
 finally{guard.cancel();for(const name of names)delete require.cache[name];}
}
(async()=>{for(const scenario of ['ok','dynamic','bad-import','cached','changed','missing','repeat','tamper','node-tamper'])await run(scenario);await realTransform();
let clock=0,invalid=0,integrity=true;const live=makeLiveGate({ready:()=>true,gate:()=>clock<100,integrity:()=>integrity,invalidate:()=>invalid++});
assert(live());clock=100;assert.equal(live(),false);assert.equal(invalid,1);clock=0;assert.equal(live(),false);assert.equal(invalid,1);
let fault=0;const other=makeLiveGate({ready:()=>true,gate:()=>true,integrity:()=>integrity,invalidate:()=>fault++});assert(other());integrity=false;assert.equal(other(),false);assert.equal(fault,1);
assert.throws(()=>boundedTransform('x'.repeat(4*1024*1024+1)),/unsupported/);assert.throws(()=>boundedTransform('\ud800'),/unsupported/);
process.stdout.write('PASS: delayed CJS, real transform composition, dynamic import and live gates only\n');})().catch(error=>{process.stderr.write(String(error.stack||error)+'\n');process.exitCode=1;});
