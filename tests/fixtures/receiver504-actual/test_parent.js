'use strict';
// Extract and execute the actual helper's input and completion paths in a VM.
// No services, Docker, OS fd0 modification or credentials are used.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),{EventEmitter}=require('node:events');
const source=fs.readFileSync(__dirname+'/parent.js','utf8');
async function input(mode){
 let socket,options;class Fake extends EventEmitter {constructor(value){super();options=value;socket=this;this.destroyed=false;}destroy(){this.destroyed=true;}}
 const keys=['backend_cert','backend_key','gateway_cert','gateway_key','ingress_cert','ingress_key','seed'];const obj={};for(const key of keys)obj[key]=Buffer.alloc(key==='seed'?32:1,1).toString('base64');
 const body=Buffer.from(JSON.stringify(obj)),h=Buffer.alloc(8);h.write('R5I1');h.writeUInt32BE(body.length,4);
 const functionSource=source.slice(source.indexOf('function readPrivate()'),source.indexOf('function frame('));
 const context={Buffer,JSON,Error,KEYS:keys,setTimeout,clearTimeout,net:{Socket:Fake}};
 const read=vm.runInNewContext(functionSource+'\nreadPrivate',context);let settled=false;const result=read();result.then(()=>settled=true,()=>settled=true);
 assert.deepEqual({...options},{fd:3,readable:true,writable:false,allowHalfOpen:true});
 if(mode==='early-close')socket.emit('close');else if(mode==='error')socket.emit('error',Error('input'));else socket.emit('data',Buffer.concat([h,body]));
 if(mode==='error-after')socket.emit('error',Error('close'));
 if(mode!=='early-close'){await Promise.resolve();assert.equal(settled,false);assert(socket.destroyed);socket.emit('close');}
 if(mode==='error'||mode==='error-after'||mode==='early-close')await assert.rejects(result);else {const values=await result;assert.equal(values.seed.length,32);for(const value of Object.values(values))value.fill(0);}
}
async function stalled(closeEvent){
 let socket;class Fake extends EventEmitter {constructor(){super();socket=this;this.destroyed=false;}destroy(){this.destroyed=true;}}
 const timers=[];const context={Buffer,JSON,Error,KEYS:[],net:{Socket:Fake},setTimeout(fn,ms){const item={fn,ms,cleared:false};timers.push(item);return item;},clearTimeout(item){if(item)item.cleared=true;}};
 const code=source.slice(source.indexOf('function readPrivate()'),source.indexOf('function frame('));const read=vm.runInNewContext(code+'\nreadPrivate',context);
 let spawned=false;const result=read().then(()=>{spawned=true;},()=>{});socket.emit('data',Buffer.from('R5'));
 timers.find(t=>t.ms===5000).fn();assert(socket.destroyed);assert.equal(spawned,false);
 if(closeEvent)socket.emit('close');else timers.find(t=>t.ms===1000).fn();
 await result;assert.equal(spawned,false);
}
async function tail(failure){
 const start=source.lastIndexOf(' }finally{\n  clearTimeout(timeout)');assert(start>0);const tail=source.slice(start);
 const labels=[];const context={Buffer,Error,Promise,setTimeout,clearTimeout,process:{exit(){throw Error('exit');},exitCode:0},console:{log:x=>labels.push(x),error:x=>labels.push(x)},stopChild:async()=>{if(failure)throw Error('failed');},shutdown:async()=>{},setImmediate};
 const program='(async()=>{let done=true,timeout,cleanupTimer,pending=Buffer.alloc(0),held,privateInput,child,proxy,backend,ingress;try{'+tail;
 vm.runInNewContext(program,context);await new Promise(resolve=>setImmediate(resolve));
 assert.equal(labels.filter(x=>x.startsWith('PASS')).length,failure?0:1);if(failure)assert.equal(context.process.exitCode,1);
}
(async()=>{await input();await input('error');await input('error-after');await input('early-close');await stalled(true);await stalled(false);await tail(false);await tail(true);console.log('receiver 504 parent input and cleanup VM tests passed');})().catch(()=>{console.error('receiver 504 parent VM test failed');process.exitCode=1;});
