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
function diagnostic(){
 const section=source.slice(source.indexOf('const STAGES='),source.indexOf('function readPrivate()'));
 const api=vm.runInNewContext(section+'\n({diag,diagnostic})',{Set,Number,Math});
 api.diag.stage='metadata';api.diag.hello=true;api.diag.spawned=true;api.diag.refresh=123;api.diag.proxy='nonzero';
 assert.equal(api.diagnostic(),'FAIL phase=metadata hello=1 spawned=1 ready=0 refresh=16 proxy=nonzero preflight=none env=0 exec=0 args=0 tty=0 argv_probe=0 bootstrap=unknown missing=0 extra=0 known=0 unknown=0');
 api.diag.failure='private-path-secret';api.diag.stage='unknown-secret';api.diag.proxy='private-error';api.diag.refresh=Infinity;api.diag.hello='private';
 const value=api.diagnostic();assert.equal(value,'FAIL phase=input hello=0 spawned=1 ready=0 refresh=0 proxy=other preflight=none env=0 exec=0 args=0 tty=0 argv_probe=0 bootstrap=unknown missing=0 extra=0 known=0 unknown=0');assert(!value.includes('private'));
 api.diag.failure='request';api.diag.stage='cleanup';api.diag.probe={state:'private-name',bootstrap:'private-name',missing_mask:2048,known_mask:128,extra_count:17,unknown_extra:'private-value'};const bounded=api.diagnostic();assert(bounded.includes('phase=request'));assert(bounded.includes('missing=0 extra=0 known=0 unknown=0'));assert(!bounded.includes('private'));
}
function probeMask(){
 const probe=fs.readFileSync(__dirname+'/proxy-preflight.js','utf8');let output='';
 const allowed=['FLOWS','HOME','HOSTNAME','LANG','NODE_PATH','NODE_RED_VERSION','NODE_VERSION','PATH','TZ','UV_USE_IO_URING','YARN_VERSION'];const env=Object.fromEntries(allowed.map(k=>[k,'private-value']));delete env.HOME;env.QEMU_EXECVE='private-value';env['malicious-key-name']='private-value';
 const fake={env,execPath:'/usr/local/bin/node',execArgv:[],argv:['/usr/local/bin/node','/work/tests/fixtures/receiver504-actual/proxy-preflight.js'],stdin:{},stdout:{write(x){output+=x;}},stderr:{}};
 vm.runInNewContext(probe,{process:fake,require(){return {};},SyntaxError});const v=JSON.parse(output);assert.equal(v.missing_mask,2);assert.equal(v.extra_count,2);assert.equal(v.known_mask,2);assert.equal(v.unknown_extra,true);assert.equal(v.env_keys,false);assert(!output.includes('malicious'));assert(!output.includes('private'));
 for(let i=0;i<30;i++)env['private-'+i]='private-value';output='';vm.runInNewContext(probe,{process:fake,require(){return {};},SyntaxError});assert.equal(JSON.parse(output).extra_count,16);assert(!output.includes('private'));
}
async function preflight(mode){
 let child,args,options;const timers=[];function spawn(...values){[args,options]=[values[1],values[2]];child=new EventEmitter();child.stdin=new EventEmitter();child.stdin.end=()=>{};child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=()=>{};return child;}
 const section=source.slice(source.indexOf('function runPreflight('),source.indexOf('function processStart('));
 const run=vm.runInNewContext(section+'\nrunPreflight',{spawn,Buffer,JSON,Object,Number,Promise,Error,setTimeout(fn,ms){const t={fn,ms};timers.push(t);return t;},clearTimeout(){}});
 const result=run({synthetic:'environment'});assert.deepEqual(Array.from(args),['/work/tests/fixtures/receiver504-actual/proxy-preflight.js']);assert.deepEqual(Array.from(options.stdio),['pipe','pipe','pipe']);
 if(mode==='ok')child.stdout.emit('data',Buffer.from(JSON.stringify({env_keys:true,missing_mask:0,extra_count:0,known_mask:0,unknown_extra:false,exec_path:true,exec_argv:true,pipe_tty:true,argv_probe:true,bootstrap:'ok'})));
 if(mode==='bad')child.stdout.emit('data',Buffer.from('{"secret":"do-not-copy"}'));
 if(mode==='inconsistent')child.stdout.emit('data',Buffer.from(JSON.stringify({env_keys:true,missing_mask:0,extra_count:1,known_mask:0,unknown_extra:false,exec_path:true,exec_argv:true,pipe_tty:true,argv_probe:true,bootstrap:'ok'})));
 child.emit('close',0,null);const value=await result;assert.equal(value.state,mode==='ok'?'ok':'other');assert(!JSON.stringify(value).includes('secret'));
}
async function preflightFailure(mode){
 let child,kills=0;const timers=[];function spawn(){child=new EventEmitter();child.stdin=new EventEmitter();child.stdin.end=()=>{};child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=signal=>{assert.equal(signal,'SIGKILL');kills++;};return child;}
 const section=source.slice(source.indexOf('function runPreflight('),source.indexOf('function processStart('));
 const run=vm.runInNewContext(section+'\nrunPreflight',{spawn,Buffer,JSON,Object,Number,Promise,Error,setTimeout(fn,ms){const t={fn,ms,cleared:false};timers.push(t);return t;},clearTimeout(t){if(t)t.cleared=true;}});
 let settled=false,continued=false;const result=run({}).then(value=>{settled=true;continued=true;return value;},error=>{settled=true;throw error;});
 assert.equal(timers[0].ms,3000);
 if(mode==='stdout')child.stdout.emit('data',Buffer.alloc(513,65));
 if(mode==='stderr')child.stderr.emit('data',Buffer.alloc(4097,65));
 if(mode==='timeout'||mode==='missing-close')timers[0].fn();
 assert.equal(kills,1);await Promise.resolve();assert.equal(settled,false);
 if(mode==='missing-close'){
  const watchdog=timers.find(x=>x.ms===1000);assert(watchdog);watchdog.fn();await assert.rejects(result);assert.equal(continued,false);
 }else{
  child.emit('close',null,'SIGKILL');const value=await result;assert.equal(value.state,'timeout');assert(!JSON.stringify(value).includes('A'));assert(!JSON.stringify(value).includes('PASS'));assert.equal(continued,true);
 }
}
function roles(){
 const code=source.slice(source.indexOf('function ingressRole('),source.indexOf('(async()=>{\n let privateInput'));const check=vm.runInNewContext(code+'\ningressRole',{}),d={export_leaf:'export',receiver_evidence_leaf:'evidence'};
 assert(check('POST','/v1/causal-events','export',d));assert(check('POST','/v1/causal-evidence/receiver','evidence',d));
 for(const [method,path,peer] of [['POST','/v1/causal-events','evidence'],['POST','/v1/causal-evidence/receiver','export'],['GET','/v1/causal-events','export'],['POST','/other','evidence']])assert.equal(check(method,path,peer,d),false);
}
async function tail(failure){
 const start=source.lastIndexOf(' }catch(error){diag.failure=diag.stage;throw error;}finally{\n  clearTimeout(timeout)');assert(start>0);const tail=source.slice(start);
 const labels=[];const context={Buffer,Error,Promise,setTimeout,clearTimeout,process:{exit(){throw Error('exit');},exitCode:0},console:{log:x=>labels.push(x),error:x=>labels.push(x)},stopChild:async()=>{if(failure)throw Error('failed');},shutdown:async()=>{},setImmediate,diag:{stage:'complete'},diagnostic:()=> 'FAIL phase=cleanup'};
 const program='(async()=>{let done=true,timeout,cleanupTimer,pending=Buffer.alloc(0),receiverBytes,producerBytes,exportKey,evidenceKey,held,privateInput,child,proxy,backend,ingress;try{'+tail;
 vm.runInNewContext(program,context);await new Promise(resolve=>setImmediate(resolve));
 assert.equal(labels.filter(x=>x.startsWith('PASS')).length,failure?0:1);if(failure)assert.equal(context.process.exitCode,1);
}
(async()=>{roles();diagnostic();probeMask();await input();await input('error');await input('error-after');await input('early-close');await stalled(true);await stalled(false);await preflight('ok');await preflight('bad');await preflight('inconsistent');for(const mode of ['stdout','stderr','timeout','missing-close'])await preflightFailure(mode);await tail(false);await tail(true);console.log('receiver 504 parent input and cleanup VM tests passed');})().catch(()=>{console.error('receiver 504 parent VM test failed');process.exitCode=1;});
