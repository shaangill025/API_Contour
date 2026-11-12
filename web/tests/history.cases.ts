import test from 'node:test';
import assert from 'node:assert/strict';
import {api, ApiError} from '../src/api.ts';
import {observation, observations} from '../src/validate.ts';
import {requestEpoch} from '../src/domain.ts';
const op='11111111-1111-4111-8111-111111111111';
const id='22222222-2222-4222-8222-222222222222';
const record=()=>({id,operation_id:op,structure:{kind:'object',fields:{payload:{kind:'unknown',reason:'limit'}},additional:null},visibility:'structure',completeness:'partial',reasons:['limit','sampled'],route_uncertain:true,first_seen:'2026-11-11T12:00:00Z',last_seen:'2026-11-11T12:01:00Z',queued_at:'2026-11-11T12:02:00Z',expires_at:'2026-11-12T12:02:00Z',sample_numerator:1,sample_denominator:3,count:5,parser_profile:'http_json_v1',status_code:null,structure_fingerprint:'a'.repeat(64),policy_revision:'18446744073709551615',protocol:'http',direction:'request',operation:'POST',route_template:'/items',canonicalization_version:1,origin_evidence:'unavailable'});
test('later requests and unmount invalidate earlier async responses',()=>{
  const gate=requestEpoch(); const first=gate.start(); const second=gate.start();
  assert.equal(gate.current(first),false); assert.equal(gate.current(second),true);
  gate.invalidate(); assert.equal(gate.current(second),false);
});
test('validates full evidence including unknown, sampling, exact u64 and unavailable historical origin',()=>{
  const item=observation(record()); assert.equal(item.policy_revision,'18446744073709551615');
  assert.deepEqual(item.structure,{kind:'object',fields:{payload:{kind:'unknown',reason:'limit'}},additional:null});
  assert.equal(item.origin_evidence,'unavailable'); assert.deepEqual(observations({items:[item],next_cursor:id},op).items,[item]);
});
test('rejects wrong scope, unsupported fields, invalid tree and bounded metadata',()=>{
  const invalid=[{...record(),operation_id:id},{...record(),origin_evidence:'verified'},{...record(),policy_revision:'18446744073709551616'},
    {...record(),sample_numerator:4},{...record(),reasons:['private']},{...record(),structure:{kind:'unknown',reason:'secret'}},
    {...record(),structure:{kind:'string',example:'private'}},{...record(),extra:'private'},{...record(),structure_fingerprint:'bad'}];
  for (const item of invalid) assert.throws(()=>observations({items:[item],next_cursor:null},op));
  assert.throws(()=>observations({items:[record()],next_cursor:op},op));
  assert.throws(()=>observations({items:Array.from({length:51},record),next_cursor:null},op));
});
test('history GETs are scoped, same-origin and reject mismatched detail or cursor',async()=>{
  const previous=globalThis.fetch; const calls:{url:string;init?:RequestInit}[]=[];
  globalThis.fetch=async(url,init)=>{ calls.push({url:String(url),init}); return Response.json(calls.length===1 ? {items:[record()],next_cursor:id} : record()); };
  try {
    await api.observations(op); await api.observation(op,id);
    assert.equal(calls[0].url,`/v1/observations?operation_id=${op}&limit=50`);
    assert.equal(calls[1].url,`/v1/observations/${id}?operation_id=${op}`);
    assert.equal(calls[0].init?.credentials,'same-origin'); assert.deepEqual(calls[0].init?.headers,{Accept:'application/json'});
    assert.throws(()=>api.observations(op,'not-a-cursor')); assert.equal(calls.length,2);
    globalThis.fetch=async()=>Response.json({...record(),operation_id:id});
    await assert.rejects(api.observation(op,id),(e:unknown)=>e instanceof ApiError && e.status===0);
    globalThis.fetch=async()=>new Response('x'.repeat(131073));
    await assert.rejects(api.observation(op,id),(e:unknown)=>e instanceof ApiError && e.status===0);
    globalThis.fetch=async()=>new Response('{}',{status:403});
    await assert.rejects(api.observations(op),(e:unknown)=>e instanceof ApiError && e.status===403);
  } finally {globalThis.fetch=previous;}
});

test('historical origin validates exact bounded response and matching selected IDs', async()=>{
  const previous=globalThis.fetch; const calls:{url:string;init?:RequestInit}[]=[];
  const origin={project_id:id,service_id:id,environment_id:id,deployment_id:id,instance_id:id,lifecycle_id:id,credential_id:id,grant_id:id};
  const verified={observation_id:id,operation_id:op,status:'verified',origin};
  try {
    globalThis.fetch=async(url,init)=>{calls.push({url:String(url),init}); return Response.json(verified);};
    assert.deepEqual(await api.observationOrigin(op,id),verified);
    assert.equal(calls[0].url,`/v1/observations/${id}/origin?operation_id=${op}`);
    assert.equal(calls[0].init?.credentials,'same-origin'); assert.equal(calls[0].init?.cache,'no-store');
    assert.deepEqual(calls[0].init?.headers,{Accept:'application/json'});
    for (const bad of [{...verified,observation_id:op},{...verified,operation_id:id},{...verified,extra:1},
      {...verified,origin:{...origin,grant_id:'bad'}},{...verified,origin:{...origin,extra:id}},
      {...verified,status:'unavailable'},{...verified,status:'other'}, {...verified,origin:null}]) {
      globalThis.fetch=async()=>Response.json(bad);
      await assert.rejects(api.observationOrigin(op,id),(e:unknown)=>e instanceof ApiError && e.status===0);
    }
    globalThis.fetch=async()=>Response.json({observation_id:id,operation_id:op,status:'unavailable',origin:null});
    assert.equal((await api.observationOrigin(op,id)).status,'unavailable');
    globalThis.fetch=async()=>new Response('{}',{status:403});
    await assert.rejects(api.observationOrigin(op,id),(e:unknown)=>e instanceof ApiError && e.status===403);
    globalThis.fetch=async()=>new Response('x'.repeat(4097));
    await assert.rejects(api.observationOrigin(op,id),(e:unknown)=>e instanceof ApiError && e.status===0);
    assert.throws(()=>api.observationOrigin('bad',id));
  } finally {globalThis.fetch=previous;}
});
test('origin request aborts on selection change and stale responses are ignored',async()=>{
  const previous=globalThis.fetch; const gate=requestEpoch(); const first=gate.start(); const controller=new AbortController();
  let aborted=false;
  globalThis.fetch=async(_url,init)=>new Promise((_resolve,reject)=>init?.signal?.addEventListener('abort',()=>{aborted=true; reject(new Error('aborted'));},{once:true}));
  try {
    const pending=api.observationOrigin(op,id,controller.signal);
    const second=gate.start(); controller.abort();
    await assert.rejects(pending); assert.equal(aborted,true);
    assert.equal(gate.current(first),false); assert.equal(gate.current(second),true);
    gate.invalidate(); assert.equal(gate.current(second),false);
  } finally {globalThis.fetch=previous;}
});

test('session fence rejects old A after switch to B and old completion cannot clear newer generation',async()=>{
  const {sessionFenced,SessionChanged}=await import('../src/api.ts');
  const previous=globalThis.fetch; const a='sv1_'+'a'.repeat(43), b='sv1_'+'b'.repeat(43);
  let view=a; let release!:()=>void; let readStarted!:()=>void;
  const started=new Promise<void>(resolve=>{readStarted=resolve;});
  const gate=new Promise<void>(resolve=>{release=resolve;});
  globalThis.fetch=async()=>Response.json({authenticated:true},{headers:{'x-contour-session-view':view}});
  const epoch=requestEpoch(); let displayed='';
  async function run(value:string, delay:boolean) {
    const serial=epoch.start(); const controller=new AbortController();
    try {
      const result=await sessionFenced(async()=>{if(delay){readStarted();await gate;} return value;},controller.signal);
      if(epoch.current(serial)) displayed=result;
    } catch(e) { if(epoch.current(serial)) displayed='cleared'; if (!(e instanceof SessionChanged)) throw e; }
  }
  try {
    const old=run('A',true); await started; view=b;
    await run('B',false); release(); await old;
    assert.equal(displayed,'B');
  } finally { release(); globalThis.fetch=previous; }
});
test('session view requires exact non-cookie marker and authentication body',async()=>{
  const {sessionView,SessionViewFailure}=await import('../src/api.ts'); const previous=globalThis.fetch;
  try {
    for(const [marker,body] of [['a'.repeat(43),{authenticated:true}],['sv1_'+'a'.repeat(43),{authenticated:false}],['sv1_'+'a'.repeat(43),{authenticated:true,extra:true}]] as const) {
      globalThis.fetch=async()=>Response.json(body,{headers:{'x-contour-session-view':marker}});
      await assert.rejects(sessionView(),(e:unknown)=>e instanceof SessionViewFailure);
    }
  } finally {globalThis.fetch=previous;}
});

test('shared invalidation clears subscribed history immediately and ignores an old-session 401 after B is observed',async()=>{
  const {onSessionInvalidated,invalidateSession,sessionView,request}=await import('../src/api.ts');
  const previous=globalThis.fetch; let clears=0; let release!:()=>void; let started!:()=>void;
  const gate=new Promise<void>(resolve=>{release=resolve;}); const began=new Promise<void>(resolve=>{started=resolve;});
  const unsubscribe=onSessionInvalidated(()=>{clears++;});
  try {
    invalidateSession(); assert.equal(clears,1);
    const a='sv1_'+'c'.repeat(43), b='sv1_'+'d'.repeat(43); let marker=a;
    globalThis.fetch=async input=>{
      if (String(input)==='/auth/session') return Response.json({authenticated:true},{headers:{'x-contour-session-view':marker}});
      started(); await gate; return new Response('{}',{status:401});
    };
    await sessionView(); const old=request('operations'); await began;
    marker=b; await sessionView(); assert.equal(clears,2);
    release(); await assert.rejects(old); assert.equal(clears,2,'stale A failure must not invalidate B');
    invalidateSession(); assert.equal(clears,3,'sign-out signal reaches the same handler');
  } finally { release(); unsubscribe(); globalThis.fetch=previous; }
});

test('A to B to A probes cannot attach a business response authenticated as B',async()=>{
  const {sessionFenced,SessionChanged}=await import('../src/api.ts'); const previous=globalThis.fetch;
  const a='sv1_'+'e'.repeat(43), b='sv1_'+'f'.repeat(43); let probes=0;
  globalThis.fetch=async input=>String(input)==='/auth/session'
    ? (probes++,Response.json({authenticated:true},{headers:{'x-contour-session-view':a}}))
    : Response.json(record(),{headers:{'x-contour-session-view':b}});
  try {
    await assert.rejects(sessionFenced((signal,view)=>api.observation(op,id,signal,view),new AbortController().signal),SessionChanged);
    assert.equal(probes,1,'mismatched business response stops before the second probe');
  } finally {globalThis.fetch=previous;}
});
test('detail and origin each require their own matching business response view',async()=>{
  const {sessionFenced,SessionChanged}=await import('../src/api.ts'); const previous=globalThis.fetch;
  const a='sv1_'+'g'.repeat(43), b='sv1_'+'h'.repeat(43);
  const origin={observation_id:id,operation_id:op,status:'unavailable',origin:null};
  try {
    for (const mismatch of ['detail','origin']) {
      globalThis.fetch=async input=>{
        const url=String(input);
        if(url==='/auth/session') return Response.json({authenticated:true},{headers:{'x-contour-session-view':a}});
        const isOrigin=url.includes('/origin?');
        return Response.json(isOrigin ? origin : record(),{headers:{'x-contour-session-view':(isOrigin ? mismatch==='origin' : mismatch==='detail') ? b : a}});
      };
      await assert.rejects(sessionFenced((signal,view)=>Promise.all([api.observation(op,id,signal,view),api.observationOrigin(op,id,signal,view)]),new AbortController().signal),SessionChanged);
    }
  } finally {globalThis.fetch=previous;}
});
test('same-session 401 still invalidates while a newer session probe stalls',async()=>{
  const {sessionView,request,onSessionInvalidated,invalidateSession}=await import('../src/api.ts');
  const previous=globalThis.fetch; const a='sv1_'+'i'.repeat(43); let clears=0; let release!:()=>void; let probeStarted!:()=>void;
  const gate=new Promise<void>(resolve=>{release=resolve;}); const started=new Promise<void>(resolve=>{probeStarted=resolve;}); let count=0;
  const unsubscribe=onSessionInvalidated(()=>{clears++;});
  try {
    invalidateSession(); clears=0;
    globalThis.fetch=async input=>{
      if(String(input)==='/auth/session') { if(++count===2){probeStarted();await gate;} return Response.json({authenticated:true},{headers:{'x-contour-session-view':a}}); }
      return new Response('{}',{status:401});
    };
    await sessionView(); const pending=sessionView(); await started;
    await assert.rejects(request('operations')); assert.equal(clears,1);
    release(); await pending;
  } finally {release(); unsubscribe(); globalThis.fetch=previous;}
});
