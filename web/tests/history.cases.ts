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
