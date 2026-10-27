import test from 'node:test';
import assert from 'node:assert/strict';
import {api, ApiError, request} from '../src/api.ts';
import {failureStale} from '../src/domain.ts';
import type {Review} from '../src/domain.ts';
test('decision sends only exact revision using same-origin verified session; 409 is never retried', async () => {
  const previous = globalThis.fetch;
  const calls: {url: string; init?: RequestInit}[] = [];
  globalThis.fetch = async (url, init) => {calls.push({url:String(url),init}); return new Response('{}',{status:409});};
  try {
    await assert.rejects(api.decide({id:'review-id',revision:3,status:'pending'} as Review,'approve'), (e: unknown) => e instanceof ApiError && e.status === 409);
    assert.equal(calls.length,1);
    assert.equal(calls[0].url,'/v1/reviews/review-id/decision');
    assert.deepEqual(JSON.parse(calls[0].init?.body as string),{decision:'approve',expected_revision:3});
    assert.equal(calls[0].init?.credentials,'same-origin');
    assert.equal(calls[0].init?.cache,'no-store');
    assert.deepEqual(calls[0].init?.headers,{Accept:'application/json','Content-Type':'application/json'});
  } finally {globalThis.fetch = previous;}
});
test('failed live catalog never falls back to fixture data', async () => {
  const previous = globalThis.fetch;
  globalThis.fetch = async () => {throw new Error('network details must not leak');};
  try {await assert.rejects(api.operations(),(e: unknown) => e instanceof ApiError && !e.message.includes('network details'));}
  finally {globalThis.fetch = previous;}
});

test('deadline ends stalled headers and stalled JSON body without retry', async () => {
  const previous = globalThis.fetch;
  try {
    for (const phase of ['headers','body']) {
      let calls = 0;
      globalThis.fetch = async (_url, init) => {
        calls++;
        const stalled = () => new Promise<never>((_resolve,reject) => {
          init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), {once:true});
        });
        if (phase === 'headers') return stalled();
        return {ok:true,json:stalled} as unknown as Response;
      };
      const outcome = await Promise.race([
        request('contracts/import',{content:'private'},20).then(()=>'resolved',e=>e),
        new Promise(resolve=>setTimeout(()=>resolve('still busy'),100)),
      ]);
      assert.ok(outcome instanceof ApiError, `${phase}: request remained busy past its deadline`);
      assert.equal(outcome.status,0); assert.match(outcome.message,/unavailable/); assert.equal(calls,1);
    }
  } finally {globalThis.fetch=previous;}
});

test('initial catalog 503 followed by empty 200 does not lock a fresh import draft', async () => {
  const previous=globalThis.fetch; let calls=0; let stale=false;
  globalThis.fetch=async()=>++calls===1 ? new Response('{}',{status:503}) : Response.json({items:[],next_cursor:null});
  try {
    await assert.rejects(api.operations(), (e:unknown)=>e instanceof ApiError && e.status===503);
    stale=failureStale(stale,'catalog');
    assert.deepEqual(await api.operations(),{items:[],next_cursor:null});
    assert.equal(stale,false,'successful empty catalog must leave fresh imports available');
    assert.equal(failureStale(true,'catalog'),true,'catalog recovery cannot clear a review conflict');
  } finally {globalThis.fetch=previous;}
});

test('lost response keeps the same create key for explicit retry; confirmed success releases it', async () => {
  const previous=globalThis.fetch; const keys: string[]=[]; let calls=0;
  globalThis.fetch=async (_url, init)=>{
    keys.push((init?.headers as Record<string,string>)['Idempotency-Key']);
    calls++;
    if (calls===1) throw new Error('response lost after commit');
    return Response.json({ok:true});
  };
  try {
    const body={content:'private artifact',format:'openapi_json'};
    await assert.rejects(request('contracts/import',body), (e:unknown)=>e instanceof ApiError && e.status===0);
    assert.equal(calls,1,'no automatic retry');
    await request('contracts/import',body);
    assert.equal(keys[0],keys[1]);
    await request('contracts/import',body);
    assert.notEqual(keys[1],keys[2]);
    assert.match(keys[0],/^[0-9a-f-]{36}$/);
  } finally {globalThis.fetch=previous;}
});

test('uncertain creates retain keys, while a definite conflict releases them', async () => {
  const previous=globalThis.fetch; const keys:string[]=[]; let calls=0;
  globalThis.fetch=async (_url,init)=>{
    keys.push((init?.headers as Record<string,string>)['Idempotency-Key']);
    return new Response('{}',{status:++calls===1 ? 503 : 409});
  };
  try {
    for (let i=0;i<3;i++) await assert.rejects(request('comparisons',{operation_id:'same'}));
    assert.equal(keys[0],keys[1]); assert.notEqual(keys[1],keys[2]);
  } finally {globalThis.fetch=previous;}
});

test('invalid successful create response preserves the pending key', async () => {
  const previous=globalThis.fetch; const keys:string[]=[];
  globalThis.fetch=async (_url,init)=>{
    keys.push((init?.headers as Record<string,string>)['Idempotency-Key']);
    return Response.json({bad:true});
  };
  try {
    const body={project_id:'scope',service_id:'scope',format:'openapi_json',content:'private'} as const;
    await assert.rejects(api.import(body));
    await assert.rejects(api.import(body));
    assert.equal(keys[0],keys[1]);
  } finally {globalThis.fetch=previous;}
});
