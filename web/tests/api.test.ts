import test from 'node:test';
import assert from 'node:assert/strict';
import {api, ApiError, request} from '../src/api.ts';
import {failureStale} from '../src/domain.ts';
import type {Review} from '../src/domain.ts';
class FakeStorage implements Storage {
  private values = new Map<string,string>();
  get length() { return this.values.size; }
  clear() { this.values.clear(); }
  getItem(key:string) { return this.values.get(key) ?? null; }
  key(index:number) { return [...this.values.keys()][index] ?? null; }
  removeItem(key:string) { this.values.delete(key); }
  setItem(key:string,value:string) { this.values.set(key,String(value)); }
}
Object.defineProperty(globalThis, 'sessionStorage', {value:new FakeStorage(), configurable:true});
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
    return Response.json({ok:true,id:(init?.headers as Record<string,string>)['Idempotency-Key']});
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

test('uncertain create keys survive subsequent conflict responses', async () => {
  const previous=globalThis.fetch; const keys:string[]=[]; let calls=0;
  globalThis.fetch=async (_url,init)=>{
    keys.push((init?.headers as Record<string,string>)['Idempotency-Key']);
    return new Response('{}',{status:++calls===1 ? 503 : 409});
  };
  try {
    for (let i=0;i<3;i++) await assert.rejects(request('comparisons',{operation_id:'same'}));
    assert.equal(keys[0],keys[1]); assert.equal(keys[1],keys[2]);
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

test('lost reply survives 401 and module reload with no raw content in session storage', async () => {
  const previousFetch=globalThis.fetch; const previousStorage=globalThis.sessionStorage;
  const storage=new FakeStorage(); Object.defineProperty(globalThis,'sessionStorage',{value:storage,configurable:true});
  const keys:string[]=[]; let calls=0;
  globalThis.fetch=async (_url,init)=>{
    calls++; keys.push((init?.headers as Record<string,string>)['Idempotency-Key']);
    if (calls===1) throw new Error('lost reply');
    if (calls===2) return new Response('{}',{status:401});
    return Response.json({ok:true,id:(init?.headers as Record<string,string>)['Idempotency-Key']});
  };
  try {
    const first=await import('../src/api.ts?reauth-before');
    const body={content:'sensitive unique artifact',format:'openapi_json'};
    await assert.rejects(first.request('contracts/import',body));
    assert.equal(calls,1,'no automatic retry');
    assert.ok(storage.getItem('apicontour.pending-creates.v1'));
    assert.ok(!storage.getItem('apicontour.pending-creates.v1')?.includes(body.content));
    await assert.rejects(first.request('contracts/import',body));
    const reloaded=await import('../src/api.ts?reauth-after');
    await reloaded.request('contracts/import',body);
    assert.equal(calls,3); assert.equal(keys[0],keys[1]); assert.equal(keys[1],keys[2]);
    assert.equal(storage.getItem('apicontour.pending-creates.v1'),'[]');
  } finally {
    globalThis.fetch=previousFetch;
    Object.defineProperty(globalThis,'sessionStorage',{value:previousStorage,configurable:true});
  }
});

test('unavailable session storage blocks create before transmission', async () => {
  const previousFetch=globalThis.fetch; const previousStorage=globalThis.sessionStorage; let calls=0;
  const storage=new FakeStorage(); storage.setItem=()=>{throw new Error('storage disabled');};
  Object.defineProperty(globalThis,'sessionStorage',{value:storage,configurable:true});
  globalThis.fetch=async ()=>{calls++; return Response.json({});};
  try {
    const fresh=await import('../src/api.ts?storage-disabled');
    await assert.rejects(fresh.request('reviews',{operation_id:'private'}));
    assert.equal(calls,0);
  } finally {
    globalThis.fetch=previousFetch;
    Object.defineProperty(globalThis,'sessionStorage',{value:previousStorage,configurable:true});
  }
});

test('malformed or oversized persisted state blocks create without replacing it', async () => {
  const previousFetch=globalThis.fetch; const previousStorage=globalThis.sessionStorage; let calls=0;
  const storage=new FakeStorage(); storage.setItem('apicontour.pending-creates.v1','x'.repeat(12001));
  Object.defineProperty(globalThis,'sessionStorage',{value:storage,configurable:true});
  globalThis.fetch=async ()=>{calls++; return Response.json({});};
  try {
    const fresh=await import('../src/api.ts?storage-corrupt');
    await assert.rejects(fresh.request('reviews',{operation_id:'private'}));
    assert.equal(calls,0);
    assert.equal(storage.getItem('apicontour.pending-creates.v1')?.length,12001);
  } finally {
    globalThis.fetch=previousFetch;
    Object.defineProperty(globalThis,'sessionStorage',{value:previousStorage,configurable:true});
  }
});

test('shared key remains until all concurrent create calls settle', async () => {
  const previousFetch=globalThis.fetch; const previousStorage=globalThis.sessionStorage;
  Object.defineProperty(globalThis,'sessionStorage',{value:new FakeStorage(),configurable:true});
  const keys:string[]=[]; let releaseFirst!:()=>void; let releaseSecond!:()=>void; let bothStarted!:()=>void;
  const firstGate=new Promise<void>(resolve=>{releaseFirst=resolve;});
  const secondGate=new Promise<void>(resolve=>{releaseSecond=resolve;});
  const started=new Promise<void>(resolve=>{bothStarted=resolve;});
  globalThis.fetch=async (_url,init)=>{
    const key=(init?.headers as Record<string,string>)['Idempotency-Key']; keys.push(key);
    const n=keys.length;
    if (n===2) bothStarted();
    if (n===1) await firstGate; else if (n===2) await secondGate;
    return Response.json({id:key});
  };
  try {
    const fresh=await import('../src/api.ts?concurrent-create'); const body={operation_id:'parallel'};
    const first=fresh.request('reviews',body); const second=fresh.request('reviews',body);
    await started; releaseFirst();
    await Promise.race([first,second]);
    await fresh.request('reviews',body);
    assert.equal(keys[0],keys[1]); assert.equal(keys[1],keys[2]);
    releaseSecond(); await Promise.all([first,second]);
    await fresh.request('reviews',body);
    assert.notEqual(keys[2],keys[3]);
  } finally { releaseFirst(); releaseSecond(); globalThis.fetch=previousFetch; Object.defineProperty(globalThis,'sessionStorage',{value:previousStorage,configurable:true}); }
});

test('pending recovery exposes only type and opaque id after a lost response', async () => {
  const previousFetch=globalThis.fetch; const previousStorage=globalThis.sessionStorage;
  Object.defineProperty(globalThis,'sessionStorage',{value:new FakeStorage(),configurable:true});
  globalThis.fetch=async ()=>{throw new Error('lost');};
  try {
    const fresh=await import('../src/api.ts?pending-recovery');
    await assert.rejects(fresh.request('reviews',{candidate_contract_id:'private'}));
    const pending=fresh.pendingRecovery();
    assert.equal(pending.length,1); assert.equal(pending[0].type,'review'); assert.match(pending[0].id,/^[0-9a-f-]{36}$/);
    assert.ok(!JSON.stringify(pending).includes('private'));
    fresh.acknowledgeRecovery(pending[0].id); assert.deepEqual(fresh.pendingRecovery(),[]);
  } finally {globalThis.fetch=previousFetch; Object.defineProperty(globalThis,'sessionStorage',{value:previousStorage,configurable:true});}
});

test('mismatched success id keeps the pending create recoverable', async () => {
  const previousFetch=globalThis.fetch; const previousStorage=globalThis.sessionStorage;
  Object.defineProperty(globalThis,'sessionStorage',{value:new FakeStorage(),configurable:true});
  globalThis.fetch=async ()=>Response.json({id:'00000000-0000-4000-8000-000000000000'});
  try {
    const fresh=await import('../src/api.ts?mismatched-id');
    await assert.rejects(fresh.request('reviews',{comparison:'private'}));
    assert.equal(fresh.pendingRecovery().length,1);
  } finally {globalThis.fetch=previousFetch; Object.defineProperty(globalThis,'sessionStorage',{value:previousStorage,configurable:true});}
});
