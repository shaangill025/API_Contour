import type {ComparisonRequest, ImportRequest, Origin, Review, ReviewRequest} from './domain.ts';
import * as validate from './validate.ts';
import {decisionBody, safeFailure, validUuid} from './domain.ts';
export class ApiError extends Error {
  status: number;
  constructor(status: number) { super(safeFailure(status)); this.status = status; }
}
// Invalidation carries no session data. A failed request may invalidate only the
// generation in which it started; a newer observed session owns a newer generation.
const sessionEvents=new EventTarget();
let sessionGeneration=0, latestProbe=0; let observedView:string|null=null;
export function onSessionInvalidated(listener:()=>void):()=>void {
  sessionEvents.addEventListener('invalidated',listener);
  return ()=>sessionEvents.removeEventListener('invalidated',listener);
}
export function invalidateSession(expected?:number) {
  if (expected!==undefined && expected!==sessionGeneration) return;
  sessionGeneration++; observedView=null; latestProbe++;
  sessionEvents.dispatchEvent(new Event('invalidated'));
}
// Storage contains only bounded hashes and opaque resource IDs, never request contents.
const storageKey = 'apicontour.pending-creates.v1';
const pendingCreates = new Map<string, string>();
const inFlight = new Map<string, number>();
const completed = new Set<string>();
const createPaths = new Set(['contracts/import', 'comparisons', 'reviews']);
let loaded = false;
let storageFault = false;
type Pending = {fingerprint: string; key: string; previouslyUncertain: boolean};
function loadPending() {
  if (storageFault) throw new ApiError(0);
  if (loaded) return;
  try {
    const raw = sessionStorage.getItem(storageKey);
    if (raw !== null) {
      if (raw.length > 12000) throw new Error('invalid pending state');
      const entries: unknown = JSON.parse(raw);
      if (!Array.isArray(entries) || entries.length > 64) throw new Error('invalid pending state');
      for (const item of entries) {
        if (!Array.isArray(item) || item.length !== 3 || typeof item[0] !== 'string' ||
            !/^(contracts\/import|comparisons|reviews):[0-9a-f]{64}$/.test(item[0]) ||
            typeof item[1] !== 'string' || !validUuid(item[1]) || item[2] !== true ||
            pendingCreates.has(item[0]) || [...pendingCreates.values()].includes(item[1])) {
          throw new Error('invalid pending state');
        }
        pendingCreates.set(item[0], item[1]);
      }
    }
    loaded = true;
  } catch { storageFault = true; throw new ApiError(0); }
}
function savePending() {
  if (storageFault) throw new ApiError(0);
  try {
    sessionStorage.setItem(storageKey, JSON.stringify([...pendingCreates].map(([fingerprint,key]) => [fingerprint,key,true])));
  } catch { storageFault = true; throw new ApiError(0); }
}
async function createKey(path: string, body: string, signal: AbortSignal, check:()=>void): Promise<Pending> {
  const hash = await abortable(crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)), signal);
  check();
  const fingerprint = `${path}:${Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('')}`;
  loadPending();
  let key = pendingCreates.get(fingerprint);
  const previouslyUncertain = key !== undefined;
  if (!key) {
    if (pendingCreates.size >= 64) throw new ApiError(0);
    key = crypto.randomUUID();
    pendingCreates.set(fingerprint, key);
  }
  // Persist as uncertain before transmission, including if this tab closes mid-request.
  savePending();
  inFlight.set(key, (inFlight.get(key) ?? 0) + 1);
  return {fingerprint, key, previouslyUncertain};
}
function releaseCreate(entry: Pending | undefined) {
  if (entry && pendingCreates.get(entry.fingerprint) === entry.key) {
    pendingCreates.delete(entry.fingerprint);
    savePending();
  }
}
function finishCreate(entry: Pending | undefined) {
  if (!entry) return;
  const count = inFlight.get(entry.key) ?? 0;
  if (count <= 1) {
    inFlight.delete(entry.key);
    if (completed.delete(entry.key)) releaseCreate(entry);
  } else inFlight.set(entry.key, count - 1);
}
export function pendingRecovery(): {type: 'import' | 'comparison' | 'review'; id: string}[] {
  loadPending();
  return [...pendingCreates].map(([fingerprint,id]) => ({
    type: fingerprint.startsWith('reviews:') ? 'review' : fingerprint.startsWith('comparisons:') ? 'comparison' : 'import', id,
  }));
}
export function acknowledgeRecovery(id: string) {
  loadPending();
  const entry = [...pendingCreates].find(([,key]) => key === id);
  if (!entry) return;
  if ((inFlight.get(id) ?? 0) > 0) { completed.add(id); return; }
  releaseCreate({fingerprint:entry[0],key:id,previouslyUncertain:true});
}
// Race non-cooperative stages too; remove the listener regardless of which side settles.
function abortable<T>(work: PromiseLike<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve,reject) => {
    let done=false;
    const finish=(action:()=>void)=>{if(done)return; done=true; signal.removeEventListener('abort',onAbort); action();};
    const onAbort=()=>finish(()=>reject(new ApiError(0)));
    signal.addEventListener('abort',onAbort,{once:true});
    if (signal.aborted) onAbort();
    Promise.resolve(work).then(value=>finish(()=>resolve(value)),error=>finish(()=>reject(error)));
  });
}
// Authentication belongs to the same-origin server. No browser-supplied identity headers,
// token persistence, remote URL configuration, or automatic retries.
export async function request<T>(path: string, body?: unknown, deadlineMs = 30_000, validateResult?: (value: unknown) => T, responseLimit?: number, signal?: AbortSignal, expectedView?: string): Promise<T> {
  const sessionAtStart=sessionGeneration;
  const controller = new AbortController();
  const deadlineAt = performance.now()+deadlineMs;
  const deadline = setTimeout(() => controller.abort(), deadlineMs);
  const check = () => { if (controller.signal.aborted || performance.now() >= deadlineAt) { controller.abort(); throw new ApiError(0); } };
  const abort = () => controller.abort();
  if (signal?.aborted) controller.abort(); else signal?.addEventListener('abort', abort, {once:true});
  let entry: Pending | undefined;
  try {
    check();
    const payload = body === undefined ? undefined : JSON.stringify(body);
    check();
    if (payload !== undefined && createPaths.has(path)) entry = await createKey(path, payload, controller.signal, check);
    check();
    const response = await abortable(fetch(`/v1/${path}`, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin',
      signal: controller.signal, cache: 'no-store',
      headers: body === undefined ? {Accept: 'application/json'} :
        {Accept: 'application/json', 'Content-Type': 'application/json', ...(entry ? {'Idempotency-Key': entry.key} : {})},
      ...(payload === undefined ? {} : {body: payload}),
    }), controller.signal);
    check();
    if (expectedView!==undefined && response.status!==401 && response.headers.get('x-contour-session-view')!==expectedView) throw new SessionChanged();
    if (!response.ok) {
      if (response.status===401) invalidateSession(sessionAtStart);
      if (entry && !entry.previouslyUncertain && inFlight.get(entry.key) === 1 &&
          [400, 401, 403, 404, 409, 413, 422, 429].includes(response.status)) releaseCreate(entry);
      throw new ApiError(response.status);
    }
    let responseBody: unknown;
    if (responseLimit !== undefined) {
      const length=response.headers.get('content-length');
      if (length !== null && (!/^[0-9]+$/.test(length) || Number(length)>responseLimit)) throw new ApiError(0);
      if (!response.body) throw new ApiError(0);
      const reader=response.body.getReader(); const chunks: Uint8Array[]=[]; let total=0;
      try {
        while (true) { const part=await abortable(reader.read(),controller.signal); check(); if (part.done) break; total+=part.value.length; if (total>responseLimit) throw new ApiError(0); chunks.push(part.value); }
      } catch (error) { controller.abort(); void reader.cancel().catch(()=>{}); throw error; }
      finally { reader.releaseLock(); }
      const bytes=new Uint8Array(total); let offset=0; for (const chunk of chunks) {bytes.set(chunk,offset); offset+=chunk.length;}
      responseBody=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
    } else responseBody = await abortable(response.json(),controller.signal);
    check();
    const result = validateResult ? validateResult(responseBody) : responseBody as T;
    check();
    if (entry) {
      if (!responseBody || typeof responseBody !== 'object' || !('id' in responseBody) || responseBody.id !== entry.key) throw new ApiError(0);
      completed.add(entry.key);
    }
    return result;
  } catch (error) { throw error instanceof ApiError || error instanceof SessionChanged ? error : new ApiError(0); }
  finally {
    try { finishCreate(entry); }
    finally { clearTimeout(deadline); signal?.removeEventListener('abort', abort); controller.abort(); }
  }
}
export class SessionViewFailure extends ApiError {}
// The view is an opaque, non-authoritative session generation marker, never a credential.
export async function sessionView(signal?: AbortSignal): Promise<string> {
  const sessionAtStart=sessionGeneration; const probe=++latestProbe;
  const controller=new AbortController(); const abort=()=>controller.abort();
  if (signal?.aborted) controller.abort(); else signal?.addEventListener('abort',abort,{once:true});
  const deadline=setTimeout(abort,30_000);
  try {
    const response=await fetch('/auth/session',{method:'GET',credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'},signal:controller.signal});
    if (!response.ok) { if (response.status===401) invalidateSession(sessionAtStart); throw new ApiError(response.status); }
    const view=response.headers.get('x-contour-session-view');
    const length=response.headers.get('content-length');
    if (!view || !/^sv1_[A-Za-z0-9_-]{43}$/.test(view) || (length!==null && (!/^[0-9]+$/.test(length) || Number(length)>128)) || !response.body) throw new Error('Invalid session view');
    const reader=response.body.getReader(); let total=0; const chunks:Uint8Array[]=[];
    try { while (true) { const part=await reader.read(); if (part.done) break; total+=part.value.length; if (total>128) throw new Error('Invalid session view'); chunks.push(part.value); } }
    finally { reader.releaseLock(); }
    const bytes=new Uint8Array(total); let offset=0; for (const chunk of chunks) { bytes.set(chunk,offset); offset+=chunk.length; }
    const body:unknown=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
    if (!body || typeof body!=='object' || Array.isArray(body) || Object.keys(body).length!==1 || !('authenticated' in body) || body.authenticated!==true) throw new Error('Invalid session view');
    if (sessionAtStart===sessionGeneration && probe===latestProbe && observedView!==view) {
      const hadView=observedView!==null; sessionGeneration++; observedView=view;
      if (hadView) sessionEvents.dispatchEvent(new Event('invalidated'));
    }
    return view;
  } catch (e) { throw new SessionViewFailure(e instanceof ApiError ? e.status : 0); }
  finally { clearTimeout(deadline); signal?.removeEventListener('abort',abort); controller.abort(); }
}
export class SessionChanged extends Error {}
export async function sessionFenced<T>(read: (signal: AbortSignal, view: string)=>Promise<T>, signal: AbortSignal, onView?: (view:string)=>void): Promise<T> {
  const before=await sessionView(signal);
  if (signal.aborted) throw new SessionChanged();
  onView?.(before);
  const value=await read(signal,before);
  if (signal.aborted) throw new SessionChanged();
  const after=await sessionView(signal);
  if (signal.aborted || before!==after) throw new SessionChanged();
  return value;
}
export const api = {
  operations: (cursor?: string, origin?: Origin | null) => {
    const params = new URLSearchParams({limit:'50',include_origin:'true'});
    if (cursor) params.set('cursor',cursor);
    if (origin) for (const key of ['project_id','service_id','environment_id','deployment_id','instance_id'] as const) params.set(`origin_${key}`,origin[key]);
    return request<unknown>(`operations?${params}`).then(validate.catalog);
  },
  operation: (id: string) => request<unknown>(`operations/${encodeURIComponent(id)}?include_origin=true`).then(validate.operation),
  observations: (operationId: string, cursor?: string, signal?: AbortSignal, expectedView?: string) => {
    if (!validUuid(operationId) || (cursor !== undefined && !validUuid(cursor))) throw new ApiError(400);
    const params=new URLSearchParams({operation_id:operationId,limit:'50'});
    if (cursor !== undefined) params.set('cursor',cursor);
    return request(`observations?${params}`,undefined,30_000,value=>validate.observations(value,operationId),4_000_000,signal,expectedView);
  },
  observation: (operationId: string, id: string, signal?: AbortSignal, expectedView?: string) => {
    if (!validUuid(operationId) || !validUuid(id)) throw new ApiError(400);
    const params=new URLSearchParams({operation_id:operationId});
    return request(`observations/${encodeURIComponent(id)}?${params}`,undefined,30_000,value=>{
      const item=validate.observation(value);
      if (item.id!==id || item.operation_id!==operationId) throw new Error('Invalid response');
      return item;
    },131072,signal,expectedView);
  },
  observationOrigin: (operationId: string, id: string, signal?: AbortSignal, expectedView?: string) => {
    if (!validUuid(operationId) || !validUuid(id)) throw new ApiError(400);
    const params=new URLSearchParams({operation_id:operationId});
    return request(`observations/${encodeURIComponent(id)}/origin?${params}`,undefined,30_000,
      value=>validate.historicalOrigin(value,operationId,id),4096,signal,expectedView);
  },
  import: (body: ImportRequest) => request('contracts/import', body, 30_000, validate.contract),
  compare: (body: ComparisonRequest) => request('comparisons', body, 30_000, validate.comparison),
  comparison: (id: string) => request<unknown>(`comparisons/${encodeURIComponent(id)}`).then(validate.comparison),
  createReview: (body: ReviewRequest) => request('reviews', body, 30_000, validate.review),
  review: (id: string) => request<unknown>(`reviews/${encodeURIComponent(id)}`).then(validate.review),
  decide: (review: Review, decision: 'approve' | 'reject') =>
    request<unknown>(`reviews/${encodeURIComponent(review.id)}/decision`, decisionBody(review, decision)).then(validate.review),
};
