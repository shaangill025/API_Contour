import type {ComparisonRequest, ImportRequest, Review, ReviewRequest} from './domain.ts';
import * as validate from './validate.ts';
import {decisionBody, safeFailure} from './domain.ts';
export class ApiError extends Error {
  status: number;
  constructor(status: number) { super(safeFailure(status)); this.status = status; }
}
// Only hashes and random resource IDs survive an uncertain request in this tab.
const pendingCreates = new Map<string, string>();
const createPaths = new Set(['contracts/import', 'comparisons', 'reviews']);
async function createKey(path: string, body: string): Promise<{fingerprint: string; key: string}> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body));
  const fingerprint = `${path}:${Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('')}`;
  let key = pendingCreates.get(fingerprint);
  if (!key) {
    if (pendingCreates.size >= 64) throw new ApiError(0);
    key = crypto.randomUUID();
    pendingCreates.set(fingerprint, key);
  }
  return {fingerprint, key};
}
function releaseCreate(entry: {fingerprint: string; key: string} | undefined) {
  if (entry && pendingCreates.get(entry.fingerprint) === entry.key) pendingCreates.delete(entry.fingerprint);
}
// Authentication belongs to the same-origin server. No browser-supplied identity headers,
// token persistence, remote URL configuration, or automatic retries.
export async function request<T>(path: string, body?: unknown, deadlineMs = 30_000, validateResult?: (value: unknown) => T): Promise<T> {
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), deadlineMs);
  let entry: {fingerprint: string; key: string} | undefined;
  try {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    if (payload !== undefined && createPaths.has(path)) entry = await createKey(path, payload);
    const response = await fetch(`/v1/${path}`, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin',
      signal: controller.signal, cache: 'no-store',
      headers: body === undefined ? {Accept: 'application/json'} :
        {Accept: 'application/json', 'Content-Type': 'application/json', ...(entry ? {'Idempotency-Key': entry.key} : {})},
      ...(payload === undefined ? {} : {body: payload}),
    });
    if (!response.ok) {
      if ([400, 401, 403, 404, 409, 413, 422, 429].includes(response.status)) releaseCreate(entry);
      throw new ApiError(response.status);
    }
    const responseBody: unknown = await response.json();
    const result = validateResult ? validateResult(responseBody) : responseBody as T;
    releaseCreate(entry);
    return result;
  } catch (error) { throw error instanceof ApiError ? error : new ApiError(0); }
  finally { clearTimeout(deadline); }
}
export const api = {
  operations: (cursor?: string) => request<unknown>(`operations?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`).then(validate.catalog),
  operation: (id: string) => request<unknown>(`operations/${encodeURIComponent(id)}`).then(validate.operation),
  import: (body: ImportRequest) => request('contracts/import', body, 30_000, validate.contract),
  compare: (body: ComparisonRequest) => request('comparisons', body, 30_000, validate.comparison),
  comparison: (id: string) => request<unknown>(`comparisons/${encodeURIComponent(id)}`).then(validate.comparison),
  createReview: (body: ReviewRequest) => request('reviews', body, 30_000, validate.review),
  review: (id: string) => request<unknown>(`reviews/${encodeURIComponent(id)}`).then(validate.review),
  decide: (review: Review, decision: 'approve' | 'reject') =>
    request<unknown>(`reviews/${encodeURIComponent(review.id)}/decision`, decisionBody(review, decision)).then(validate.review),
};
