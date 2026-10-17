import type {ComparisonRequest, ImportRequest, Review, ReviewRequest} from './domain.ts';
import * as validate from './validate.ts';
import {decisionBody, safeFailure} from './domain.ts';
export class ApiError extends Error {
  status: number;
  constructor(status: number) { super(safeFailure(status)); this.status = status; }
}
// Authentication belongs to the same-origin server. No browser-supplied identity headers,
// token persistence, remote URL configuration, or automatic retries.
export async function request<T>(path: string, body?: unknown, deadlineMs = 30_000): Promise<T> {
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), deadlineMs);
  try {
    const response = await fetch(`/v1/${path}`, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin',
      signal: controller.signal, cache: 'no-store',
      headers: body === undefined ? {Accept: 'application/json'} :
        {Accept: 'application/json', 'Content-Type': 'application/json'},
      ...(body === undefined ? {} : {body: JSON.stringify(body)}),
    });
    if (!response.ok) throw new ApiError(response.status);
    return await response.json() as T;
  } catch (error) { throw error instanceof ApiError ? error : new ApiError(0); }
  finally { clearTimeout(deadline); }
}
export const api = {
  operations: (cursor?: string) => request<unknown>(`operations?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`).then(validate.catalog),
  operation: (id: string) => request<unknown>(`operations/${encodeURIComponent(id)}`).then(validate.operation),
  import: (body: ImportRequest) => request<unknown>('contracts/import', body).then(validate.contract),
  compare: (body: ComparisonRequest) => request<unknown>('comparisons', body).then(validate.comparison),
  comparison: (id: string) => request<unknown>(`comparisons/${encodeURIComponent(id)}`).then(validate.comparison),
  createReview: (body: ReviewRequest) => request<unknown>('reviews', body).then(validate.review),
  review: (id: string) => request<unknown>(`reviews/${encodeURIComponent(id)}`).then(validate.review),
  decide: (review: Review, decision: 'approve' | 'reject') =>
    request<unknown>(`reviews/${encodeURIComponent(review.id)}/decision`, decisionBody(review, decision)).then(validate.review),
};
