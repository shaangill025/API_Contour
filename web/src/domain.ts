export type Kind = 'declared' | 'approved' | 'observed';
export type Assessment = 'compatible' | 'incompatible' | 'inconclusive';
export interface Operation {
  id: string; project_id: string; service_id: string; environment_id: string;
  protocol: string; operation: string; route_template: string;
  approved_contract_id: string | null; last_seen: string;
  visibility: string; completeness: string; direction: string;
}
export interface Contract {
  id: string; project_id: string; service_id: string; kind: 'declared' | 'approved';
  revision: number; created_at: string; warnings: string[];
}
export interface ComparisonRequest {
  operation_id: string; left_id: string; left_kind: Kind; right_id: string; right_kind: Kind;
}
export interface Comparison extends ComparisonRequest {
  id: string; result: Assessment; direction: string;
  differences: {path: string; kind: string; assessment: Assessment; reason: string}[];
}
export interface ReviewRequest {
  operation_id: string; comparison_id: string; candidate_contract_id: string;
  expected_baseline_id: string | null;
}
export interface Review extends ReviewRequest {
  id: string; revision: number; status: 'pending' | 'approved' | 'rejected';
  created_at: string; deciding_actor_id: string | null; decided_at: string | null;
}
export interface Page<T> { items: T[]; next_cursor: string | null }
export type ImportFormat = 'openapi_json' | 'asyncapi_json' | 'graphql_sdl' | 'protobuf_descriptor';
export interface ImportRequest { project_id: string; service_id: string; format: ImportFormat; content: string }

export const uuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
export function validUuid(value: string): boolean { return new RegExp(`^${uuidPattern}$`).test(value); }
export function comparisonMatches(c: Comparison, r: ComparisonRequest): boolean {
  return c.operation_id === r.operation_id && c.left_id === r.left_id && c.right_id === r.right_id &&
    c.left_kind === r.left_kind && c.right_kind === r.right_kind;
}
export function reviewMatches(r: Review, c: Comparison, baseline: string | null): boolean {
  return r.operation_id === c.operation_id && r.comparison_id === c.id &&
    r.candidate_contract_id === c.right_id && r.expected_baseline_id === baseline;
}
export function decisionBody(review: Review, decision: 'approve' | 'reject') {
  if (review.status !== 'pending' || !Number.isSafeInteger(review.revision) || review.revision < 1) {
    throw new Error('Reload a pending review before making a decision.');
  }
  return {decision, expected_revision: review.revision};
}
export function safeFailure(status: number): string {
  if (status === 401) return 'Sign in through your installation to continue.';
  if (status === 403) return 'Access denied for this scope. Ask your administrator for access.';
  if (status === 404) return 'This resource is unavailable or outside your authorized scope.';
  if (status === 409) return 'The server state changed. Your context is preserved. Reload explicitly before continuing.';
  if (status === 413) return 'The artifact exceeds the import size limit.';
  if (status === 422 || status === 400) return 'The request was not accepted. Check the selected scope and supplied contract.';
  if (status === 429) return 'The request limit was reached. Try again explicitly later.';
  return 'The service is unavailable. A write may have completed. Your context is preserved; reload explicitly before retrying.';
}

export function failureStale(current: boolean, scope: 'catalog' | 'mutation'): boolean { return scope === 'catalog' ? current : true; }
