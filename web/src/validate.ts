import type {Comparison, Contract, Operation, Page, Review} from './domain.ts';
import {validUuid} from './domain.ts';
type ObjectValue = Record<string, unknown>;
function object(value: unknown): ObjectValue {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid response');
  return value as ObjectValue;
}
function strings(o: ObjectValue, keys: string[]) {
  for (const key of keys) if (typeof o[key] !== 'string') throw new Error('Invalid response');
}
function ids(o: ObjectValue, keys: string[]) {
  strings(o, keys);
  for (const key of keys) if (!validUuid(o[key] as string)) throw new Error('Invalid response');
}
function member(value: unknown, values: string[]) {
  if (typeof value !== 'string' || !values.includes(value)) throw new Error('Invalid response');
}
function nullableId(value: unknown) {
  if (value !== null && (typeof value !== 'string' || !validUuid(value))) throw new Error('Invalid response');
}
function revision(value: unknown) {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw new Error('Invalid response');
}
const directions = ['request','response','publish','consume','operation','connection'];
const kinds = ['declared','approved','observed'];
const assessments = ['compatible','incompatible','inconclusive'];
export function operation(value: unknown): Operation {
  const o = object(value); ids(o,['id','project_id','service_id','environment_id']);
  strings(o,['protocol','operation','route_template']); nullableId(o.approved_contract_id);
  member(o.direction,directions);
  const unobserved = o.last_seen === null && o.visibility === null && o.completeness === null;
  if (!unobserved) {
    strings(o,['last_seen']);
    member(o.visibility,['structure','operation','connection']);
    member(o.completeness,['complete','partial','unavailable']);
  }
  return value as Operation;
}
export function catalog(value: unknown): Page<Operation> {
  const o = object(value);
  if (!Array.isArray(o.items) || o.items.length > 200 || (o.next_cursor !== null && typeof o.next_cursor !== 'string')) throw new Error('Invalid response');
  o.items.forEach(operation); return value as Page<Operation>;
}
export function contract(value: unknown): Contract {
  const o = object(value); ids(o,['id','project_id','service_id']); strings(o,['created_at']);
  revision(o.revision); member(o.kind,['declared','approved']);
  if (!Array.isArray(o.warnings) || o.warnings.length > 200) throw new Error('Invalid response');
  o.warnings.forEach(w => member(w,['unsupported_construct','removed_value','unresolved_reference','partial_import']));
  return value as Contract;
}
export function comparison(value: unknown): Comparison {
  const o = object(value); ids(o,['id','operation_id','left_id','right_id']);
  member(o.left_kind,kinds); member(o.right_kind,kinds); member(o.direction,directions); member(o.result,assessments);
  if (!Array.isArray(o.differences) || o.differences.length > 10000) throw new Error('Invalid response');
  o.differences.forEach(value => {
    const d = object(value); strings(d,['path']); member(d.assessment,assessments);
    member(d.kind,['added','removed','type_changed','nullability_changed','requiredness_changed','unknown']);
    member(d.reason,['directional_constraint','insufficient_evidence','unsupported_construct','structural_difference']);
  }); return value as Comparison;
}
export function review(value: unknown): Review {
  const o = object(value); ids(o,['id','operation_id','comparison_id','candidate_contract_id']);
  strings(o,['created_at']); revision(o.revision); nullableId(o.expected_baseline_id); nullableId(o.deciding_actor_id);
  member(o.status,['pending','approved','rejected']);
  if (o.decided_at !== null && typeof o.decided_at !== 'string') throw new Error('Invalid response');
  return value as Review;
}
