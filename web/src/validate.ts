import type {Comparison, Contract, Observation, Operation, Page, Review, Shape} from './domain.ts';
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
function exact(o: ObjectValue, keys: string[]) {
  if (Object.keys(o).length !== keys.length || keys.some(key => !Object.hasOwn(o,key))) throw new Error('Invalid response');
}
function boundedText(value: unknown, max: number) {
  if (typeof value !== 'string' || value.length < 1 || value.length > max) throw new Error('Invalid response');
}
function shape(value: unknown, depth = 1, budget = {nodes: 0}): Shape {
  if (depth > 32 || ++budget.nodes > 65536) throw new Error('Invalid response');
  const o = object(value);
  member(o.kind,['null','boolean','integer','number','string','binary','unknown','object','array','union']);
  if (o.kind === 'unknown') { exact(o,['kind','reason']); member(o.reason,['empty','unsupported','limit','malformed','encrypted']); }
  else if (o.kind === 'object') {
    exact(o,['kind','fields','additional']); const fields = object(o.fields); const names = Object.keys(fields);
    if (names.length > 256) throw new Error('Invalid response');
    for (const name of names) { if (!name || [...name].length > 64) throw new Error('Invalid response'); shape(fields[name],depth+1,budget); }
    if (o.additional !== null) shape(o.additional,depth+1,budget);
  } else if (o.kind === 'array') { exact(o,['kind','items']); shape(o.items,depth+1,budget); }
  else if (o.kind === 'union') {
    exact(o,['kind','alternatives']); if (!Array.isArray(o.alternatives) || o.alternatives.length < 2 || o.alternatives.length > 64) throw new Error('Invalid response');
    o.alternatives.forEach(item => shape(item,depth+1,budget));
  } else exact(o,['kind']);
  return value as Shape;
}
export function observation(value: unknown): Observation {
  const o=object(value);
  exact(o,['id','operation_id','structure','visibility','completeness','reasons','route_uncertain','first_seen','last_seen','queued_at','expires_at','sample_numerator','sample_denominator','count','parser_profile','status_code','structure_fingerprint','policy_revision','protocol','direction','operation','route_template','canonicalization_version','origin_evidence']);
  ids(o,['id','operation_id']); shape(o.structure);
  if (new TextEncoder().encode(JSON.stringify(o.structure)).length>65536) throw new Error('Invalid response');
  if (typeof o.structure_fingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(o.structure_fingerprint) || o.canonicalization_version !== 1 || o.origin_evidence !== 'unavailable' || typeof o.route_uncertain !== 'boolean') throw new Error('Invalid response');
  if (typeof o.policy_revision !== 'string' || !/^[1-9][0-9]{0,19}$/.test(o.policy_revision) || BigInt(o.policy_revision)>18446744073709551615n) throw new Error('Invalid response');
  for (const key of ['first_seen','last_seen','queued_at','expires_at']) { boundedText(o[key],35); if ((o[key] as string).length<20) throw new Error('Invalid response'); }
  boundedText(o.parser_profile,64); boundedText(o.protocol,32); boundedText(o.direction,32); boundedText(o.operation,2048); boundedText(o.route_template,2048);
  member(o.direction,directions); member(o.visibility,['structure','operation','connection']); member(o.completeness,['complete','partial','unavailable']);
  if (!Array.isArray(o.reasons) || o.reasons.length>8 || new Set(o.reasons).size!==o.reasons.length) throw new Error('Invalid response');
  o.reasons.forEach(reason=>member(reason,['permission','encrypted','unsupported','sampled','limit','malformed','source_gap','clock_skew']));
  for (const [key,max] of [['count',1000000000],['sample_numerator',1000000],['sample_denominator',1000000]] as const) if (!Number.isSafeInteger(o[key]) || (o[key] as number)<1 || (o[key] as number)>max) throw new Error('Invalid response');
  if ((o.sample_numerator as number) > (o.sample_denominator as number) || (o.status_code !== null && (!Number.isInteger(o.status_code) || (o.status_code as number)<100 || (o.status_code as number)>599))) throw new Error('Invalid response');
  return value as Observation;
}
export function observations(value: unknown, operationId: string): Page<Observation> {
  const o=object(value); exact(o,['items','next_cursor']); nullableId(o.next_cursor);
  if (!Array.isArray(o.items) || o.items.length>50) throw new Error('Invalid response');
  const items=o.items.map(observation); if (items.some(item=>item.operation_id!==operationId) || new Set(items.map(item=>item.id)).size!==items.length) throw new Error('Invalid response');
  if (o.next_cursor !== null && (!items.length || items[items.length-1].id !== o.next_cursor)) throw new Error('Invalid response');
  return value as Page<Observation>;
}
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
  const absent = o.origin_evidence_available === undefined && o.origins === undefined && o.origins_truncated === undefined;
  if (!absent) {
    if (typeof o.origin_evidence_available !== 'boolean' || typeof o.origins_truncated !== 'boolean' || !Array.isArray(o.origins) || o.origins.length > 32) throw new Error('Invalid response');
    if (!o.origin_evidence_available && (o.origins.length || o.origins_truncated)) throw new Error('Invalid response');
    for (const value of o.origins) { const origin = object(value); ids(origin,['project_id','service_id','environment_id','deployment_id','instance_id']); member(origin.proof_status,['verified']); }
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
