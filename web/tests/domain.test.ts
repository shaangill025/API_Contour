import test from 'node:test';
import assert from 'node:assert/strict';
import {comparisonMatches, decisionBody, failureStale, reviewMatches, safeFailure, validUuid} from '../src/domain.ts';
import type {Comparison, Review} from '../src/domain.ts';
const c = {operation_id:'operation',id:'comparison',left_id:'baseline',right_id:'candidate',left_kind:'declared',right_kind:'declared'} as Comparison;
const r = {id:'review',operation_id:'operation',comparison_id:'comparison',candidate_contract_id:'candidate',expected_baseline_id:null,revision:7,status:'pending'} as Review;
test('exact comparison identity includes kinds and operation', () => {
  assert.equal(comparisonMatches(c,c),true);
  for (const changed of [{operation_id:'other'},{left_id:'other'},{right_id:'other'},{left_kind:'approved'},{right_kind:'observed'}]) {
    assert.equal(comparisonMatches({...c,...changed} as Comparison,c),false);
  }
});
test('review binds exact candidate, comparison and expected approved association', () => {
  assert.equal(reviewMatches(r,c,null),true);
  assert.equal(reviewMatches(r,c,'new-baseline'),false);
  assert.equal(reviewMatches({...r,candidate_contract_id:'other'},c,null),false);
  assert.equal(reviewMatches({...r,comparison_id:'other'},c,null),false);
});
test('decision uses loaded revision and cannot decide closed reviews', () => {
  assert.deepEqual(decisionBody(r,'approve'),{decision:'approve',expected_revision:7});
  assert.deepEqual(decisionBody(r,'reject'),{decision:'reject',expected_revision:7});
  assert.throws(() => decisionBody({...r,status:'approved'},'approve'));
  assert.throws(() => decisionBody({...r,revision:0},'reject'));
});
test('conflict requires explicit reload; inaccessible errors do not echo input', () => {
  assert.match(safeFailure(409),/Reload explicitly/);
  assert.match(safeFailure(403),/Access denied/);
  assert.match(safeFailure(401),/Sign in/);
  assert.match(safeFailure(503),/unavailable/);
});
test('UUID syntax validation never maps names or generates IDs', () => {
  assert.equal(validUuid('00000000-0000-4000-8000-000000000001'),true);
  assert.equal(validUuid('00000000-0000-4000-8000-00000000000A'),false);
  assert.equal(validUuid('baseline'),false);
  assert.equal(validUuid('../reviews'),false);
});

import {comparison, catalog, contract, review} from '../src/validate.ts';
const id = '00000000-0000-4000-8000-000000000001';
test('comparison rejects unknown result or object-valued text before rendering', () => {
  const value = {id,operation_id:id,left_id:id,right_id:id,left_kind:'declared',right_kind:'declared',direction:'request',result:'inconclusive',differences:[{path:'body.a',kind:'unknown',assessment:'inconclusive',reason:'unsupported_construct'}]};
  assert.equal(comparison(value),value);
  assert.throws(() => comparison({...value,result:'approved'}));
  assert.throws(() => comparison({...value,differences:[{...value.differences[0],path:{html:'unsafe'}}]}));
});
test('malformed page, import and concurrency metadata stop workflow', () => {
  assert.throws(() => catalog({items:[{}],next_cursor:null}));
  assert.throws(() => contract({id,project_id:id,service_id:id,created_at:'now',revision:1,kind:'declared',warnings:[{message:'raw'}]}));
  const value = {id,operation_id:id,comparison_id:id,candidate_contract_id:id,created_at:'now',revision:1,status:'pending',expected_baseline_id:null,deciding_actor_id:null,decided_at:null};
  assert.equal(review(value),value);
  assert.throws(() => review({...value,revision:1.5}));
  assert.throws(() => review({...value,expected_baseline_id:'invented'}));
});

test('catalog failure preserves fresh import availability and existing mutation conflicts', () => {
  const draftStale = failureStale(false,'catalog');
  assert.equal(draftStale,false,'catalog failure must not poison a fresh import draft');
  assert.equal(failureStale(true,'catalog'),true,'catalog reload must preserve existing mutation conflict');
  assert.equal(failureStale(false,'mutation'),true,'uncertain mutation must require explicit recovery');
});

test('review eligibility binds comparison left to exact expected approved baseline', () => {
  const first = {...c,left_kind:'declared',right_kind:'declared'} as Comparison;
  assert.equal(reviewMatches(r,first,null),true);
  const approved = {...first,left_kind:'approved',left_id:'head'} as Comparison;
  const withHead = {...r,expected_baseline_id:'head'};
  assert.equal(reviewMatches(withHead,approved,'head'),true);
  assert.equal(reviewMatches(withHead,{...approved,left_id:'other-head'},'head'),false);
  assert.equal(reviewMatches(withHead,first,'head'),false);
  assert.equal(reviewMatches(r,{...first,left_kind:'approved'},null),false);
  assert.equal(reviewMatches(r,{...first,right_kind:'observed'},null),false);
});

test('imported-only operations have explicit absent observation evidence', () => {
  const op = {id, project_id:id, service_id:id, environment_id:id, protocol:'http', operation:'POST', route_template:'/orders', approved_contract_id:null, direction:'response', last_seen:null, visibility:null, completeness:null};
  assert.deepEqual(catalog({items:[op],next_cursor:null}).items,[op]);
  assert.throws(() => catalog({items:[{...op,last_seen:'2026-10-27T00:00:00Z'}],next_cursor:null}));
  assert.throws(() => catalog({items:[{...op,visibility:'structure'}],next_cursor:null}));
});
