# SQL31 disposable qualification plan

Status: **plan only; not executed or an acceptance claim**. The SQL31 source,
tests and continuation have not been applied or integrated into the existing
supervisor. Run only after independent review, the owner's pending retention
decision, and an authorized, responsive disposable PostgreSQL environment.
Issuer assertions and synthetic SQL facts do not prove authenticated transport,
marker signature possession, or real-world causality.

## Existing continuation and fixture boundaries

1. Use the reviewed existing SQL29 supervisor and its isolated synthetic ingress,
   REQUEST/proof/catalog, producer session/marker, gateway, receiver enrollment,
   observer and receiver fixture. Preserve its protected source checks and
   failure propagation. Its observer admissions require the committed REQUEST
   and verified origin proof first. Do not fabricate origin proofs or catalog
   projections with direct inserts. The SQL29 combined request and fixed SQL31 suffix must run in one psql backend; each supervisor execute call otherwise opens a fresh backend:
   `pg_temp.observer_seed`, `receiver_claim29`, `receiver_pairs`, and the
   fixture's tenant context do not survive a reconnect. Use READ COMMITTED,
   `ON_ERROR_STOP`, and autocommit; check each transaction committed. Confirm
   that SQL29's observer-first pair has its required predecessor and later
   successor and that authority is still current before continuing. The current
   fixture has a short session lifetime, so measure elapsed time and fail rather
   than silently reissue or extend it.
2. The fixed continuation module
   `tests/fixtures/causal-edge-reconciliation/driver.py` supplies, in order,
   SQL30, SQL31, `seed.sql`, `clock_boundaries.sql`,
   `db/tests/causal_join_facts_integrity.sql`, and
   `db/tests/causal_edge_reconciliation.sql`. Append that fixed list to the SQL29 combined request before its single execute call; it is not a standalone database runner. Run the SQL29 receiver race afterward, and issue the SQL31 receipt only after both succeed. Preserve its
   SQL30 HEAD identity check and independently fingerprint candidate SQL31,
   fixture and tests. Install migrations in ledger order 1..30 then 31 as the
   trusted installer in the same backend; record their results. Do not weaken
   migration checks, substitute arbitrary input SQL, or call a successful
   source load a successful SQL run.
3. `seed.sql` reads the committed SQL29 synthetic claims and builds canonical
   SQL20 batches with the SQL20 canonicalizer. As the dedicated SQL20 writer,
   it submits the producer attempt (fixed batch `31000000-0000-4000-8000-000000000001`,
   event `31` repeated 16 times, sequence 1, scope/root/activity/attempt/digest
   from `observer_seed`) and the receiver root (fixed batch ending `0002`,
   event `32` repeated 16 times, sequence 1, root from observer-first receiver
   fact). Each `accept_causal_batch` statement is independently autocommitted.
   Confirm the returned receipt is not a duplicate and read back the exact
   committed batch/event identities, digest and receipt links under an approved
   owner context. Confirm the SQL29 observer and receiver records were already
   independently committed. Reusing this fixed seed in the same database or
   with an already-used runtime sequence is invalid; use a fresh database.
4. `db/tests/causal_committed_batch_integrity.sql` has different fixed tenant,
   runtime and batch IDs from `causal_inbox_basic.sql`. Run it separately in a
   fresh SQL20-basic fixture, same backend, after installing only the reviewed
   private batch helper in an appropriate test transaction. Do not append it
   to the SQL29 continuation list or change its IDs. Check both the positive
   control and each rolled-back corruption case; a setup failure is not RED.

## Arrival-order fixture expansion (missing)

Let P be the committed SQL20 producer attempt, O the committed SQL27 observer,
R the matched receiver fact/assignment and SQL20 root. Test all six orders:
P-O-R, P-R-O, O-P-R, O-R-P, R-P-O, and R-O-P. R consists of two separate
public admissions: SQL29 receiver fact and SQL20 receiver-root batch; commit
both before marking R present and also probe their individual missing states.
A fresh disposable database per permutation is the simplest way to preserve
all independent session, gateway, attempt, root, batch and event uniqueness;
if one database is used, provision new authorized runtime epochs and claims,
marker/attempt scopes, sequence numbers, batch/event IDs, delivery handles,
receiver local roots and verified REQUEST/proofs for each case through existing
public paths. Independent attempts cannot be invented by changing a marker
field without the matching issuer assertion and proof. Record exact per-case
identities and avoid collisions with the SQL29 graph fixture. Do not delete or
alter committed immutable facts to construct an arrival sequence. The existing
corruption tests use privileged trigger disabling only in transactions that
are always rolled back; they are adversarial controls, not arrival fixtures.

After each successful fact commit, invoke the reconciler in a fresh
READ COMMITTED transaction with the correct tenant and dedicated role. Before
all required facts are present, expect NULL and no edge or edge quota change;
all sender authority still must be current. After the final required commit,
expect one edge and exact typed keys, both service/instance scopes, selected
fact/batch/event/receipt digests, REQUEST/proof/marker scope and required retry
predecessors in provenance. Subsequent exact retry must return identical bytes,
keep `resolved_at` and `expires_at` unchanged, and add no charge. Commit the
resolution before treating it as durable. A separate public-root/assignment
suborder matrix should test both R components arriving first and verify no
fabricated substitute supplies the missing component.

## Evidence and coverage matrix

| Requirement | Existing fixed source | Missing qualification or fixture |
| --- | --- | --- |
| Valid join, typed fields, retry | SQL29 observer-first continuation, SQL20 seed and edge controls | Integrate supervisor, execute; add remaining five arrival orders and independent commits. |
| Missing/corrupt/duplicate attempt and root | Rolled-back join-helper controls and missing-root resolver control | Execute; add public-writer wrong-scope cases, missing attempt at resolver, and direct root/attempt mismatch cases. |
| REQUEST/proof/marker/binding/receiver integrity | Existing SQL29 observer/receiver admission controls; SQL31 helper/provenance controls | Exercise SQL31 rejection against wrong committed mappings, scope, binding and every typed field; distinguish missing from corruption and no output leakage. |
| Retry chain/fanout | SQL29 graph admission and SQL31 predecessor expiry, later-successor and ambiguity controls | Construct legitimate linked deliveries through public writers; check missing predecessor, fork, cycle/length boundary, cross-request and selected-edge exact retry after a later successor. |
| Current authority and historical edge | SQL31 closed-gateway and original observer-cutoff rollback controls | Exercise producer, receiver, source, credential, policy and enrollment revocation/expiry independently at join and retry; preserve byte-identical committed history, no charge or mutation. |
| Quota and rollback | SQL31 full-quota and delayed-expiry controls | Execute and confirm transactional usage and edge readback; cover limit-minus-charge boundaries and each failure stage. |
| Clocks and retention | UTC configuration, non-UTC caller/720-hour control, finite/null/lower-bound private checks | Differentially compare copied authority predicates; deterministic server-side test of 100→110→105 and all nested sample paths; evaluate owner's retention interpretation and DST boundary. |
| Isolation/concurrency | Existing SQL29 receiver admission race, not an SQL31 resolver race | Add separate synchronized identical/conflicting SQL31 resolution races and revocation races; verify commit winners, retryable 40001 behavior, no partial state. |
| ACL and tenant isolation | SQL31 role/table/helper checks and wrong-tenant resolver control | Execute under every intended restricted role; test missing session/tenant context and indirect function access without granting raw edge/provenance tables. |

Existing source controls are *prepared*, not executed evidence. The checked
clock differential tests need an isolated test-only clock model or controlled
server harness; never expose a caller-selectable production clock. Cover null,
infinite, lower-than-logical-time and backwards-after-nested-sample inputs,
including missing/unresolved and exact-retry paths. Check that unchanged
SQL19/28/29 helpers and ACLs remain intact. SQL31's private helper copies must
be independently compared for row predicates, locks, time checks, exceptions,
and positive authority against their exact source, including evaluation-order
and finite-bound differences.

## Readback and race assertions

Snapshot tenant usage immediately before each action. On the first successful
edge, assert exactly one row and usage delta
`octet_length(canonical_edge)+256 + octet_length(provenance)+256`; compare all
seven typed request/service fields to their committed fact and binding sources.
Fact admissions have their own pre-existing accounting: record their deltas
separately, including canonical batch bytes, observer/receiver payloads,
receipts and any one-time reservation/assignment charges. Do not infer edge
charge by subtracting before fact creation, change the quota denominator, or
count physical index/WAL usage as verified by logical quota. Check rollback
of edge, usage and clock-floor changes on a failed operation. Compare stored
canonical bytes, `resolved_at`, `expires_at`, charges and provenance before
and after exact retry and later revocation; `expires_at` must follow the final
approved retention interpretation and the UTC duration check.

For simultaneous identical resolution, synchronize separate connections only
after all facts commit. The tenant try-advisory gate may return `40001`; retry
that caller only in a fresh transaction while original authority and cutoffs
remain valid. Assert one durable row, one edge charge and identical returned
bytes for any successful exact retry. For conflicting candidates, use distinct
publicly admitted identities or wrong authorized selection without mutating
immutable history; assert no incorrect edge and no extra charge, and document
whether the admission itself rejected the conflict. Race revocation against
resolution in both lock orders: if resolution commits first, historical bytes
stay intact and subsequent current-authority retry fails; if revocation wins,
no edge or charge may commit. Do not treat an unavailable second connection,
a skipped race, or a timeout as a pass.
