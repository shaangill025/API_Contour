# SQL31 clock high-water review proposal

Status: **unapproved, inactive design for review**. The unexecuted SQL31
candidate is not qualified by this note. This proposal does not resolve the
owner's pending choice between the final-authority snapshot and literal
pre-return retention interpretations.

## Defect and dependency map

SQL31 takes `initial_at` or `final_at`, passes it as a lower bound, and later
compares `return_at` against that old value and the originally read tenant
floor. SQL19 `causal_session_locked` invokes SQL28's replacement
`causal_runtime_authority_locked`; each takes its own `clock_timestamp()` and
compares it to the supplied lower bound, not to the other's later sample.
SQL28 `receiver_claim_current` calls that session helper. SQL29
`receiver_enrollment_current` calls receiver claim; `receiver_assignment_current`
calls enrollment; `receiver_observer_current` independently calls producer
session. SQL31 calls both SQL29 chains and producer session directly in
initial, final, and missing-fact paths. Thus a permitted sequence of samples
100, 110, 105, and return 105 can succeed while the return clock is below an
observed clock of 110. Comparing the clocks immediately before and after an
unchanged boolean helper cannot recover an unseen intermediate sample.

## Candidate A: explicit checked-time propagation

Create SQL31-private variants of the SQL28 runtime and SQL19 session
predicates returning `(valid, checked_at)`, with session feeding the runtime
sample into its own next sample. Private variants of SQL28 receiver claim and
SQL29 enrollment, assignment and observer predicates must propagate that
maximum through every nested call. SQL31 must sequence calls imperatively,
carry the maximum across both authority chains, all branches and return, and
reject any backwards or nonfinite sample. Other predicates are kept equivalent;
the original functions, ACLs and other callers remain untouched. This avoids
shared mutable state but changes many signatures and boolean expressions, so
is a substantial fork requiring exact semantic and differential review.

## Candidate B: transaction-local tenant floor as sampled high-water

A narrower interface is a private SQL31 clock sampler that takes no time from a
caller, requires the current tenant's Q gate, reads a fresh database clock,
rejects null/nonfinite/backward values against the *current* locked
`origin_tenant_state.clock_floor`, then advances that floor to the sample in
the same transaction and returns it. SQL31 already obtains Q and locks this row
before quota and new rows. The helper must only be called after that row lock
and never create the row, acquire a later lock first, accept an external clock,
or grant PUBLIC/runtime/reconciler execution. Its tenant must be derived from
`tenant_context()` and missing state must fail closed. Existing RLS applies.

SQL31-private copies of the same dependency chain above would keep their
boolean interfaces, replace both nested SQL19/28 clock reads with that sampler,
and route all internal calls to their private counterparts. SQL31's own
initial, final and return samples must also use the sampler. Replacing just the
outer helpers or only their direct calls is insufficient: any remaining call
to the original nested session/runtime helper can still hide a sample. Every
old `UPDATE ... clock_floor=final_at` based on a stale local value must be
removed or made monotonic; otherwise it can erase an intermediate high-water.
The last successful sample is already persisted in the transaction. A failed
resolver statement rolls floor advances, the edge, and quota back together.
An unresolved successful return still retains its floor advance. The sampler
must not be called during a tenant operation before the normal floor-row lock,
or by another public entrypoint. No session GUC, caller-created temporary
object, or new shared lock is needed.

The existing predicates that catch exceptions require particular care: a
PL/pgSQL exception block rolls back its subtransaction, including floor
updates. A caught exception must cause the private predicate to return false
and the resolver to raise, never continue successfully after losing a sample.
Any deliberate unresolved result must occur only after successful authority
checks. Inspect all exception and short-circuit paths, nested calls, row
triggers, ownership, grants, and writes to the floor. An UPDATE-based sampler
adds writes/WAL and creates no independent lock-order guarantee merely by
being private. Q and credential/collector gates must independently be reviewed
against every authority mutation path. Repeated samples, SQL evaluation order,
rollback-to-savepoint, and pooled connection reuse need review.

Compared with A, B preserves boolean call signatures and avoids explicit
high-water threading at every layer, but still requires the same private call
graph copies and a transactional UPDATE on every sample. Its state is durable
on success rather than local to the call. It must not change the semantics or
access of existing SQL19/28/29 functions. The explicit-propagation design is now present in the unexecuted SQL31 candidate. It requires independent source review and live differential qualification; the alternative remains a proposal.

## Required evidence before qualification

- Differentially compare each private predicate against its exact SQL19/28/29
  source on valid, expired, revoked, closed, wrong-scope, missing and corrupt
  fixtures. Verify both positive and negative paths and all exception handlers;
  existing protected functions and their ACLs must remain byte-for-byte intact.
- Deterministically exercise a test-only private copy with server-side sample
  sequences 100→110→105, 100→110→110, nonfinite, and lower-than-existing-floor;
  prove backward/nonfinite rejection, equality acceptance, cross-helper
  propagation, and no public or generic caller-controlled clock in production.
  Test same conditions on missing-fact and retry paths, plus rollback of the
  floor and edge/quota after late failure. A test copy does not substitute for
  a real database run of the production private functions.
- Prove post-write cutoff coverage for gateway enrollment/policy, receiver
  enrollment and backend/evidence windows, both sessions' expiry/grant/policy,
  selected receiver and observer, required observer predecessors, both SQL20
  batch cutoffs, and monotonicity. Verify no future successor shortens the
  selected edge lifetime; preserve immutable original retry provenance.
- Execute a separate `causal_inbox_basic.sql` fixture before
  `causal_committed_batch_integrity.sql`: that test depends on its fixed
  tenant/runtime/batch IDs and cannot be appended to the SQL29 receiver fixture
  or blindly added to its fixed driver. Run SQL31 seed via public admission APIs
  in the SQL29 same-backend fixture and verify real independent commits.
- Run controlled contention/revocation and late-expiry tests against a
  disposable PostgreSQL with full failure propagation, review gate ordering and
  role privileges, and rerun after final changes. Source inspection and a
  syntactic check are not SQL execution, TLS proof, or a completion claim.

## Checked-time predicate mapping (candidate, unqualified)

The SQL31 candidate defines a private result carrying validity and the latest
sampled server time. The earlier helper draft is archived in the local task record as
`checked-time-draft-archived.sql`; it is not a migration or an active fixture. The
candidate mappings are:

| Draft | Existing source predicate | Intended change |
| --- | --- | --- |
| `causal31_runtime_checked` | SQL28 `causal_runtime_authority_locked` | Return its existing sample alongside the unchanged authority expression. |
| `causal31_session_checked` | SQL19 `causal_session_locked` | Compare its second server sample against the returned runtime sample and return both result and sample. |
| `causal31_receiver_claim_checked` | SQL28 `receiver_claim_current` | Propagate the nested session result and clock. |
| `causal31_receiver_enrollment_checked` | SQL29 `receiver_enrollment_current` | Propagate the nested receiver claim result and clock. |
| `causal31_receiver_assignment_checked` | SQL29 `receiver_assignment_current` | Propagate the nested enrollment result and clock. |
| `causal31_receiver_observer_checked` | SQL29 `receiver_observer_current` | Propagate the nested producer-session result and clock. |

The candidate evaluates some nested checks before their surrounding
boolean expression so their result can be captured. This can change error
ordering or cause a nested call that an existing expression would not execute.
It needs explicit differential review; do not integrate it merely on the
strength of matching expressions. The candidate threads returned times through resolver paths; it has no SQL
qualification or deterministic backwards-clock test. All original helper
functions remain untouched. Before integration, reviewers must compare each
predicate, lock call, row query, null/exception path and time-bound check against
its mapped source. The resolver must carry the maximum through all successful
nested calls and every initial, unresolved, final and return path, rejecting
backwards samples before changing the floor or returning an edge. Production
must derive every sample from the database clock; controlled sequences belong
only to an isolated test implementation, never a caller-controlled production
clock.
