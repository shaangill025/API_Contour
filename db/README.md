# PostgreSQL identity and policy storage

`bootstrap.sql` provisions separate non-login owner and runtime roles using a
database administrator. The owner has database CREATE for migrations. Migration
0001 gives runtime scoped identity reads and writes; migration 0002 removes its
write grants and creates the final separation described below. Runtime has no
owner membership, CREATE, TRUNCATE, role-management or RLS-bypass permission.
After migration 0002, use separate administrative and ingestion logins.
Collectors must never receive database access.

`0001_identity.sql` runs in one transaction, records version 1, and creates UUID
identity hierarchy, exact collector workload assignments and enrolled sources.
All tenant-owned foreign keys include tenant_id. Sources reference the entire
assigned collector/project/service/environment/deployment tuple. Source nonces
are unique within tenant and collector. No payload or free-form name columns exist.
Every tenant table enables and forces RLS. The migration ledger is owner-only.

The future application must derive tenant identity from authenticated authority
and set `apicontour.tenant_id` transaction-locally with parameterized
`SELECT set_config('apicontour.tenant_id', $1, true)`. Missing/empty context denies
rows. Transaction-local context reverts on commit or rollback. A pre-existing
session-level setting would be restored; tests demonstrate this behavior. Initialize
connections with empty tenant context, never set it session-wide, and run tenant
queries only inside transactions with an explicit trusted context. This custom setting isolates honest
application queries; it does not constrain malicious holders of SQL credentials,
who can select another tenant context. Authentication and trusted context binding
remain required. Migration 0002 separates administrative and ingestion grants.

Run `bash scripts/test-postgres.sh` after the pinned official PostgreSQL image is
available locally. The script never pulls images. It creates one labeled container
with no network, host mounts or published ports, temporary data in container tmpfs,
and a bounded readiness wait. It cleans only its returned container ID. Fixture
trust is limited to its local UNIX socket; TCP listening is disabled and host auth
rejects. Its known inert password is test data, never deployment guidance.

Tests provision a real restricted LOGIN inheriting runtime, seed two tenants with
reused IDs, and verify exact negative SQLSTATEs, full assignment foreign keys,
forced RLS/ownership/grants, no-context denial, and commit/rollback context reset
on the same connection. An injected migration error proves transactional schema
rollback; it is not a destructive rollback or recovery procedure.

`provision_authority.sql` creates restricted non-login administrative and ingestion
groups inheriting runtime. `0002_policy.sql` atomically turns runtime into a read
group, grants administrators identity INSERT and only the required authorization
column updates, and adds forced-RLS policy history, collector authorization and
source authorization. Neither application group owns tables or can delete,
truncate, update identity tuples or modify policy history. Bind these groups to
separate managed logins. Migration execution requires a provisioning executor
already holding SUPERUSER or BYPASSRLS; owner/runtime membership alone is
insufficient and fails with SQLSTATE 42501 before backfill. The migration grants
no bypass capability to any role.

Policy revisions are exact numeric integers from 1 through u64 maximum and store
the original signed envelope as 1–1,048,576 bytes. SQL does not verify signatures
or match envelope metadata to row keys. The future application must do both before
insertion, including verifying original nanosecond timestamp text rather than a
PostgreSQL timestamp projection. Immutable history cannot be overwritten; active
revision cannot decrease or clear. An unchanged revision permits operational
enable/disable or revocation. Revocation is terminal for that collector identity.
Source authorization binds the immutable source/collector assignment to a closed
technique and 1–128 unique syntax-checked parser profiles.

The migration uses `RESET ROLE` inside its transaction to backfill every existing
collector disabled under provisioning authority, then restores the owner role.
Existing forced RLS excludes the owner from identity reads. No BYPASSRLS grant or
RLS disabling is used. New collectors atomically receive disabled authorization;
existing sources receive no invented profiles. A failure after backfill and grant
changes rolls back the upgrade, including restoring runtime's prior DML.

All trusted administrative and future ingestion callers use READ COMMITTED:
begin a transaction, set the authenticated tenant context locally, execute
`SELECT contour.lock_collector($1, $2)` as a separate blocking statement, then
read authorization in a new statement and hold the lock through the eventual
inbox commit. The shared transaction advisory key is
`hashtextextended('apicontour/collector/1:' || tenant || ':' || collector, 0)` in
the bigint namespace. Hash collisions cause extra serialization only. Mutation
triggers take the same key with a nonblocking try-lock and reject contention with
SQLSTATE 40001; they also reject other isolation levels with 25001. A try-lock
cannot prove the caller acquired a lock in an earlier statement, so the fresh
snapshot sequence remains a trusted application obligation. All functions use
invoker rights and a fixed search path; PUBLIC execution is revoked.

The isolated fixture runs the unchanged identity suite before migration 0002,
checks both injected migration failures and atomic rejection of a restricted
owner/runtime provisioning login, backfill, restricted real logins, state and
profile constraints, and two actual PostgreSQL sessions. The Python standard
library driver observes advisory waits, verifies fresh post-wait reads, prompt
40001 errors, source-profile locking, rollback lock release and isolation rejection.
Waits and execution are bounded, and cleanup targets owned sessions.

Authentication, application signature/metadata verification, ingress transactions,
receipts, retention, queue purge and backup/restore remain unimplemented. SQL
credential holders remain trusted: they can choose a tenant setting or hold locks.
