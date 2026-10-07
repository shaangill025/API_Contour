# PostgreSQL identity foundation

`bootstrap.sql` provisions separate non-login owner and runtime roles using a
database administrator. The owner has database CREATE for migrations; runtime
has schema USAGE and scoped identity SELECT/INSERT/UPDATE/DELETE only. It has no
owner membership, CREATE, TRUNCATE, role-management or RLS-bypass permission.
Bind runtime to a separately managed application login during deployment.
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
remain required. Split administrative and ingestion DML grants before ingress.

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

Policy history, revocation, authenticated source binding, inbox transactions,
concurrent retries, receipts, retention and backup/restore remain unimplemented.
