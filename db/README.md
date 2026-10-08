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

HTTP authentication and durable HTTP acceptance remain unimplemented.
Atomic Rust submission is described below. Retention cleanup, queue purge and backup/restore also
remain unimplemented. SQL credential holders remain trusted: they can choose a
tenant setting or hold locks.

## Native TLS transport

`contour-postgres` accepts checked deployment settings and an explicit PEM trust
bundle (1–8 certificates, at most 64 KiB). It parses every certificate and rejects
unconsumed non-whitespace input. System trust roots are disabled; TLS 1.2 is the
minimum, with certificate/hostname verification and SNI enabled. Callers cannot
choose plaintext, disable verification, pass a DSN/options string, or obtain a
mutable driver configuration or raw client.

Connection establishment runs under one cooperative async deadline covering DNS,
socket connection, TLS and authentication. Per-address socket timeouts remain an
additional bound. A Tokio runtime with I/O and timers enabled is required; a
runtime with disabled facilities can panic inside Tokio. OS resolver work in its
blocking pool may continue after cancellation, and a timeout cannot interrupt
non-yielding native work. This is not a hard runtime or DNS-thread termination
guarantee. The owned connection aborts its driver on drop; explicit close drops
the client and waits within the deadline, then aborts on timeout. Driver cancellation
takes effect when Tokio next polls the task. Cancellation of close preserves this
ownership. The public diagnostic query is a fixed bounded TLS health check.

`python3 scripts/test-postgres-tls.py --authority` runs the required TLS and
authority fixtures. Omitting the flag runs only transport tests.
It requires the pinned local PostgreSQL image and installed OpenSSL, creates
ephemeral synthetic credentials/certificates, and cleans its owned containers,
network, files and protocol listeners. The existing no-network SQL fixture is
unchanged. Actual PostgreSQL proves trusted TLS, hostname/CA rejection and backend
cleanup. The TLS fixture uses a dedicated bridge with IP masquerading disabled
and a checked 127.0.0.1-only dynamic published port. It performs no externally
directed operations; this configuration is not a comprehensive egress firewall.
Synthetic protocol listeners separately prove refusal before credentials,
TLS/authentication stalls, cooperative deadlines and transport EOF cleanup.
An authenticated synthetic protocol session also stalls the fixed health query;
unit tests cover close timeout and cancellation without detaching the driver.
The authority and submission layers below use this transport. HTTP authentication
remains separate.

## Authority validation

`ConnectedDatabase::validate_authority` takes a checked batch, independently
authenticated expected tenant/collector identity, and installed policy keys. It
starts READ COMMITTED, binds tenant context locally, acquires the collector lock
in a separate statement, and reads fresh database authority. It loads only the
requested historical revisions, current revision and requested source assignments.
Metadata preflight bounds each envelope to 1 MiB and the deduplicated aggregate
to 16 MiB before any envelope-bearing query. Numeric revision projections use
`numeric(20,0)::text`, preserving exact u64 values even when stored with a scale.

Original envelope bytes are signature-verified and checked against row identity
and revision. Historical policies are verified at queue time; their expiration
at admission does not itself reject retained records. Current authorization must
be enabled and nonrevoked, with a currently valid signed lease. Every record is
checked against both policy scopes and its full enrolled source/workload tuple.
Database time is refreshed after loading and before the final full admission
check, including record expiry and batch age. Signed nanosecond timestamps are
not projected through PostgreSQL timestamps.

One absolute cooperative deadline covers BEGIN, settings, lock wait, reads,
synchronous verification checks and rollback. Statement, lock and idle-transaction
timeouts provide additional database bounds. A guard is armed before BEGIN and
disarmed only after confirmed rollback and empty tenant context. Cancellation,
deadline or uncertain cleanup invalidates the connection and aborts its driver.
Ordinary errors can preserve the session after confirmed cleanup. Validation
always rolls back and returns only `Result<(), AuthorityError>`; it provides no
reusable authority token for later persistence. A future inbox consumer must reuse
the private loader inside its own locked transaction.

`AuthorityTooLarge` means split required, not revocation or signature rejection.
Split into smaller batches with new batch IDs, retaining original record IDs,
queue times and expiry times. Each split still includes current policy overhead.
The `--authority` TLS fixture proves restricted-login admission, aggregate
rejection before envelope fetch, split success, real lock-wait cancellation and
timeout cleanup while runtimes remain alive, fresh state after lock waits, and
lease/record expiry during loading. Synthetic TLS also exercises cancellation
while BEGIN is pending. Direct cancellation during ROLLBACK is inspected through
guard ownership but is not deterministically executed by this fixture.

Transaction setup, cancellation ownership, context cleanup, absolute deadline
checks and exact server-time conversion are private shared helpers. Scoped current
revision lookup and row policy signature verification are also shared internally;
they expose no public transaction or reusable authorization token. The existing
validation API retains its full aggregate metadata preflight before any envelope
fetch. Checked batches expose the same versioned digest as either 32 bytes or the
original lowercase hex string. The submission method below reuses these helpers;
the validation method remains a rollback-only check.

## Durable inbox storage

`0003_ingestion.sql` creates immutable `ingestion_batches` headers and
`ingestion_payloads` bodies keyed by `(tenant_id, collector_id, batch_id)`. Headers
reference the scoped collector and payloads reference the full header key. A
header stores a 32-byte request digest with digest version 1, record count 1–500,
a PostgreSQL 16 built-in `gen_random_uuid()` receipt default and server
`clock_timestamp()` acceptance timestamp default. No UUID extension is required.
The complete checked batch is bytea, format 1, bounded to 1–1,048,576 bytes.
Arbitrary names can contain NUL; PostgreSQL JSONB or TEXT cannot represent that
contract, so the application must use a lossless versioned byte encoding.

Both tables belong to `contour_owner`, enable and force tenant RLS, and grant
SELECT/INSERT only to `contour_ingestion`. Shared runtime and administrators have
no inbox read or insert grant. UPDATE/DELETE triggers reject changes even for a
privileged executor; no application role receives UPDATE, DELETE or TRUNCATE.
Insert triggers reuse the collector guard and its READ COMMITTED/context checks.
As with authority mutation, the try-lock guard cannot prove a separate earlier
blocking statement or validate a signed lease. SQL credentials remain trusted.

The application must derive and verify the digest, verify authenticated collector
authority and signatures, set trusted local tenant context, acquire the collector
lock in a separate statement, and read fresh authority afterward. It must insert
the header and complete checked payload in one transaction, use
`synchronous_commit=on`, and return a receipt only after known commit success.
The schema permits a standalone header: the foreign key ensures payload ownership,
while pair atomicity and digest/body agreement remain application obligations.
A database receipt default alone does not establish durable HTTP acceptance.

No cleanup is implemented. Initial deduplication headers are retained indefinitely,
which exceeds the minimum seven-day receipt retention requirement. Payload
processing and a bounded retention consumer are mandatory later work; there is
no automatic expiry, queue processing, or deletion job in this migration.

The existing PostgreSQL fixture additionally injects a mid-migration-3 error and
verifies DDL, grants and ledger rollback, then upgrades to ledger versions 1–3.
Real restricted logins exercise scoped identity reuse, joins and foreign keys,
byte/count/version limits, default receipts, forbidden modification, and atomic
header rollback on payload failure. NUL/control/Unicode bytes round-trip exactly;
an actual JSONB NUL conversion is rejected. This verifies SQL storage behavior,
not Rust submission, retry handling, crash recovery or HTTP integration.

## Atomic Rust submission

`ConnectedDatabase::submit_batch` takes a checked batch, independently authenticated
expected tenant/collector and installed policy keys. Under one collector lock it
checks present enabled/nonrevoked signed authority, derives the 32-byte digest and
persists a header plus complete bytea payload atomically. New batches receive full
historical/source/record admission, refreshed immediately before COMMIT, with
`synchronous_commit=on`. PostgreSQL generates the receipt UUID and acceptance time.
`DurableReceipt::status()` distinguishes a newly committed `Accepted` result from
an integrity-checked committed retry's `Duplicate`; `ReceiptStatus::as_str()` maps
to the API's `accepted`/`duplicate` strings. Both retain the original PostgreSQL
receipt UUID/time. Full receipt equality includes status, so compare UUID/time
explicitly when checking persisted receipt identity across retries. A confirmed
new COMMIT remains `Accepted` if subsequent context cleanup fails; uncertain
COMMIT still yields `OutcomeUnknown`, not a receipt or success status.

Exact retries require matching digest/version, an intact bounded header/payload
pair and checked payload decoding with matching identity/count/digest. They return
the original receipt under valid present authority without re-admitting expired
historical records. Conflicting ID reuse fails without changing stored rows.
Current envelope loading is bounded to 1 MiB; that staged envelope counts toward
the 16 MiB aggregate before remaining envelopes are fetched. The existing
validation API still gates all metadata before fetching any envelope.

Known COMMIT success latches acceptance immediately. Subsequent cleanup failure
invalidates the connection without erasing that receipt. COMMIT timeout/loss yields
`OutcomeUnknown` and invalidates the connection: retry the original ID and exact
content. Precommit cancellation cannot acknowledge acceptance.

The mandatory `--authority` TLS fixture also runs restricted-login submission
cases: concurrent duplicates, conflicts, scoped/integrity-checked retries, current
authority and expiry rules, all-record/payload-failure atomicity, and NUL/control/
Unicode bytea round trips. It observes cancellation cleanup while the probe runtime
remains alive, a timeout during real deferred-trigger COMMIT, and replay after
discarding an application result. That discard is not dropped server COMMIT
acknowledgement proof. The additional recovery cases below exercise actual server
acknowledgement faults and process restart; no HTTP integration is claimed.

The default TLS profile retains disposable tmpfs data. Mandatory `--authority`
uses a fresh Docker-managed named volume, verifies its exact PGDATA mount and
ownership label, and removes the owned container, volume and network on completion.
No host data directory is mounted. An owned loopback TLS proxy verifies the real
backend CA/hostname and uses the same leaf certificate on both sides to preserve
SCRAM channel binding. It bounds startup packets, message lengths and execution,
observes PostgreSQL `CommandComplete COMMIT` plus idle `ReadyForQuery`, and drops
that server acknowledgement. The client must report `OutcomeUnknown` and refuse
session reuse; exact replay returns the original persisted receipt and changed
content conflicts. A separate fault forwards COMMIT success then cuts the context
cleanup query, proving acceptance survives with an invalidated connection.

The fixture also SIGKILLs its owned PostgreSQL container during another uncommitted
COMMIT, starts the same container/volume, waits for the actual PostgreSQL process
and rechecks the loopback port binding. A previously accepted complete pair retains
the exact header, digest, payload bytes and receipt; the interrupted pair is absent.
This proves PostgreSQL process crash recovery for the fixture, not power-loss,
backup/restore, replication or high availability guarantees.

## Transactional catalog consumer

`ConnectedDatabase::process_catalog_batch` takes an operator-bound tenant,
collector, and batch UUID. Use a separate managed login with only
`contour_catalog_worker` membership and the existing verified TLS settings.
The method exposes no SQL, caller payload, or reusable capture grant.
It processes accepted history even when later capture is disabled or revoked.

The consumer checks bounded inbox metadata before it fetches payload bytes.
It decodes the checked batch and verifies its scope, ID, count, and versioned
digest. A unique completion claim serializes concurrent consumers of the same
batch. Operations, immutable variants, every original observation, and the claim
commit in one transaction with `synchronous_commit=on`. Operation and structure
hash conflicts require an exact canonical-byte match. Reused variants must also
match the derived normalized structure-wire bytes. Policy revision identity
includes the collector. Source counts and sampling fractions remain separate;
this method does not compute unique traffic totals. Name arrays use JSON bytes
so that NUL, control characters, and Unicode remain intact.

`Processed` means that COMMIT succeeded. `AlreadyProcessed` means that the
integrity-checked batch already has a committed version-1 completion claim.
A known COMMIT survives a later cleanup failure. `OutcomeUnknown` requires a
retry of the same batch ID on a new connection. Cancellation, deadline, or
uncertain cleanup invalidates the session. The `_until` method can shorten the
configured deadline. Current-authority callers still acquire their collector
lock; the catalog consumer uses tenant context and its own unique claim.

The required `--authority` fixture includes a restricted catalog-worker login.
It checks stored evidence, concurrent claims, accepted history after revocation,
scope isolation, corruption, bounded metadata reads, canonical collisions,
later-record rollback, cancellation while the runtime remains alive, and actual
server COMMIT acknowledgement loss and cleanup failure. The existing owned
PostgreSQL restart also checks exact committed catalog bytes, rollback of an
interrupted catalog COMMIT, and exact replay after recovery. Scheduling, retention,
catalog HTTP queries, and end-user authorization remain separate work.
