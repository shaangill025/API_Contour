# Privacy and security

## Collection policy

Capture starts disabled. A collector must have an enrolled identity and a valid signed policy. Policy fields include tenant, collector group, version, issue and expiry times, allowed services, enabled techniques, allowed structural names, denied paths, inspection limits, queue limits and retention.

An expired or invalid policy stops new capture. Revocation stops collection and sending. Local queued records remain subject to policy retention and purge rules. A policy change that narrows collection must purge pending records that no longer comply. An old permissive policy cannot resume after a new version is accepted.

Policy leases last at most 15 minutes. Renew normally every 5 minutes. An offline collector can capture only until its current lease expires; immediate offline revocation is impossible. The server rejects revoked identities immediately upon its revocation transaction. Customer-facing status must distinguish local lease exposure from server admission.

Persist the highest accepted policy revision with the collector identity in protected local state. This state contains no observations. Where trustworthy persistent state is unavailable, restart requires an online policy refresh before capture. After restoring a local snapshot, renew online before capture. Reject lower revisions and signature profiles not installed in the trusted release configuration. Do not trust an algorithm selected solely by a received policy.

An online authority exchange uses a new challenge for each attempt. The client
must verify the complete TLS response, matching challenge and identity, policy
signature, and exact requested source set before it can create a live authority
handle. The handle is not serializable. Its monotonic lease starts at request
start and must conservatively deduct elapsed exchange time from the remaining
signed lease; never extend expiry or exceed 15 minutes. Cached responses and
restored local files cannot create this handle. Failed refresh cannot renew it.
The server endpoint and a database snapshot alone do not implement this client
lifecycle or bootstrap enrollment.

Before committing ingestion, the server resolves the active policy, source and workload assignments from authenticated identity. The submitted revision must exist for that identity. The historical submitted revision must have been valid when each record was queued. The collector must also hold a currently valid enabled policy when sending. Validate records against both the historical revision and the current policy; a narrower current scope wins. An expired historical lease alone does not discard an otherwise admissible queued record, but expired or revoked current authorization rejects the whole batch before persistence. Old records are not grandfathered into a broader scope.

The server independently checks field/header/query names against approved names, route literals against approved_route_segments, parser profile, technique, scope and resource limits. Routes consist only of approved literal segments and fixed placeholders such as {segment} or {id}; no arbitrary URL, query, fragment or authority is accepted. Unknown local segments become placeholders. Syntax checks alone are insufficient. Denied templates take precedence. Rejection logs contain safe codes and IDs only.

Use a reviewed signature implementation and key rotation procedure. Exact library and algorithm pins are preflight outputs. Do not create custom cryptography. Collector enrollment uses a short-lived, single-use bootstrap credential delivered through the customer's secret-management process. The platform issues a scoped client identity. No bootstrap credential belongs in a package or source file.

### Native signed policy profile

The installed profile is `ed25519-v1`: Ed25519 with strict verification using
ed25519-dalek 2.2.0. Trusted release configuration supplies at most eight distinct
key IDs (1–64 Unicode scalars) and validated, non-weak 32-byte public keys. The
envelope cannot install keys or select another algorithm. Rotation and revocation
still require an authenticated configuration update and their own integration.

Signing bytes are the UTF-8 bytes `apicontour/policy/1` followed by one LF byte,
then the exact decoded payload bytes. Do not canonicalize, parse or reserialize
the payload before verification. Payload and 64-byte signature use canonical
unpadded URL-safe base64. Both envelope and payload reject unknown, missing and
duplicate decoded field names. The combined encoded JSON envelope is limited to
1,048,576 bytes before JSON decoding, even when individual schema field limits
would permit a larger sum. Arrays and decoded string lengths are checked before
growing the owned policy model; JSON scanning/unescaping is bounded by that outer
byte limit.

Native policy UUIDs use 36-character lowercase hexadecimal spelling and exact
identity comparison. Revisions and resource integers use exact unsigned values
through u64 maximum, including mathematically integral JSON decimal/exponent
tokens. Timestamps use the existing bounded RFC 3339 profile: uppercase T/Z,
1–9 fractional digits when present, numeric offsets, no leap seconds or year zero.
The lease must be positive and at most 900 seconds; acceptance requires
`issued_at <= now < expires_at`. A verified disabled policy does not enable
capture. Verification alone does not establish enrollment, revocation status,
persistent highest revision, source admission or queue purge.

### Pure native admission

The native admission validator takes a checked batch and a caller-supplied
authoritative snapshot: exact tenant/collector identity, a verified current policy,
verified historical policies by revision, and source assignments by source ID.
Each registry has at most 500 unique entries. A source assignment binds tenant,
collector, project, service, environment and deployment together with a closed
technique and 1–128 unique parser profiles. Request fields never establish these
assignments. The caller must authenticate the identity, check revocation and
recheck the snapshot in the eventual persistence transaction.

Historical authorization must be enabled and valid at each record's queued_at;
historical expiry at admission does not invalidate that record. Current
authorization must be enabled and valid at admission. Revisions cannot exceed
the current revision; current and historical entries sharing a revision must
have identical original signed payload bytes, compared by private SHA-256 digest.
This in-memory guard does not persist the highest accepted revision.

Both policies must approve the service, authoritative source technique, parser,
operation (through approved_names), every header/query name and every structural
field recursively, including additional-value nodes, arrays and union branches.
Both depth limits apply. Record expiry may not exceed queued_at plus either
policy's queue TTL. Inspection bytes and total queue bytes cannot be inferred
from a sanitized shape and are not validated by this pure function. Structural
fingerprints are recomputed, but transaction binding and persistence remain later
consumer responsibilities.

Routes use one exact interpretation: root `/` or an absolute slash path with no
trailing or repeated slash. Dot segments, controls, backslashes, percent escapes,
authority/colon syntax, query and fragment syntax are rejected. Only whole-segment
`{segment}` and `{id}` placeholders are allowed; all literal segments require
approval under both policies. There is no decoding, case folding or normalization.
Denied templates use the same grammar; an invalid denial rule rejects the input
snapshot. For paths with the same segment count, denial overlaps when each pair
is equal or either member is a placeholder. Consequently `/admin/{id}` denies
`/admin/{segment}`, and `/admin` denies `/{segment}`. Information lost by
placeholder substitution requires conservative rejection.

Admission does not authenticate, check live revocation, persist data or revision
state, purge queues, or guarantee a database transaction. It returns only a safe
error code or successful validation of the supplied snapshot.

## Local sanitization

1. Check the operation against policy before body inspection.
2. Normalize the route from approved templates or safe local rules.
3. Remove payload values and disallowed metadata.
4. Convert approved content into structural nodes.
5. Apply size, depth and field-count limits.
6. Queue only the sanitized result.

Field names, dynamic keys, URL segments, hostnames, topic names and error messages can contain secrets. Use approved static names or placeholders. Replace dynamic property names with a map node. Never export a value hash as a substitute for removing the value. Do not export enums, examples, defaults, descriptions or literal GraphQL arguments from observed traffic.

Strip query values, user information and fragments from URLs. Store approved query parameter names only. Keep approved header names and coarse structural presence only; never header values. Routes with unresolved segments use placeholders and an uncertain-route flag. Untrusted identifiers must not become metric labels.

For imported OpenAPI, AsyncAPI, GraphQL and protobuf definitions, remove examples, defaults, extensions and comments that can carry values before persistence. Approved contract constraints may be represented only by the separately reviewed declared-contract model. Observed structure must never copy those values.

Raw data may exist transiently inside the original process or local bounded parser memory. Do not write it to spool files, temporary files, logs, traces, crash dumps, telemetry, database rows, backups or support bundles. Minimize copies and lifetime. Do not promise guaranteed memory erasure for every native runtime.

## Access boundaries

Authenticate collector traffic with mTLS and server certificate validation. Bind tenant and collector identity to credentials; reject conflicting body fields. Authenticate users through OIDC. Validate issuer, audience, expiry and authorization on every operation. Use scoped service identities for CI.

Roles are viewer, service owner, policy administrator, operator and security reviewer. Permissions are additive only within assigned projects. Approving contracts requires service-owner permission. Changing capture scope requires policy-administrator permission. Audit both actions. Infrastructure administration does not automatically grant application approval rights.

PostgreSQL application roles must not own tables, be superusers or have BYPASSRLS. Use tenant-scoped keys and row policies. Test queries, workers, imports, exports, backups and connection-pool reuse for isolation. See [PostgreSQL row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

## Threat cases and controls

| Threat | Required control and proof |
|---|---|
| Malicious body or schema | Bounded parsers; no XML external entities; no remote schema reference fetch; fuzz tests |
| Collector impersonation | Scoped identities, revocation and replay tests |
| Cross-tenant access | Authorization and database isolation tests with two tenants |
| Value leakage | Seed synthetic secrets into all input surfaces; inspect every persistent and export sink |
| Queue exhaustion | Hard quotas, drop counters and sustained overload tests |
| Malicious import URL or webhook | No remote reference resolution; administrator-approved destinations and restricted egress |
| Compromised collector | Ingress validation, per-collector quotas and quarantine; do not treat sanitization claims as trusted proof |
| UI injection | Treat field names and imports as data; escape rendering; restrictive content policy |

Data described as structure can remain confidential. Apply access controls and encryption to structural records too. Sanitization tests must include metadata, not only bodies. [OpenTelemetry sensitive-data guidance](https://opentelemetry.io/docs/security/handling-sensitive-data/) supports local minimization as a general practice; it does not certify APIContour.
