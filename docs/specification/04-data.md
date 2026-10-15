# Structural data and persistence

## Identity

The server assigns tenant, project, service and environment identifiers. A registered deployment identifier separates versions of a service. Collector credentials constrain these identifiers. The operation key consists of tenant, project, service, environment, protocol, direction, method or operation kind, and sanitized route or channel template. Deployment is a comparison dimension. It must not split the stable operation identity.

Each record also carries source_id, an enrolled UUID scoped to tenant and collector. It identifies one logical capture source, such as a process instance or approved runtime hook. The registration maps it to approved workload metadata without storing raw process arguments or user identifiers. A new source instance gets a new ID. Credentials constrain source assignment.

Do not merge operations across services by path alone. Do not infer shared identity from an IP address alone. Unknown attribution remains explicit. Identity rules and aliases are versioned. A changed rule creates a reviewable remapping; it must not silently rewrite approved history.

### Operation key encoding v1

The checked batch projection encodes an eight-string JSON array in this order:
tenant, project, service, environment, protocol, direction, operation, template.
Use exact UTF-8, no whitespace, no Unicode normalization or aliases. Escape quote
and backslash; encode every control character as lowercase `\u00xx`. Output is
bounded to 2,048 bytes. The key fingerprint is lowercase SHA-256 of UTF-8
`apicontour/operation/1\n` followed by those bytes. The future catalog must retain
the version and exact tuple, not trust a caller-supplied hash as identity proof.

Deployment, collector, source, parser profile, policy revision, visibility and
route uncertainty remain separate provenance. Equal keys do not authorize merging
uncertain attribution or summing sources as unique traffic. Projection checks
syntax only; trusted inbox integrity and scope checks remain required before
persistence. Catalog processing and versioned remapping remain separate work.

## Structure nodes

The initial node model has kinds null, boolean, integer, number, string, binary, object, array, union and unknown. Nodes contain no observed values, value lengths, enum values or value hashes. Schema files use JSON Schema 2020-12 as a wire definition, not as the inference algorithm.

Object fields use policy-approved names. Names are case-sensitive Unicode strings without normalization. Sort names by their UTF-8 bytes for canonicalization. Reject duplicate JSON keys before extraction. An object with dynamic names uses one additional-values node; it does not export those names. An empty object is different from unknown or truncated content.

Classify a valid JSON numeric token from its exact decimal value without binary floating-point conversion. A token representing a mathematical integer is integer, including 1.0 and 1e3. Other numeric tokens are number. Reject non-finite tokens. Numeric magnitude is not stored. Limit numeric token length before conversion.

An array node contains the union of inspected item structures. An empty array has unknown item structure, not null. A union contains unique alternatives sorted by canonical bytes. Flatten nested unions. Collapse a union with one alternative. Keep integer and number distinct in observed variants. Compatibility rules may treat integer as a subset of number.

Missing and null differ. A missing field produces no field node in that observation. Null produces a null node. An incomplete observation cannot establish that a field is missing. Requiredness is a declared/approved constraint. Observed presence frequency must not be labeled a guarantee.

Unknown nodes carry a reason: empty, unsupported, limit, malformed or encrypted. Preserve incomplete status for the whole observation when a parser limit prevents full inspection. Do not treat unknown as a compatible wildcard during discrepancy checks.

## Canonicalization and fingerprints

Canonical form is a JSON array tree: [kind] for primitive nodes; ["unknown",reason] for unknown; ["object",[[name,node],...],additionalNodeOrNull] for objects; ["array",node] for arrays; ["union",[node,...]] for unions. Encode as UTF-8 with no whitespace. Escape quote and backslash; encode control characters as lowercase \\u00xx; leave other Unicode unchanged. Reject unpaired surrogates. Sort before encoding. Do not include counts, timestamps, observed values or transport identifiers.

Fingerprint input is UTF-8 `apicontour/structure/1\n` followed by canonical bytes. Use SHA-256 and lowercase hexadecimal. The server recomputes it. The identity of a persisted variant also includes operation, direction, structural-policy revision, parser profile and canonicalization version. A fingerprint is not proof of authorization or privacy.

Cross-language golden vectors must prove stable bytes for ordering, nested maps, unions, empty containers, exact numbers, Unicode, null, missing and limits. No implementation may use a language's default object hash as the contract hash.

## Evidence

Each observation reports visibility: structure, operation or connection. Completeness is complete, partial or unavailable. Reasons include permission, encrypted, unsupported, sampled, limit, malformed and source_gap. Request and response observations are independent. Direction and status-code metadata link them where a safe local correlation exists; do not export request IDs containing user values.

Approved request header names, response header names and query parameter names can accompany a record as distinct bounded lists. No header or query value can be transmitted. Names must be checked against policy; syntax validation alone does not make them safe.

Count is the number of locally observed interactions represented by one record. It is not total traffic unless the collector proves complete coverage. Sampling numerator/denominator and source identity accompany the count. Multiple collectors can see the same interaction. The platform shows separate source counts and does not sum them as unique business requests.

The checked batch operation projection borrows each record's structure and full
evidence: record/source identifiers, policy revision, canonicalization version,
visibility, completeness, reasons, count, sampling, status, observation times,
queue times and approved header/query names. It does not combine records or turn
sampled counts into traffic estimates. Unknown nodes remain unknown. A catalog
worker must validate durable inbox integrity and trusted scope before persisting
this projection; a decoded batch alone does not establish authority.

## PostgreSQL model

| Table group | Keys and purpose |
|---|---|
| tenants, projects, services, environments, deployments | Scoped identity and ownership |
| collectors, policies, policy_assignments | Enrollment, revocation, signed policy revisions |
| ingestion_batches, ingestion_payloads | Durable sanitized inbox and deduplication keys |
| operations, variants | Stable operation identity and immutable structure documents |
| observation_windows | Per-source counts, visibility, first/last time and loss context |
| declared_contracts, approved_contracts | Immutable versions and approval associations |
| discrepancies, reviews | Compared versions, decision, reviewer and concurrency version |
| audit_events | Actor, action, target, outcome and safe timestamps |
| delivery_outbox | Approved integration deliveries and retry state |

All tenant-owned foreign keys include tenant_id. Use unique constraints for scoped identities and batch IDs. Store authoritative canonical and wire structures in bounded bytea: accepted names can contain NUL, which JSONB cannot represent. Store common filters in typed columns. Optional JSONB projections must be lossless for their represented subset. Never modify an existing immutable contract version. Approval references exact versions and the review revision.

Accepting a batch is one transaction: write inbox and idempotency record together. Workers atomically mark processing and update derived records, or use equivalent transactional deduplication. Crash recovery must not double counts. Keep the deduplication record longer than the permitted retry interval.

Migrations use a separate role. Test install, upgrade, restore and rollback/recovery on actual PostgreSQL. Database rollback must not mean blindly reversing a destructive migration. Retention removes dependent records in an explicit order and preserves required approval evidence. Backup retention is part of deletion policy.

## Declared contract subset

R1 comparison supports operation identity, request/response direction, field types, required fields, nullability, object additional-properties policy and array item types. References must resolve within the supplied artifact. Cycles are represented as bounded named references in declared contracts, not expanded without limit.

Imports may contain enum values, examples, defaults, prose, patterns and extensions. Remove these from persisted content in this baseline and report removed_value or unsupported_construct. A comparison that depends on removed constraints is inconclusive, not compatible. Export must disclose the omissions. Do not imply lossless round-trip support. The richer source file remains in the customer's source repository, not in APIContour storage.

A partial observation remains evidence of present fields, but cannot prove field removal or changed requiredness. Presence statistics use only observations eligible for that field; incomplete parents are excluded from absence counts. Declared contract removal can be incompatible even when no recent traffic was observed.

### Catalog storage v1

Migration 0004 stores immutable UUID operations and variants, per-record source
evidence, and a transactional processed-batch claim. Exact canonical operation
bytes accompany a versioned hash. A variant key includes the collector-scoped
policy revision, parser profile and canonicalization version. Digest conflicts
require exact byte comparison by the trusted processor; mismatches fail closed.
Timestamp originals and approved-name JSON arrays preserve nanoseconds and NUL
escapes. No catalog row sums observations from different sources as unique traffic.
The worker and reader database roles have separate tenant-scoped grants, without
inheriting ingestion or administrative access. Storage alone does not implement
trusted processing or authenticated user queries. See `db/README.md` for the
transaction and adapter obligations.

### Bounded observed structural comparison

The native `compare_observed` function compares two checked operation observations.
The left side is the baseline; the right side is the candidate. Their full operation
keys must match, including tenant, project, service, environment, protocol and
request/response direction. Parser profiles and canonical versions must also match.
This check is not user authorization. An adapter must load both observations through
an authorized catalog scope before it calls the comparison function.

A successful observed comparison is always `Inconclusive`, including equal known
structures with no differences. Field addition, observed field absence, type changes,
and null membership changes describe evidence. They do not establish requiredness,
contract removal or request/response compatibility. Unknown nodes emit insufficient
evidence, including unknown items in an empty array. Incomplete, sampled or uncertain
observations retain an explicit evidence limitation without hiding other differences.
Changed general unions emit an unsupported-construct result; the function does not
attempt general union subtyping. An object `additional` observation is not a declared
additional-properties permission or prohibition.

Paths address the structural model. The nonempty root is `#`. Object fields use
`#/fields/<name>`, with `~` escaped as `~0` and `/` as `~1`; arrays use `#/items`,
additional observed structure uses `#/additional`, and general union members use
`#/alternatives/<normalized-index>`. Nested paths use the same segments. These are
JSON-pointer-style model paths, not URLs or paths into captured payload values.
Unicode and NUL remain intact in JSON strings. A field named `items`, `additional`,
`*` or `$` stays under `fields` and cannot collide with a structural segment.
Nullable single-base unions compare the base at the same logical path.

Traversal follows normalized UTF-8 field and union order. Limits are 1,024 Unicode
scalars per path, 10,000 differences, 1 MiB of aggregate stored path bytes, and 32,768
traversal visits, including recursive equality checks. Each visit can inspect at
most 64 immediate union members and bounded field names. Null-membership flags
are unknown when a union contains unknown evidence without an observed null member.
Primitive null-to-non-null changes retain both null-membership and type differences.
Checked input shapes retain their existing 32-level and 65,536-byte
canonical bounds. A limit returns an explicit error without a partial comparison.
No truncated result can imply compatibility. The result is an in-memory native
projection; comparison persistence, declared models and the public HTTP API remain
separate implementation work.

The mandatory `--catalog-reader` fixture runs comparison cases after reader checks.
It submits signed-policy-admitted records, processes their accepted inbox batches,
and reloads the records through the restricted reader before comparison. Coverage
includes a synthetic source-authorized parser-profile mismatch and separate
per-path, aggregate UTF-8 path-byte, and recursive-equality work limits. These
fixtures do not establish support for the synthetic parser profile. The 10,000
difference-count guard remains inspected rather than executed; the simple input
size bound does not prove that guard unreachable.

### Internal declared graph codec v1

The checked declared model is a flat graph, separate from observed shapes. Node
IDs and local definition names are preserved. Object properties have an explicit
required boolean. Nullability is Null membership in a union, not a second flag.
Additional properties are explicitly allowed, forbidden, or constrained by a node.
Arrays and unions refer to node IDs. Every edge resolves. Structural edges must
be acyclic; recursive paths use named Reference nodes and are never expanded.
Unions contain 2–64 distinct target IDs. This is not semantic graph-isomorphism
normalization: different IDs can describe equal shapes.

Unknown reasons are unspecified, omitted and unsupported. Omitted nodes require
removed_value; unsupported nodes require unsupported_construct. Every node has
closed omission codes, and the document summary equals their union. Codes contain
no values, prose or source URLs. Local names still need trusted import sanitization;
this codec does not establish that a name is safe to publish.

Input and deterministic compact UTF-8 output each have a 1 MiB bound. There are
at most 4,096 nodes, 32,768 edges including root/definition/reference edges, 256
properties per object, 256 definitions and 64 Unicode scalars per local name.
Operation identity reuses the checked eight-component key and its 2,048-byte
bound. Node/collection limits apply during decoding; the edge accumulator also
bounds retained node edges before a new node is stored. A single bounded node
is temporary scratch. Graph validation uses bounded iterative traversal.

Serialization sorts node IDs, definition/property names by UTF-8 and union target
IDs. Duplicate IDs/names/targets, unresolved references, unknown fields/tags and
inconsistent omission summaries are rejected. The codec has no observed-structure
fingerprint and makes no graph-isomorphism hash claim. It is an internal sanitized
model, not an OpenAPI/JSON Schema importer, database migration or compatibility
engine. Those adapters remain required work.
