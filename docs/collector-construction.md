# Checked record construction

`contour-core` provides pure record construction and batch assembly. It does not
implement a queue, capture authorization, privacy approval, UUID generation or
network delivery.

`RecordMetadata` borrows IDs, operation/route/parser metadata and header/query
names, with checked observation timestamps and numeric counts. Workload identity
order is project, service, environment, deployment. `RecordDraft::from_observation`
consumes an existing `Observation`, bounds every borrowed string and list before
copying, and reuses the record wire validator. The result is opaque and cannot be
serialized or passed directly to batch assembly. Metadata, drafts and checked
records have redacted Debug output; failures use static `BatchError` categories.

`RecordDraft::declare_queue_times` consumes a draft and explicitly declares checked
queue/expiry timestamps, returning an immutable `CheckedRecord`. These are supplied
values, not proof that enqueue occurred. Read-only getters preserve their original
RFC3339 text. IDs likewise receive lowercase UUID syntax checks, not randomness
or identity authentication guarantees.

`Batch::assemble` consumes 1–500 checked records, a supplied batch ID, expected
tenant/collector and creation time. It reuses envelope validation, rejects duplicate
record IDs and inconsistent timestamps, and caps normalized serialization at
1 MiB. Assembled batches use the same wire format and versioned request digest as
`Batch::from_wire_json`. The constructor maps the existing observation completeness
and limit/permission/malformed reasons; wire decoding retains its wider reason set.

Checked shapes omit business values. Operation, route, field and header/query names
are still untrusted metadata: syntactic construction can succeed even when those
names are forbidden. Full `validate_admission` with current/historical signed policy
and authoritative source assignments remains mandatory before persistence or use
as captured data. Construction does not establish policy freshness or revocation.

A future memory queue must accept only `RecordDraft`, check current signed policy,
source and every recursive metadata/name/route rule through shared admission before
persistence, reserve capacity, then privately stamp immutable queue/expiry times
on successful admission. It must not accept caller-declared `CheckedRecord` times
as proof of enqueue. Queue accounting, expiry, retries, splitting and an approved
random UUID source remain separate implementation slices. This API makes no
callback latency or allocation-free capture claim.
