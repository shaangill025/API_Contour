# Bounded sanitized retention

`MemoryQueue` is a single-owner in-memory retention component. It has no export,
freeze, in-flight, delivery, network or durable storage API. It accepts only opaque
`RecordDraft`, not caller-declared `CheckedRecord` queue timestamps.

Limits are 1–500 retained records and 1–256 MiB of conservative wire charges,
further restricted by the current signed policy's queue byte quota. Each entry is
charged its draft's bounded record serialization plus 391 bytes: two maximum
35-byte timestamp replacements, a comma and 320 bytes of complete batch envelope
reserve. No serialized copy is retained. Charges overestimate eventual wire bytes;
they are not an RSS, allocator overhead or allocation-free callback guarantee.
Temporary serialization uses the existing 1 MiB capped writer. Caller-owned draft
allocation and trusted snapshot registries are outside the retained charge.

Admission first reconciles current authority, expires old records and checks the
same complete record/source/recursive metadata/name/route/depth/profile/TTL rules
used by `validate_admission`. New capture must use the current revision. With
exclusive ownership it reserves capacity, samples its checked local wall clock
again, reconciles and revalidates, then privately stamps immutable queue and expiry
times before retaining the record. Full queues drop the new draft without changing
retained data. Duplicate retained record IDs reject. A backward clock sample within
admission fails closed. Timestamps remain unchanged on reconciliation.

Call `reconcile` on every trusted snapshot update; admission also calls it
automatically. Narrowed scope or missing historical/source authorization purges
noncompliant entries. Quota shrink evicts oldest entries until charges fit. An
unusable current lease/disabled policy purges retained data conservatively. Expired
historical leases alone do not purge records valid when queued. `revoke` permanently
disables and clears this object; there is no reactivation or transfer API.

The identity-bound in-process revision/content guard survives clearing and signed
disabled updates. It is not protected persistent high-water storage. Snapshots
remain caller-supplied authority; neither construction nor this queue proves
enrollment, operational revocation discovery, online freshness or trusted restart.
No authenticated boolean is accepted. Those lifecycle and startup integrations
remain mandatory before claiming a complete collector.

`QueueStats` reports retained charges/counts and saturating dropped, expired, purged
and rejected counters. Rejected includes rejected snapshot operations. Debug and
errors do not expose record metadata. Frozen/in-flight accounting, retry bytes/IDs,
splitting and random UUID generation belong to later slices; none is implemented
here. Unit tests are not callback contention/latency or network integration proof.
