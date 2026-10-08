# Bounded sanitized retention

`MemoryQueue` owns in-memory retention and one frozen batch. It has no network,
retry scheduler, splitting or durable storage implementation. It accepts only opaque
`RecordDraft`, not caller-declared `CheckedRecord` queue timestamps.

Limits are 1–500 retained records and 1–256 MiB of conservative wire charges,
further restricted by the current signed policy's queue byte quota. Each entry is
charged its draft's bounded record serialization plus 391 bytes: two maximum
35-byte timestamp replacements, a comma and 320 bytes of complete batch envelope
reserve. A frozen batch additionally charges its owned serialized buffer. Record
charges remain while frozen/in flight. Charges overestimate eventual wire bytes;
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
errors do not expose record metadata. The acknowledged counter counts records
released by matching receipt evidence; purged counts local discard/cancellation,
not proof that a server never accepted them. Unit tests are not callback contention/
latency or network integration proof.

## Frozen ownership

`freeze` selects a bounded FIFO prefix, preserving record counts and original
queue/expiry timestamps. It first measures bounded serialization without allocating
the retained output, checks quota for the additional exact wire length, then
creates the immutable owned wire buffer and digest. Failed payload sizing or
buffer reservation leaves records and charges intact. Mandatory reconciliation
can independently purge data invalid under the supplied current snapshot.

`FrozenView` borrows ID, exact bytes, digest, creation time and earliest original
record deadline. `delivery_view` rechecks current shared admission and marks local
in-flight ownership without releasing capacity. Repeated views retain identical
bytes/IDs/counts/deadlines. Freshness is checked when issuing the view, not throughout
subsequent I/O. Rust borrowing prevents queue mutation while that view is held;
future transport must handle cancellation and any additional copies explicitly.
Caller copies are outside queue-owned accounting; no owned payload transfer API exists.

Any selected record becoming expired or noncompliant cancels the whole frozen
batch. The queue never edits content under its active ID. Quota shrink likewise
cancels the oldest frozen group before further FIFO eviction. Cancellation drops
its wire charge and records together; expired records and other purged records
have distinct loss counters. Revocation drops all pending/frozen data.

`Acknowledgement::from_transport` checks scoped IDs and receipt UUID/time syntax.
The caller must supply evidence from independently authenticated transport and a
known committed server result. This constructor does not establish either fact.
`acknowledge` additionally requires in-flight ownership and exact active identity,
batch ID, digest and opaque `DeliveryBinding`. A binding routes callbacks by local
process-instance/generation; it is not authorization, randomness or durable identity.
Stale/mismatched evidence leaves data and counters unchanged. Matching evidence
releases only that frozen group. `discard_frozen` requires its exact binding and
counts whole-group local loss; it is not a generic Boolean release operation.

Supplied batch IDs receive syntax checks only. Callers must use a unique ID for
different content; there is no unbounded retired-ID ledger or global reuse guarantee.
The server's immutable digest conflict check remains mandatory. Local generations
prevent stale callbacks releasing a replacement, including deliberate same-ID
reuse. Random UUID generation and authenticated HTTP delivery remain separate work.
