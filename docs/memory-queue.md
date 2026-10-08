# Bounded sanitized retention

`MemoryQueue` owns in-memory retention and one frozen batch. It has no network,
retry scheduler, splitting or durable storage implementation. It accepts only opaque
`RecordDraft`, not caller-declared `CheckedRecord` queue timestamps.

Limits are 1–500 retained records and 1–256 MiB of conservative wire charges,
further restricted by the current signed policy's queue byte quota. Each entry is
assigned a base allowance C: its bounded draft record serialization plus 391
bytes for two maximum 35-byte timestamp replacements, a comma and 320 bytes of
complete batch envelope. Admission reserves 3C, using checked arithmetic, for the
retained record allowance, eventual frozen wire and one transport copy. Reserved
charges remain unchanged while freezing/in flight, so an exactly full queue can
still deliver a bounded prefix without additional byte headroom. Charges
overestimate eventual wire bytes;
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
the retained output and verifies its actual wire length W does not exceed the
sum S of selected base allowances. It then creates the immutable owned wire
buffer and digest. For total retained base allowances C_total, retained record
wire allowance plus frozen wire plus one transport copy is bounded by
C_total + 2W <= C_total + 2S <= 3C_total. The independent 500-record/1 MiB batch
limit still applies. Failed payload sizing or an inconsistent allowance leaves
records and reserved charges intact. Mandatory reconciliation
can independently purge data invalid under the supplied current snapshot.

`FrozenView` borrows ID, exact bytes, digest, creation time and earliest original
record deadline. `delivery_view` rechecks current shared admission and marks local
in-flight ownership without releasing capacity. Repeated views retain identical
bytes/IDs/counts/deadlines. Freshness is checked when issuing the view, not throughout
subsequent I/O. Rust borrowing prevents queue mutation while that view is held;
future transport must handle cancellation explicitly. No owned payload transfer
API exists. Arbitrary caller allocations are not metered by this library.

`reserve_delivery` rechecks current authority and returns a non-Clone
`DeliveryReservation` holding the exclusive mutable queue borrow. Its mutable
`view` exposes only borrowed frozen data. A transport consumer must accept
`&mut DeliveryReservation`, allocate at most one bounded copy within its reserved
allowance, and keep request-body/socket/driver ownership local to that consumer's
future. Do not detach a driver or export a body that outlives the reservation.
Concurrent mutable sends cannot share this handle. On cancellation, drop all
network/body owners before dropping the reservation and reconciling or purging.
Dropping the handle alone retains all charges and the exact batch for retry.
A matching acknowledgment consumes the handle only after authenticated known-commit
receipt validation and transport cleanup. This API does not perform those steps.

Any selected record becoming expired or noncompliant cancels the whole frozen
batch. The queue never edits content under its active ID. Quota shrink likewise
cancels the oldest frozen group before further FIFO eviction. Cancellation releases
its records and their complete upfront reservations together; expired records
and other purged records
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
