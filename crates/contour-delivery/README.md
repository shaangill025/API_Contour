# Authenticated attempts and bounded retry decisions

`DeliveryClient` uses an operator-resolved socket address, a separate verified TLS
server name, explicit trust roots and client credentials. It sends HTTP/1 over
TLS 1.2/1.3 to `/v1/batches`; redirects, system roots, DNS resolution, session
resumption and early data are disabled. Configuration is not enrollment.

`send_once(&mut DeliveryReservation)` takes one transport copy of already charged
frozen bytes. Its absolute deadline starts before sampling the wall clock and is
clipped to the reservation's verified authority lease and record TTL. Request,
socket and HTTP driver remain owned by the future and drop on cancellation.
Conversion from the verified lease to a monotonic deadline depends on the
operator-trusted wall clock. Callers must cancel and drop that future before
applying a trusted policy update;
the exclusive queue borrow deliberately prevents concurrent reconciliation.

Only a complete bounded 200 receipt with exactly four fields, matching batch UUID,
canonical receipt UUID and checked RFC3339 time creates `CheckedReceipt`. Consume
it with the same reservation to acknowledge after network owners have dropped.
Failures retain the original frozen identity, binding, digest, bytes and charges.
A transport failure can conservatively reject an otherwise ready response;
retrying the same frozen batch recovers the server's duplicate receipt.

`RetryController` is bound to one frozen delivery binding. It owns metadata only,
never the queue or a payload/reservation. Retry ceilings double from 1 to 60 seconds
with uniform millisecond full jitter from Ring. A single bounded `Retry-After`
(delta seconds or standard HTTP date) is capped at 300 seconds; malformed or
duplicate values fall back to jitter. Status/header classification ignores error
bodies. Only successful 200 replies use the strict receipt body decoder.

400/422 requests discard; the owner passes the controller binding to
`MemoryQueue::discard_frozen`, which checks it and increments a safe loss counter.
401/403 hard-pauses for authorized enrollment renewal, 409 stops for conflict and
413 requires splitting without retrying unchanged content. Other 5xx, 429 and
uncertain transport failures preserve exact retry data. Terminal states have no resume method; constructing another controller is not
proof of authorized renewal. No boolean or cached-policy online-grant shortcut is
provided. Splitting/enrollment are not implemented.

Waits are cancelable and clipped to original record TTL. Drop all network and
reservation owners before waiting, service the bounded capture channel separately,
and obtain fresh trusted authority/source inputs before reserving again. Cancel
wait/send on trusted scope updates and reconcile; known identity revocation purges.
While paused, `MemoryQueue::expire_retained()` performs deletion-only maintenance
without granting authority, renewing timestamps, changing identity or high-water
revision evidence. The owner must schedule this at `retained_until()`.

This is a caller-driven controller, not the full background scheduler, splitting,
discovery, enrollment, durable local storage or revocation notification. It does
not claim scheduling guarantees beyond cooperative deadlines or authenticate an
online startup grant. Those remaining integrations are required release work.

The separate local `--delivery-only` fixture runs the actual full queue
through verified HTTPS and restricted PostgreSQL, then checks release to zero.
Fault relays first obtain a committed receipt from the actual server, damage its
reply and verify unchanged retries recover the same receipt and persisted bytes.
The cancellation case waits for a real committed partial response before dropping
a pending send future, then checks peer EOF while the probe runtime remains alive.
The late case deliberately pauses polling while a complete committed reply arrives,
resumes after the deadline and checks rejection; this is not a branch coverage claim.
