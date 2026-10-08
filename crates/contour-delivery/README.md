# One authenticated delivery attempt

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

This library implements one attempt, not a retry scheduler, splitting, discovery,
persistent storage or revocation notification. Non-200 status is classified;
`Retry-After` parsing and scheduling remain a later API extension. It does not
claim wall-clock or process scheduling guarantees beyond cooperative deadlines.

The separate local `--delivery-only` fixture runs the actual full queue
through verified HTTPS and restricted PostgreSQL, then checks release to zero.
Fault relays first obtain a committed receipt from the actual server, damage its
reply and verify unchanged retries recover the same receipt and persisted bytes.
The cancellation case waits for a real committed partial response before dropping
a pending send future, then checks peer EOF while the probe runtime remains alive.
The late case deliberately pauses polling while a complete committed reply arrives,
resumes after the deadline and checks rejection; this is not a branch coverage claim.
