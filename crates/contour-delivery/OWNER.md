# Caller-driven collector owner

`CollectorOwner` starts paused. Only its private completed authenticated
`/v1/collector-authority` exchange grants admission or send authority. The fixed
DeliveryClient supplies TLS identity and endpoint; installed PolicyKeys verify the
original raw signed envelope. Each exchange generates 32 fresh random bytes and
checks the challenge, configured tenant/collector and exact unique requested
source set. Requests are at most 32KiB; complete replies at most 8MiB.

A live lease ends at request-start monotonic time plus the smaller of 15 minutes
and signed expiry minus authenticated database checked_at. Completion, admission,
freeze and delivery also enforce local policy time checks. Delivery uses an outer
monotonic lease deadline around existing transport deadlines. Dropping refresh or
send futures drops owned I/O and reservation borrows and leaves the owner paused.
Call refresh after cancellation before resuming work. Refresh failures pause;
HTTP403 does not permanently revoke the queue.

The same MemoryQueue preserves revision/content highwater across every refresh.
Current policy is included in AdmissionInputs history. Verified historical policies
needed by pending/frozen records remain retained, including policies since expired.
Unused history is pruned; at most 500 policies and 8MiB of original signed-envelope
lengths are retained. This is a logical envelope-byte budget, not a measured heap
or RSS bound. A refresh that cannot fit pauses without forgetting retained policy
history. No serialized authority or restart cache grants access.

Successful local admit/freeze results report the committed queue mutation even
if authority expires during that operation. Live authority is then cleared; later
admission/send requires refresh. Inspect is_live separately from local success.

Callers admit structural RecordDraft values, freeze a bounded prefix, send once,
and service retry waits and deletion-only expire_retained maintenance. Checked
receipts are acknowledged only after transport ownership ends. Retry decisions
reuse RetryController; 400/422 discard the frozen binding, 401/403 require online
refresh, and terminal conflict/split states remain stopped. Refresh narrowing
reconciles the queue before any later send. This slice does not implement raw
capture sanitization, enrollment, scheduling, durable queues or general 413 split.

`python3 scripts/test-postgres-tls.py --https-only` builds owner_probe and runs
scripts/test-collector-owner.py through the actual local mTLS/Postgres fixture.
The fixture checks startup denial, online refresh/admission/send, durable receipt
identity and zero charge, narrowing/highwater, temporary denial/renewal, retained
history after policy expiry, pending-send cancellation before narrowing, retry waits
and terminal statuses, signed revision conflicts, and real TLS challenge/source/
identity/late/cancelled/truncated reply rejection and server-name/root failures. It is synthetic
fixture data and requires the existing local tools/image. The signed-padding fixture exercises aggregate history capacity exhaustion and
retained charges; the 500-policy count bound is inspected, not stress-tested.
