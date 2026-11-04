# Causal HTTPS receipt (experimental)

A separately configured `CausalServer` accepts `POST /v1/causal-events` over
mandatory verified mTLS. The operator registry maps the verified leaf digest
to an already committed session. This mapping is enrollment configuration; it
does not attest the process or producer code that used the certificate. There
is no remote session issuer or durable session recovery in this endpoint.

After a confirmed inbox commit, the `application/json` response contains exactly
`batch_id`, `runtime_id`, `session_epoch`, `batch_digest`, `receipt_id`,
`accepted_at`, and `status`. Status is `accepted` or `duplicate`. `batch_digest`
is lowercase SHA-256 of UTF-8 `apicontour/causal-events/1\n` followed by the
exact canonical batch bytes. `session_epoch` is an unsigned 64-bit JSON number;
clients must parse it without a lossy floating-point conversion. The receipt UUID
and acceptance time are database results. Batch identity and digest let a sender
correlate a receipt with its original frozen bytes; they do not authenticate a
client-supplied acknowledgement.

A failed or interrupted commit can yield `outcome_unknown`; retry the same
canonical bytes, batch UUID, and session epoch. Replaying into a different epoch
is not supported. Errors contain closed redacted codes and a request ID. No wire
attempt, capture-policy enforcement at the producer, durable queue, graph, or
cross-instance proof is implied by receipt acceptance.
