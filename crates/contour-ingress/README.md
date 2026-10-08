# Operator-configured HTTPS ingestion

`CollectorTls` requires client authentication with explicit Ring and supplied DER
trust anchors. TLS 1.2/1.3 and HTTP/1.1 are supported; session storage, tickets
and early data are disabled. Server and root bundles each contain 1–8
certificates totaling at most 64 KiB. The DER private key is 1–16 KiB; key-memory
erasure is not guaranteed. Configuration must come from the operator. A Tokio
runtime with I/O and timers enabled is required.

`cargo +1.88.0 test -p contour-ingress --locked --offline` executes the separate
mandatory TLS integration fixture with ephemeral keys and bounded loopback
sockets. It checks both TLS versions, missing/untrusted/wrong-purpose clients,
full repeated handshakes, and stalled/cancelled socket cleanup. The HTTP/Rustls/
Ring dependencies use exact reviewed pins without AWS-LC or vendored native
OpenSSL; Ring compiles bundled C/assembly. Database native TLS is unchanged.

`IngestionServer` owns a mandatory-mTLS HTTP/1 listener and the connections it
accepts. `PrincipalRegistry` maps the SHA-256 fingerprint of the verified leaf
certificate to one checked tenant/collector pair. Configuration is bounded to
128 unique fingerprints; certificate subjects and HTTP identity headers do not
grant authority. Enrollment, certificate rotation and online revocation remain
separate work.

The endpoint accepts exactly `POST /v1/batches`, JSON, with no query string,
compression, upgrades or trailers. It permits one request per connection, at
most 64 headers and 16 KiB of headers, and at most 1 MiB of actual streamed body
bytes. The configured connection cap is 1–64; excess sockets are closed before
TLS or task creation. These are logical bounds, not an RSS guarantee.

A cooperative absolute deadline starts before TLS and covers the request body,
database submission and response. Explicit shutdown aborts and joins owned
connections; dropping the serving future aborts them. DNS helper cancellation
and synchronous CPU work have the limits documented by the PostgreSQL adapter;
this is not a hard real-time deadline.

The body must match the certificate's installed scope before database access.
The handler uses `submit_batch` directly after structural decoding, preserving
the committed retry path for expired historical records and the current policy
checks. A 200 response contains the durable receipt's original batch ID, receipt
ID and acceptance time, with `accepted` for the first insertion or `duplicate`
for an integrity-checked retry. Known COMMIT success survives cleanup failure.

Handler errors contain static code/message, an OS-random request UUID, and a
retryable flag. Hyper framing/header errors can close the connection or return
its own protocol response before dispatch. A 503, timeout, or truncated/lost
response must be retried with the same batch ID and content: it can follow a
committed transaction. In particular, `outcome_unknown` is not a rejection.

`python3 scripts/test-postgres-tls.py --authority` retains the existing TLS,
authority, atomic submission and recovery cases. The separately required
`python3 scripts/test-postgres-tls.py --https-only` runs the actual HTTPS-to-
restricted-PostgreSQL flow. Both preserve their 240-second gate budgets. The
temporary keys, certificate registry and listener
are synthetic fixture configuration. There is no production executable,
collector delivery client, queue acknowledgement integration or enrollment API.

Shutdown joins owned HTTP tasks and aborts their owned database drivers. Remote
PostgreSQL work waiting on a lock can remain until its configured lock/statement
timeout detects the closed client; immediate remote query cancellation is not
promised. The fixture observes local STOPPED/client EOF and subsequent backend
release within that timeout plus a fixed margin while its runtime remains alive.
