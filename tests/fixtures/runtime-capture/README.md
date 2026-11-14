# Runtime capture live fixture (not yet executed)

The owning command is `python3 scripts/test-postgres-tls.py --runtime-capture`.
It requires the existing pinned PostgreSQL image locally, Docker, OpenSSL,
and offline Cargo dependencies. It creates a fresh private Cargo target and
checks source and artifact identities. It opens loopback listeners and an
owned PostgreSQL container; only the authorized actual-test lane should run it.
The command uses `scripts/test-runtime-capture.py` for lifecycle and assertions.

The fixture is an actual Hyper HTTP/1 application, with independent loopback
plaintext and host-terminated mTLS listeners. It has no authority bypass. The
owner must supply an isolated, approved V2 authority and delivery endpoint,
including a currently signed policy, enrolled collector and runtime source.
Use the same setup and credential construction as
`scripts/test-postgres-origin-sensor.py` and `origin_sensor_probe`: no
production credentials, no application body logging, and no claims based only
on queue counts. Authorize `POST`, `probe`, `result`, `pilot`, and
`http_json_v1` in that signed policy. Set the source workload to the four
configured project/service/environment/deployment IDs. Four owner slots use
the existing signed limits and owner queue limits.

Build `cargo build --locked --offline -p contour-ingress --example runtime_capture_probe`.
Supply one JSON config with the fields in the example's `Config`: DER host
server certificate/key and client CA, loopback delivery address, delivery TLS
name, CA and enrolled client certificate/key, tenant, collector, source,
four workload IDs, policy key ID and its 32-byte public key file. The owner
starts the probe with piped stdin/stdout and owns all processes and resources.
`READY <http_port> <https_port>` is emitted only after a successful actual
authority synchronization. HTTPS clients must verify the server and present
an independently issued client certificate.

Commands are line based. `DRAIN` freezes and delivers each slot and prints
`DRAIN <losses> <acknowledged_batches>`; `SYNC` refreshes authority;
`DETACH` waits for adapter detachment; `ATTACH` replaces it;
`STOP` ends the host. Each command must be bounded by an external deadline.
The driver must fail on nonzero exit, unexpected output, timeout, retry,
rejected delivery, or unexplained losses. DRAIN acknowledgement is necessary
but insufficient: inspect committed V2 delivery records after each case.

Use the query pattern in `scripts/test-postgres-origin-sensor.py`'s
`snapshot()`: join `ingestion_v2_metadata` to `ingestion_payloads`
and expand the checked batch records, left joining `origin_proofs`. Return
one `{record, metadata}` dictionary per record, with normalized status
as a JSON integer or null, the metadata fields consumed by `assertions.py`,
and `origin_proof` null if no proof row exists. Filter by the isolated
tenant and collector. `assert_new_records` compares immutable history,
directions, exact structures, fixed scope, statuses and unattributed origin.
Ensure signed policy permits the two expected field names. Compare with a
gateway observation under equivalent scope and policy, accounting for the
gateway fixture's configured application response.

For each transport, start with an empty committed snapshot, POST fragmented
`{"probe":true}` to `/pilot` with JSON content type, and verify the host
returns status 201, the unchanged content type and `{"result":1}`. DRAIN
and assert exactly the two structures in `NORMAL`; spoof the origin witness
header and repeat, still expecting unattributed records. Test mismatched path,
method and query, unsupported request encoding, request declared trailers,
actual chunked trailers, dropped/errored body, malformed and oversized JSON,
and the `x-fixture-trailers: yes` response mode. Verify bytes, status and
trailers independently from record expectations. For malformed/oversized
bodies assert the existing extractor's typed unknown or existing downstream
admission rejection, as observed from actual delivery; do not count absent
records as a typed result.

To exercise stale callbacks, send part of a chunked request with
`x-fixture-hold: yes`, then send `WAIT_HOLD` and wait for `HELD`; the host has
polled the first body frame and waits at the barrier. Send `DETACH`, then
`RELEASE` and send the remaining chunk and finish. Verify no old-stream
admission after acknowledged detach. ATTACH and verify a fresh stream can
deliver; repeat with overlapping requests. Change/revoke the real authority
and SYNC to exercise an epoch switch, and let the real lease expire for the
deadline case. Assert each boundary from committed records and application
wire behavior. The example has no deterministic body error injection; the
owning driver must add this before claiming that case.

The fixture has not yet been executed. It does not currently automate all
cases described above, including gateway comparison, deadline/epoch changes,
and deterministic body-error injection. No services, ports, SQL, privacy,
performance, or lifecycle tests were run by the worker.
