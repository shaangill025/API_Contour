# Native gateway local performance screen

`python3 scripts/bench-native-gateway.py` runs an owned, synthetic, local screen:
three paired blocks in fixed A→B→C order, with 50 sequential requests per lane, using A (direct Envoy to the
verified HTTPS destination) as the primary baseline, B (Envoy to a gateway with
an unsynchronized pool), and C (Envoy to the gateway with a real authority and
capture delivery). The client uses the same replica and connection strategy in
each lane. The output is explicitly `SCREEN_ONLY` and is not target acceptance.
The nearest-rank p99 of 50 successes is the maximum; one successful readiness
request is not representative warmup. Connections from the client are fresh and
concurrency is one. The closed-loop achieved rate is not saturated capacity and
may omit coordinated delay; fixed order permits drift. It does not measure
callback latency, establish causal attribution, or explain capture-count differences.

Prerequisites, supplied and run by the operator: the complete existing synthetic
`.local-mvp` TLS mounts expected by `deploy/pilot/compose.yaml` and the native
profile, including independent gateway-to-destination identity and capture
server/collector identities; Docker and OpenSSL; and the existing pinned base
images needed for the fixture build and runtime. The checkout's `.local-mvp`
must refer to that synthetic mount. No shared pilot database or shared image tag
is used. The driver creates an owned Compose project, internal networks, fresh
signer/passwords and a tmpfs PostgreSQL database, and removes its resources on
exit. The image build uses locked existing dependencies and may need ordinary
build networking. The live fixture has **not** been run by the implementer.

A derives from the existing Envoy generators, retains the same authenticated
downstream edge, uses an exact destination SAN and SNI, trusted destination CA,
HTTP/1.1 ALPN, and converts the native gateway's configured destination client
certificate and key to PEM. It brackets wrong-name and wrong-CA controls with positive forwarding, checks
the downstream authenticated TLS handshake, and requires a fresh typed upstream
certificate-verification counter from the same Envoy container. A forced
unavailable-destination control must fail the TLS-negative assertion. The
fixture-only Envoy admin binds to loopback and is queried by a disposable pinned
Node container sharing that edge container’s network namespace. B uses
a fixture-only gateway that never synchronizes. C uses a fixture-only online
runner that completes the real pool synchronization before accepting requests,
keeps the normal poll and delivery tasks, and performs no refresh during the
measured block. Each C process is fresh; startup readiness must persist request
and response observations, and the elapsed time and remaining signed-policy
lease are bounded. Persisted request/response counts are scoped, shape checked,
and compared after a bounded drain, both per block and in aggregate. Matching
counts do not establish per-request coverage or continuous authority; delayed
readiness and failed attempts can cross windows. The process-lifetime PID1 VmHWM
is recorded for each C block; the overall value is null if any block is missing.
It is neither stack RSS nor target evidence.

Offline checks: `python3 scripts/bench-native-gateway.py --self-test`,
`node --check tests/fixtures/native-perf/client.js`,
`node --check tests/fixtures/native-perf/edge-ready.js`,
`node --check tests/fixtures/native-perf/admin-stats.js`, and
`cargo check --locked -p contour-ingress --example native_perf_paused --example native_perf_online --offline`.
The direct baseline and runtime isolation still require the operator's live run.

For separately obtained sanitized measurements, `--report` reads JSON from
stdin. The input contains `blocks` (each with `A`, `B`, and `C` objects with
`attempted`, `success_ms`, `errors`, `timeouts`, and `elapsed_ms`), `capture`
(`successful_C_requests`, `persisted_request_observations`,
`persisted_response_observations`, `drain_seconds`), and
`gateway_pid1_vmhwm_kib_by_block` (one integer or null per block). Do not include payloads, markers,
identities, credentials or request IDs. The report helper does not verify
fixture configuration, lease, or provenance of supplied measurements.

The online fixture accepts SIGUSR1 only inside its owned Linux container. Each
request produces one bounded, numeric `NATIVE_PERF_METRICS` snapshot after the
existing authority poll returns. The driver checks the exact gateway container,
requires a fresh consecutive snapshot, checks monotonic counters and rejects
malformed or missing output. It records per-C-block before/after values and
deltas for the pool's aggregate loss counter and delivery outcomes (acknowledged,
deferred, error, empty). These are aggregate outcomes, not counts of unique
requests or a breakdown of loss reasons. The parsed gateway configuration's
actual slot, records-per-slot and bytes-per-slot values are reported numerically
for each C process; the fixture does not alter them.

The database cohort snapshots separately report total ingested record counts,
processed and pending batch counts for the unique collector in this owned
project, and the scoped projected-window count. The metrics and database
snapshots are taken outside the measured request window and are not atomic with
one another. Readiness, retries, delivery, and drain can cross those boundaries.
Even a matching aggregate count or a positive counter cannot establish
per-request coverage, continuous authority, a loss reason, or a target pass.
Missing or nonconsecutive signal output fails the screen; it is never replaced
by a zero. Linux signal delivery, logging, and SQL snapshots require a separate
operator-run live check.

Instrumentation can perturb lane C: delivery counters perform atomic operations
inside its worker loop, and snapshot output can block the current-thread runtime
if Docker logging stalls. Snapshots are requested outside the measured window,
but this remains a SCREEN_ONLY diagnostic rather than performance acceptance.
A saturated counter has an unknown delta and causes the screen to fail rather
than reporting zero.
