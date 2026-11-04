# Fixed Node-RED runtime ownership experiment

This is a dormant, instrumented synthetic profile for Node-RED 5.0.9 and Node
24.22.1. It is not enabled in the normal application or qualified for arbitrary
flows. Its bounded ledger contains closed intent kinds and opaque identifiers;
messages, business values, URLs and headers do not enter that ledger. No transport
header is added. An intent alone does not authenticate an API call or prove a wire
attempt, cross-instance continuation or complete causal graph.

## Run the complete qualification

```sh
python3 -B scripts/test-nodered-causal.py
```

The command requires Python 3, OpenSSL and Docker. It uses only this image:

```
docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963
```

It pulls that exact digest only when absent. All 23 offline regressions run inside
the image against its Node 24 and unmodified vendor source. Four separate runtime
cases then exercise the legacy HTTP baseline and the instrumented HTTPS profile
with valid trust, an unrelated CA, and a mismatched server name. The TLS fixture
checks normal fan-out with reversed completion, serial calls, a 503 retry, and
request→Catch→count parent chains on rejected TLS exchanges. The offline suite
also covers getter reentry, method and hook mutation, one-use handoffs, bounds,
expiry, CommonJS parent/cache behavior and failure cleanup.

Containers use read-only mounts and filesystems, network isolation with only
container loopback, dropped capabilities, resource limits, and no host ports.
Private synthetic certificates are generated and removed by the driver. Container
removal requires the owned label and immutable ID. Timeouts, daemon errors, changed
sources and unproven cleanup fail the run. There are no acceptance skip switches.
The command never reads or changes an existing `.local-mvp` directory.

## Selected instrumented profile

`error-integration/bootstrap.js` accepts only the exact fixture entrypoint, flow,
Node/Flow/HTTP source hashes, launch environment and single preload declared in
`error-integration/profile.js`. It temporarily compiles the two pinned vendor
modules with private lexical handoffs, restores the CommonJS compiler, and binds
actual node identities after the fixed flow starts. It exports only snapshots and
invalidation; installed control and bridge objects are not application exports.

The selected profile creates roots only for actual POST `/run` requests at node
`in`, using own method/URL data descriptors before scrubbing. Queries, case or
trailing-slash variants remain forwarded but unowned. This predicate conveys no
capture authorization; server-owned profile and session binding are still needed.
Normal delivery consumes the exact pending dispatch event before application
getters run. Error delivery captures its owned parent before the Catch method
lookup. Stage/target checks, fresh control-event bindings and finally cleanup
prevent the tested reentry and replay cases from stealing a delivery. Unqualified
calls forward with explicit loss. Pending state and event count/bytes are bounded;
expiry is checked at subsequent hooks and snapshots. Deep caller reflection,
hostile native code, global intrinsic replacement and module-cache tampering are
outside this profile.

The bootstrap and profile are immutable owner-supplied trust roots. The operator
must enforce the pinned image, read-only source mounts, fixed entrypoint/module
set, absence of additional preloads, and isolated networking. In-process hashes
and guards cannot attest those prerequisites. `registryIntact` and `ready` are
local indicators, not platform attestation or capture authorization.

## Evidence boundaries and legacy fixtures

The ordinary `bootstrap.js`, `runtime.js`, `profile.js` and original HTTP/TLS
fixtures remain as an unchanged comparison baseline. That hook-only baseline
reports loss on direct Catch dispatch; it does not qualify error-path ownership.
The complete command uses the separate instrumented profile for HTTPS and Catch
qualification. Historical models explain rejected mechanisms and are not runtime
or transport evidence.

This selected-profile qualification does not establish authenticated event
ingestion, signed runtime enrollment or live sessions, a real gateway attempt
witness, cross-instance identity, durable graph storage, platform lifecycle
handling, performance targets, universal product coverage or full MVP acceptance.
Those capabilities need their own implementation and execution evidence.
