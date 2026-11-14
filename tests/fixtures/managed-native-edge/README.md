# Owned native-edge held-stream fixture

These fixed synthetic scripts are fixture inputs, not an executable qualification
by themselves. Run the destination in the owned destination container with its
existing `/pilot/tls/server.key`, `/pilot/tls/server.crt`, and `/pilot/ca.crt`
mounts. Run the client in the owned replica with its existing `/pilot/tls/client.*`
and `/pilot/ca.crt` mounts. Keep the native Envoy, native gateway, internal
network and no-host-port boundary intact; use a separate owner-controlled stdin
for each process. The scripts print only fixed status labels.

For a held request, start `held_client.js request`; wait for `CLIENT_WRITTEN` and
for the destination's `REQUEST_PREFIX`. The latter proves that the first request
bytes reached the destination. Publish and independently confirm the edge
rotation while the client has not ended the request. Then send
`RELEASE_REQUEST` to the client and require its `PASS` and clean exit.

For a held response, start `held_client.js response`; wait for the destination's
`RESPONSE_WRITTEN` and the client's `RESPONSE_PREFIX`. The latter proves that the
first response bytes reached the replica. Publish and independently confirm the
edge rotation while the destination withholds the suffix. Then send
`RELEASE_RESPONSE` to the destination and require the client's `PASS` and clean
exit. Repeat both controls around rollback as well as renewal. Reject any `DIAG`,
unexpected output, failed process, deadline, mismatched bytes, or cleanup error.

The client uses normal TLS negotiation and actual replica mTLS. The separate
native-edge confirmation probe uses TLS 1.2 only to observe the server's acceptance
of client authentication without generating a synthetic HTTP capture. This
fixture does not establish throughput, an end-to-end latency SLA, or lifecycle
reload for the other native identities.

The source-only owner API uses separate private `state`, `published`, and
`watched` directories. A native integration must mount `published` read-only at
`/certs` and the directory `watched` read-only at `/run/watch`; mounting only an
individual `sds.json` file would prevent observing atomic replacements. The
read-only `native_edge_probe.js` must also be mounted at
`/pilot/native_edge_probe.js` in the selected replica. The `NativeReplicaPeer`
constructor requires operator-verified replica and Envoy container IDs, image
IDs, network ID, and complete expected source mappings for the four critical
mounts, eight existing replica profile mounts, and three fixed Envoy mounts.
Its confirmation rechecks those identities, the recorded start times, and the
unique Envoy alias before and after the TLS probe.

`prepare_initial()` verifies the exact created replica and Envoy identities, then
writes bootstrap SDS while retaining a pending journal. Start those same
containers; `bind_initial_peer()` observes their real start times and durably
records them before `reconcile()` confirms the served certificate. A binding
intent left without a complete result requires intervention; a recovered result
may be reconciled only against the same observed starts. The checked-in Compose
overlay does not yet provide that ordering or these mounts. A failed or
ambiguous publication remains pending and blocks new rotations. `renew_due()` is
an explicit owner call, not a background scheduler. All versions are retained;
32 versions is a fail-closed capacity limit, not a retention or garbage-collection
policy. The Docker CLI timeout is not by itself proof that a daemon-side exec has
been reaped, so the actual lane must verify process cleanup.
