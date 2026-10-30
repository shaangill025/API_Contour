# Opt-in native HTTP/1 pilot

The native overlay is a fixture scaffold. It does not establish production
origin, causal attribution, HTTP/2, performance, or general MVP readiness.

Combine `compose.yaml` and `native-overlay.yaml` with profile `native-capture` only
on an owned local stack. The existing `apicontour-local_default` network must be
available. Build the local application image using the pinned project Dockerfile;
preload the digest-pinned Envoy and Node-RED images. No host port is published by
the overlay. Use the pilot's `PILOT_TARGET=https://pilot-gateway:9443/pilot`.

After the ordinary owned local stack and stock pilot have been initialized,
create the closed pilot capture profile and its separate identities once:

```sh
python3 deploy/local/capture_init.py --profile pilot
python3 deploy/local/capture_provision.py --profile pilot
python3 deploy/pilot/native_prepare.py
```

The pilot profile reuses the existing restricted ingress and worker login
credentials; it does not create or change those roles. The fixed 0304 instance
records the observer capture point and is not evidence of workload origin.
Existing or partially created identities are never overwritten. If a pilot
policy expires or its journal needs reconciliation, explicitly run
`python3 deploy/local/capture_renew.py --profile pilot`; do not regenerate keys.
Immediately before each startup, the operator wrapper must run
`python3 deploy/pilot/native_prepare.py --check` and stop if it fails. Running
Compose directly bypasses that preflight.

Preparation creates two separate, private directories under `.local-mvp/pilot/native`:

* `forwarder/` contains `envoy.json`, `edge.pem`, `edge.key`, `pilot-ca.pem`,
  `observer-ca.pem`, `forwarder.pem`, and `forwarder.key`.
  The edge certificate must have the exact `pilot-destination` DNS SAN expected by
  the stock Node-RED TLS configuration. The Envoy forwarder certificate is a
  separate client identity trusted by the observer.
* `gateway/` contains `gateway.json` and only that process's required DER identity,
  trust, collector, and policy-key files. The schema is illustrated by
  `deploy/local/native-gateway.example.json`. The observer server certificate must
  include `native-gateway.test`; its pinned forwarder leaf must exactly match the
  Envoy client certificate. The upstream server must have a literal SAN matching
  `upstream_name`, and any upstream client identity must be independently scoped.

The configured method/path must match the fixed Node-RED request and the route
must be the same literal path and match its signed capture scope. The source/workload IDs, policy key, and
queue sublimits must correspond to the provisioned enrollment and signed policy.
`upstream_address` and `delivery_address` accept operator-configured IP sockets or
hostnames. Each hostname is resolved once at startup with a deadline; the selected
socket remains fixed until restart. CA and literal DNS SAN verification still apply.
No request chooses a destination.

Declared HTTP/1 trailers are forwarded when the downstream advertises
`TE: trailers`; the gateway propagates that capability to its upstream hop.
Hyper drops response trailers if the downstream did not advertise that capability,
so this fixture does not claim transparent forwarding of unadvertised trailers.
The gateway ends a connection after 30 seconds, including any stalled body stream.

The overlay is not proof of successful capture. Check actual Node-RED requests and
responses, TLS negative controls, original forwarding under capture failure,
accepted and duplicate delivery receipts, and storage projections on the approved
runtime lane. Do not inspect or print payloads, keys, or credential contents.

Run the owned qualification with `python3 scripts/test-native-pilot.py` after the
normal local stack and default capture roles have been provisioned. It requires
the exact pinned images in the local Docker cache and refuses existing pilot
containers. It tests request/response structure and scope, specific TLS rejection
events, restored capture after each negative, forwarding during ingress outage,
and later capture recovery. It preserves enrolled keys/configuration and removes
only its own containers and generated negative-test keys. Logs are bounded and
private. `--self-test` exercises driver failure handling without the live stack.

Outage counts establish forwarding availability and later delivery recovery; they
do not establish that observation copying paused during the outage. Exact
lost-receipt retry, full sink sentinel checks, performance, HTTP/2, originating
instance attribution and causal tracing remain separate qualification work.
The native gateway emits at most three fixed certificate-rejection diagnostics per
process; errors, certificates, addresses, headers and bodies are never interpolated.
