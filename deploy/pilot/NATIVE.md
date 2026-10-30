# Opt-in native HTTP/1 pilot

The native overlay is a fixture scaffold. It does not provision enrollment, keys,
certificates, a signed policy, or database state; it does not establish production
origin, causal attribution, HTTP/2, performance, or general MVP readiness.

Combine `compose.yaml` and `native-overlay.yaml` with profile `native-capture` only
on an owned local stack. The existing `apicontour-local_default` network must be
available. Build the local application image using the pinned project Dockerfile;
preload the digest-pinned Envoy and Node-RED images. No host port is published by
the overlay. Use the pilot's `PILOT_TARGET=https://pilot-gateway:9443/pilot`.

Provision two separate, private directories under `.local-mvp/pilot/native`:

* `forwarder/` contains `envoy.json`, `edge.pem`, `edge.key`, `pilot-ca.pem`,
  `observer-ca.pem`, `forwarder.pem`, and `forwarder.key`. Generate `envoy.json`
  from `python3 deploy/pilot/native_envoy.py` without logging credential contents.
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
