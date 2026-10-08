# Collector ingress TLS

This component configures mandatory client authentication with explicit Ring and
operator-supplied DER trust anchors. It supports TLS 1.2/1.3 and advertises only
HTTP/1.1. Session storage, TLS 1.3 tickets and early data are disabled. Successful
TLS does not establish enrollment or tenant/collector identity; trusted credential
binding and database authority checks belong to the next request-handler slice.
No HTTP server, admission response or durable receipt endpoint is implemented here.

`CollectorTls::from_der` accepts 1–8 server certificates and 1–8 client roots;
each bundle totals at most 64 KiB. The DER private key is 1–16 KiB. Its cooperative
handshake deadline is 1 ms–30 seconds. Errors and cancellation drop the owned
socket. A Tokio runtime with I/O and timers enabled is required. Deployment keys
and trust configuration must never come from requests. Key-memory erasure is not
guaranteed. The caller still bounds concurrent connections and tasks.

Run `cargo +1.88.0 test -p contour-ingress --locked --offline`. The integration
fixture requires an installed OpenSSL command, creates ephemeral synthetic keys
in its private owned temporary directory, and uses bounded loopback sockets.
It exchanges application bytes over TLS 1.2/1.3, denies missing/untrusted/wrong-
purpose client certificates, repeats connections with cached client configuration
to prove full handshakes, and checks stalled/cancelled socket cleanup.
This is actual TLS integration evidence, not HTTP-to-PostgreSQL acceptance.

Dependencies use exact reviewed HTTP and Rustls/Ring pins, without AWS-LC or
vendored native OpenSSL. Ring compiles bundled C/assembly. The locked native
database TLS dependencies remain unchanged. License and MSRV metadata were
inspected; Rust 1.88 compilation verifies the current macOS graph. Linux and
full dependency advisory scanning remain separate verification requirements.
