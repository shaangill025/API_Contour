# Origin witness qualification fixture

Run `python3 scripts/test-envoy-origin-witness.py --self-test` for offline Python checks. Run `node tests/fixtures/origin-witness/backend.js --self-test`
for the observer classification checks.
Run the command without options only in the explicitly authorized Docker environment.
It creates synthetic ephemeral credentials, a private frontend bridge, and a
separate internal backend Docker network.
It requires the two pinned images to be cached, OpenSSL, and Docker. The only
published port is the Envoy listener on loopback. Output contains case names and
closed outcomes only. Temporary private files are removed during cleanup.
Docker local logs retain at most one 1 MiB file per container, containing only
synthetic startup or TLS diagnostics. Container removal deletes those logs; this
script does not snapshot them before cleanup.

The observer authenticates and pins the forwarder before classifying one metadata
header against DER-derived test hashes. The fixture tests Envoy's metadata channel;
it does not implement or qualify Native extraction, stripping, queueing, evidence,
trailers, production origin attribution, or a policy grant. A reused upstream
connection is checked, not assumed. Failure or unexecuted cases are not evidence.
