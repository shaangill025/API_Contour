# Candidate factory probe fixture

`stage_sources.stage(root, empty_private_directory)` copies and verifies the
23 manifest-bound source files, returning the first four paths in the exact
mount order. Append the seven independently prepared TLS paths in the order
CA, export key, export certificate, product key, product certificate, server
key, server certificate. Keep the source paths and their ancestors under
operator control until the launched container has been removed.

The Rust example accepts one JSON input path. Its `Inputs` struct defines the
closed fields. Supply actual 32-byte lowercase hexadecimal SHA-256 identities
for the selected export leaf, fixed image, Docker executable, internal network,
and every fixture peer. The password is read from
`CONTOUR_CAUSAL_ISSUER_PASSWORD`, not the JSON or command line. Issue and
create journal directories must be fresh, private and distinct. The fixture
owner label corresponds to `org.apicontour.fixture-owner`; peer and network
owner values must match actual inspected labels. The two operator-supplied
journal commitments must describe the staged source and key configuration.

The supervisor must bound and drain both output streams, retain the private
JSON and journal files, and treat a create/start error as outcome unknown.
`READY` is the correlated launcher startup event. Sending `STOP\n` drops the
local relay future; `CAPTURE_CLOSED` is emitted only after the existing local
cleanup observer confirms process-group absence. Business-listener survival
and the same container PID and start time must still be checked independently.
Never adopt a container from an uncertain attempt.

The companion `scripts/test-postgres-causal-factory.py` builds a fresh probe,
creates a disposable PostgreSQL SQL24 fixture, and uses a separate internal
network with two pinned-image TLS peers. Its endpoint deliberately refuses
export batches, so it cannot establish exporter admission or an ACK. It
attempts mTLS business requests before and after dropping the local capture.
An HTTP response from `/run` proves incoming listener mTLS only; it can return
before the downstream request finishes. The script has not yet passed an actual runtime qualification; source and
offline tests alone do not establish startup, TLS, cleanup, wire or graph
behavior. Uncertain resources and their journals are retained for review.
