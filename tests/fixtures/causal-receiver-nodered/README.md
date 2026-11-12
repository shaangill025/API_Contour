# Node-RED incoming request identity fixture

`actual.js` is an actual-runtime seam test for the private receiver's pre-Express
HTTPS handler and an unmodified Node-RED 5.0.9 HTTP-in node, cloneMessage and
fanout. It requires Node 24.22.3 and the pinned candidate image; it must be run
only by the owned container driver with the approved isolation fences. The
fixture does not establish profile 504, a loader, enrollment, deployment, SQL,
edge behavior or publisher provenance.

The driver mounts the repository read-only with the same relative layout under
`/work`, supplies an owned writable `/data` tmpfs, and starts
`/work/tests/fixtures/causal-receiver-nodered/actual.js`. The checked-in
`causal-receiver-material` files are synthetic test PKI only. The fixture creates
an ephemeral loopback HTTPS listener inside the network-disabled container with
server-name, CA, client-certificate and authorization checks enabled. It writes
only its fixed flow file under `/data`, before serving requests.

Two concurrent mTLS requests are held before Express until both arrive. A hook
on the actual HTTP-in output consumes the private registration and requires the
same native request identity across the original message and cloneMessage;
pre-delivery observations require the same identity across actual fanout
messages. The two private roots and requests must differ. A duplicate carrier
must be scrubbed and forwarded once without registration. All requests require
reserved-header scrubbing. Output consists only of fixed phase/count labels.
The fixture bounds requests, startup and shutdown and removes its temporary flow
state. A passing syntax check alone is not runtime evidence.
