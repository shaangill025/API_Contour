"""Live-case driver called by an owner that supplies a running probe and DB snapshot.

The caller owns starting/stopping the signed authority and probe, certificate
material, deadlines for commands, and tenant-scoped committed-record snapshots.
"""
import http.client

from assertions import NORMAL, assert_new_records


def run(command, snapshot, source, workload, http_port, https_port, tls_context):
    """Run a fail-closed subset on real HTTP and verified mTLS HTTPS.

    command(text) must enforce a timeout and return one complete probe output
    line. snapshot() must return committed V2 rows normalized as README states.
    Additional lifecycle, raw trailer, drop/error and comparison cases remain
    required separately.
    """
    if snapshot():
        raise AssertionError("fixture collector must start with no records")

    def drain():
        words = command("DRAIN").split()
        if len(words) != 3 or words[0] != "DRAIN" or not all(x.isascii() and x.isdigit() for x in words[1:]):
            raise AssertionError("invalid drain outcome")
        if words[1] != "0":
            raise AssertionError("unexpected capture loss")

    def request(port, tls, path="/pilot", headers=None):
        connection = (http.client.HTTPSConnection("localhost", port, context=tls_context, timeout=10)
                      if tls else http.client.HTTPConnection("127.0.0.1", port, timeout=10))
        try:
            values = {"Content-Type": "application/json", "x-contour-origin-witness": "f" * 64}
            values.update(headers or {})
            connection.request("POST", path, iter([b'{"probe":', b"true}"]), values, encode_chunked=True)
            response = connection.getresponse()
            body = response.read()
            if response.status != 201 or response.getheader("content-type") != "application/json" or body != b'{"result":1}':
                raise AssertionError("application response changed")
        finally:
            connection.close()

    for port, tls in ((http_port, False), (https_port, True)):
        before = snapshot()
        request(port, tls)
        drain()
        assert_new_records(before, snapshot(), NORMAL, source, workload)

        before = snapshot()
        request(port, tls, path="/pilot?ignored=1")
        drain()
        assert_new_records(before, snapshot(), {}, source, workload)

        before = snapshot()
        request(port, tls, headers={"Content-Encoding": "gzip"})
        drain()
        assert_new_records(before, snapshot(), {"response": NORMAL["response"]}, source, workload)

    if command("DETACH") != "DETACHED":
        raise AssertionError("detach failed")
    before = snapshot()
    request(http_port, False)
    drain()
    assert_new_records(before, snapshot(), {}, source, workload)
    if command("ATTACH") != "ATTACHED":
        raise AssertionError("attach failed")
    before = snapshot()
    request(http_port, False)
    drain()
    assert_new_records(before, snapshot(), NORMAL, source, workload)
