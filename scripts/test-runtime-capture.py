"""Owned runtime capture qualification, called by the PostgreSQL TLS fixture.

No service is created on import. This uses a synthetic enrolled V2 collector,
the production HTTPS authority/delivery server, and the fixture application.
"""
import http.client
import hashlib
import json
import os
from pathlib import Path
import queue
import runpy
import socket
import ssl
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
ITEM = "00000000-0000-0000-0000-000000000001"


class Child:
    def __init__(self, args, env):
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, env=env, cwd=ROOT)
        self.lines = queue.Queue()
        def pump():
            for line in self.process.stdout:
                self.lines.put(line)
            self.lines.put(None)
        self.thread = threading.Thread(target=pump)
        self.thread.start()

    def line(self, deadline=20):
        value = self.lines.get(timeout=deadline)
        if value is None or len(value) > 1024:
            raise RuntimeError("fixture child ended or returned invalid output")
        return value.strip()

    def command(self, command, deadline=20):
        if self.process.poll() is not None:
            raise RuntimeError("fixture child exited")
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()
        return self.line(deadline)

    def verify_eof(self):
        self.thread.join(5)
        if self.thread.is_alive() or self.lines.get(timeout=5) is not None or not self.lines.empty():
            raise RuntimeError('fixture child output after shutdown')

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.thread.join(5)
        if self.thread.is_alive():
            raise RuntimeError("fixture reader did not stop")
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            pipe.close()


def run_cases(container, execute, setup, directory, environment):
    del container
    port = int(environment["CONTOUR_RUNTIME_POSTGRES_PORT"])
    origin_exe = environment["CONTOUR_ORIGIN_HTTPS_PROBE"]
    runtime_exe = environment["CONTOUR_RUNTIME_CAPTURE_PROBE"]
    if not 1 <= port <= 65535:
        raise ValueError("invalid fixture port")

    def command(argv):
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=20, cwd=ROOT, env=environment)
        if result.returncode:
            raise RuntimeError("certificate generation failed")

    def certificate(name):
        ext = directory / (name + ".ext")
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n")
        command(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=synthetic-fixture",
                 "-keyout", str(directory / (name + ".key")), "-out", str(directory / (name + ".csr"))])
        command(["openssl", "x509", "-req", "-in", str(directory / (name + ".csr")), "-CA", str(directory / "ca.crt"),
                 "-CAkey", str(directory / "ca.key"), "-CAcreateserial", "-days", "1", "-sha256", "-extfile", str(ext),
                 "-out", str(directory / (name + ".crt"))])
        command(["openssl", "x509", "-in", str(directory / (name + ".crt")), "-outform", "DER", "-out", str(directory / (name + ".crt.der"))])
        command(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(directory / (name + ".key")), "-outform", "DER",
                 "-out", str(directory / (name + ".key.der"))])

    def change(policy):
        policy.update(approved_names=["POST", "probe", "result"], approved_route_segments=["pilot"],
                      queue_bytes=1048576, queue_ttl_seconds=60)
    body, collector, source = setup("runtime_capture", change=change, current=1, history=(1,))
    tenant = body["tenant_id"]
    certificate("http-client")
    for name in ("ca", "server"):
        command(["openssl", "x509", "-in", str(directory / (name + ".crt")), "-outform", "DER", "-out", str(directory / (name + ".crt.der"))])
    command(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(directory / "server.key"), "-outform", "DER",
             "-out", str(directory / "server.key.der")])
    child_env = dict(environment, CONTOUR_ORIGIN_DATABASE_USER="contour_origin_ingress_test")
    origin = app = None
    try:
        origin = Child([origin_exe, str(port), str(directory), tenant, collector, "5000"], child_env)
        words = origin.line().split()
        if len(words) != 2 or words[0] != "READY" or not words[1].isdigit():
            raise RuntimeError("authority fixture did not start")
        origin_port = int(words[1])
        if not 1 <= origin_port <= 65535:
            raise RuntimeError("authority fixture port invalid")
        config = {
            "server_certificate_der": str(directory / "server.crt.der"),
            "server_key_der": str(directory / "server.key.der"),
            "client_ca_der": str(directory / "ca.crt.der"),
            "delivery_address": "127.0.0.1:%d" % origin_port, "delivery_name": "localhost",
            "delivery_ca_der": str(directory / "ca.crt.der"),
            "delivery_client_certificate_der": str(directory / "http-client.crt.der"),
            "delivery_client_key_der": str(directory / "http-client.key.der"),
            "tenant": tenant, "collector": collector, "source": source, "workload": [ITEM] * 4,
            "policy_key_id": "fixture", "policy_key_file": str(directory / "signer.raw"),
        }
        config_path = directory / "runtime-capture.json"
        config_path.write_text(json.dumps(config))
        assets = [directory / name for name in ('server.crt.der', 'server.key.der', 'ca.crt.der',
                  'http-client.crt.der', 'http-client.key.der', 'http-client.crt', 'http-client.key',
                  'ca.crt', 'signer.raw', 'runtime-capture.json')]
        asset_hashes = {path: hashlib.sha256(path.read_bytes()).digest() for path in assets}
        app = Child([runtime_exe, str(config_path)], child_env)
        words = app.line().split()
        if len(words) != 3 or words[0] != "READY" or not all(word.isdigit() for word in words[1:]):
            raise RuntimeError("runtime fixture did not start")
        http_port, https_port = map(int, words[1:])
        if any(not 1 <= value <= 65535 for value in (http_port, https_port)):
            raise RuntimeError("runtime fixture port invalid")

        def snapshot():
            sql = """SELECT coalesce(json_agg(json_build_object(
              'record', r.value->'record',
              'metadata', json_build_object('source_id',m.source_id,'parser_profile',m.parser_profile,
                'project_id',m.project_id,'service_id',m.service_id,'environment_id',m.environment_id,
                'deployment_id',m.deployment_id,'attribution_class',m.attribution_class,
                'origin_proof',p.record_id))), '[]'::json)
              FROM contour.ingestion_v2_metadata m
              JOIN contour.ingestion_payloads b USING (tenant_id,collector_id,batch_id)
              LEFT JOIN contour.origin_proofs p USING (tenant_id,collector_id,batch_id,record_id)
              CROSS JOIN LATERAL jsonb_array_elements(convert_from(b.checked_batch,'UTF8')::jsonb->'records') r(value)
              WHERE m.tenant_id='%s' AND m.collector_id='%s'
              AND r.value->'record'->>'record_id'=m.record_id::text;""" % (tenant, collector)
            rows = json.loads(execute(sql))
            if not isinstance(rows, list) or len(rows) > 100:
                raise AssertionError("fixture snapshot invalid")
            return rows

        tls = ssl.create_default_context(cafile=str(directory / "ca.crt"))
        tls.load_cert_chain(str(directory / "http-client.crt"), str(directory / "http-client.key"))
        fixture_dir = str(ROOT / "tests/fixtures/runtime-capture")
        sys.path.insert(0, fixture_dir)
        try:
            driver = runpy.run_path(str(Path(fixture_dir) / "driver.py"))
            assertion = runpy.run_path(str(Path(fixture_dir) / "assertions.py"))
            driver["run"](app.command, snapshot, source, [ITEM] * 4, http_port, https_port, tls)
            before = snapshot()
            # The first fragment is processed before HELD. The exact stream then
            # resumes only after detach has acknowledged revocation.
            stream = socket.create_connection(("127.0.0.1", http_port), timeout=10)
            stream.settimeout(10)
            try:
                stream.sendall(b"POST /pilot HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nx-fixture-hold: yes\r\nConnection: close\r\n\r\n9\r\n{\"probe\":\r\n")
                if app.command("WAIT_HOLD") != "HELD" or app.command("DETACH") != "DETACHED":
                    raise AssertionError("held detach failed")
                if app.command("RELEASE") != "RELEASED":
                    raise AssertionError("held release failed")
                stream.sendall(b"5\r\ntrue}\r\n0\r\n\r\n")
                response = http.client.HTTPResponse(stream)
                response.begin()
                if response.status != 201 or response.read() != b'{"result":1}':
                    raise AssertionError("held application response changed")
            finally:
                stream.close()
            result = app.command("DRAIN").split()
            if len(result) != 3 or result[0] != "DRAIN" or not all(part.isdigit() for part in result[1:]):
                raise AssertionError("held drain failed")
            assertion["assert_new_records"](before, snapshot(), {}, source, [ITEM] * 4)
            if app.command("ATTACH") != "ATTACHED":
                raise AssertionError("replacement attach failed")
            before = snapshot()
            connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=10)
            try:
                connection.request("POST", "/pilot", b'{"probe":true}', {"Content-Type": "application/json"})
                response = connection.getresponse()
                if response.status != 201 or response.read() != b'{"result":1}':
                    raise AssertionError("replacement application response changed")
            finally:
                connection.close()
            result = app.command("DRAIN").split()
            if len(result) != 3 or result[0] != "DRAIN" or not all(part.isdigit() for part in result[1:]):
                raise AssertionError("replacement drain failed")
            assertion["assert_new_records"](before, snapshot(), assertion["NORMAL"], source, [ITEM] * 4)
        finally:
            sys.path.remove(fixture_dir)
        app.process.stdin.write('STOP\n')
        app.process.stdin.flush()
        app.process.wait(timeout=10)
        if app.process.returncode or app.process.stderr.read():
            raise RuntimeError('application shutdown failed')
        app.verify_eof()
        if origin.command('') != 'STOPPED':
            raise RuntimeError('authority shutdown failed')
        origin.process.stdin.write('\n')
        origin.process.stdin.flush()
        origin.process.wait(timeout=10)
        if origin.process.returncode or origin.process.stderr.read():
            raise RuntimeError('authority cleanup failed')
        origin.verify_eof()
        if any(hashlib.sha256(path.read_bytes()).digest() != digest for path, digest in asset_hashes.items()):
            raise RuntimeError('fixture material changed')
        deadline = time.monotonic() + 10
        while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_origin_ingress_test';") != '0':
            if time.monotonic() >= deadline:
                raise RuntimeError('authority database connections leaked')
            time.sleep(.1)
    finally:
        failures = []
        for child in (app, origin):
            if child is not None:
                try: child.stop()
                except BaseException as error: failures.append(error)
        if failures:
            primary = sys.exception()
            if primary is not None: failures.insert(0, primary)
            raise BaseExceptionGroup('fixture child cleanup failed', failures) from None
