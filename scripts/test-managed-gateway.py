#!/usr/bin/env python3
"""Isolated synthetic HTTPS transport check; requires Docker and OpenSSL."""
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gateway_config", ROOT / "deploy/gateway/config.py")
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)
SENTINEL = b"synthetic-gateway-secret-4d78d7"


def cmd(*args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, **kwargs)


def certs(p):
    def openssl(*args):
        cmd("openssl", *args, cwd=p)
    for name in ("ca", "other"):
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", name + ".key", "-out", name + ".pem", "-days", "2", "-subj", "/CN=" + name, "-addext", "basicConstraints=critical,CA:true", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always")
    for name, host in (("down", "gateway.test"), ("up", "upstream.test"), ("wrong", "wrong.test"), ("expired", "upstream.test")):
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", name + ".key", "-out", name + ".csr", "-subj", "/CN=" + host)
        (p / (name + ".ext")).write_text("basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\nsubjectAltName=DNS:" + host + "\nextendedKeyUsage=serverAuth\n")
        if name == "expired":
            (p / "index.txt").write_text("")
            (p / "serial").write_text("01\n")
            (p / "ca.cnf").write_text("[ca]\ndefault_ca=local\n[local]\ndatabase=index.txt\nserial=serial\nnew_certs_dir=.\ncertificate=ca.pem\nprivate_key=ca.key\ndefault_md=sha256\npolicy=policy\nx509_extensions=ext\n[policy]\ncommonName=supplied\n[ext]\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\nsubjectAltName=DNS:upstream.test\nextendedKeyUsage=serverAuth\n")
            openssl("ca", "-batch", "-config", "ca.cnf", "-in", name + ".csr", "-out", name + ".pem", "-startdate", "20200101000000Z", "-enddate", "20210101000000Z")
        else:
            openssl("x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", name + ".pem", "-days", "1", "-extfile", name + ".ext")
    for name in ("down", "up", "wrong", "expired"):
        openssl("verify", "-x509_strict", "-purpose", "sslserver", "-no_check_time", "-CAfile", "ca.pem", name + ".pem")
    for f in p.iterdir():
        os.chmod(f, 0o600)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        self.connection.settimeout(3)
        with self.server.counter_lock:
            self.server.http_hits += 1
        try:
            length = int(self.headers["Content-Length"])
        except (TypeError, ValueError):
            self.send_error(400)
            return
        if not 0 <= length <= 4096:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        assert self.path == "/probe?q=1" and self.headers["X-Test"] == "synthetic" and body == SENTINEL
        self.send_response(201)
        self.send_header("X-Reply", "synthetic")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TLSServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    CERT_ALERTS = frozenset({"SSLV3_ALERT_BAD_CERTIFICATE", "TLSV1_ALERT_UNKNOWN_CA",
                             "SSLV3_ALERT_CERTIFICATE_EXPIRED", "SSLV3_ALERT_CERTIFICATE_UNKNOWN"})

    def __init__(self, *args):
        self.counter_lock = threading.Lock()
        self.handshakes = 0
        self.cert_rejections = 0
        self.http_hits = 0
        super().__init__(*args)

    def counts(self):
        with self.counter_lock:
            return self.handshakes, self.cert_rejections, self.http_hits

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(3)
        try:
            tls = self.context.wrap_socket(sock, server_side=True)
            with self.counter_lock:
                self.handshakes += 1
            return tls, addr
        except ssl.SSLError as error:
            if error.reason in self.CERT_ALERTS:
                with self.counter_lock:
                    self.cert_rejections += 1
            sock.close()
            raise
        except Exception:
            sock.close()
            raise


def serve(p, cert, tls_version):
    server = TLSServer(("127.0.0.1", 0), Handler)
    server.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # TLS 1.2 lets the server observe the client certificate-validation alert
    # during the handshake, before accepting an HTTP request.
    server.context.minimum_version = tls_version
    server.context.maximum_version = tls_version
    server.context.load_cert_chain(p / (cert + ".pem"), p / (cert + ".key"))
    server.thread = threading.Thread(target=server.serve_forever, daemon=True)
    server.thread.start()
    return server


def stop(server):
    server.shutdown()
    server.server_close()
    server.thread.join(timeout=5)
    assert not server.thread.is_alive()


def request(port, ca):
    ctx = ssl.create_default_context(cafile=str(ca))
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    with ctx.wrap_socket(sock, server_hostname="gateway.test") as tls:
        tls.sendall(b"POST /probe?q=1 HTTP/1.1\r\nHost: gateway.test\r\nX-Test: synthetic\r\nConnection: close\r\nContent-Length: " + str(len(SENTINEL)).encode() + b"\r\n\r\n" + SENTINEL)
        response = http.client.HTTPResponse(tls)
        response.begin()
        return response.status, response.getheader("X-Reply"), response.read()


def network_profile(platform):
    if platform == "darwin":
        return "host.docker.internal", "0.0.0.0", 8443, ["-p", "127.0.0.1::8443"]
    if platform == "linux":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        if port < 1024:
            raise RuntimeError("kernel selected privileged port")
        return "127.0.0.1", "127.0.0.1", port, ["--network", "host"]
    raise RuntimeError("unsupported gateway fixture platform: " + platform)


def main():
    if os.getuid() == 0:
        raise RuntimeError("run the fixture as a nonroot user")
    if sys.platform not in ("darwin", "linux"):
        raise RuntimeError("unsupported gateway fixture platform: " + sys.platform)
    cmd("docker", "image", "inspect", gateway.IMAGE)
    name = "contour-gateway-fixture-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="contour-gateway-") as d:
        p = Path(d)
        certs(p)
        # The directory is private on the host; container sees only its read-only mount.
        server = None
        try:
            for cert, ca, expected, tls_version in (("up", "ca.pem", 201, ssl.TLSVersion.TLSv1_3), ("up", "ca.pem", 201, ssl.TLSVersion.TLSv1_2), ("wrong", "ca.pem", 503, ssl.TLSVersion.TLSv1_2), ("up", "other.pem", 503, ssl.TLSVersion.TLSv1_2), ("expired", "ca.pem", 503, ssl.TLSVersion.TLSv1_2)):
                server = serve(p, cert, tls_version)
                upstream_host, listen_address, listen_port, networking = network_profile(sys.platform)
                cfg = gateway.config(upstream_host, server.server_port, ca="/fixture/" + ca, listen_address=listen_address, listen_port=listen_port)
                config_path = p / (cert + "-" + ca + "-" + tls_version.name + ".json")
                config_path.write_text(json.dumps(cfg))
                os.chmod(config_path, 0o600)
                mounts = []
                for source, destination in ((config_path, "envoy.json"), (p / "down.pem", "down.pem"), (p / "down.key", "down.key"), (p / ca, ca)):
                    mounts += ["-v", str(source) + ":/fixture/" + destination + ":ro"]
                try:
                    cmd("docker", "run", "--pull", "never", "--rm", "--user", f"{os.getuid()}:{os.getgid()}", *mounts, gateway.IMAGE, "envoy", "--mode", "validate", "-c", "/fixture/envoy.json")
                except subprocess.CalledProcessError as e:
                    raise RuntimeError(e.stderr.decode()) from e
                cmd("docker", "run", "--pull", "never", "-d", "--name", name, "--user", f"{os.getuid()}:{os.getgid()}", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "256m", "--cpus", "1", "--pids-limit", "128", "--log-driver", "none", *networking, *mounts, gateway.IMAGE, "envoy", "-c", "/fixture/envoy.json", "--log-level", "off", "--concurrency", "1")
                port = (int(cmd("docker", "port", name, "8443/tcp").stdout.decode().strip().rsplit(":", 1)[1])
                        if sys.platform == "darwin" else listen_port)
                assert cmd("docker", "inspect", "--format", "{{.State.Running}}", name).stdout.strip() == b"true"
                deadline = time.monotonic() + 15
                last_error = None
                while True:
                    try:
                        status, header, body = request(port, p / "ca.pem")
                        handshakes, rejections, hits = server.counts()
                        if expected == 201 and status == 201:
                            assert handshakes >= 1 and hits >= 1
                            break
                        if expected == 503 and status == 503 and rejections >= 1:
                            assert hits == 0, "rejected upstream reached HTTP handler"
                            break
                        assert status == 503, (cert, ca, status)
                    except ssl.SSLCertVerificationError as error:
                        raise AssertionError(("downstream certificate verification failed", error.verify_code)) from None
                    except ssl.SSLError:
                        last_error = ("tls", None)
                    except OSError as error:
                        last_error = ("socket", error.errno if isinstance(error.errno, int) else None)
                    if time.monotonic() >= deadline:
                        state = json.loads(cmd("docker", "inspect", "--format", '{{json .State}}', name).stdout)
                        safe_state = (bool(state["Running"]), int(state["ExitCode"]), bool(state["OOMKilled"]))
                        raise AssertionError(("upstream TLS evidence missing", cert, ca, server.counts(), safe_state, last_error))
                    time.sleep(.1)
                if expected == 201:
                    assert header == "synthetic" and body == SENTINEL
                    try:
                        request(port, p / "other.pem")
                        raise AssertionError("untrusted downstream accepted")
                    except ssl.SSLCertVerificationError:
                        pass
                    with socket.create_connection(("127.0.0.1", port), timeout=3) as plain:
                        plain.sendall(b"GET / HTTP/1.1\r\nHost: gateway.test\r\n\r\n")
                        try: data = plain.recv(1024)
                        except ConnectionResetError: data = b""
                        assert b"HTTP/" not in data
                assert cmd("docker", "inspect", "--format", "{{.State.Running}}", name).stdout.strip() == b"true"
                # Docker logs are disabled; inspect available sink anyway for the sentinel.
                logs = subprocess.run(["docker", "logs", name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
                assert SENTINEL not in logs.stdout + logs.stderr
                assert cmd("docker", "inspect", "--format", "{{.HostConfig.LogConfig.Type}}", name).stdout.strip() == b"none"
                cmd("docker", "rm", "-f", name)
                server_counts = server.counts()
                stop(server); server = None
                print("PASS", cert, ca, tls_version.name, status, "upstream counters", server_counts)
        finally:
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
            if server: stop(server)
    print("PASS downstream trust, plaintext rejection, response fidelity, disabled log sink")


if __name__ == "__main__": main()
