"""Actual PostgreSQL TLS plus labeled synthetic protocol failures; Python 3.9+."""
import json
import os
import queue
import runpy
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4"
SSL_REQUEST = struct.pack("!II", 8, 80877103)


def run(argv, input=None, timeout=30, env=None):
    result = subprocess.run(argv, input=input, capture_output=True, text=True,
                            timeout=timeout, env=env, cwd=ROOT)
    if result.returncode:
        raise RuntimeError("fixture command failed: " + argv[0])
    return result.stdout.strip()


def exact(stream, count):
    data = b""
    while len(data) < count:
        chunk = stream.recv(count-len(data))
        if not chunk:
            raise AssertionError("protocol closed before expected bytes")
        data += chunk
    return data


class ProtocolServer:
    def __init__(self, mode, directory):
        self.mode = mode
        self.error = None
        self.connection = None
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(1)
        self.listener.settimeout(8)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(directory/"server.crt", directory/"server.key")
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        try:
            stream, _ = self.listener.accept()
            self.connection = stream
            with stream:
                stream.settimeout(5)
                if exact(stream, 8) != SSL_REQUEST:
                    raise AssertionError("unexpected SSL request")
                stream.sendall(b"N" if self.mode == "refusal" else b"S")
                if self.mode in ["auth", "health", "begin"]:
                    stream = self.context.wrap_socket(stream, server_side=True)
                    self.connection = stream
                    length = struct.unpack("!I", exact(stream, 4))[0]
                    if not 8 <= length <= 8192:
                        raise AssertionError("startup packet bound")
                    startup = exact(stream, length-4)
                    if startup[:4] != struct.pack("!I", 196608):
                        raise AssertionError("unexpected startup version")
                    if self.mode in ["health", "begin"]:
                        # Synthetic AuthenticationOk + ReadyForQuery, then no query reply.
                        stream.sendall(b"R"+struct.pack("!II", 8, 0)+b"Z"+struct.pack("!I", 5)+b"I")
                        if exact(stream, 1) != (b"P" if self.mode=="health" else b"Q"):
                            raise AssertionError("expected query never began")
                        if self.mode=="begin":
                            length=struct.unpack("!I",exact(stream,4))[0]
                            if not 4<length<8192 or not exact(stream,length-4).startswith(b"START TRANSACTION"):
                                raise AssertionError("expected BEGIN never began")
                        while stream.recv(8192):
                            pass
                        stream.close()
                        return
                    # Successful TLS and Startup, deliberately never authenticate.
                    if stream.recv(1) != b"":
                        raise AssertionError("auth stall did not close")
                    stream.close()
                elif self.mode == "tls":
                    # Consume ClientHello without responding; observe cancellation EOF.
                    saw_hello = False
                    while True:
                        data = stream.recv(8192)
                        if not data:
                            break
                        saw_hello = True
                    if not saw_hello:
                        raise AssertionError("TLS handshake never started")
                elif stream.recv(1) != b"":
                    raise AssertionError("credentials sent after plaintext refusal")
        except Exception as error:
            self.error = error

    def finish(self):
        self.thread.join(8)
        if self.thread.is_alive():
            raise AssertionError("protocol session cleanup timeout")
        if self.error:
            raise AssertionError("synthetic protocol assertion failed") from self.error

    def close(self):
        if self.connection:
            self.connection.close()
        self.listener.close()
        self.thread.join(2)
        if self.thread.is_alive():
            raise AssertionError("owned protocol thread did not stop")


def main():
    flags = sys.argv[1:]
    if len(flags)>1 or any(flag not in ['--authority','--https-only','--delivery-only'] for flag in flags):
        raise ValueError("choose one supported fixture mode")
    for tool in ["docker", "openssl", "cargo"]:
        if not shutil.which(tool):
            raise RuntimeError("required fixture tool missing")
    run(["docker", "image", "inspect", IMAGE])  # Never download images here.
    run(["cargo", "build", "-p", "contour-postgres", "--example", "tls_probe", "--locked", "--offline"], timeout=180)
    if "--authority" in sys.argv:
        run(["cargo", "build", "-p", "contour-postgres", "--example", "authority_probe", "--locked", "--offline"], timeout=180)
        run(["cargo", "build", "-p", "contour-postgres", "--example", "submit_probe", "--locked", "--offline"], timeout=180)
    elif "--https-only" in sys.argv or "--delivery-only" in sys.argv:
        run(["cargo", "build", "-p", "contour-ingress", "--example", "https_probe", "--locked", "--offline"], timeout=180)
    if "--delivery-only" in sys.argv:
        run(["cargo", "build", "-p", "contour-delivery", "--example", "delivery_probe", "--locked", "--offline"], timeout=180)
    metadata = json.loads(run(["cargo", "metadata", "--format-version", "1", "--no-deps", "--offline"]))
    probe = str(Path(metadata["target_directory"])/"debug"/"examples"/"tls_probe")
    network = container = volume = None
    servers = []
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="contour-tls-") as folder:
        directory = Path(folder)
        password = secrets.token_hex(24)
        environment = dict(os.environ, CONTOUR_FIXTURE_PASSWORD=password)
        try:
            (directory/"request.cnf").write_text("[req]\ndistinguished_name=dn\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")
            for name in ["ca", "untrusted"]:
                run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                     "-sha256", "-config", str(directory/"request.cnf"), "-extensions", "ca",
                     "-subj", "/CN=APIContour inert fixture " + name, "-keyout", str(directory/(name+".key")), "-out", str(directory/(name+".crt"))])
            run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                 "-sha256", "-config", str(directory/"request.cnf"),
                 "-keyout", str(directory/"server.key"), "-out", str(directory/"server.csr")])
            (directory/"extensions").write_text("subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
            run(["openssl", "x509", "-req", "-in", str(directory/"server.csr"), "-CA", str(directory/"ca.crt"),
                 "-CAkey", str(directory/"ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(directory/"extensions"), "-out", str(directory/"server.crt")])
            network = run(["docker", "network", "create", "--driver", "bridge", "--opt",
                           "com.docker.network.bridge.enable_ip_masquerade=false", "contour-tls-"+secrets.token_hex(6)])
            network_settings = json.loads(run(["docker", "network", "inspect", network]))[0]
            if network_settings["Driver"] != "bridge" or network_settings["Options"].get("com.docker.network.bridge.enable_ip_masquerade") != "false":
                raise AssertionError("fixture bridge configuration mismatch")
            data_mount = ["--tmpfs", "/var/lib/postgresql/data:rw,nosuid,noexec,size=256m"]
            if "--authority" in sys.argv or "--https-only" in sys.argv or "--delivery-only" in sys.argv:
                volume = "contour-recovery-" + secrets.token_hex(12)
                run(["docker", "volume", "create", "--label", "contour.fixture=" + volume, volume])
                data_mount = ["--mount", "type=volume,source=" + volume + ",target=/var/lib/postgresql/data"]
            container = run(["docker", "create", "--network", network, "--publish", "127.0.0.1::5432",
                             "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
                             *data_mount,
                             "-e", "POSTGRES_DB=contour_fixture", "-e", "POSTGRES_PASSWORD="+password,
                             "-e", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256", IMAGE, "sh", "-c",
                             "chown postgres:postgres /tmp/server.key /tmp/server.crt && chmod 600 /tmp/server.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key"])
            if volume:
                mounts = json.loads(run(["docker", "inspect", container]))[0]["Mounts"]
                owned = [mount for mount in mounts if mount["Destination"] == "/var/lib/postgresql/data"]
                if len(owned) != 1 or owned[0]["Type"] != "volume" or owned[0]["Name"] != volume:
                    raise AssertionError("recovery volume mount mismatch")
            for file in ["server.key", "server.crt"]:
                run(["docker", "cp", str(directory/file), container+":/tmp/"+file])
            run(["docker", "start", container])
            deadline = time.monotonic()+60
            while True:
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("PostgreSQL TLS startup timed out")
                try:
                    ready = subprocess.run(["docker", "exec", container, "sh", "-c",
                                            'test "$(cat /proc/1/comm)" = postgres && pg_isready -U postgres -d contour_fixture'],
                                           capture_output=True, timeout=min(5,remaining))
                except subprocess.TimeoutExpired:
                    ready = None
                if ready is not None and ready.returncode == 0:
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("PostgreSQL TLS startup timed out")
                try:
                    state = run(["docker", "inspect", "--format", "{{.State.Running}}|{{.State.ExitCode}}|{{.State.OOMKilled}}", container],timeout=min(5,deadline-time.monotonic())).split('|')
                except subprocess.TimeoutExpired:
                    state = None
                if state is not None and state[0] == 'false':
                    raise RuntimeError("owned PostgreSQL fixture stopped: exit %d, OOM %s" % (int(state[1]),state[2]))
                time.sleep(min(0.2,max(0,deadline-time.monotonic())))
            sql = ["docker", "exec", "-i", container, "psql", "-XAtq", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "contour_fixture"]
            run(sql, "CREATE ROLE contour_tls LOGIN PASSWORD '"+password+"';")
            hba = "local all all trust\nhostnossl all all all reject\nhostssl contour_fixture contour_tls all scram-sha-256\nhostssl all all all reject\n"
            run(["docker", "exec", "-i", container, "sh", "-c", "cat > /var/lib/postgresql/data/pg_hba.conf"], hba)
            run(sql, "SELECT pg_reload_conf();")
            bindings = json.loads(run(["docker", "inspect", container]))[0]["NetworkSettings"]["Ports"]["5432/tcp"]
            if len(bindings) != 1 or bindings[0]["HostIp"] != "127.0.0.1":
                raise AssertionError("fixture port is not loopback-only: " + repr(bindings))
            port = bindings[0]["HostPort"]

            def check(host, port, ca, mode, milliseconds=3000):
                output = run([probe, host, str(port), str(directory/ca), str(milliseconds), mode], timeout=12, env=environment)
                expected = "Deadline" if mode == "HealthDeadline" else mode
                if password in output or output != expected:
                    raise AssertionError("unsafe or unexpected fixture output")

            for mode in ["success", "drop"]:
                process = subprocess.Popen([probe, "localhost", port, str(directory/"ca.crt"), "3000", mode],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           text=True, env=environment)
                marker = queue.Queue()
                reader = threading.Thread(target=lambda: marker.put(process.stdout.readline()), daemon=True)
                reader.start()
                try:
                    if marker.get(timeout=12).strip() != "TLS_CONNECTED":
                        raise AssertionError("trusted PostgreSQL TLS health failed")
                    cleanup_deadline = time.monotonic()+5
                    while run(sql, "SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls';") != "0":
                        if time.monotonic() >= cleanup_deadline:
                            raise AssertionError("driver leaked PostgreSQL backend")
                        time.sleep(0.05)
                    if process.poll() is not None:
                        raise AssertionError("runtime exited before cleanup was observed")
                    output, errors = process.communicate(input="\n", timeout=3)
                    if process.returncode or output or errors:
                        raise AssertionError("unsafe or failed live probe exit")
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=3)
                    reader.join(2)
                    for pipe in [process.stdin, process.stdout, process.stderr]:
                        pipe.close()
            check("localhost", port, "untrusted.crt", "Connection")
            check("127.0.0.1", port, "ca.crt", "Connection")
            print("Actual PostgreSQL trusted CA, TLS health, bad CA, wrong hostname and backend cleanup passed")
            if "--https-only" in sys.argv or "--delivery-only" in sys.argv:
                authority_probe = str(Path(metadata["target_directory"])/"debug"/"examples"/"authority_probe")
                runpy.run_path(str(ROOT/"scripts/test-postgres-authority.py"))["run_cases"](container,sql,authority_probe,port,directory,environment,https_only=True,delivery_only="--delivery-only" in sys.argv)
            elif "--authority" in sys.argv:
                authority_probe = str(Path(metadata["target_directory"])/"debug"/"examples"/"authority_probe")
                runpy.run_path(str(ROOT/"scripts/test-postgres-authority.py"))["run_cases"](container,sql,authority_probe,port,directory,environment)
                server = ProtocolServer("begin", directory)
                servers.append(server)
                last = json.loads((directory/"batch.json").read_text())
                process = subprocess.Popen([authority_probe,str(server.port),str(directory/"ca.crt"),str(directory/"signer.raw"),str(directory/"batch.json"),"Cancel",last["tenant_id"],last["collector_id"],"5000"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
                marker = queue.Queue()
                reader = threading.Thread(target=lambda: marker.put(process.stdout.readline()), daemon=True)
                reader.start()
                try:
                    if marker.get(timeout=12).strip() != "Invalidated":
                        raise AssertionError("BEGIN cancellation did not invalidate")
                    server.finish()
                    if process.poll() is not None:
                        raise AssertionError("BEGIN probe exited before EOF proof")
                    out, errors = process.communicate(input="\n", timeout=3)
                    if process.returncode or out or errors:
                        raise AssertionError("unsafe BEGIN probe exit")
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=3)
                    reader.join(2)
                    for pipe in [process.stdin, process.stdout, process.stderr]:
                        pipe.close()
                print("Synthetic BEGIN cancellation invalidation and EOF while runtime alive passed")
            for mode in ["refusal", "tls", "auth", "health"]:
                server = ProtocolServer(mode, directory)
                servers.append(server)
                expected = "HealthDeadline" if mode == "health" else ("Connection" if mode == "refusal" else "Deadline")
                check("localhost", server.port, "ca.crt", expected, 300)
                server.finish()
            print("Synthetic protocol refusal-before-credentials, TLS/auth/health deadlines and EOF cleanup passed")
        finally:
            cleanup_errors = []
            for server in servers:
                try:
                    server.close()
                except Exception as error:
                    cleanup_errors.append(error)
            for kind, identity in [("container", container), ("volume", volume), ("network", network)]:
                if identity:
                    try:
                        if kind == "volume":
                            metadata = json.loads(run(["docker", "volume", "inspect", identity]))[0]
                            if metadata["Labels"].get("contour.fixture") != identity:
                                raise AssertionError("refusing unowned volume cleanup")
                        argv = ["docker", "rm", "-f", identity] if kind == "container" else ["docker", kind, "rm", identity]
                        run(argv)
                    except Exception as error:
                        cleanup_errors.append(error)
            if cleanup_errors:
                raise RuntimeError("owned protocol cleanup failed") from cleanup_errors[0]


if __name__ == "__main__":
    main()
