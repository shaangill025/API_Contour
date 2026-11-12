"""Actual PostgreSQL TLS plus labeled synthetic protocol failures; Python 3.9+."""
import json
import hashlib
import stat
import os
import queue
import runpy
from pathlib import Path
import secrets
import selectors
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


def bounded_git(args,limit):
    process=subprocess.Popen(['git',*args],cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    selector=selectors.DefaultSelector(); data=bytearray(); errors=bytearray(); deadline=time.monotonic()+15
    try:
        for pipe,target in ((process.stdout,data),(process.stderr,errors)):
            os.set_blocking(pipe.fileno(),False); selector.register(pipe,selectors.EVENT_READ,target)
        while selector.get_map():
            remaining=deadline-time.monotonic()
            if remaining<=0: raise TimeoutError('fixture source check deadline')
            events=selector.select(remaining)
            if not events: raise TimeoutError('fixture source check deadline')
            for key,_ in events:
                chunk=os.read(key.fd,min(65536,limit+1-len(data)-len(errors)))
                if not chunk: selector.unregister(key.fileobj); continue
                key.data.extend(chunk)
                if len(data)+len(errors)>limit: raise ValueError('fixture source check output exceeds bound')
        remaining=deadline-time.monotonic()
        if remaining<=0 or process.wait(timeout=remaining)!=0 or errors: raise ValueError('fixture source check failed')
        return bytes(data)
    finally:
        selector.close()
        if process.poll() is None: process.kill();process.wait(timeout=5)
        process.stdout.close();process.stderr.close()


def runtime_source_snapshot():
    """Bind all tracked and nonignored source, including uncommitted task files."""
    head = bounded_git(['rev-parse', 'HEAD'], 128).decode('ascii').strip()
    if len(head) != 40 or any(c not in '0123456789abcdef' for c in head):
        raise ValueError('fixture source head invalid')
    names = bounded_git(['ls-files', '--cached', '--others', '--exclude-standard', '-z'], 16_777_216).split(b'\0')
    for optional in ('.cargo/config', '.cargo/config.toml', 'rust-toolchain', 'rust-toolchain.toml'):
        if (ROOT/optional).exists() and optional.encode() not in names:
            names.append(optional.encode())
    result = {}
    for raw in names:
        if not raw: continue
        name = raw.decode('utf-8')
        path = ROOT / name
        if name in result or Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('fixture source path invalid')
        if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
            raise ValueError('fixture source unavailable')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > 134_217_728:
                raise ValueError('fixture source size invalid')
            digest = hashlib.sha256()
            with os.fdopen(fd, 'rb', closefd=False) as source:
                for chunk in iter(lambda: source.read(1_048_576), b''):
                    digest.update(chunk)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise ValueError('fixture source changed during hashing')
            result[name] = digest.hexdigest()
        finally:
            os.close(fd)
    if not result: raise ValueError('fixture source empty')
    return head, result


def checked_history_loader():
    """Check clean source and exact committed bytes before executing fixture code."""
    name='scripts/test-human-observation-history.py'; path=ROOT/name
    for candidate in (path,*path.parents):
        if candidate.is_symlink(): raise ValueError('fixture source has symlink ancestor')
    if bounded_git(['status','--porcelain','--untracked-files=all'],16_777_216): raise ValueError('fixture source is not clean')
    tracked=bounded_git(['show','HEAD:'+name],1_000_000)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>1_000_000: raise ValueError('fixture source invalid')
        with os.fdopen(fd,'rb',closefd=False) as source: raw=source.read(1_000_001)
        if raw!=tracked: raise ValueError('fixture source differs from committed version')
        namespace={'__file__':str(path),'__name__':'history_fixture'}
        exec(compile(raw,str(path),'exec'),namespace)
        after=os.fstat(fd)
        if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)!=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns) or hashlib.sha256(path.read_bytes()).digest()!=hashlib.sha256(raw).digest(): raise ValueError('fixture source changed while loading')
        return namespace
    finally: os.close(fd)


def fixture_environment(password, target, sensor_image=None):
    environment = dict(os.environ, CONTOUR_FIXTURE_PASSWORD=password,
        CONTOUR_ORIGIN_PROBE=str(Path(target)/'debug/examples/origin_submit_probe'),
        CONTOUR_ORIGIN_HTTPS_PROBE=str(Path(target)/'debug/examples/origin_https_probe'))
    # Only the explicit fixture mode can activate the separately bounded pilot.
    environment.pop('CONTOUR_FIXTURE_PSQL_OWNER', None)
    environment.pop('CONTOUR_ORIGIN_SENSOR_IMAGE', None)
    environment.pop('CONTOUR_HUMAN_ORIGIN_FIXTURE', None)
    environment.pop('CONTOUR_HUMAN_OBSERVATION_HISTORY_FIXTURE', None)
    environment.pop('CONTOUR_ORIGIN_REPLACEMENT_FIXTURE', None)
    environment.pop('CONTOUR_ORIGIN_ADMISSION_FIXTURE', None)
    environment.pop('CONTOUR_TLS_DISCOVERY_MATRIX', None)
    environment.pop('CONTOUR_RUNTIME_CAPTURE_FIXTURE', None)
    environment.pop('CONTOUR_RUNTIME_CAPTURE_PROBE', None)
    environment.pop('CONTOUR_RUNTIME_POSTGRES_PORT', None)
    if sensor_image is not None:
        environment['CONTOUR_ORIGIN_SENSOR_IMAGE'] = sensor_image
    return environment


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
    if len(flags)>1 or any(flag not in ['--authority','--origin-sensor','--tls-discovery-matrix','--origin-replacement-only','--origin-admission-only','--https-only','--delivery-only','--refresh-only','--catalog-reader','--comparison-store','--service-import-store','--human-import','--review-store','--human-origin','--human-observation-history','--runtime-capture'] for flag in flags):
        raise ValueError("choose one supported fixture mode")
    admission = flags == ['--origin-admission-only']
    replacement = flags == ['--origin-replacement-only'] or admission
    matrix = flags == ['--tls-discovery-matrix']
    origin_sensor = flags == ['--origin-sensor'] or replacement or matrix
    if origin_sensor:
        sys.dont_write_bytecode = True
    human_history = flags == ['--human-observation-history']
    runtime_capture = flags == ['--runtime-capture']
    supervised = human_history or runtime_capture
    if supervised: sys.dont_write_bytecode = True
    human_origin = flags == ['--human-origin'] or human_history
    authority_mode = '--authority' in flags or origin_sensor or human_origin or runtime_capture
    history_fixture = checked_history_loader() if human_history else (runpy.run_path(str(ROOT/'scripts/test-human-observation-history.py')) if runtime_capture else None)
    history_source = history_fixture['source_snapshot']() if human_history else (runtime_source_snapshot() if runtime_capture else None)
    fixture_image = None
    if supervised:
        fixture_directory=history_fixture['OwnedFixtureDirectory']()
        target=fixture_directory.path/'cargo-target'
        fixture_directory.intent('target',{'version':1,'path':str(target)})
        target.mkdir(mode=0o700)
        os.environ['CARGO_TARGET_DIR']=str(target)
        history_artifacts={}
    for tool in ["docker", "openssl", "cargo"]:
        if not shutil.which(tool):
            raise RuntimeError("required fixture tool missing")
    run(["docker", "image", "inspect", IMAGE])  # Never download images here.
    if supervised:
        initial_metadata=json.loads(run(['cargo','metadata','--format-version','1','--no-deps','--offline']))
        if initial_metadata.get('target_directory')!=str(target): raise ValueError('fixture target mismatch')
        package_ids={item['name']:item['id'] for item in initial_metadata['packages']}
    def build(argv,timeout=30):
        if not supervised: return run(argv,timeout=timeout)
        expected=[argv[i+1] for i,item in enumerate(argv[:-1]) if item=='--example']
        package=argv[argv.index('-p')+1]
        if package not in package_ids: raise ValueError('fixture package unavailable')
        if not expected or len(set(expected))!=len(expected): raise ValueError('fixture build examples invalid')
        output=run(argv+['--message-format=json'],timeout=timeout)
        selected=history_fixture['select_artifacts'](output,expected,package_ids[package],target)
        history_artifacts.update(selected)
    build(["cargo", "build", "-p", "contour-postgres", "--example", "tls_probe", "--locked", "--offline"], timeout=180)
    if runtime_capture:
        build(["cargo", "build", "-p", "contour-ingress", "--example", "runtime_capture_probe", "--locked", "--offline"], timeout=180)
    if origin_sensor:
        # Separate opt-in qualification: never add image builds or Node-RED to
        # the existing authority check's 240-second command budget.
        if run(['git','status','--porcelain','--untracked-files=all']):
            raise AssertionError('origin fixture build requires a frozen clean checkout')
        source = run(['git','rev-parse','HEAD'])
        fixture_image = 'contour-origin-sensor-fixture:' + source[:12]
        run(['docker','build','--pull=false','--build-arg','SOURCE_HEAD='+source,
             '-f','tests/fixtures/origin-sensor/Dockerfile','-t',fixture_image,'.'], timeout=600)
    if authority_mode or "--refresh-only" in sys.argv:
        build(["cargo", "build", "-p", "contour-postgres", "--example", "authority_probe", "--locked", "--offline"], timeout=180)
        build(["cargo", "build", "-p", "contour-postgres", "--example", "submit_probe", "--locked", "--offline"], timeout=180)
        if authority_mode:
            build(["cargo", "build", "-p", "contour-postgres", "--example", "v2_submit_probe", "--example", "origin_submit_probe", "--locked", "--offline"], timeout=180)
            build(["cargo", "build", "-p", "contour-ingress", "--example", "origin_https_probe", "--locked", "--offline"], timeout=180)
        build(["cargo", "build", "-p", "contour-postgres", "--example", "catalog_probe", "--locked", "--offline"], timeout=180)
        build(["cargo", "build", "-p", "contour-postgres", "--example", "refresh_probe", "--locked", "--offline"], timeout=180)
        if human_origin:
            build(["cargo", "build", "-p", "contour-postgres", "--example", "human_catalog_probe", "--locked", "--offline"], timeout=180)
            build(["cargo", "build", "-p", "contour-platform", "--example", "human_origin_business_probe", "--locked", "--offline"], timeout=180)
    elif "--service-import-store" in sys.argv or "--human-import" in sys.argv:
        build(["cargo", "build", "-p", "contour-postgres", "--example", "service_import_probe", "--example", "declared_store_probe", "--example", "review_store_probe", "--example", "comparison_store_probe", "--example", "public_review_probe", "--example", "human_catalog_probe", "--locked", "--offline"], timeout=180)
    elif "--review-store" in sys.argv:
        build(["cargo", "build", "-p", "contour-postgres", "--example", "declared_store_probe", "--example", "approval_probe", "--example", "review_store_probe", "--locked", "--offline"], timeout=180)
        build(["cargo", "build", "-p", "contour-core", "--example", "import_probe", "--locked", "--offline"], timeout=180)
    elif "--comparison-store" in sys.argv:
        build(["cargo", "build", "-p", "contour-postgres", "--example", "declared_store_probe", "--example", "approval_probe", "--example", "comparison_store_probe", "--locked", "--offline"], timeout=180)
        build(["cargo", "build", "-p", "contour-core", "--example", "import_probe", "--locked", "--offline"], timeout=180)
    elif "--catalog-reader" in sys.argv:
        for example in ["submit_probe", "catalog_probe", "catalog_reader_probe", "declared_store_probe", "approval_probe"]:
            build(["cargo", "build", "-p", "contour-postgres", "--example", example, "--locked", "--offline"], timeout=180)
        build(["cargo", "build", "-p", "contour-core", "--example", "comparison_probe", "--example", "declared_comparison_probe", "--example", "import_probe", "--locked", "--offline"], timeout=180)
    elif "--https-only" in sys.argv or "--delivery-only" in sys.argv:
        build(["cargo", "build", "-p", "contour-ingress", "--example", "https_probe", "--locked", "--offline"], timeout=180)
    if "--https-only" in sys.argv:
        build(["cargo", "build", "-p", "contour-core", "--example", "operation_probe", "--locked", "--offline"], timeout=180)
        build(["cargo", "build", "-p", "contour-delivery", "--example", "owner_probe", "--locked", "--offline"], timeout=180)
    if "--delivery-only" in sys.argv:
        build(["cargo", "build", "-p", "contour-delivery", "--example", "delivery_probe", "--example", "owner_probe", "--example", "pool_probe", "--locked", "--offline"], timeout=180)
        build(["cargo", "build", "-p", "contour-postgres", "--example", "catalog_probe", "--locked", "--offline"], timeout=180)
    metadata = json.loads(run(["cargo", "metadata", "--format-version", "1", "--no-deps", "--offline"]))
    if supervised:
        if metadata['target_directory']!=str(target): raise ValueError('fixture cargo target changed')
        sys.addaudithook(history_fixture['artifact_guard'](target,history_artifacts))
        if runtime_capture and runtime_source_snapshot()!=history_source: raise ValueError('fixture source changed during build')
    probe = str(Path(metadata["target_directory"])/"debug"/"examples"/"tls_probe")
    network = container = volume = None
    servers = []
    os.umask(0o077)
    if not supervised: fixture_directory = tempfile.TemporaryDirectory(prefix="contour-tls-")
    with fixture_directory as folder:
        directory = Path(folder)
        password = secrets.token_hex(24)
        environment = fixture_environment(password, metadata['target_directory'], fixture_image)
        if runtime_capture:
            environment['CONTOUR_RUNTIME_CAPTURE_FIXTURE'] = '1'
            environment['CONTOUR_RUNTIME_CAPTURE_PROBE'] = str(target/'debug/examples/runtime_capture_probe')
        if matrix: environment['CONTOUR_TLS_DISCOVERY_MATRIX'] = '1'
        if replacement: environment['CONTOUR_ORIGIN_REPLACEMENT_FIXTURE'] = '1'
        if admission: environment['CONTOUR_ORIGIN_ADMISSION_FIXTURE'] = '1'
        if human_origin:
            environment['CONTOUR_HUMAN_ORIGIN_FIXTURE'] = '1'
        if human_history:
            environment['CONTOUR_HUMAN_OBSERVATION_HISTORY_FIXTURE'] = '1'
        fixture_owner=secrets.token_hex(16) if supervised else None
        history_uncertain=False; history_image_id=None; network_name=None; history_started=None
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
            network_name="contour-tls-"+secrets.token_hex(6)
            if supervised:
                history_image_id=json.loads(run(['docker','image','inspect',IMAGE]))[0]['Id']
                if not history_image_id.startswith('sha256:') or len(history_image_id)!=71: raise ValueError('fixture image identity invalid')
                fixture_directory.intent('network',{'version':1,'name':network_name,'owner':fixture_owner})
                history_uncertain=True
            network = run(["docker", "network", "create", *(['--internal'] if origin_sensor else []), *(['--label','org.apicontour.observation-owner='+fixture_owner] if supervised else []), "--driver", "bridge", "--opt",
                           "com.docker.network.bridge.enable_ip_masquerade=false", network_name])
            network_settings = json.loads(run(["docker", "network", "inspect", network]))[0]
            if supervised:
                if len(network)!=64 or any(c not in '0123456789abcdef' for c in network) or network_settings.get('Id')!=network or network_settings.get('Name')!=network_name or (network_settings.get('Labels') or {}).get('org.apicontour.observation-owner')!=fixture_owner or (network_settings.get('Containers') or {}): raise ValueError('fixture network identity uncertain')
                history_uncertain=False
            if network_settings["Driver"] != "bridge" or network_settings["Options"].get("com.docker.network.bridge.enable_ip_masquerade") != "false":
                raise AssertionError("fixture bridge configuration mismatch")
            if origin_sensor and not network_settings['Internal']:
                raise AssertionError('origin fixture network must be internal')
            data_mount = ["--tmpfs", "/var/lib/postgresql/data:rw,nosuid,noexec,size=256m"]
            if authority_mode or "--https-only" in sys.argv or "--delivery-only" in sys.argv or "--refresh-only" in sys.argv or "--catalog-reader" in sys.argv or "--comparison-store" in sys.argv or "--service-import-store" in sys.argv or "--review-store" in sys.argv:
                volume = "contour-recovery-" + secrets.token_hex(12)
                if supervised:
                    fixture_directory.intent('volume',{'version':1,'name':volume,'owner':fixture_owner}); history_uncertain=True
                created_volume=run(["docker", "volume", "create", "--label", "contour.fixture=" + volume, *(['--label','org.apicontour.observation-owner='+fixture_owner] if supervised else []), volume])
                if supervised:
                    obj=json.loads(run(['docker','volume','inspect',volume]))[0]
                    if created_volume!=volume or obj.get('Name')!=volume or (obj.get('Labels') or {}).get('org.apicontour.observation-owner')!=fixture_owner: raise ValueError('fixture volume identity uncertain')
                    history_uncertain=False
                data_mount = ["--mount", "type=volume,source=" + volume + ",target=/var/lib/postgresql/data"]
            if not supervised: fixture_owner = secrets.token_hex(16)
            if supervised:
                fixture_directory.intent('container',{'version':1,'owner':fixture_owner,'network':network,'volume':volume,'image_id':history_image_id}); history_uncertain=True
            container = run(["docker", "create", *(['--init'] if supervised else []), "--label", "org.apicontour.fixture-owner="+fixture_owner, "--network", network,
                             *([] if origin_sensor else ['--publish', '127.0.0.1::5432']),
                             "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
                             *data_mount,
                             "-e", "POSTGRES_DB=contour_fixture", "-e", "POSTGRES_PASSWORD="+password,
                             "-e", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256", IMAGE, "sh", "-c",
                             "chown postgres:postgres /tmp/server.key /tmp/server.crt && chmod 600 /tmp/server.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key"])
            if supervised:
                obj=json.loads(run(['docker','inspect',container]))[0]
                mounts=obj.get('Mounts') or []; selected=[m for m in mounts if m.get('Destination')=='/var/lib/postgresql/data']
                if len(container)!=64 or any(c not in '0123456789abcdef' for c in container) or obj.get('Id')!=container or obj.get('Image')!=history_image_id or (obj.get('Config') or {}).get('Image')!=IMAGE or ((obj.get('Config') or {}).get('Labels') or {}).get('org.apicontour.fixture-owner')!=fixture_owner or (obj.get('HostConfig') or {}).get('Init') is not True or len(selected)!=1 or selected[0].get('Name')!=volume: raise ValueError('fixture container identity uncertain')
                history_uncertain=False
            if '--authority' in flags or supervised:
                environment['CONTOUR_FIXTURE_PSQL_OWNER'] = fixture_owner
            if volume:
                mounts = json.loads(run(["docker", "inspect", container]))[0]["Mounts"]
                owned = [mount for mount in mounts if mount["Destination"] == "/var/lib/postgresql/data"]
                if len(owned) != 1 or owned[0]["Type"] != "volume" or owned[0]["Name"] != volume:
                    raise AssertionError("recovery volume mount mismatch")
            for file in ["server.key", "server.crt"]:
                run(["docker", "cp", str(directory/file), container+":/tmp/"+file])
            if supervised: history_uncertain=True
            run(["docker", "start", container])
            if supervised:
                current=json.loads(run(['docker','inspect',container]))[0]
                state=current.get('State') or {}; attached=(current.get('NetworkSettings') or {}).get('Networks') or {}
                if current.get('Id')!=container or state.get('Running') is not True or not isinstance(state.get('StartedAt'),str) or state['StartedAt'].startswith('0001-') or len(attached)!=1 or next(iter(attached.values())).get('NetworkID')!=network: raise ValueError('fixture start identity uncertain')
                history_started=state['StartedAt']
                fixture_directory.intent('generation',{'version':1,'container':container,'network':network,'started_at':history_started})
                history_uncertain=False
            deadline = time.monotonic()+60
            while True:
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("PostgreSQL TLS startup timed out")
                try:
                    readiness = ("""test "$(cat /proc/1/comm)" = docker-init && p=$(head -n 1 /var/lib/postgresql/data/postmaster.pid) && case "$p" in *[!0-9]*|'') exit 1;; esac && test "$p" -gt 1 && test "$(cat /proc/$p/comm)" = postgres && psql -XqAt -v ON_ERROR_STOP=1 -U postgres -d contour_fixture -c "SELECT current_database()='contour_fixture' AND current_setting('listen_addresses')='*' AND current_setting('ssl')='on';" | grep -qx t""" if supervised else 'test "$(cat /proc/1/comm)" = postgres && pg_isready -U postgres -d contour_fixture')
                    ready = subprocess.run(["docker", "exec", container, "sh", "-c", readiness],
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
            hba = "local all all trust\nhostnossl all all all reject\nhostssl contour_fixture contour_tls,contour_v2_ingress_test,contour_origin_ingress_test,contour_human_reader_tls,contour_human_writer_tls,contour_catalog_tls,contour_catalog_reader_tls,contour_declared_writer_tls,contour_declared_reader_tls,contour_approval_writer_tls,contour_comparison_writer_tls,contour_comparison_reader_tls,contour_review_writer_tls,contour_review_reader_tls all scram-sha-256\nhostssl all all all reject\n"
            run(["docker", "exec", "-i", container, "sh", "-c", "cat > /var/lib/postgresql/data/pg_hba.conf"], hba)
            run(sql, "SELECT pg_reload_conf();")
            if origin_sensor:
                # This mode has no host endpoints. All traffic and PostgreSQL
                # TLS clients share the owned internal network namespace.
                ports = json.loads(run(['docker','inspect',container]))[0]['NetworkSettings']['Ports']
                if any(ports.values()):
                    raise AssertionError('origin fixture must not publish host ports')
                runpy.run_path(str(ROOT/'scripts/test-postgres-authority.py'))['run_cases'](
                    container,sql,probe,'5432',directory,environment,origin_sensor_only=True)
                return
            bindings = json.loads(run(["docker", "inspect", container]))[0]["NetworkSettings"]["Ports"]["5432/tcp"]
            if len(bindings) != 1 or bindings[0]["HostIp"] != "127.0.0.1":
                raise AssertionError("fixture port is not loopback-only: " + repr(bindings))
            port = bindings[0]["HostPort"]

            if runtime_capture:
                environment['CONTOUR_RUNTIME_POSTGRES_PORT'] = port
                runpy.run_path(str(ROOT/'scripts/test-postgres-authority.py'))['run_cases'](
                    container,sql,probe,port,directory,environment,origin_sensor_only=True)
                print('Runtime capture record checks passed; cleanup pending')
                return

            def check(host, port, ca, mode, milliseconds=3000):
                output = run([probe, host, str(port), str(directory/ca), str(milliseconds), mode], timeout=12, env=environment)
                expected = "Deadline" if mode == "HealthDeadline" else "Connection" if mode == "SingleConnection" else mode
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
            check("127.0.0.1", port, "ca.crt", "SingleConnection")
            print("Actual PostgreSQL trusted CA, TLS health, bad CA, wrong hostname and backend cleanup passed")
            if "--https-only" in sys.argv or "--delivery-only" in sys.argv:
                authority_probe = str(Path(metadata["target_directory"])/"debug"/"examples"/"authority_probe")
                runpy.run_path(str(ROOT/"scripts/test-postgres-authority.py"))["run_cases"](container,sql,authority_probe,port,directory,environment,https_only=True,delivery_only="--delivery-only" in sys.argv)
            elif "--human-import" in sys.argv:
                runpy.run_path(str(ROOT/"scripts/test-human-import.py"))["run_cases"](container,sql,port,directory,environment)
            elif "--service-import-store" in sys.argv:
                runpy.run_path(str(ROOT/"scripts/test-service-import-store.py"))["run_cases"](container,sql,port,directory,environment)
            elif "--review-store" in sys.argv:
                fixture=runpy.run_path(str(ROOT/"scripts/test-review-store.py"))
                fixture["bootstrap"](sql,port,directory,environment)
                fixture["run_cases"](container,sql,port,directory,environment)
            elif "--comparison-store" in sys.argv:
                fixture=runpy.run_path(str(ROOT/"scripts/test-comparison-store.py"))
                fixture["bootstrap"](sql,port,directory,environment)
                fixture["run_cases"](container,sql,port,directory,environment)
            elif "--catalog-reader" in sys.argv:
                submit_probe = str(Path(metadata["target_directory"])/"debug"/"examples"/"submit_probe")
                runpy.run_path(str(ROOT/"scripts/test-postgres-authority.py"))["run_cases"](container,sql,submit_probe,port,directory,environment,catalog_reader_only=True)
                runpy.run_path(str(ROOT/"scripts/test-declared-store.py"))["run_cases"](container,sql,port,directory,environment)
                runpy.run_path(str(ROOT/"scripts/test-approval.py"))["run_cases"](container,sql,port,directory,environment)
            elif "--refresh-only" in sys.argv:
                authority_probe = str(Path(metadata["target_directory"])/"debug"/"examples"/"authority_probe")
                runpy.run_path(str(ROOT/"scripts/test-postgres-authority.py"))["run_cases"](container,sql,authority_probe,port,directory,environment,refresh_only=True)
            elif authority_mode:
                authority_probe = str(Path(metadata["target_directory"])/"debug"/"examples"/"authority_probe")
                runpy.run_path(str(ROOT/"scripts/test-postgres-authority.py"))["run_cases"](container,sql,authority_probe,port,directory,environment)
                if human_history:
                    history_fixture['require_receipt'](directory)
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
            if supervised:
                primary = sys.exception()
                try:
                    if history_uncertain: raise RuntimeError('fixture creation outcome uncertain; resources retained')
                    history_fixture['cleanup_resources'](run,container,volume,network,fixture_owner,history_image_id,network_name,IMAGE,history_started)
                except BaseException as error:
                    cleanup_errors.append(error)
                try:
                    if (history_fixture['source_snapshot']() if human_history else runtime_source_snapshot())!=history_source: raise RuntimeError('fixture source changed')
                except BaseException as error:
                    cleanup_errors.append(error)
                if cleanup_errors:
                    if primary is not None: cleanup_errors.insert(0,primary)
                    raise BaseExceptionGroup('fixture and cleanup failures',cleanup_errors) from None
                if primary is None: fixture_directory.complete=True
            else:
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
