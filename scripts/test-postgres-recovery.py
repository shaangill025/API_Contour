"""Owned real PostgreSQL crash recovery and bounded TLS acknowledgement faults."""
import copy
import json
import queue
import select
import socket
import ssl
import struct
import subprocess
import threading
import time

SSL_REQUEST = struct.pack('!II', 8, 80877103)


class CommitProxy:
    def __init__(self, backend_port, directory, mode):
        self.backend_port = int(backend_port)
        self.directory = directory
        self.mode = mode
        self.error = None
        self.fault = threading.Event()
        self.committed = threading.Event()
        self.stop = threading.Event()
        self.connections = []
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def exact(self, stream, count):
        data = bytearray()
        while len(data) < count:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or self.stop.is_set():
                raise TimeoutError('owned proxy deadline')
            stream.settimeout(min(3, remaining))
            chunk = stream.recv(count - len(data))
            if not chunk:
                raise AssertionError('proxy peer closed before fault')
            data.extend(chunk)
        return bytes(data)

    def frame(self, stream):
        kind = self.exact(stream, 1)
        length = self.exact(stream, 4)
        size = struct.unpack('!I', length)[0]
        if not 4 <= size <= 2 * 1048576:
            raise AssertionError('proxy frame bound')
        body = self.exact(stream, size - 4)
        return kind, body, kind + length + body

    def serve(self):
        try:
            self.deadline = time.monotonic() + 30
            front, _ = self.listener.accept()
            self.connections.append(front)
            if self.exact(front, 8) != SSL_REQUEST:
                raise AssertionError('proxy SSL request mismatch')
            front.sendall(b'S')
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(self.directory / 'server.crt', self.directory / 'server.key')
            front = context.wrap_socket(front, server_side=True)
            self.connections.append(front)
            backend = socket.create_connection(('127.0.0.1', self.backend_port), timeout=5)
            self.connections.append(backend)
            backend.sendall(SSL_REQUEST)
            if self.exact(backend, 1) != b'S':
                raise AssertionError('backend refused TLS')
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_verify_locations(cafile=str(self.directory / 'ca.crt'))
            backend = context.wrap_socket(backend, server_hostname='localhost')
            self.connections.append(backend)
            leaf = ssl.PEM_cert_to_DER_cert((self.directory / 'server.crt').read_text())
            if backend.getpeercert(binary_form=True) != leaf:
                raise AssertionError('proxy channel-binding leaf mismatch')
            length = self.exact(front, 4)
            size = struct.unpack('!I', length)[0]
            if not 8 <= size <= 8192:
                raise AssertionError('proxy startup bound')
            startup = self.exact(front, size - 4)
            if startup[:4] != struct.pack('!I', 196608):
                raise AssertionError('proxy startup version')
            backend.sendall(length + startup)
            commit_sent = completion = False
            while time.monotonic() < self.deadline and not self.stop.is_set():
                readable = [stream for stream in [front, backend] if stream.pending()]
                if not readable:
                    readable, _, _ = select.select([front, backend], [], [], 0.2)
                for stream in readable:
                    kind, body, frame = self.frame(stream)
                    if stream is front:
                        if self.mode == 'cleanup' and self.committed.is_set():
                            if kind != b'P' or b"current_setting('apicontour.tenant_id'" not in body:
                                raise AssertionError('fault was not context cleanup')
                            self.fault.set()
                            return
                        if kind == b'Q' and body == b'COMMIT\0':
                            commit_sent = True
                        backend.sendall(frame)
                    else:
                        if commit_sent and kind == b'C' and body == b'COMMIT\0':
                            completion = True
                        if completion and kind == b'Z':
                            if body != b'I':
                                raise AssertionError('COMMIT did not end transaction')
                            self.committed.set()
                            if self.mode == 'drop':
                                self.fault.set()
                                return
                        if not (self.mode == 'drop' and completion):
                            front.sendall(frame)
            raise TimeoutError('proxy fault was not reached')
        except Exception as error:
            if not self.stop.is_set():
                self.error = error
        finally:
            for stream in self.connections:
                stream.close()
            self.listener.close()

    def finish(self):
        self.thread.join(8)
        if self.thread.is_alive() or self.error or not self.fault.is_set() or not self.committed.is_set():
            raise AssertionError('owned COMMIT fault proof failed') from self.error

    def close(self):
        self.stop.set()
        for stream in self.connections:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            stream.close()
        self.listener.close()
        self.thread.join(8)
        if self.thread.is_alive():
            raise AssertionError('owned proxy thread leaked')


def frame_bounds():
    class Fragmented:
        def __init__(self, data):
            self.data = data

        def settimeout(self, timeout):
            if not 0 < timeout <= 3:
                raise AssertionError('unbounded proxy read')

        def recv(self, count):
            chunk, self.data = self.data[:min(count, 2)], self.data[min(count, 2):]
            return chunk

    proxy = object.__new__(CommitProxy)
    proxy.deadline = time.monotonic() + 1
    proxy.stop = threading.Event()
    frame = b'C' + struct.pack('!I', 11) + b'COMMIT\0'
    if proxy.frame(Fragmented(frame)) != (b'C', b'COMMIT\0', frame):
        raise AssertionError('fragmented frame changed')
    for size in [3, 2 * 1048576 + 1]:
        stream = Fragmented(b'D' + struct.pack('!I', size) + b'unread')
        try:
            proxy.frame(stream)
        except AssertionError:
            if stream.data != b'unread':
                raise AssertionError('out-of-bounds body was read')
        else:
            raise AssertionError('out-of-bounds frame accepted')
    try:
        proxy.frame(Fragmented(b'C\x00'))
    except AssertionError:
        pass
    else:
        raise AssertionError('truncated frame accepted')


def run_cases(container, execute, setup, check, probe, port, directory, environment):
    frame_bounds()
    def run(argv, timeout=30):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise AssertionError('owned recovery command failed')
        return result.stdout.strip()

    def scope(body):
        return "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (body['tenant_id'], body['collector_id'], body['batch_id'])

    def snapshot(body):
        return execute("SELECT row_to_json(b)::text,encode(p.checked_batch,'hex') FROM contour.ingestion_batches b JOIN contour.ingestion_payloads p USING(tenant_id,collector_id,batch_id) WHERE %s;" % scope(body).replace('tenant_id=', 'b.tenant_id=').replace('collector_id=', 'b.collector_id=').replace('batch_id=', 'b.batch_id='))

    def original_receipt(body):
        row = execute("SELECT receipt_id::text,floor(extract(epoch FROM accepted_at)*1000000000)::bigint FROM contour.ingestion_batches WHERE %s;" % scope(body))
        if not row:
            raise AssertionError('committed pair missing')
        return 'Accepted ' + row.replace('|', ' ')

    for mode, wanted in [('drop', 'OutcomeUnknown'), ('cleanup', 'AcceptedInvalidated')]:
        body, _, _ = setup('recovery_' + mode)
        proxy = CommitProxy(port, directory, mode)
        try:
            result = check(body, wanted, port_override=proxy.port)
            proxy.finish()
        finally:
            proxy.close()
        before = snapshot(body)
        receipt = original_receipt(body)
        if not before or check(body) != receipt or mode == 'cleanup' and result != receipt:
            raise AssertionError('COMMIT fault did not preserve original pair/receipt')
        conflicting = copy.deepcopy(body)
        conflicting['records'][0]['count'] += 1
        check(conflicting, 'Conflict')
        if snapshot(body) != before:
            raise AssertionError('fault replay mutated persisted pair')

    persisted, _, _ = setup('recovery_persisted')
    receipt = check(persisted)
    before = snapshot(persisted)
    interrupted, _, _ = setup('recovery_interrupted')
    execute("CREATE FUNCTION contour.recovery_commit_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(30); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER recovery_delay AFTER INSERT ON contour.ingestion_batches DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION contour.recovery_commit_delay();")
    path = directory / 'recovery-interrupted.json'
    path.write_text(json.dumps(interrupted))
    process = subprocess.Popen([probe, str(port), str(directory / 'ca.crt'), str(directory / 'signer.raw'), str(path), 'OutcomeUnknown', interrupted['tenant_id'], interrupted['collector_id'], '5000'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
    markers = queue.Queue()
    reader = threading.Thread(target=lambda: markers.put(process.stdout.readline()), daemon=True)
    reader.start()
    try:
        until = time.monotonic() + 4
        while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls' AND query='COMMIT' AND wait_event='PgSleep';") != '1':
            if time.monotonic() > until:
                raise AssertionError('crash did not interrupt uncommitted real pair')
            time.sleep(0.02)
        run(['docker', 'kill', '--signal', 'KILL', container])
        if json.loads(run(['docker', 'inspect', container]))[0]['State']['Running']:
            raise AssertionError('owned PostgreSQL was not killed')
        run(['docker', 'start', container])
        until = time.monotonic() + 60
        while True:
            ready = subprocess.run(['docker', 'exec', container, 'sh', '-c', 'test "$(cat /proc/1/comm)" = postgres && pg_isready -U postgres -d contour_fixture'], capture_output=True, timeout=5)
            if ready.returncode == 0:
                break
            if time.monotonic() >= until:
                raise AssertionError('owned PostgreSQL recovery startup timed out')
            time.sleep(0.2)
        bindings = json.loads(run(['docker', 'inspect', container]))[0]['NetworkSettings']['Ports']['5432/tcp']
        if len(bindings) != 1 or bindings[0]['HostIp'] != '127.0.0.1':
            raise AssertionError('restarted fixture binding is not loopback-only')
        restarted_port = bindings[0]['HostPort']
        if markers.get(timeout=15).strip() != 'OutcomeUnknown' or process.poll() is not None:
            raise AssertionError('crashed commit was acknowledged or runtime exited')
        if execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls';") != '0':
            raise AssertionError('crashed probe driver/backend survived')
        out, errors = process.communicate(input='\n', timeout=3)
        if process.returncode or out or errors:
            raise AssertionError('crashed submission probe failed')
        execute('DROP TRIGGER recovery_delay ON contour.ingestion_batches; DROP FUNCTION contour.recovery_commit_delay();')
        if snapshot(persisted) != before or check(persisted, port_override=restarted_port) != receipt:
            raise AssertionError('real PostgreSQL crash changed durable pair/receipt/digest/bytes')
        counts = execute("SELECT (SELECT count(*) FROM contour.ingestion_batches WHERE %s),(SELECT count(*) FROM contour.ingestion_payloads WHERE %s);" % (scope(interrupted), scope(interrupted)))
        if counts != '0|0':
            raise AssertionError('interrupted uncommitted pair survived crash')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        reader.join(2)
        for pipe in [process.stdin, process.stdout, process.stderr]:
            pipe.close()
    print('Verified TLS server-COMMIT-ack drop and known-COMMIT cleanup failure preserve checked receipts')
    print('Owned PostgreSQL SIGKILL/restart preserves exact durable pair and removes interrupted uncommitted pair')
