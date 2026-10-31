"""Owned lost-response relay for the real pool, TLS ingress and catalog fixture."""
import contextlib
import datetime
import hashlib
import http.client
import http.server
import json
from pathlib import Path
import queue
import socket
import ssl
import subprocess
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 1_048_576


def validate_receipt(value, batch, status):
    if set(value) != {'batch_id', 'status', 'receipt_id', 'accepted_at'} or value['batch_id'] != batch or value['status'] != status:
        raise AssertionError('receipt mismatch')
    import uuid
    uuid.UUID(value['receipt_id'])
    instant = datetime.datetime.fromisoformat(value['accepted_at'].replace('Z', '+00:00'))
    if instant.tzinfo is None:
        raise AssertionError('receipt time missing zone')
    return value['receipt_id'], instant


def domain_digest(raw):
    value = json.loads(raw)
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    return hashlib.sha256(b'apicontour/batch/1\n' + canonical).hexdigest()


def validate_replay(raw, first_wire, value, batch, receipt):
    if raw != first_wire or domain_digest(raw) != domain_digest(first_wire):
        raise AssertionError('frozen batch changed')
    if validate_receipt(value, batch, 'duplicate') != receipt:
        raise AssertionError('duplicate receipt changed')


IDENTITY_FIELDS = ('record_id', 'source_id', 'project_id', 'service_id',
                   'environment_id', 'deployment_id', 'protocol', 'direction',
                   'operation', 'route_template')


def validate_batch_identity(raw, expected):
    batch = json.loads(raw)
    if any(batch.get(key) != expected[key] for key in ('tenant_id', 'collector_id', 'batch_id')):
        raise AssertionError('batch identity mismatch')
    records = batch.get('records')
    if not isinstance(records, list) or len(records) != 1:
        raise AssertionError('batch record count mismatch')
    record = expected['records'][0]
    if any(records[0].get(key) != record[key] for key in IDENTITY_FIELDS):
        raise AssertionError('record identity mismatch')


def validate_pool_receipt(value, receipt):
    if value != {'status': 'Duplicate', 'receipt_id': receipt[0]}:
        raise AssertionError('pool receipt mismatch')


def validate_snapshot(actual, expected):
    if actual != expected:
        raise AssertionError('durable receipt or counts changed')


def validate_observation(observed, expected):
    if observed != expected:
        raise AssertionError('catalog observation identity mismatch')


def operation_key(body):
    record = body['records'][0]
    fields = ('project_id', 'service_id', 'environment_id', 'protocol', 'direction', 'operation', 'route_template')
    return json.dumps([body['tenant_id']] + [record[key] for key in fields], ensure_ascii=False, separators=(',', ':')).encode().hex()


def run_cases(execute, setup, server, directory, environment, pool_probe, catalog_probe, pg_port):
    body, _, _ = setup('pool_lost_receipt', current=1, history=(1,))
    scope = "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (body['tenant_id'], body['collector_id'], body['batch_id'])
    evidence = {'sends': 0}
    errors = []

    def durable_snapshot():
        return execute("SELECT receipt_id::text, (extract(epoch FROM accepted_at)*1000000)::bigint, encode(request_digest,'hex'), (SELECT count(*) FROM contour.ingestion_batches WHERE %s), (SELECT count(*) FROM contour.ingestion_payloads WHERE %s) FROM contour.ingestion_batches WHERE %s;" % (scope, scope, scope), timeout=3).split('|')

    @contextlib.contextmanager
    def relay(upstream):
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *args): pass
            def do_POST(self):
                # A watchdog bounds total work even if individual reads make progress.
                connections = [self.connection]
                def abort():
                    for connection in connections:
                        try: connection.shutdown(socket.SHUT_RDWR)
                        except OSError: pass
                timer = threading.Timer(8, abort); timer.start()
                try:
                    self.connection.settimeout(3)
                    size = int(self.headers['Content-Length'])
                    if not 0 <= size <= LIMIT: raise AssertionError('request bound')
                    raw = self.rfile.read(size)
                    if len(raw) != size: raise AssertionError('truncated request')
                    if self.path == '/v1/batches': validate_batch_identity(raw, body)
                    context = ssl.create_default_context(cafile=str(directory/'ca.crt'))
                    context.load_cert_chain(directory/'http-client.crt', directory/'http-client.key')
                    connection = http.client.HTTPSConnection('localhost', upstream, context=context, timeout=3)
                    try:
                        connection.request('POST', self.path, raw, {'Content-Type':'application/json'})
                        if connection.sock is not None: connections.append(connection.sock)
                        response = connection.getresponse()
                        payload = response.read(LIMIT+1)
                        if response.status != 200 or len(payload) > LIMIT: raise AssertionError('upstream response')
                        value = json.loads(payload)
                    finally:
                        connection.close()
                    if self.path == '/v1/batches':
                        evidence['sends'] += 1
                        send = evidence['sends']
                        if send == 1:
                            evidence['wire'] = raw
                            evidence['receipt'] = validate_receipt(value, body['batch_id'], 'accepted')
                            durable = durable_snapshot()
                            receipt, instant = evidence['receipt']
                            epoch = datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)
                            delta = instant - epoch
                            micros = (delta.days*86400+delta.seconds)*1000000+delta.microseconds
                            validate_snapshot(durable, [receipt, str(micros), domain_digest(raw), '1', '1'])
                            evidence['durable'] = durable
                            # No response line, headers or body are written to the downstream.
                            self.close_connection = True
                            try: self.connection.shutdown(socket.SHUT_RDWR)
                            except OSError: pass
                            return
                        if send != 2: raise AssertionError('unexpected retry count')
                        validate_replay(raw, evidence['wire'], value, body['batch_id'], evidence['receipt'])
                    self.send_response(200)
                    self.send_header('Content-Type','application/json')
                    self.send_header('Content-Length',str(len(payload)))
                    self.send_header('Connection','close')
                    self.end_headers()
                    self.wfile.write(payload)
                    self.close_connection = True
                except BaseException as error:
                    errors.append(error)
                    self.close_connection = True
                finally:
                    timer.cancel(); timer.join()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(directory/'server.crt', directory/'server.key')
        context.load_verify_locations(str(directory/'ca.crt'))
        context.verify_mode = ssl.CERT_REQUIRED
        context.set_alpn_protocols(['http/1.1'])
        class Server(http.server.HTTPServer):
            def get_request(self):
                raw, address = super().get_request()
                raw.settimeout(3)
                def abort_handshake():
                    try: raw.shutdown(socket.SHUT_RDWR)
                    except OSError: pass
                timer = threading.Timer(5, abort_handshake); timer.start()
                try: return context.wrap_socket(raw, server_side=True), address
                except BaseException:
                    raw.close()
                    raise
                finally:
                    timer.cancel(); timer.join()
        service = Server(('127.0.0.1',0), Handler)
        service.timeout = 3
        thread = threading.Thread(target=service.serve_forever, daemon=True); thread.start()
        try:
            yield service.server_port
        except BaseException as exc:
            original = exc
            raise
        finally:
            original = locals().get('original')
            try:
                service.shutdown(); service.server_close(); thread.join(10)
                if thread.is_alive() or errors: raise AssertionError('owned relay failed')
            except BaseException as cleanup_error:
                if original is not None: raise BaseExceptionGroup('relay work and cleanup failed', [original, cleanup_error])
                raise

    @contextlib.contextmanager
    def pool(port):
        process = subprocess.Popen([pool_probe,str(directory),str(port)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
        process.stdin.write(json.dumps(body)+'\n'); process.stdin.flush()
        lines = queue.Queue()
        reader = threading.Thread(target=lambda: [lines.put(line) for line in process.stdout],daemon=True); reader.start()
        def call(action):
            process.stdin.write(action+'\n'); process.stdin.flush()
            try: return json.loads(lines.get(timeout=12))
            except queue.Empty: raise AssertionError('pool command deadline') from None
        try: yield call
        except BaseException as exc:
            original = exc
            raise
        finally:
            original = locals().get('original')
            try:
                try:
                    process.stdin.close(); process.wait(timeout=5)
                    if process.returncode: raise AssertionError('pool process failed')
                finally:
                    if process.poll() is None: process.kill(); process.wait(timeout=3)
                    reader.join(3)
                    for stream in (process.stdout, process.stderr): stream.close()
                    if reader.is_alive(): raise AssertionError('pool reader leaked')
            except BaseException as cleanup_error:
                if original is not None: raise BaseExceptionGroup('pool work and cleanup failed', [original, cleanup_error])
                raise

    with server(body) as upstream, relay(upstream) as port, pool(port) as call:
        if call('capture') != {'captured':True}: raise AssertionError('pool capture failed')
        if call('send') != {'deferred':True}: raise AssertionError('lost receipt not deferred')
        if call('wait') != {'waited':True}: raise AssertionError('retry wait failed')
        validate_pool_receipt(call('send'), evidence['receipt'])
        validate_snapshot(durable_snapshot(), evidence['durable'])
        if call('send') != {'empty':True}: raise AssertionError('acknowledged batch retained')
    if evidence['sends'] != 2: raise AssertionError('unexpected send count')
    counts = execute('SELECT (SELECT count(*) FROM contour.ingestion_batches WHERE %s),(SELECT count(*) FROM contour.ingestion_payloads WHERE %s);' % (scope,scope))
    if counts != '1|1': raise AssertionError('inbox pair count')
    for status in ('Processed', 'AlreadyProcessed'):
        result = subprocess.run([catalog_probe,str(pg_port),str(directory/'ca.crt'),body['batch_id'],status,body['tenant_id'],body['collector_id'],'5000'],input='\n',text=True,capture_output=True,timeout=15,env=environment)
        if result.returncode or result.stdout.strip() != status or result.stderr: raise AssertionError('catalog processing failed')
    counts = execute("SELECT (SELECT count(*) FROM contour.catalog_processed_batches WHERE %s),(SELECT count(*) FROM contour.observation_windows WHERE %s),(SELECT count(*) FROM contour.variants WHERE tenant_id='%s' AND collector_id='%s');" % (scope,scope,body['tenant_id'],body['collector_id']))
    if counts != '1|1|1': raise AssertionError('catalog count mismatch')
    record = body['records'][0]
    observed = execute("SELECT w.record_id::text,w.source_id::text,w.project_id::text,w.service_id::text,w.environment_id::text,w.deployment_id::text,encode(o.canonical_key,'hex') FROM contour.observation_windows w JOIN contour.operations o ON o.tenant_id=w.tenant_id AND o.operation_id=w.operation_id WHERE w.tenant_id='%s' AND w.collector_id='%s' AND w.batch_id='%s';" % (body['tenant_id'],body['collector_id'],body['batch_id'])).split('|')
    expected = [record[key] for key in ('record_id','source_id','project_id','service_id','environment_id','deployment_id')] + [operation_key(body)]
    validate_observation(observed, expected)
    print('pool accepted response loss, exact duplicate retry and catalog once: passed',flush=True)


class OfflineTests(unittest.TestCase):
    def test_identity_and_snapshot_mutations_fail(self):
        import copy
        record = {key: key for key in IDENTITY_FIELDS}
        expected = {'tenant_id':'tenant', 'collector_id':'collector', 'batch_id':'batch', 'records':[record]}
        validate_batch_identity(json.dumps(expected).encode(), expected)
        for key in ('tenant_id', 'collector_id', 'batch_id'):
            mutated = copy.deepcopy(expected); mutated[key] += '-wrong'
            with self.assertRaises(AssertionError): validate_batch_identity(json.dumps(mutated).encode(), expected)
        for key in IDENTITY_FIELDS:
            mutated = copy.deepcopy(expected); mutated['records'][0][key] += '-wrong'
            with self.assertRaises(AssertionError): validate_batch_identity(json.dumps(mutated).encode(), expected)
        observation = [record[key] for key in ('record_id','source_id','project_id','service_id','environment_id','deployment_id')] + [operation_key(expected)]
        validate_observation(observation, observation.copy())
        for index in range(len(observation)):
            altered = observation.copy(); altered[index] += '-wrong'
            with self.assertRaises(AssertionError): validate_observation(altered, observation)
        with self.assertRaises(AssertionError): validate_pool_receipt({'status':'Duplicate','receipt_id':'wrong'}, ('receipt', None))
        snapshot = ['receipt', 'time', 'digest', '1', '1']
        validate_snapshot(snapshot, snapshot.copy())
        for index in range(len(snapshot)):
            altered = snapshot.copy(); altered[index] += '-wrong'
            with self.assertRaises(AssertionError): validate_snapshot(altered, snapshot)

    def test_receipt_requires_original_identity_and_timestamp(self):
        value = {'batch_id':'batch', 'status':'accepted', 'receipt_id':'00000000-0000-4000-8000-000000000001','accepted_at':'2026-01-01T00:00:00Z'}
        first = validate_receipt(value, 'batch', 'accepted')
        duplicate = dict(value, status='duplicate')
        self.assertEqual(validate_receipt(duplicate, 'batch', 'duplicate'), first)
        validate_replay(b'{}', b'{}', duplicate, 'batch', first)
        with self.assertRaises(AssertionError): validate_replay(b'{ }', b'{}', duplicate, 'batch', first)
        with self.assertRaises(AssertionError): validate_replay(b'{}', b'{}', dict(duplicate, accepted_at='2026-01-01T00:00:01Z'), 'batch', first)
        with self.assertRaises(AssertionError): validate_receipt(duplicate, 'other', 'duplicate')
        self.assertEqual(domain_digest(b'{\"b\":2,\"a\":1}'), domain_digest(b'{\"a\":1, \"b\":2}'))
        self.assertNotEqual(domain_digest(b'{\"a\":1}'), domain_digest(b'{\"a\":2}'))

if __name__ == '__main__':
    unittest.main()
