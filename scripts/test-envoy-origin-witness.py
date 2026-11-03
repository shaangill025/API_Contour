#!/usr/bin/env python3
"""Qualify only the synthetic Envoy metadata channel; no production attribution."""
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import signal
import ssl
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
NODE = 'docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963'

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

gateway = load('gateway_config', 'deploy/gateway/config.py')
native_envoy = load('native_envoy', 'deploy/pilot/native_envoy.py')
pilot = load('pilot_bounded', 'scripts/test-native-pilot.py')
HEADER = 'x-contour-origin-witness'


def configuration():
    # Use the production V2 configuration; adapt only fixture addresses and TLS files.
    cfg = native_envoy.config(origin_v2=True)
    cfg['static_resources']['listeners'][0]['address']['socket_address']['port_value'] = 8443
    listener = cfg['static_resources']['listeners'][0]['filter_chains'][0]
    down = listener['transport_socket']['typed_config']['common_tls_context']
    down['tls_certificates'] = [{'certificate_chain': {'filename': '/fixture/down.pem'},
                                 'private_key': {'filename': '/fixture/down.key'}}]
    down['validation_context'] = {'trusted_ca': {'filename': '/fixture/ca.pem'}}
    cluster = cfg['static_resources']['clusters'][0]
    cluster['load_assignment']['endpoints'][0]['lb_endpoints'][0]['endpoint']['address']['socket_address']['address'] = 'observer'
    transport = cluster['transport_socket']['typed_config']
    transport['sni'] = 'observer.test'
    upstream = transport['common_tls_context']
    upstream['validation_context']['trusted_ca']['filename'] = '/fixture/ca.pem'
    upstream['validation_context']['match_typed_subject_alt_names'][0]['matcher']['exact'] = 'observer.test'
    upstream['tls_certificates'] = [{'certificate_chain': {'filename': '/fixture/forwarder.pem'},
                                     'private_key': {'filename': '/fixture/forwarder.key'}}]
    return cfg


def cert_hash(path):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(path.read_text())).hexdigest()


def classify(values, expected):
    # Mirrors the observer's strict cardinality and syntax checks for offline tests.
    value = values[0] if len(values) == 1 else ''
    return next((name for name, digest in expected.items()
                 if len(value) == 64 and all(c in '0123456789abcdef' for c in value)
                 and value == digest), 'none')


def preserve_cleanup(work, cleanup):
    failure = None
    try:
        work()
    except BaseException as exc:
        failure = exc
    try:
        cleanup()
    except BaseException as exc:
        if failure is not None:
            raise BaseExceptionGroup('probe and cleanup failed', [failure, exc])
        raise
    if failure is not None:
        raise failure


class ExchangeDeadline(Exception):
    pass


def bounded_exchange(work, seconds=5):
    # Own the main-thread process timer for the entire connect/TLS/HTTP exchange.
    previous = signal.getsignal(signal.SIGALRM)
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise RuntimeError('exchange deadline timer already in use')
    def expired(_signum, _frame):
        raise ExchangeDeadline()
    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        return work()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class Driver:
    def __init__(self, folder):
        self.folder = folder
        self.name = 'contour-origin-' + uuid.uuid4().hex[:16]
        self.net = self.name + '-backend'
        self.frontend = self.name + '-frontend'
        self.edge = self.name + '-edge'
        self.backend = self.name + '-observer'
        self.created = []
        self.seq = 0
        self.env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')

    def run(self, *args, seconds=30):
        self.seq += 1
        return pilot.run_bounded(list(args), cwd=ROOT, env=self.env,
            log=self.folder / ('%03d.log' % self.seq), seconds=seconds)

    def write(self, name, content):
        pilot.private_write(self.folder / name, content.encode())

    def certs(self):
        p = self.folder
        self.run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                 '-subj', '/CN=synthetic-ca', '-keyout', str(p/'ca.key'), '-out', str(p/'ca.pem'),
                 '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        for name, san, usage in [('down', 'gateway.test', 'serverAuth'),
                                 ('server', 'observer.test', 'serverAuth'),
                                 ('forwarder', 'forwarder.test', 'clientAuth'),
                                 ('a', 'client-a.test', 'clientAuth'), ('b', 'client-b.test', 'clientAuth')]:
            self.run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN='+san,
                     '-keyout', str(p/(name+'.key')), '-out', str(p/(name+'.csr')))
            self.write(name+'.ext', 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\nsubjectAltName=DNS:'+san+'\n')
            self.run('openssl', 'x509', '-req', '-in', str(p/(name+'.csr')), '-CA', str(p/'ca.pem'),
                     '-CAkey', str(p/'ca.key'), '-CAcreateserial', '-days', '1', '-sha256',
                     '-extfile', str(p/(name+'.ext')), '-out', str(p/(name+'.pem')))
        self.write('expected.json', json.dumps({'forwarder': cert_hash(p/'forwarder.pem'),
                                               'a': cert_hash(p/'a.pem'), 'b': cert_hash(p/'b.pem')}))
        self.write('envoy.json', json.dumps(configuration()))

    def docker(self, *args):
        return self.run('docker', *args, seconds=60)

    def setup(self):
        for image in (gateway.IMAGE, NODE):
            self.docker('image', 'inspect', image)
        self.certs()
        # Creation may succeed even if the CLI times out before acknowledging it.
        self.created.append(('network', self.net))
        self.docker('network', 'create', '--internal', self.net)
        self.created.append(('network', self.frontend))
        self.docker('network', 'create', self.frontend)
        common = ['--pull', 'never', '--user', f'{os.getuid()}:{os.getgid()}',
                  '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                  '--pids-limit', '128', '--memory', '256m', '--log-driver', 'local',
                  '--log-opt', 'max-size=1m', '--log-opt', 'max-file=1', '--log-opt', 'compress=false']
        def mounts(names):
            return [item for name in names for item in ('-v', str(self.folder/name)+':/fixture/'+name+':ro')]
        self.created.append(('container', self.backend))
        self.docker('run', '-d', '--network', self.net, *common, *mounts(['ca.pem', 'server.pem', 'server.key', 'expected.json']),
                    '--name', self.backend, '--network-alias', 'observer',
                    '-v', str(ROOT/'tests/fixtures/origin-witness/backend.js')+':/observer.js:ro',
                    '--entrypoint', 'node', NODE, '/observer.js')
        self.created.append(('container', self.edge))
        self.docker('create', '--network', self.frontend, *common, *mounts(['ca.pem', 'down.pem', 'down.key', 'forwarder.pem', 'forwarder.key', 'envoy.json']),
                    '--name', self.edge, '-p', '127.0.0.1::8443',
                    gateway.IMAGE, 'envoy', '-c', '/fixture/envoy.json', '--log-level', 'error', '--concurrency', '1')
        self.docker('network', 'connect', self.net, self.edge)
        self.docker('start', self.edge)
        output = self.docker('port', self.edge, '8443/tcp').decode().strip()
        self.port = int(output.rsplit(':', 1)[1])

    def request(self, client, extra=(), *, tls13=False):
        return bounded_exchange(lambda: self.exchange(client, extra, tls13=tls13))

    def exchange(self, client, extra=(), *, tls13=False):
        context = ssl.create_default_context(cafile=str(self.folder/'ca.pem'))
        if tls13:
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        if client:
            context.load_cert_chain(str(self.folder/(client+'.pem')), str(self.folder/(client+'.key')))
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname='gateway.test') as conn:
                request = b'GET / HTTP/1.1\r\nHost: gateway.test\r\nConnection: close\r\n'
                for key, value in extra:
                    request += key.encode() + b': ' + value.encode() + b'\r\n'
                conn.sendall(request + b'\r\n')
                response = http.client.HTTPResponse(conn)
                response.begin()
                body = response.read(32)
                return response.status, body, response.getheader('x-fixture-match'), response.getheader('x-fixture-connection')

    def cases(self):
        deadline = time.monotonic() + 15
        while True:
            try:
                first = self.request('a')
                break
            except (OSError, http.client.HTTPException):
                if time.monotonic() >= deadline:
                    raise RuntimeError('listener unavailable') from None
                time.sleep(.2)
        def check(name, result, label):
            if result[:3] != (200, b'ok', label) or not result[3] or not result[3].isdigit():
                raise RuntimeError(name + ' failed')
            print(name + ': passed', flush=True)
            return result[3]
        ids = [check('client-a', first, 'a')]
        ids.append(check('client-b', self.request('b'), 'b'))
        cases = [
            ('forged', [('x-contour-origin-witness', '0'*64)]),
            ('mixed-case', [('X-ConTour-Origin-Witness', '1'*64)]),
            ('duplicate', [(HEADER, '0'*64), ('X-Contour-Origin-Witness', '1'*64)]),
            ('connection-nominated', [('Connection', 'X-Contour-Origin-Witness, X-Other'),
                                      ('x-CoNtOuR-OrIgIn-WiTnEsS', '2'*64)]),
            ('multiple-connection', [('Connection', 'x-other'), ('cOnNeCtIoN', 'X-CONTOUR-ORIGIN-WITNESS'),
                                     (HEADER, '3'*64)])]
        for name, headers in cases:
            ids.append(check(name, self.request('a', headers), 'a'))
        ids.append(check('interleaved-b', self.request('b'), 'b'))
        ids.append(check('interleaved-a', self.request('a'), 'a'))
        if len(set(ids)) != 1:
            raise RuntimeError('upstream connection reuse not demonstrated')
        print('upstream-connection-reused: passed', flush=True)
        self.missing_certificate_case()
        check('authenticated-after-missing-certificate', self.request('a', tls13=True), 'a')
        print('missing-client-certificate: passed', flush=True)

    def missing_certificate_case(self):
        try:
            self.request(None, tls13=True)
        except ssl.SSLError as exc:
            if getattr(exc, 'reason', None) == 'TLSV13_ALERT_CERTIFICATE_REQUIRED':
                return
            raise RuntimeError('missing client certificate: unexpected TLS failure') from exc
        raise RuntimeError('missing client certificate accepted')

    def cleanup(self):
        failures = []
        for kind, name in reversed(self.created):
            try:
                if kind == 'container':
                    self.docker('rm', '-f', name)
                else:
                    # Listing succeeds for an absent network, unlike network inspect.
                    # Compare exact names so the unique owned name is the only target.
                    names = self.docker('network', 'ls', '--filter', 'name='+name,
                                        '--format', '{{.Name}}').decode().splitlines()
                    if name in names:
                        self.docker('network', 'rm', name)
            except BaseException as exc:
                failures.append(exc)
        if failures:
            raise BaseExceptionGroup('owned Docker cleanup failed', failures)


class OfflineTests(unittest.TestCase):
    def test_config(self):
        c = configuration()['static_resources']
        listener = c['listeners'][0]['filter_chains'][0]
        self.assertTrue(listener['transport_socket']['typed_config']['require_client_certificate'])
        h = listener['filters'][0]['typed_config']['route_config']['request_headers_to_add'][0]
        self.assertEqual(h['header']['value'], '%DOWNSTREAM_PEER_FINGERPRINT_256%')
        self.assertEqual(h['append_action'], 'OVERWRITE_IF_EXISTS_OR_ADD')
        self.assertTrue(h['keep_empty_value'])
        self.assertIn('tls_certificates', c['clusters'][0]['transport_socket']['typed_config']['common_tls_context'])

    def test_classification_closed(self):
        expected = {'a': 'a'*64, 'b': 'b'*64}
        for values in ([], [''], ['x'*64], ['a'*63], ['c'*64], ['a'*64, 'b'*64], ['a'*64+', '+ 'b'*64]):
            self.assertEqual(classify(values, expected), 'none')
        self.assertEqual(classify(['A'*64], expected), 'none')

    def test_missing_certificate_requires_specific_tls_alert(self):
        driver = Driver(Path('/unused'))
        for failure in (ConnectionRefusedError(), TimeoutError(), http.client.BadStatusLine(''),
                        ssl.SSLError(1, 'unexpected TLS failure')):
            def request(*args, failure=failure, **kwargs):
                raise failure
            driver.request = request
            with self.assertRaises((OSError, http.client.HTTPException, RuntimeError)):
                driver.missing_certificate_case()
        failure = ssl.SSLError(1, 'certificate required')
        failure.reason = 'TLSV13_ALERT_CERTIFICATE_REQUIRED'
        calls = []
        def rejected(*args, **kwargs):
            calls.append((args, kwargs))
            raise failure
        driver.request = rejected
        driver.missing_certificate_case()
        self.assertEqual(calls, [((None,), {'tls13': True})])

    def test_missing_certificate_accepted_is_failure(self):
        driver = Driver(Path('/unused'))
        driver.request = lambda *args, **kwargs: (200, b'ok', 'none', '1')
        with self.assertRaises(RuntimeError):
            driver.missing_certificate_case()

    def test_network_create_timeout_cleans_owned_network(self):
        for create_index in (1, 2):
            driver = Driver(Path('/unused'))
            calls = []
            made = []
            def docker(*args):
                calls.append(args)
                if args[:2] == ('network', 'create'):
                    made.append(args[-1])
                    if len(made) == create_index:
                        raise TimeoutError('create acknowledgement lost')
                if args[:2] == ('network', 'ls'):
                    return ('\n'.join(made) + '\nother-network\n').encode()
                return b''
            driver.docker = docker
            driver.certs = lambda: None
            with self.assertRaises(TimeoutError):
                preserve_cleanup(driver.setup, driver.cleanup)
            for network in made:
                self.assertIn(('network', 'rm', network), calls)
            self.assertNotIn(('network', 'rm', 'other-network'), calls)

    def test_absolute_deadline_stops_trickling_exchange(self):
        # Fake HTTP headers arrive repeatedly; each pause is below socket timeout.
        driver = Driver(Path('/unused'))
        driver.port = 12345
        fake_socket = mock.MagicMock()
        fake_context = mock.MagicMock()
        fake_context.wrap_socket.return_value.__enter__.return_value = fake_socket
        def trickle_headers():
            while True:
                time.sleep(.01)
        response = mock.MagicMock()
        response.begin.side_effect = trickle_headers
        started = time.monotonic()
        previous = signal.getsignal(signal.SIGALRM)
        with mock.patch.object(ssl, 'create_default_context', return_value=fake_context), \
             mock.patch.object(socket, 'create_connection') as connect, \
             mock.patch.object(http.client, 'HTTPResponse', return_value=response):
            connect.return_value.__enter__.return_value = fake_socket
            with self.assertRaises(ExchangeDeadline):
                bounded_exchange(lambda: driver.exchange(None), seconds=.12)
        self.assertTrue(response.begin.called)
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertIs(signal.getsignal(signal.SIGALRM), previous)

    def test_existing_timer_is_not_modified(self):
        signal.setitimer(signal.ITIMER_REAL, 10)
        try:
            before = signal.getsignal(signal.SIGALRM)
            with self.assertRaises(RuntimeError):
                bounded_exchange(lambda: None)
            self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 0)
            self.assertIs(signal.getsignal(signal.SIGALRM), before)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

    def test_network_create_timeout_and_cleanup_failure_are_preserved(self):
        driver = Driver(Path('/unused'))
        def docker(*args):
            if args[:2] == ('network', 'create'):
                raise KeyboardInterrupt()
            if args[:2] == ('network', 'ls'):
                return (driver.net + '\n').encode()
            if args[:2] == ('network', 'rm'):
                raise RuntimeError('cleanup failed')
            return b''
        driver.docker = docker
        driver.certs = lambda: None
        with self.assertRaises(BaseExceptionGroup) as caught:
            preserve_cleanup(driver.setup, driver.cleanup)
        self.assertIsInstance(caught.exception.exceptions[0], KeyboardInterrupt)
        self.assertIsInstance(caught.exception.exceptions[1], BaseExceptionGroup)
        self.assertIsInstance(caught.exception.exceptions[1].exceptions[0], RuntimeError)

    def test_absent_network_needs_no_removal(self):
        driver = Driver(Path('/unused'))
        driver.created.append(('network', driver.net))
        calls = []
        def docker(*args):
            calls.append(args)
            return b'other-network\n'
        driver.docker = docker
        driver.cleanup()
        self.assertFalse(any(args[:2] == ('network', 'rm') for args in calls))

    def test_cleanup_preserves_both_failures(self):
        def fail(): raise KeyboardInterrupt()
        def cleanup(): raise RuntimeError()
        with self.assertRaises(BaseExceptionGroup) as caught:
            preserve_cleanup(fail, cleanup)
        self.assertEqual(len(caught.exception.exceptions), 2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(OfflineTests))
        return 0 if result.wasSuccessful() else 1
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='contour-origin-witness-') as directory:
        os.chmod(directory, 0o700)
        driver = Driver(Path(directory))
        preserve_cleanup(lambda: (driver.setup(), driver.cases()), driver.cleanup)
    return 0

if __name__ == '__main__':
    try:
        code = main()
    except BaseException:
        print('origin-witness: failed', file=sys.stderr)
        code = 1
    sys.exit(code)
