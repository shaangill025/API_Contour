import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
import sys
import subprocess
from unittest import mock
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('certificates', ROOT / 'deploy/gateway/certificates.py')
certificates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(certificates)
spec = importlib.util.spec_from_file_location('gateway_fixture', ROOT / 'scripts/test-managed-gateway.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class CertificateLifecycleTest(unittest.TestCase):
    def test_rotation_failures_rollback_and_threshold(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture.certs(root)
            manager = certificates.Certificates(root / 'published', root / 'ca.pem', root / 'ca.key', 'gateway.test')
            with self.assertRaisesRegex(ValueError, 'state'):
                manager.renewal_due(0)
            manager.activate(root / 'down.pem', root / 'down.key')
            first = os.readlink(root / 'published/current')
            first_cert = (root / 'published/current/cert.pem').read_bytes()
            self.assertFalse(manager.renewal_due(0))
            self.assertTrue(manager.renewal_due(2 * 86400))
            for cert, key in [('wrong.pem', 'wrong.key'), ('down.pem', 'wrong.key'), ('expired.pem', 'expired.key'), ('other.pem', 'other.key')]:
                with self.assertRaises(ValueError):
                    manager.activate(root / cert, root / key)
                self.assertEqual(first, os.readlink(root / 'published/current'))
            manager.issue()
            second = os.readlink(root / 'published/current')
            self.assertNotEqual(first, second)
            manager.rollback()
            self.assertTrue(first_cert == (root / 'published/current/cert.pem').read_bytes())
            manager.issue()
            versions = list((root / 'published').glob('v-*'))
            self.assertEqual(2, len(versions))
            (root / 'published/current').unlink()
            os.symlink('../ca.pem', root / 'published/current')
            with self.assertRaisesRegex(ValueError, 'state'):
                manager.rollback()

    def test_rejects_appended_key_and_nonregular_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture.certs(root)
            manager = certificates.Certificates(root / 'published', root / 'ca.pem', root / 'ca.key', 'gateway.test')
            manager.activate(root / 'down.pem', root / 'down.key')
            first = os.readlink(root / 'published/current')
            (root / 'joined').write_bytes((root / 'down.pem').read_bytes() + (root / 'ca.key').read_bytes())
            (root / 'big').write_bytes(b'x' * 200000)
            os.mkfifo(root / 'fifo')
            for candidate in ('joined', 'big', 'fifo'):
                with self.assertRaises(ValueError):
                    manager.activate(root / candidate, root / 'down.key')
                self.assertEqual(first, os.readlink(root / 'published/current'))

    def test_failed_switch_preserves_history(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture.certs(root)
            manager = certificates.Certificates(root / 'published', root / 'ca.pem', root / 'ca.key', 'gateway.test')
            manager.activate(root / 'down.pem', root / 'down.key')
            manager.issue()
            first = os.readlink(root / 'published/current')
            previous = (root / 'published/current/previous').read_text()
            real_replace = os.replace
            def fail_current(src, dest):
                if str(dest).endswith('/current'):
                    raise OSError('injected')
                return real_replace(src, dest)
            with mock.patch.object(certificates.os, 'replace', side_effect=fail_current):
                with self.assertRaises(OSError):
                    manager.issue()
            self.assertEqual(first, os.readlink(root / 'published/current'))
            self.assertEqual(previous, (root / 'published/current/previous').read_text())

    def test_expired_current_can_be_replaced(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture.certs(root)
            manager = certificates.Certificates(root / 'published', root / 'ca.pem', root / 'ca.key', 'gateway.test')
            manager.activate(root / 'down.pem', root / 'down.key')
            (root / 'index.txt').write_text('')
            (root / 'serial').write_text('33\n')
            config = (root / 'ca.cnf').read_text().replace('DNS:upstream.test', 'DNS:gateway.test')
            (root / 'ca.cnf').write_text(config)
            fixture.cmd('openssl', 'ca', '-batch', '-config', 'ca.cnf', '-in', 'down.csr', '-out', 'expired-down.pem', '-startdate', '20200101000000Z', '-enddate', '20210101000000Z', cwd=root)
            canonical = fixture.cmd('openssl', 'x509', '-in', 'expired-down.pem', cwd=root).stdout
            (root / 'published/current/cert.pem').write_bytes(canonical)
            self.assertTrue(manager.renewal_due(0))
            manager.issue()
            self.assertFalse(manager.renewal_due(0))
            with self.assertRaises(ValueError):
                manager.rollback()

    def test_issuer_key_never_reaches_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture.certs(root)
            manager = certificates.Certificates(root / 'published', root / 'ca.pem', root / 'ca.key', 'gateway.test')
            manager.activate(root / 'down.pem', root / 'down.key')
            fixture.cmd('openssl', 'req', '-new', '-key', 'ca.key', '-out', 'reused.csr', '-subj', '/CN=gateway.test', cwd=root)
            fixture.cmd('openssl', 'x509', '-req', '-in', 'reused.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-set_serial', '1234', '-out', 'reused.pem', '-days', '1', '-extfile', 'down.ext', cwd=root)
            original = os.readlink(root / 'published/current')
            with self.assertRaisesRegex(ValueError, 'issuer key'):
                manager.activate(root / 'reused.pem', root / 'ca.key')
            with self.assertRaises(ValueError):
                manager.activate(root / 'down.pem', root / 'ca.key')
            self.assertEqual(original, os.readlink(root / 'published/current'))
            for path in (root / 'published').rglob('*'):
                if path.is_file() and not path.is_symlink():
                    self.assertFalse((root / 'ca.key').read_bytes() in path.read_bytes())

    def test_cleanup_requires_checked_daemon_and_absence(self):
        spec = importlib.util.spec_from_file_location('lifecycle_fixture', ROOT / 'scripts/test-managed-certificate-lifecycle.py')
        lifecycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lifecycle)
        with mock.patch.object(lifecycle.fixture, 'cmd', side_effect=RuntimeError('daemon unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'daemon unavailable'):
                lifecycle.cleanup_container('synthetic')
        present = mock.Mock(stdout=b'synthetic\n')
        with mock.patch.object(lifecycle.fixture, 'cmd', return_value=present):
            with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
                lifecycle.cleanup_container('synthetic')

    def test_exchange_rejects_oversized_and_trickled_responses(self):
        spec = importlib.util.spec_from_file_location('lifecycle_fixture', ROOT / 'scripts/test-managed-certificate-lifecycle.py')
        lifecycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lifecycle)
        class Stream:
            def __init__(self, chunks):
                self.chunks = iter(chunks)
            def settimeout(self, timeout):
                pass
            def recv(self, maximum):
                return next(self.chunks, b'')[:maximum]
        with self.assertRaisesRegex(ValueError, 'headers too large'):
            lifecycle._response(Stream([b'x' * 1024] * 9), lifecycle.time.monotonic() + 5)
        with self.assertRaisesRegex(ValueError, 'body too large'):
            lifecycle._response(Stream([b'HTTP/1.1 201 Created\r\nContent-Length: 4097\r\n\r\n']), lifecycle.time.monotonic() + 5)
        ticks = iter([0, 1, 2, 3])
        with mock.patch.object(lifecycle.time, 'monotonic', side_effect=lambda: next(ticks)):
            with self.assertRaisesRegex(TimeoutError, 'deadline'):
                lifecycle._response(Stream([b'H', b'T', b'T', b'P']), 2)

    def test_validation_timeout_cleanup_attempts_both_and_preserves_failure(self):
        spec = importlib.util.spec_from_file_location('lifecycle_fixture', ROOT / 'scripts/test-managed-certificate-lifecycle.py')
        lifecycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lifecycle)
        seen = []
        def cleanup(name):
            seen.append(name)
            if name == 'validation':
                raise RuntimeError('cleanup unavailable')
        timeout = subprocess.TimeoutExpired('docker validation', 45)
        with mock.patch.object(lifecycle, 'cleanup_container', side_effect=cleanup), mock.patch.object(lifecycle.fixture, 'stop') as stop:
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                try:
                    raise timeout
                finally:
                    lifecycle.cleanup_owned(('validation', 'runtime'), object(), sys.exception())
        self.assertIs(timeout, caught.exception)
        self.assertEqual(['validation', 'runtime'], seen)
        self.assertIn('validation', caught.exception.__notes__[0])
        stop.assert_called_once()
        with mock.patch.object(lifecycle, 'cleanup_container', side_effect=cleanup), mock.patch.object(lifecycle.fixture, 'stop'):
            with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
                lifecycle.cleanup_owned(('validation', 'runtime'), object(), None)

    def test_sds_document_only_current_validated_version(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture.certs(root)
            manager = certificates.Certificates(root / 'published', root / 'ca.pem', root / 'ca.key', 'gateway.test')
            with self.assertRaisesRegex(ValueError, 'state'):
                manager.sds_document()
            manager.activate(root / 'down.pem', root / 'down.key')
            first = json.loads(manager.sds_document())
            version = os.readlink(root / 'published/current')
            self.assertEqual(version, first['version_info'])
            secret = first['resources'][0]['tls_certificate']
            self.assertEqual('/certs/' + version + '/cert.pem', secret['certificate_chain']['filename'])
            self.assertEqual('/certs/' + version + '/key.pem', secret['private_key']['filename'])
            self.assertNotIn('BEGIN', json.dumps(first))
            manager.issue()
            second = json.loads(manager.sds_document())
            self.assertNotEqual(first['version_info'], second['version_info'])
            manager.rollback()
            self.assertNotIn(json.loads(manager.sds_document())['version_info'], [first['version_info'], second['version_info']])
            (root / 'published/current/cert.pem').write_text('invalid')
            with self.assertRaises(ValueError):
                manager.sds_document()
            (root / 'published/current').unlink()
            os.symlink('../ca.pem', root / 'published/current')
            with self.assertRaisesRegex(ValueError, 'state'):
                manager.sds_document()

    def test_sds_publish_is_fixed_and_propagates_failure(self):
        spec = importlib.util.spec_from_file_location('lifecycle_fixture', ROOT / 'scripts/test-managed-certificate-lifecycle.py')
        lifecycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lifecycle)
        manager = mock.Mock()
        manager.sds_document.return_value = b'{"version_info":"synthetic"}'
        with mock.patch.object(lifecycle.fixture, 'cmd', side_effect=RuntimeError('publish failed')) as cmd:
            with self.assertRaisesRegex(RuntimeError, 'publish failed'):
                lifecycle.publish_sds('owned-container', manager)
        args, kwargs = cmd.call_args
        self.assertEqual(args[:4], ('docker', 'exec', '-i', 'owned-container'))
        self.assertEqual(kwargs['input'], manager.sds_document.return_value)
        self.assertIn('mv -f /run/watch/sds.pending /run/watch/sds.json', args[-1])
        manager.sds_document.side_effect = ValueError('invalid state')
        with mock.patch.object(lifecycle.fixture, 'cmd') as cmd:
            with self.assertRaisesRegex(ValueError, 'invalid state'):
                lifecycle.publish_sds('owned-container', manager)
            cmd.assert_not_called()

    def test_ca_key_outside_mount(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            with self.assertRaisesRegex(ValueError, 'outside'):
                certificates.Certificates(p, p / 'ca.pem', p / 'ca.key', 'gateway.test')


if __name__ == '__main__':
    unittest.main()
