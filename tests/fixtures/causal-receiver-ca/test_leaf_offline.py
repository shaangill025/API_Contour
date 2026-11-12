"""Offline tests use mocked OpenSSL; they do not establish certificate validity."""
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from deploy.pilot import receiver_ca as checker

FIXTURE = Path(__file__).resolve().parent.parent / 'causal-receiver-material/product.pem'
VERSION = b'OpenSSL 3.6.3 9 Jun 2026\n'
RUN = checker._run
DS = b'X509v3 Key Usage: critical\n    Digital Signature, Key Encipherment\n'


class LeafUsageOfflineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.cert = self.root / 'leaf.pem'
        shutil.copyfile(FIXTURE, self.cert)
        self.cert.chmod(0o600)
        self.tool = self.root / 'openssl'
        self.tool_id = ('tool', 1)
        self.tool_mock = mock.patch.object(checker, '_tool', side_effect=lambda _: self.tool_id).start()
        self.addCleanup(mock.patch.stopall)
        self.usage = DS
        self.run_mock = mock.patch.object(checker, '_run', side_effect=lambda tool, args, file: VERSION if args == ['version'] else self.usage).start()

    def inspect(self):
        return checker.inspect_local_leaf_usage(self.cert, self.tool)

    def test_positive_and_exact_fingerprint(self):
        receipt = self.inspect()
        self.assertEqual(receipt.revalidate(), hashlib.sha256(self.cert.read_bytes()).digest())
        self.assertEqual(self.run_mock.call_count, 2)

    def test_absent_forbidden_malformed_and_duplicate_usage(self):
        for output in (b'No extensions in certificate\n',
                       b'X509v3 Key Usage: critical\n    Key Encipherment\n',
                       b'X509v3 Key Usage:\n    Digital Signature, Digital Signature\n',
                       b'X509v3 Key Usage:\n    Digital Signature, Unknown\n'):
            with self.subTest(output=output):
                self.usage = output
                with self.assertRaisesRegex(ValueError, 'invalid leaf key usage'):
                    self.inspect()

    def test_receipt_rejects_file_and_tool_drift(self):
        receipt = self.inspect()
        self.cert.chmod(0o644)
        with self.assertRaises(ValueError): receipt.revalidate()
        self.cert.chmod(0o600)
        self.tool_id = ('tool', 2)
        with self.assertRaisesRegex(ValueError, 'leaf receipt drift'): receipt.revalidate()
        self.tool_id = ('tool', 1)
        data = self.cert.read_bytes()
        self.cert.unlink()
        self.cert.write_bytes(data)
        self.cert.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'leaf receipt drift'): receipt.revalidate()

    def test_protected_path_and_single_bounded_pem(self):
        link = self.root / 'link.pem'
        link.symlink_to(self.cert)
        with self.assertRaises(ValueError): checker.inspect_local_leaf_usage(link, self.tool)
        data = self.cert.read_bytes()
        self.cert.write_bytes(data + data)
        with self.assertRaises(ValueError): self.inspect()
        self.cert.write_bytes(b'x' * 65537)
        with self.assertRaises(ValueError): self.inspect()

    def test_subprocess_failure_and_version_reject(self):
        self.run_mock.side_effect = ValueError('certificate inspection timeout')
        with self.assertRaisesRegex(ValueError, 'timeout'): self.inspect()
        self.run_mock.side_effect = lambda tool, args, file: b'OpenSSL wrong\n'
        with self.assertRaisesRegex(ValueError, 'unqualified OpenSSL'): self.inspect()

    def test_runner_bounds_output_and_timeout(self):
        process = mock.Mock()
        process.stdout = mock.Mock()
        process.stdout.fileno.return_value = 11
        process.poll.return_value = None
        selector = mock.Mock()
        selector.get_map.return_value = {11: object()}
        selector.select.return_value = [object()]
        with mock.patch.object(checker.subprocess, 'Popen', return_value=process), \
             mock.patch.object(checker.selectors, 'DefaultSelector', return_value=selector), \
             mock.patch.object(checker.os, 'read', return_value=b'x' * 65537):
            with self.assertRaisesRegex(ValueError, 'output too large'):
                RUN(self.tool, ['version'], self.cert)
        process.kill.assert_called_once()
        process.reset_mock()
        selector.select.return_value = []
        with mock.patch.object(checker.subprocess, 'Popen', return_value=process), \
             mock.patch.object(checker.selectors, 'DefaultSelector', return_value=selector):
            with self.assertRaisesRegex(ValueError, 'timeout'):
                RUN(self.tool, ['version'], self.cert)
        process.kill.assert_called_once()


if __name__ == '__main__': unittest.main()
