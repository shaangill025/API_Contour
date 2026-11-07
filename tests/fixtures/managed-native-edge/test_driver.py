import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('managed_edge_driver', ROOT / 'scripts/test-managed-native-edge.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class DriverTests(unittest.TestCase):
    def test_only_exact_missing_object_is_absence(self):
        def result(stderr):
            return lambda *a, **k: subprocess.CompletedProcess(a, 1, b'', stderr)
        args = ['docker', 'inspect', 'missing']
        self.assertIsNone(driver.command(result(b'Error: No such object: missing\n'), args, allow_absent=True))
        for err in (b'Cannot connect to the Docker daemon\n', b'Error: No such object: another\n'):
            with self.assertRaises(RuntimeError):
                driver.command(result(err), args, allow_absent=True)
        with self.assertRaises(RuntimeError):
            driver.command(result(b'Error: No such object: missing\n'), args)

    def test_replica_definition_is_exact_readonly_and_on_owned_network(self):
        definition = driver.replica_definition('owned-replica', 'owned-network', 'a'*32, {'/pilot/file': '/tmp/file'})
        replica = definition['services']['replica']
        self.assertEqual(replica['entrypoint'], ['node', '/usr/src/node-red/node_modules/node-red/red.js', '--userDir', '/data', '--settings', '/pilot/settings.js'])
        self.assertEqual(replica['labels'][driver.LABEL], 'a'*32)
        self.assertTrue(replica['read_only'])
        self.assertEqual(replica['volumes'], [{'type': 'bind', 'source': '/tmp/file', 'target': '/pilot/file', 'read_only': True}])
        self.assertNotIn('ports', replica)
        self.assertEqual(definition['networks']['default'], {'external': True, 'name': 'owned-network'})

    def test_durable_intent_exclusive_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            driver.durable_record(folder, 'intent.json', {'id': 'one'})
            self.assertEqual(json.loads((folder/'intent.json').read_text()), {'id': 'one'})
            self.assertEqual((folder/'intent.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                driver.durable_record(folder, 'intent.json', {'id': 'two'})
            self.assertEqual(json.loads((folder/'intent.json').read_text()), {'id': 'one'})

    def test_container_identity_never_adopts_wrong_label_or_id(self):
        cid = 'a'*64
        def run(*args, **kwargs):
            return b'\n'.join(json.dumps(x).encode() for x in (cid, '/owned', {'x': 'bad'}, 'image', False))
        with self.assertRaises(RuntimeError):
            driver.owned_container(run, 'owned', 'owned', 'token')
        def correct(*args, **kwargs):
            return b'\n'.join(json.dumps(x).encode() for x in (cid, '/owned', {driver.LABEL: 'token'}, 'image', False))
        with self.assertRaises(RuntimeError):
            driver.owned_container(correct, 'owned', 'owned', 'token', 'b'*64)

    def test_remote_pid_absence_must_be_proved(self):
        with self.assertRaises(RuntimeError):
            driver.remote_absent(lambda *a, **k: b'PRESENT', 'container', b'12')
        with self.assertRaises(ValueError):
            driver.remote_absent(lambda *a, **k: b'ABSENT', 'container', b'12;exit')
        driver.remote_absent(lambda *a, **k: b'ABSENT', 'container', b'12')

    def test_cleanup_rejects_late_stderr_and_overflow_after_barrier(self):
        for kind in ('stderr', 'overflow'):
            with self.subTest(kind=kind):
                code = ("import sys; print('READY', flush=True); sys.stdin.readline(); "
                        + ("sys.stderr.write('DIAG tls\\n'); sys.stderr.flush()" if kind == 'stderr'
                           else "sys.stdout.write('X'*70000); sys.stdout.flush()"))
                m = driver.Monitor([sys.executable, '-c', code], service_id='fixture')
                m.wait(b'READY')
                m.proc.stdin.write(b'go\n'); m.proc.stdin.flush(); m.proc.wait(timeout=5)
                errors = driver.cleanup_monitors([m], {'fixture'})
                self.assertTrue(errors, 'cleanup accepted late invalid output')

    def test_cleanup_rejects_recorded_reader_failure(self):
        m = driver.Monitor([sys.executable, '-c', "print('READY', flush=True)"])
        m.wait(b'READY'); m.proc.wait(timeout=5)
        for thread in m.threads: thread.join(timeout=5)
        class BadStream:
            def fileno(self): raise OSError('read failure')
        m._read(BadStream(), m.out)
        self.assertTrue(driver.cleanup_monitors([m], set()), 'cleanup accepted a reader failure')

    def test_service_cleanup_requires_verified_removal_and_expected_exit(self):
        m = driver.Monitor([sys.executable, '-c', 'pass'], service_id='fixture')
        m.proc.wait(timeout=5)
        self.assertTrue(driver.cleanup_monitors([m], set()))
        m = driver.Monitor([sys.executable, '-c', 'raise SystemExit(42)'], service_id='fixture')
        m.proc.wait(timeout=5)
        self.assertTrue(driver.cleanup_monitors([m], {'fixture'}))

    def test_bootstrap_orders_prepare_start_bind_reconcile(self):
        from deploy.pilot import managed_edge_controller as controller
        obj = object.__new__(controller.ManagedEdgeController)
        obj.peer = type('Peer', (), {'envoy_cid': 'e'*64, 'cid': 'r'*64})()
        events = []
        obj._owned = lambda cid: events.append(('owned', cid))
        obj.edge = type('Edge', (), {'prepare_initial': lambda self: events.append('prepare'), 'bind_initial_peer': lambda self: events.append('bind'), 'reconcile': lambda self: events.append('reconcile')})()
        def run(args):
            events.append(('start', args[-1]))
            return (args[-1]+'\n').encode()
        with patch.object(controller, '_command', side_effect=run):
            obj.bootstrap()
        self.assertLess(events.index('prepare'), events.index(('start', 'e'*64)))
        self.assertLess(events.index(('start', 'r'*64)), events.index('bind'))
        self.assertEqual(events[-1], 'reconcile')

if __name__ == '__main__':
    unittest.main()
