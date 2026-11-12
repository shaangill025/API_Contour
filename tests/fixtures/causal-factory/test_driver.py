import json
import os
from pathlib import Path
import re
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
DRIVER = runpy.run_path(str(ROOT / 'scripts/test-postgres-causal-factory.py'))


class DriverTests(unittest.TestCase):
    def test_probe_stage_is_exact_closed_allowlist(self):
        classify = DRIVER['probe_stage']
        source = DRIVER['EXAMPLE'].read_text()
        emitted = set(re.findall(r'(?:map_err\(\|_\|\s*|Err\()"([A-Za-z ]+)"', source))
        bind_emitted = set(re.findall(r'=> "(bind_[a-z_]+)"', source))
        self.assertEqual(bind_emitted, {stage for stage in DRIVER['PROBE_STAGES']
                                        if stage.startswith('bind_')})
        emitted.update(bind_emitted)
        self.assertTrue(emitted)
        self.assertLessEqual(emitted, DRIVER['PROBE_STAGES'])
        for stage in DRIVER['PROBE_STAGES']:
            self.assertEqual(classify(b'factory probe: ' + stage.encode('ascii') + b'\n'), stage)
        for unknown in (b'factory probe: private-secret\n', b'factory probe: bind_invalid\nprivate-secret',
                        b'factory probe: bind_database_deadline: secret\n',
                        b'factory probe: bind', b'private-secret', b'x' * 10000,
                        b'factory probe: \xff\n', 'factory probe: bind\n'):
            self.assertIsNone(classify(unknown))

    def test_final_drain_clears_previous_stage_on_read_failure(self):
        stderr = b'factory probe: bind\n'
        diagnostic = {'probe_stage': DRIVER['probe_stage'](stderr)}
        self.assertEqual(diagnostic['probe_stage'], 'bind')
        for overflow, read_failed in ((True, False), (False, True), (True, True)):
            diagnostic['probe_stage'] = DRIVER['final_probe_stage'](stderr, overflow, read_failed)
            self.assertIsNone(diagnostic['probe_stage'])
            diagnostic['probe_stage'] = 'bind'
        self.assertEqual(DRIVER['final_probe_stage'](stderr, False, False), 'bind')

    def test_primary_and_stop_failure_do_not_remove_known_proxy(self):
        primary, stop = ValueError('primary'), RuntimeError('stop')
        uncertain, remote = [], []
        def fail_stop():
            raise stop
        with self.assertRaises(BaseExceptionGroup) as caught:
            DRIVER['cleanup_with_evidence'](primary, uncertain, True, ('cid', 'owner'), True, True,
                                            fail_stop, lambda: remote.append('removed'))
        self.assertEqual(caught.exception.exceptions, (primary, stop))
        self.assertTrue(any(item[0] == 'local' for item in uncertain))
        self.assertEqual(remote, [])

    def test_primary_and_stop_failure_retained_with_unknown_create(self):
        primary = ValueError('primary')
        stop = RuntimeError('stop')
        uncertain, remote = [], []
        def fail_stop():
            raise stop
        with self.assertRaises(BaseExceptionGroup) as caught:
            DRIVER['cleanup_with_evidence'](primary, uncertain, True, None, True, False,
                                            fail_stop, lambda: remote.append('removed'))
        self.assertEqual(caught.exception.exceptions, (primary, stop))
        self.assertTrue(any(item[0] == 'container' for item in uncertain))
        self.assertTrue(any(item[0] == 'local' for item in uncertain))
        self.assertEqual(remote, [])

    def test_source_snapshot_detects_loaded_helper_and_node_test_changes(self):
        changed = set()
        bridge = {'source_paths': lambda: [],
                  'digest_file': lambda p: 'changed' if str(p) in changed else 'original'}
        before = DRIVER['source_snapshot'](bridge)
        for relative in ('scripts/test-postgres-causal-https.py', 'tests/fixtures/causal-factory/test_tls_peer.js'):
            path = str(ROOT / relative)
            self.assertIn(path, before)
            changed.add(path)
            self.assertNotEqual(before, DRIVER['source_snapshot'](bridge))
            changed.clear()

    def test_same_cid_restart_is_not_same_generation(self):
        cid, owner = 'a' * 64, 'b' * 64
        info = {'Id':cid, 'Config':{'Labels':{'org.apicontour.causal.owner':owner}},
                'RestartCount':0, 'State':{'Status':'running', 'Running':True,
                                           'Pid':123, 'StartedAt':'2026-01-01T00:00:00Z'}}
        initial = DRIVER['proxy_generation'](info, cid, owner)
        info['State']['Pid'] = 124
        self.assertNotEqual(initial, DRIVER['proxy_generation'](info, cid, owner))
        info['State']['Pid'] = 123
        info['State']['StartedAt'] = '2026-01-01T00:00:01Z'
        self.assertNotEqual(initial, DRIVER['proxy_generation'](info, cid, owner))
        info['RestartCount'] = 1
        with self.assertRaises(RuntimeError):
            DRIVER['proxy_generation'](info, cid, owner)

    def test_native_linux_uid_preflight(self):
        with self.assertRaises(RuntimeError): DRIVER['check_native_uid']('linux', 501)
        DRIVER['check_native_uid']('linux', 1000)
        DRIVER['check_native_uid']('darwin', 501)

    def test_cargo_artifact_is_unique_and_contained(self):
        with tempfile.TemporaryDirectory(prefix='contour-factory-artifact-') as temp:
            target = Path(temp).resolve()
            binary = target / 'probe'
            binary.write_bytes(b'fixture')
            os.chmod(binary, 0o700)
            entry = {'reason':'compiler-artifact', 'target':{'name':'causal_factory_probe',
                'kind':['example'], 'src_path':str(DRIVER['EXAMPLE'])},
                'profile':{'test':False}, 'executable':str(binary)}
            line = json.dumps(entry)
            self.assertEqual(DRIVER['artifact']([line], target), binary)
            with self.assertRaises(RuntimeError):
                DRIVER['artifact']([line, line], target)
            entry['executable'] = '/bin/sh'
            with self.assertRaises((RuntimeError, ValueError)):
                DRIVER['artifact']([json.dumps(entry)], target)

    def test_cleanup_absence_requires_specific_daemon_response(self):
        class Result:
            returncode, stdout, stderr = 1, b'[]\n', b'Error: No such object: abc\n'
        bridge = {'run_process': lambda *args, **kwargs: Result()}
        DRIVER['require_absent'](bridge, ['docker'], 'container', 'abc')
        Result.stderr = b'permission denied\n'
        with self.assertRaises(RuntimeError):
            DRIVER['require_absent'](bridge, ['docker'], 'container', 'abc')


if __name__ == '__main__':
    unittest.main()
