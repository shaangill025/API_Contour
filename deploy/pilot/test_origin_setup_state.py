"""Fault-injection tests for the source-only setup journal protocol."""
import fcntl
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from deploy.local import capture_profiles
from deploy.pilot import origin_setup_state as setup


class Operation:
    def __init__(self):
        self.state = setup.ABSENT
        self.calls = 0
        self.fault = None

    def inspect(self): return self.state

    def apply(self):
        self.calls += 1
        if self.fault == 'before': raise RuntimeError('before commit')
        self.state = setup.EXACT
        if self.fault == 'after': raise RuntimeError('after commit')


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        state = Path(self.temp.name)/'origin-pilot'; state.mkdir(mode=0o700)
        self.profile = capture_profiles.ORIGIN_PILOT._replace(state=state)
        patch = mock.patch.object(capture_profiles, 'ORIGIN_PILOT', self.profile)
        patch.start(); self.addCleanup(patch.stop)
        self.ops = {name: Operation() for name in setup.SCHEMA_PHASES}
        self.journal = state/'setup.json'

    def run_setup(self, **kwargs): setup.run(self.profile, self.ops, **kwargs)
    def state(self): return json.loads(self.journal.read_bytes())

    def test_crash_after_commit_reconciles_without_duplicate(self):
        op = self.ops[setup.SCHEMA_PHASES[0]]; op.fault = 'after'
        with self.assertRaisesRegex(RuntimeError, 'after commit'): self.run_setup()
        self.assertEqual(self.state()['pending'], setup.SCHEMA_PHASES[0])
        op.fault = None
        self.run_setup()
        self.assertEqual(op.calls, 1)
        self.assertEqual(self.state()['completed'], len(setup.SCHEMA_PHASES))
        self.assertIsNone(self.state()['pending'])
        self.run_setup()
        self.assertTrue(all(op.calls == 1 for op in self.ops.values()))

    def test_crash_before_commit_retries_only_pending(self):
        op = self.ops[setup.SCHEMA_PHASES[0]]; op.fault = 'before'
        with self.assertRaisesRegex(RuntimeError, 'before commit'): self.run_setup()
        self.assertEqual(self.state()['completed'], 0)
        self.assertEqual(self.state()['pending'], setup.SCHEMA_PHASES[0])
        op.fault = None
        self.run_setup()
        self.assertEqual(op.calls, 2)
        self.assertTrue(all(self.ops[name].calls == 1 for name in setup.SCHEMA_PHASES[1:]))

    def test_pending_write_fault_prevents_operation(self):
        with mock.patch.object(setup.capture_renew, 'replace_durable', side_effect=OSError('write failed')):
            with self.assertRaises(OSError): self.run_setup()
        self.assertIsNone(self.state()['pending'])
        self.assertEqual(sum(op.calls for op in self.ops.values()), 0)
        self.run_setup()
        self.assertEqual(self.state()['completed'], len(setup.SCHEMA_PHASES))

    def test_completion_write_fault_keeps_pending_and_reconciles(self):
        original = setup.capture_renew.replace_durable
        def fault(path, data):
            if json.loads(data)['completed'] == 1: raise OSError('completion write failed')
            original(path, data)
        with mock.patch.object(setup.capture_renew, 'replace_durable', side_effect=fault):
            with self.assertRaises(OSError): self.run_setup()
        self.assertEqual(self.state()['pending'], setup.SCHEMA_PHASES[0])
        self.run_setup()
        self.assertEqual(self.ops[setup.SCHEMA_PHASES[0]].calls, 1)

    def test_drift_unknown_and_tamper_refuse(self):
        with self.assertRaises(RuntimeError):
            self.run_setup(after_pending=lambda phase: (_ for _ in ()).throw(RuntimeError('crash')))
        first = self.ops[setup.SCHEMA_PHASES[0]]
        for status in (setup.DRIFT, 'UNKNOWN', None):
            first.state = status
            with self.assertRaises(ValueError): self.run_setup()
            self.assertEqual(first.calls, 0)
            self.assertEqual(self.state()['pending'], setup.SCHEMA_PHASES[0])
        state = self.state(); state['pending'] = setup.SCHEMA_PHASES[1]
        self.journal.write_bytes(setup._encode(state))
        with self.assertRaises(ValueError): self.run_setup()
        self.assertEqual(first.calls, 0)

    def test_completed_phase_drift_blocks_later_work(self):
        second = self.ops[setup.SCHEMA_PHASES[1]]; second.fault = 'before'
        with self.assertRaises(RuntimeError): self.run_setup()
        self.ops[setup.SCHEMA_PHASES[0]].state = setup.ABSENT
        second.fault = None
        with self.assertRaisesRegex(ValueError, 'completed setup phase drift'): self.run_setup()
        self.assertEqual(second.calls, 1)

    def test_apply_without_exact_postcondition_does_not_advance(self):
        first = self.ops[setup.SCHEMA_PHASES[0]]
        first.apply = mock.Mock()
        with self.assertRaisesRegex(ValueError, 'postcondition not exact'): self.run_setup()
        self.assertEqual(self.state()['completed'], 0)
        self.assertEqual(self.state()['pending'], setup.SCHEMA_PHASES[0])
        self.assertTrue(all(self.ops[name].calls == 0 for name in setup.SCHEMA_PHASES[1:]))

    def test_source_digest_change_refuses(self):
        with self.assertRaises(RuntimeError):
            self.run_setup(after_pending=lambda phase: (_ for _ in ()).throw(RuntimeError('crash')))
        with mock.patch.object(setup, '_source_identity', return_value='0' * 64):
            with self.assertRaisesRegex(ValueError, 'identity or order mismatch'): self.run_setup()
        self.assertEqual(self.ops[setup.SCHEMA_PHASES[0]].calls, 0)

    def test_source_change_before_and_after_apply_preserves_pending(self):
        original = setup._source_identity()
        with mock.patch.object(setup, '_source_identity', side_effect=[original, 'changed']):
            with self.assertRaisesRegex(ValueError, 'sources changed'): self.run_setup()
        self.assertEqual(self.state()['pending'], setup.SCHEMA_PHASES[0])
        self.assertEqual(self.ops[setup.SCHEMA_PHASES[0]].calls, 0)
        with mock.patch.object(setup, '_source_identity', side_effect=[original, original, 'changed']):
            with self.assertRaisesRegex(ValueError, 'sources changed after operation'): self.run_setup()
        self.assertEqual(self.state()['pending'], setup.SCHEMA_PHASES[0])
        self.assertEqual(self.ops[setup.SCHEMA_PHASES[0]].calls, 1)
        self.run_setup()
        self.assertEqual(self.ops[setup.SCHEMA_PHASES[0]].calls, 1)

    def test_permissions_symlinks_lock_and_unknown_profile(self):
        os.chmod(self.profile.state, 0o755)
        with self.assertRaises(ValueError): self.run_setup()
        os.chmod(self.profile.state, 0o700)
        lock = self.profile.state/'setup.lock'
        lock.symlink_to(self.profile.state/'target')
        with self.assertRaises(OSError): self.run_setup()
        lock.unlink()
        fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError): self.run_setup()
        finally: os.close(fd)
        with self.assertRaises(ValueError): setup.run(self.profile._replace(ingress_login='other'), self.ops)
        self.assertFalse(self.journal.exists())
        self.run_setup()
        os.chmod(self.journal, 0o644)
        with self.assertRaises(ValueError): self.run_setup()

    def test_invalid_operations_and_preexisting_unplanned_state(self):
        with self.assertRaises(ValueError): setup.run(self.profile, {})
        self.ops[setup.SCHEMA_PHASES[0]].state = setup.EXACT
        with self.assertRaisesRegex(ValueError, 'unplanned setup state'): self.run_setup()
        self.assertEqual(self.state()['completed'], 0)
        self.assertEqual(self.ops[setup.SCHEMA_PHASES[0]].calls, 0)


if __name__ == '__main__': unittest.main()
