"""Offline protocol and source controls for synthetic marker bridge driver."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('marker_bridge',ROOT/'scripts/test-postgres-causal-marker-bridge.py')
d=importlib.util.module_from_spec(spec); spec.loader.exec_module(d)

class Driver(unittest.TestCase):
    def test_artifact_requires_exact_example_package_and_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); exe=root/'probe'; exe.write_text('x'); exe.chmod(0o700)
            entry={'reason':'compiler-artifact','target':{'name':'causal_marker_binding_probe','kind':['example'],'src_path':str(d.EXAMPLE)},'profile':{'test':False},'executable':str(exe)}
            bridge={'digest_file':lambda _: 'hash'}
            self.assertEqual(d.artifact([json.dumps(entry)],root,bridge),exe)
            with self.assertRaises(RuntimeError): d.artifact([json.dumps(entry),json.dumps(entry)],root,bridge)
            entry['target']['name']='other'
            with self.assertRaises(RuntimeError): d.artifact([json.dumps(entry)],root,bridge)
    def test_closed_input_sources_refuse_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); target=root/'target'; target.write_text('x'); link=root/'link'; link.symlink_to(target)
            with self.assertRaises(ValueError): d.safe(link)
    def test_extra_migration_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); folder=root/'db/opt-in-migrations'; folder.mkdir(parents=True)
            for n in d.OPT+d.EXTRA_SOURCE_MIGRATIONS: (folder/(n+'.sql')).write_text('fixture')
            (folder/'0024_other.sql').write_text('fixture')
            with mock.patch.object(d,'ROOT',root), self.assertRaises(ValueError): d.snapshot({'source_paths':lambda:[],'digest_file':lambda _: 'hash'})
    def test_probe_modes_are_closed_and_cover_invalidation(self):
        src=d.EXAMPLE.read_text()
        for name in ('positive','weak','wrong_role','revoked','expired','cancel'):
            self.assertIn('"'+name+'"',src)
        self.assertIn('verified_remaining().is_zero()',src)
        self.assertIn('CausalError::Conflict',src)
    def test_nonzero_or_unexpected_weak_response_never_passes(self):
        from types import SimpleNamespace
        base=['probe']*24; bridge={'IDS':['tenant','runtime'],'run_process':mock.Mock(return_value=SimpleNamespace(returncode=1,stdout=b'REFUSED\n',stderr=b''))}
        with self.assertRaisesRegex(AssertionError,'protocol mismatch'):
            d.exercise(base,{},lambda _: '0|0|0|0',bridge,{})
        bridge['run_process'].return_value=SimpleNamespace(returncode=0,stdout=b'REFUSED\nEXTRA\n',stderr=b'')
        with self.assertRaisesRegex(AssertionError,'protocol mismatch'):
            d.exercise(base,{},lambda _: '0|0|0|0',bridge,{})
    def test_initial_state_must_be_empty_before_probe(self):
        bridge={'IDS':['tenant','runtime'],'run_process':mock.Mock()}
        with self.assertRaisesRegex(AssertionError,'durable marker state'):
            d.exercise(['probe']*24,{},lambda _: '0|0|1|0',bridge,{})
        bridge['run_process'].assert_not_called()

    def test_read_error_and_late_stderr_cannot_accept_valid_prefix(self):
        import threading
        from types import SimpleNamespace
        monitor=SimpleNamespace(lock=threading.Lock(),buffers={'out':bytearray(b'READY\nREFUSED\n'),'err':bytearray()},overflow=False,read_failed=False)
        stream=SimpleNamespace(fileno=lambda:17)
        with mock.patch.object(d.os,'read',side_effect=OSError('controlled')):
            d.strict_drain(monitor,'out',stream)
        with self.assertRaisesRegex(RuntimeError,'probe output invalid'): d.monitor_output(monitor,b'READY\nREFUSED\n')
        monitor.read_failed=False
        with mock.patch.object(d.os,'read',side_effect=[b'late diagnostic',b'']):
            d.strict_drain(monitor,'err',stream)
        with self.assertRaisesRegex(RuntimeError,'probe output invalid'): d.monitor_output(monitor,b'READY\nREFUSED\n')
        monitor.buffers['err'].clear()
        d.monitor_output(monitor,b'READY\nREFUSED\n')

    def test_driver_requires_independent_row_and_cancel_entry(self):
        src=(ROOT/'scripts/test-postgres-causal-marker-bridge.py').read_text()
        self.assertIn('binding receipt differs from committed row',src)
        self.assertIn('cancellation never reached insert',src)
        self.assertIn('other credential did not keep session current',src)
        self.assertIn('cancelled backend not absent',src)

if __name__=='__main__': unittest.main()
