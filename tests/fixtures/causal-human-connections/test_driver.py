"""Offline controls for the fixed SQL32 continuation; no database is exercised."""
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]


class HumanContinuationTests(unittest.TestCase):
    def setUp(self):
        self.human = runpy.run_path(str(ROOT / 'scripts/test-causal-human-connections.py'))
        self.observer = runpy.run_path(str(ROOT / 'scripts/test-causal-observer-inbox.py'))
        self.driver = runpy.run_path(str(ROOT / 'tests/fixtures/causal-human-connections/driver.py'))
        self.values = ('MIGRATION32;', 'ACL;', 'CASES;')
        self.human['continuation_sql'].__globals__['_fixed_driver'] = {'scenario_sql': lambda: self.values}

    def test_closed_order_and_invalid_suffix(self):
        suffix = self.human['continuation_sql']()
        parts = (self.values[0], 'generate_series(1,32)', *self.values[1:])
        positions = [suffix.index(part) for part in parts]
        self.assertEqual(positions, sorted(positions))
        with self.assertRaises(TypeError):
            self.human['continuation_sql']('arbitrary path')
        for bad in [('one',), ['one', 'two', 'three'], ('one', '', 'three')]:
            self.human['continuation_sql'].__globals__['_fixed_driver'] = {'scenario_sql': lambda: bad}
            with self.assertRaises(ValueError):
                self.human['continuation_sql']()

    def test_fixed_sources_and_committed_check(self):
        calls = []
        def source(name, tracked=False):
            calls.append((name, tracked))
            return 'COMMIT;' if name.endswith('.sql') else ''
        self.driver['scenario_sql'].__globals__['_source'] = source
        self.driver['scenario_sql']()
        self.assertEqual(calls, [(name, True) for name in self.driver['FILES']])
        with self.assertRaises(ValueError):
            self.driver['_source']('arbitrary.sql')

    def test_single_request_before_race_and_failure_withholds_receipt(self):
        for failing in ('execute', 'race', None):
            calls = []
            def execute(sql, timeout=30):
                calls.append(('execute', sql, timeout))
                if failing == 'execute': raise RuntimeError('failed')
            def race(executor):
                self.assertIs(executor, execute)
                calls.append(('race',))
                if failing == 'race': raise RuntimeError('failed')
            edge = {'write_receipt': lambda directory: calls.append(('edge receipt', directory))}
            combined = 'SQL29;\nSQL31;\n' + self.human['continuation_sql']()
            if failing:
                with self.assertRaises(RuntimeError):
                    self.observer['_run_combined'](execute, combined, race, edge, 'owned')
                self.assertNotIn('edge receipt', [call[0] for call in calls])
            else:
                self.observer['_run_combined'](execute, combined, race, edge, 'owned')
                self.assertEqual([call[0] for call in calls], ['execute', 'race', 'edge receipt'])
                self.assertEqual(calls[0], ('execute', combined, 300))

    def test_receipt_requires_exact_owned_regular_file(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            self.human['write_receipt'](directory)
            self.human['require_receipt'](directory)
            with self.assertRaises(FileExistsError): self.human['write_receipt'](directory)
            path = directory / 'causal-human-connections.done'
            path.write_bytes(b'bad')
            with self.assertRaises(ValueError): self.human['require_receipt'](directory)
            path.unlink()
            path.symlink_to(directory / 'missing')
            with self.assertRaises(OSError): self.human['require_receipt'](directory)

    def test_loader_rejects_dirty_source_before_loading(self):
        supervisor = runpy.run_path(str(ROOT / 'scripts/test-postgres-tls.py'))
        loader = supervisor['checked_human_causal_loader']
        with patch.dict(loader.__globals__, {'bounded_git': lambda *args: b' M fixture'}):
            with self.assertRaisesRegex(ValueError, 'not clean'):
                loader()

    def test_entrypoint_rejects_arguments(self):
        with patch('sys.argv', ['entry', '--arbitrary']):
            with self.assertRaises(ValueError): self.human['main']()


if __name__ == '__main__':
    unittest.main()
