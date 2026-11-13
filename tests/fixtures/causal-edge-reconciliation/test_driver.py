"""Offline controls for SQL31 request composition; no database is exercised."""
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.edge = runpy.run_path(str(ROOT / 'scripts/test-causal-edge-reconciliation.py'))
        self.observer = runpy.run_path(str(ROOT / 'scripts/test-causal-observer-inbox.py'))
        self.values = ('MIGRATION30;', 'MIGRATION31;', 'SEED;', 'CLOCK;', 'JOIN;', 'EDGE;')
        self.edge['continuation_sql'].__globals__['_fixed_driver'] = {'scenario_sql': lambda: self.values}

    def test_fixed_order_and_closed_interface(self):
        suffix = self.edge['continuation_sql']()
        parts = ("generate_series(1,29)", *self.values[:1], "generate_series(1,30)",
                 *self.values[1:2], "generate_series(1,31)", *self.values[2:])
        positions = [suffix.index(part) for part in parts]
        self.assertEqual(positions, sorted(positions))
        with self.assertRaises(TypeError):
            self.edge['continuation_sql']('some-other-path')
        self.edge['continuation_sql'].__globals__['_fixed_driver'] = {'scenario_sql': lambda: ('one',)}
        with self.assertRaises(ValueError):
            self.edge['continuation_sql']()

    def test_single_combined_request_then_race_then_receipt(self):
        calls = []
        suffix = self.edge['continuation_sql']()
        def execute(sql, timeout=30):
            calls.append(('execute', sql, timeout))
        def race(executor):
            self.assertIs(executor, execute)
            calls.append(('race',))
        edge = {'write_receipt': lambda directory: calls.append(('receipt', directory))}
        self.observer['_run_combined'](execute, 'SQL29;\n' + suffix, race, edge, 'owned-dir')
        self.assertEqual([item[0] for item in calls], ['execute', 'race', 'receipt'])
        self.assertEqual(calls[0], ('execute', 'SQL29;\n' + suffix, 300))
        self.assertEqual(calls[2], ('receipt', 'owned-dir'))

    def test_failed_race_withholds_receipt(self):
        calls = []
        def execute(sql, timeout=30):
            calls.append('execute')
        def race(executor):
            calls.append('race')
            raise RuntimeError('race failed')
        edge = {'write_receipt': lambda directory: calls.append('receipt')}
        with self.assertRaises(RuntimeError):
            self.observer['_run_combined'](execute, 'SQL29;\nSQL31;', race, edge, 'owned-dir')
        self.assertEqual(calls, ['execute', 'race'])

    def test_existing_diagnostic_is_closed(self):
        receiver = runpy.run_path(str(ROOT / 'scripts/test-causal-receiver-inbox.py'))
        canary = 'private-fixture-canary'
        lines = receiver['failure_lines'](RuntimeError(canary))
        self.assertTrue(lines)
        self.assertNotIn(canary, '\n'.join(lines))


if __name__ == '__main__':
    unittest.main()
