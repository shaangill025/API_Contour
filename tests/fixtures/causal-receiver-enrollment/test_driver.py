"""Offline controls for the receiver qualification harness; starts no services."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('receiver_driver', ROOT / 'scripts/test-causal-receiver-enrollment.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class DriverTests(unittest.TestCase):
    def test_guard_blocks_before_existing_helper(self):
        with patch.object(Path, 'read_bytes', return_value=b'BEGIN; ROLLBACK;'), patch.object(driver, 'load_existing', side_effect=AssertionError('service path reached')):
            with self.assertRaisesRegex(ValueError, 'deliberately inactive'):
                driver.main([str(ROOT / 'receiver-no-service-owned-fixture-test')])

    def test_inactive_and_noncommit_sources_rejected(self):
        for raw in (b'BEGIN; ROLLBACK;', b"DO $$ BEGIN RAISE EXCEPTION 'receiver enrollment candidate incomplete; do not apply'; END $$; COMMIT;", b'BEGIN;'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                driver.require_applicable(raw)
        driver.require_applicable(b'BEGIN; COMMIT;')

    def test_stage_order_preserves_exact_sources_and_ledger(self):
        class Base:
            def __init__(self):
                self.stages = []
            def after_forward(self, stage, execute):
                self.stages.append(stage)
        hook = object.__new__(driver.Hooks)
        hook.base = Base()
        hook.complete = False
        hook.files = {'m26': b'original26', 'm27': b'original27',
                      'm28': b'original28', 'fixture': b'fixture'}
        seen = []
        def execute(sql):
            seen.append(sql)
            if sql.startswith('SELECT array_agg'):
                return '{' + ','.join(map(str, range(1, 29))) + '}'
        hook.after_forward(25, execute)
        self.assertEqual(seen[:4], ['original26', 'original27', 'original28', 'fixture'])
        self.assertTrue(hook.complete)
        with self.assertRaises(ValueError):
            hook.after_forward(25, execute)

    def test_fixture_case_tags_match_closed_parser_order(self):
        import re
        transport_spec=importlib.util.spec_from_file_location('receiver_transport',ROOT/'scripts/fixture_psql_transport.py')
        transport=importlib.util.module_from_spec(transport_spec); transport_spec.loader.exec_module(transport)
        fixture=(ROOT/'db/tests/causal_receiver_enrollment.sql').read_text()
        tags=re.findall(r'^\\echo receiver-case=([a-z-]+)$',fixture,re.MULTILINE)
        self.assertEqual(tags,list(transport._RECEIVER_CASES))

    def test_receipt_does_not_claim_races_or_peer(self):
        hook = object.__new__(driver.Hooks)
        hook.complete = True
        self.assertEqual(hook.receipt()['public_enrollment_races_verified'], False)
        self.assertEqual(hook.receipt()['authenticated_transport'], False)
        hook.complete = False
        with self.assertRaises(RuntimeError):
            hook.receipt()


if __name__ == '__main__':
    unittest.main()
