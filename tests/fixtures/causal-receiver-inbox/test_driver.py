"""Offline opt-in orchestration; no DB, TLS, or authorization proof."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('receiver_driver',ROOT/'scripts/test-causal-receiver-inbox.py')
driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)

class DriverTests(unittest.TestCase):
    def test_failure_labels_redact_messages_and_unknown_attributes(self):
        error=RuntimeError('SECRET_SENTINEL')
        error.step='cases';error.case='observer-first';error.sqlstate='42702'
        error.function='contour.accept_causal_receiver';error.line=7;error.source_line=42
        line=driver.failure_lines(error)[0]
        self.assertIn('step=cases case=observer-first sqlstate=42702',line)
        self.assertIn('line=7 input_line=42',line)
        self.assertNotIn('SECRET_SENTINEL',line)
        error.step='SECRET_SENTINEL';error.case='SECRET_SENTINEL';error.sqlstate='SECRET_SENTINEL';error.function='SECRET_SENTINEL'
        line=driver.failure_lines(error)[0]
        self.assertNotIn('SECRET_SENTINEL',line)
        self.assertIn('step=unavailable case=unavailable sqlstate=unavailable function=unavailable line=unavailable',line)
        self.assertIn('type=OtherError',driver.failure_lines(Exception('SECRET_SENTINEL'))[0])

    def test_incomplete_migration_never_runs(self):
        with self.assertRaises(ValueError):driver.require_applicable('receiver inbox candidate incomplete; do not apply\nROLLBACK;')
        driver.require_applicable('BEGIN;\nCOMMIT;')
    def test_scenario_preserves_fixed_source_order(self):
        original='guard ARRAY(SELECT generate_series(1,27)) then full observer tests;'
        values={driver.FILES[0]:'M28;',driver.FILES[1]:'BEGIN;\nCOMMIT;',driver.FILES[2]:original,driver.FILES[3]:'SEED;',driver.FILES[4]:'TEST;',driver.FILES[5]:'POST;'}
        with mock.patch.object(driver,'source',side_effect=lambda name:values[name]):
            prefix,adapted,suffix=driver.scenario_sql(original)
            self.assertEqual(prefix,'\\echo receiver29-step=migration28\nM28;\n\\echo receiver29-step=migration29\nBEGIN;\nCOMMIT;\n\\echo receiver29-step=observer-regression\n');self.assertEqual(suffix,'\\echo receiver29-step=seed\nSEED;\n\\echo receiver29-step=cases\n\\echo receiver-case=parser\nTEST;')
            self.assertEqual(adapted.replace('ARRAY(SELECT generate_series(1,29))','ARRAY(SELECT generate_series(1,27))'),original)
            with self.assertRaises(ValueError):driver.scenario_sql(original+' changed')
    def test_receipt_requires_exact_private_file(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'causal-receiver.done';path.write_bytes(b'causal-receiver-complete\n');path.chmod(0o600)
            driver.require_receipt(d);path.chmod(0o644)
            with self.assertRaises(ValueError):driver.require_receipt(d)
            path.chmod(0o600);path.write_bytes(b'wrong')
            with self.assertRaises(ValueError):driver.require_receipt(d)
    def test_race_requires_one_winner_and_live_authority_control(self):
        calls=[]
        def execute(sql,timeout=30):
            calls.append(sql)
            if "WHERE name='left';" in sql and 'receiver29_race_result' in sql:return 'accepted'
            if "WHERE name='right';" in sql and 'receiver29_race_result' in sql:return 'busy'
            if 'count(*)=1' in sql:return 'true'
            if "name='control'" in sql:return 'tenant\ntrue'
            return ''
        with mock.patch.object(driver,'source',return_value='POST-REVOCATION'):
            driver.after_scenario(execute)
        self.assertIn('\\set VERBOSITY verbose\nPOST-REVOCATION',calls);self.assertEqual(calls[-1],'DROP TABLE public.receiver29_race_seed;')
        def both_win(sql,timeout=30):
            if 'receiver29_race_result' in sql:return 'accepted'
            return 'true'
        with self.assertRaises(RuntimeError):driver.after_scenario(both_win)
    def test_only_explicit_receiver_flag_loads_fixed_driver_before_services(self):
        tls_spec=importlib.util.spec_from_file_location('receiver_tls',ROOT/'scripts/test-postgres-tls.py')
        tls=importlib.util.module_from_spec(tls_spec);tls_spec.loader.exec_module(tls)
        with mock.patch.object(tls.sys,'argv',['driver','--causal-receiver']), mock.patch.object(tls,'checked_receiver_loader',side_effect=RuntimeError('fixed loader stop')) as loader:
            with self.assertRaisesRegex(RuntimeError,'fixed loader stop'):tls.main()
            loader.assert_called_once()
        with mock.patch.object(tls.sys,'argv',['driver','--causal-receiver','--causal-observer']), mock.patch.object(tls,'checked_receiver_loader') as loader:
            with self.assertRaises(ValueError):tls.main()
            loader.assert_not_called()
        with mock.patch.object(tls.sys,'argv',['driver','--causal-observer']), mock.patch.object(tls,'checked_receiver_loader') as loader, mock.patch.object(tls,'runtime_source_snapshot',side_effect=RuntimeError('source stop')):
            with self.assertRaisesRegex(RuntimeError,'source stop'):tls.main()
            loader.assert_not_called()
    def test_seed_has_distinct_receiver_lifecycle_and_original_marker(self):
        seed=(ROOT/'tests/fixtures/causal-receiver-inbox/seed.sql').read_text()
        for v in ('ce0b','ce0d','ce0e','ce0f','ce10',"repeat('d6',32)","repeat('d7',32)","repeat('d8',32)","repeat('d9',32)"):
            self.assertIn(v,seed)
        self.assertIn('FROM receiver_claim29 c CROSS JOIN receiver_product29 m CROSS JOIN LATERAL contour.enroll_causal_receiver(ROW(',seed)
        self.assertEqual(seed.count(' AS result;'),1)
        self.assertIn('SELECT (c.claim).* INTO STRICT x FROM receiver_claim29 c;',seed)
        self.assertNotIn('SELECT claim INTO STRICT x FROM receiver_claim29',seed)
        self.assertIn('(proof).marker_attempt,(proof).marker_wire_digest',seed)
        self.assertNotIn('INSERT INTO contour.origin_proofs',seed)
        self.assertNotIn('INSERT INTO contour.observation_windows',seed)

if __name__=='__main__':unittest.main()
