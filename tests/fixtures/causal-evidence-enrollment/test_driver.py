"""Offline controls for exact 25/26 qualification hooks."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('evidence_qualification',ROOT/'scripts/test-causal-evidence-enrollment.py')
driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)

class QualificationTests(unittest.TestCase):
    def test_modes_are_closed_before_any_output_or_setup(self):
        for args in ([],['schema25'],['gateway26','relative'],['other','/tmp/example'],['schema25','/tmp/example','extra']):
            with self.subTest(args=args),mock.patch.object(driver,'load_capture') as load:
                with self.assertRaises(ValueError): driver.main(args)
                load.assert_not_called()
    def test_hooks_require_exact_stages_and_do_not_seed_schema25(self):
        checks=[];schema=mock.Mock();schema._require_migration_stage.side_effect=lambda _,n:checks.append(n)
        hooks=driver.QualificationHooks('schema25',schema,{'seed':b'never','migration':b'never','fixture':b'never'})
        execute=mock.Mock()
        hooks.after_stage17(execute);execute.assert_not_called()
        for stage in (22,23,24,25): hooks.after_forward(stage,execute)
        self.assertEqual(checks,[22,23,24]);schema.require_ready.assert_called_once_with(execute)
        self.assertEqual(hooks.receipt(),{'mode':'schema25','schema_stage':25,'scope':'synthetic-sql-only','authenticated_transport':False})
    def test_26_applies_exact_files_together_then_checks_reapply(self):
        schema=mock.Mock(); migration=(ROOT/'db/opt-in-migrations/0026_causal_evidence_enrollment.sql').read_bytes();files={'seed':b'SEED','migration':migration,'fixture':b'FIXTURE'}
        hooks=driver.QualificationHooks('gateway26',schema,files);calls=[]
        def execute(sql):
            calls.append(sql)
            if sql==driver.LEDGER: return '{'+','.join(map(str,range(1,27)))+'}'
            if sql==driver.guard_probe(migration): return '42501'
            if sql==driver.origin_inventory_sql(): return json.dumps({'version':1,'server_major':16,'items':[{}]})
            return ''
        hooks.after_stage17(execute)
        for stage in (22,23,24,25): hooks.after_forward(stage,execute)
        self.assertEqual(calls[0],'SEED')
        self.assertIn(migration.decode()+'\nFIXTURE',calls)
        self.assertEqual(calls.count(driver.guard_probe(migration)),1)
    def test_guard_probe_is_exact_and_rejects_unexpected_guard_shape(self):
        migration=(ROOT/'db/opt-in-migrations/0026_causal_evidence_enrollment.sql').read_bytes()
        guard=migration.decode().split('DO $$ BEGIN\n',1)[1].split('\nEND $$;',1)[0]
        probe=driver.guard_probe(migration)
        self.assertIn(guard,probe);self.assertIn('WHEN insufficient_privilege',probe)
        self.assertIn("SELECT '42501'",probe)
        for bad in (b'',b'DO $$ BEGIN\nEND $$;',migration.replace(b"ERRCODE='42501'",b"ERRCODE='23505'")):
            with self.assertRaises(ValueError): driver.guard_probe(bad)
    def test_reapply_wrong_sqlstate_or_metadata_drift_cannot_complete(self):
        migration=(ROOT/'db/opt-in-migrations/0026_causal_evidence_enrollment.sql').read_bytes()
        for failure in ('sqlstate','metadata','ledger'):
            with self.subTest(failure=failure):
                hooks=driver.QualificationHooks('gateway26',mock.Mock(),{'seed':b'SEED','migration':migration,'fixture':b'FIXTURE'});hooks.seeded=True;hooks.next_stage=25;metadata=[0];ledgers=[0]
                def execute(sql):
                    if sql==driver.guard_probe(migration): return '00000' if failure=='sqlstate' else '42501'
                    if sql==driver.LEDGER:
                        ledgers[0]+=1
                        return '{1}' if failure=='ledger' and ledgers[0]==2 else '{'+','.join(map(str,range(1,27)))+'}'
                    if sql==driver.origin_inventory_sql():
                        metadata[0]+=1
                        return 'changed' if failure=='metadata' and metadata[0]==2 else json.dumps({'version':1,'server_major':16,'items':[{}]})
                    return ''
                with self.assertRaises(RuntimeError): hooks.after_forward(25,execute)
                self.assertFalse(hooks.complete)
                with self.assertRaises(RuntimeError): hooks.receipt()

    def test_forward_hook_failure_blocks_writes_and_default_path_is_unchanged(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('reference_capture',ROOT/'scripts/capture-origin25-reference.py')
        capture=importlib.util.module_from_spec(spec);spec.loader.exec_module(capture)
        stage=[21]; writes=[]; fences=[]
        def execute(sql):
            if sql=='LEDGER': return '{'+','.join(map(str,range(1,stage[0]+1)))+'}'
            if sql=='INVENTORY': return json.dumps({'version':1,'server_major':16,'items':[{}]})
            stage[0]+=1;return ''
        with self.assertRaisesRegex(RuntimeError,'hook failure'):
            capture.capture_forward(execute,lambda _:b'migration',lambda *x:writes.append(x),lambda:fences.append(1),
                verify21=lambda _:None,ledger_sql='LEDGER',inventory_sql='INVENTORY',
                _after_stage=lambda *_:(_ for _ in ()).throw(RuntimeError('hook failure')))
        self.assertEqual(writes,[])
        stage[0]=21;fences.clear()
        capture.capture_forward(execute,lambda _:b'migration',lambda *x:writes.append(x),lambda:fences.append(1),
            verify21=lambda _:None,ledger_sql='LEDGER',inventory_sql='INVENTORY')
        self.assertEqual([item[0] for item in writes],[22,23,24,25]);self.assertEqual(len(fences),9)
    def test_preflight_requires_all_gateway_sources_before_output(self):
        hooks=driver.QualificationHooks('gateway26',mock.Mock())
        with self.assertRaises(ValueError): hooks.preflight({})
        self.assertIsNone(hooks.files);self.assertFalse(hooks.complete)

    def test_hook_failure_propagates_and_no_completion(self):
        hooks=driver.QualificationHooks('schema25',mock.Mock(),{'seed':b'', 'migration':b'', 'fixture':b''})
        hooks.schema.require_ready.side_effect=ValueError('unsafe')
        with self.assertRaises(ValueError): hooks.after_forward(25,mock.Mock())
        self.assertFalse(hooks.complete)
        with self.assertRaises(RuntimeError): hooks.receipt()

if __name__=='__main__': unittest.main()
