"""Offline tests for the private reference capture orchestration."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('origin25_reference',ROOT/'scripts/capture-origin25-reference.py')
driver=importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)

class ReferenceTests(unittest.TestCase):
    def test_invalid_start_is_never_adopted_or_removed(self):
        valid='2026-11-12T01:02:03.123456789Z'
        for value in (None,'','not-a-date','2026-99-12T01:02:03Z','0001-01-01T00:00:00Z'):
            with self.subTest(started=value):
                output=mock.Mock();output.path=Path('/private'); fixture={'validate_postgres':mock.Mock(return_value='running'),'validate_network':mock.Mock(),'cleanup_owned':mock.Mock()}
                inspect=mock.Mock(side_effect=[{'State':{'StartedAt':value}},{}]);started=None
                with self.assertRaises(RuntimeError):
                    started=driver.record_generation(output,fixture,inspect,'token','network','container','image')
                with self.assertRaises(RuntimeError):
                    driver.cleanup_fixture(fixture,mock.Mock(),inspect,'token','network','container','image',True,True,True,started)
                fixture['cleanup_owned'].assert_not_called();output.write.assert_not_called()
        for boundary in ('postgres','network'):
            with self.subTest(boundary=boundary):
                output=mock.Mock();fixture={'validate_postgres':mock.Mock(return_value='created' if boundary=='postgres' else 'running'),'validate_network':mock.Mock(),'cleanup_owned':mock.Mock()}
                if boundary=='network': fixture['validate_network'].side_effect=RuntimeError('network drift')
                inspect=mock.Mock(side_effect=[{'State':{'StartedAt':valid}},{}]);started=None
                with self.assertRaises(RuntimeError): started=driver.record_generation(output,fixture,inspect,'token','network','container','image')
                with self.assertRaises(RuntimeError): driver.cleanup_fixture(fixture,mock.Mock(),inspect,'token','network','container','image',True,True,True,started)
                fixture['cleanup_owned'].assert_not_called();output.write.assert_not_called()
        # A failed durable generation receipt keeps the start unknown as well.
        output=mock.Mock();output.write.side_effect=OSError('controlled');fixture={'validate_postgres':mock.Mock(return_value='running'),'validate_network':mock.Mock(),'cleanup_owned':mock.Mock()};inspect=mock.Mock(side_effect=[{'State':{'StartedAt':valid}},{}]);started=None
        with self.assertRaises(OSError): started=driver.record_generation(output,fixture,inspect,'token','network','container','image')
        with self.assertRaises(RuntimeError): driver.cleanup_fixture(fixture,mock.Mock(),inspect,'token','network','container','image',True,True,True,started)
        fixture['cleanup_owned'].assert_not_called()
        self.assertFalse(any(call.args[0]=='receipt.json' for call in output.write.call_args_list))

    def test_restarted_generation_is_retained_without_final_receipt(self):
        valid='2026-11-12T01:02:03Z';output=mock.Mock();fixture={'validate_postgres':mock.Mock(return_value='running'),'validate_network':mock.Mock(),'cleanup_owned':mock.Mock()}
        inspect=mock.Mock(side_effect=[{'State':{'StartedAt':valid}},{},{'State':{'StartedAt':'2026-11-12T01:02:04Z'}}])
        started=driver.record_generation(output,fixture,inspect,'token','network','container','image')
        with self.assertRaises(RuntimeError): driver.cleanup_fixture(fixture,mock.Mock(),inspect,'token','network','container','image',True,True,True,started)
        fixture['cleanup_owned'].assert_not_called()
        self.assertEqual([call.args[0] for call in output.write.call_args_list],['generation.json'])

    def test_capture_requires_exact_21_before_any_forward_migration(self):
        events=[]
        def execute(sql):
            events.append(sql)
            if sql=='LEDGER': return '{'+','.join(map(str,range(1,22)))+'}'
            raise AssertionError('forward migration must not run')
        with self.assertRaisesRegex(ValueError,'reference mismatch'):
            driver.capture_forward(execute,lambda _:b'migration',lambda *_:None,lambda:None,
                                   verify21=lambda _:(_ for _ in ()).throw(ValueError('reference mismatch')),
                                   ledger_sql='LEDGER',inventory_sql='INVENTORY')
        self.assertEqual(events,['LEDGER'])
    def test_capture_checks_each_exact_ledger_and_fences_before_output(self):
        events=[]; stage=[21]
        def execute(sql):
            events.append(sql)
            if sql=='LEDGER': return '{'+','.join(map(str,range(1,stage[0]+1)))+'}'
            if sql=='INVENTORY': return json.dumps({'version':1,'server_major':16,'items':[{'kind':'schema'}]})
            stage[0]+=1; return ''
        outputs=[]
        driver.capture_forward(execute,lambda n:('migration-'+str(n)).encode(),lambda n,b:outputs.append((n,b)),lambda:events.append('FENCE'),
                               verify21=lambda _:events.append('VERIFY21'),ledger_sql='LEDGER',inventory_sql='INVENTORY')
        self.assertEqual([n for n,_ in outputs],[22,23,24,25])
        self.assertLess(events.index('VERIFY21'),events.index('migration-22'))
        for version,data in outputs:
            self.assertEqual(json.loads(data)['stage'],version)
            self.assertTrue(data.endswith(b'\n'))
        self.assertEqual(events.count('FENCE'),9)
    def test_new_private_output_is_exclusive_and_rejects_symlink(self):
        import tempfile,os
        with tempfile.TemporaryDirectory() as temp:
            parent=Path(temp).resolve(); target=parent/'result'
            owner=driver.PrivateOutput(target)
            try:
                owner.write('receipt.json',b'{}')
                self.assertEqual((target/'receipt.json').stat().st_mode & 0o777,0o600)
                with self.assertRaises(FileExistsError): owner.write('receipt.json',b'overwrite')
                with self.assertRaises(ValueError): owner.write('credential.txt',b'secret')
                with self.assertRaises(FileExistsError): driver.PrivateOutput(target)
                moved=parent/'moved';target.rename(moved);target.symlink_to(moved,target_is_directory=True)
                with self.assertRaises(ValueError): owner.verify()
            finally: owner.close()
    def test_wrong_forward_ledger_never_writes_capture(self):
        output=[];calls=[]
        def execute(sql):
            calls.append(sql)
            return driver.ledger(21) if sql=='LEDGER' else ''
        with self.assertRaisesRegex(ValueError,'forward ledger mismatch'):
            driver.capture_forward(execute,lambda _:b'migration',lambda *x:output.append(x),lambda:None,
                                   verify21=lambda _:None,ledger_sql='LEDGER',inventory_sql='INVENTORY')
        self.assertEqual(output,[])
        self.assertEqual(calls,['LEDGER','migration','LEDGER'])

    def test_fence_failure_never_writes_capture(self):
        stage=[21];outputs=[];calls=[0]
        def execute(sql):
            if sql=='LEDGER': return '{'+','.join(map(str,range(1,stage[0]+1)))+'}'
            if sql=='INVENTORY': return json.dumps({'version':1,'server_major':16,'items':[{}]})
            stage[0]+=1;return ''
        def fence():
            calls[0]+=1
            if calls[0]==2: raise RuntimeError('generation changed')
        with self.assertRaisesRegex(RuntimeError,'generation changed'):
            driver.capture_forward(execute,lambda _:b'migration',lambda *x:outputs.append(x),fence,
                                   verify21=lambda _:None,ledger_sql='LEDGER',inventory_sql='INVENTORY')
        self.assertEqual(outputs,[])

    def test_bad_inventory_or_wrong_ledger_stops_without_output(self):
        for bad in ('{}','{"version":1,"server_major":15,"items":[{}]}'):
            stage=[21]; output=[]
            def execute(sql):
                if sql=='LEDGER': return '{'+','.join(map(str,range(1,stage[0]+1)))+'}'
                if sql=='INVENTORY': return bad
                stage[0]+=1;return ''
            with self.assertRaises(ValueError):
                driver.capture_forward(execute,lambda _:b'migration',lambda *args:output.append(args),lambda:None,
                                       verify21=lambda _:None,ledger_sql='LEDGER',inventory_sql='INVENTORY')
            self.assertEqual(output,[])

if __name__=='__main__': unittest.main()
