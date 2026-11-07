"""Offline controls for isolated SQL23 qualification."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('marker_driver',ROOT/'scripts/test-postgres-causal-marker-binding.py')
d=importlib.util.module_from_spec(spec); spec.loader.exec_module(d)

class Driver(unittest.TestCase):
    def test_each_case_has_fresh_exact_clone_and_cleanup(self):
        calls=[]; cases=[]
        def execute(db,sql):
            calls.append((db,sql))
            if 'current_database()' in sql: return db+'|{'+','.join(map(str,range(1,24)))+'}|0|0|0'
            return ''
        with mock.patch.object(d,'run_case',side_effect=lambda argv,ex,case,h:cases.append(case)), mock.patch('builtins.print'):
            d.qualify('a'*64,execute,{})
        self.assertEqual(tuple(cases),d.CASES)
        self.assertEqual(sum(sql.startswith('CREATE DATABASE') for _,sql in calls),len(d.CASES))
        self.assertEqual(sum(sql.startswith('DROP DATABASE') for _,sql in calls),len(d.CASES))
    def test_failed_case_drops_clone(self):
        calls=[]
        def execute(db,sql):
            calls.append(sql)
            if 'current_database()' in sql: return db+'|{'+','.join(map(str,range(1,24)))+'}|0|0|0'
            return ''
        with mock.patch.object(d,'run_case',side_effect=RuntimeError('controlled')):
            with self.assertRaisesRegex(RuntimeError,'controlled'): d.qualify('a'*64,execute,{})
        self.assertEqual(sum(x.startswith('DROP DATABASE') for x in calls),1)
    def test_clones_reject_old_ledger_and_existing_state(self):
        for value in ('marker_case_0|{'+','.join(map(str,range(1,23)))+'}|0|0|0',
                      'marker_case_0|{'+','.join(map(str,range(1,24)))+'}|0|0|1'):
            with self.assertRaises(AssertionError): d.assert_fresh(lambda *_:value,'marker_case_0')
    def test_wrong_identity_checks_are_independent_transactions(self):
        calls=[]; h={'_issue':lambda n:'ISSUE;', '_setup':lambda r:'ROLE '+r+';'}
        def execute(sql):
            calls.append(sql)
            return '0|92' if 'SELECT (SELECT count(*)' in sql else ''
        d.run_case([],execute,'wrong_identity',h)
        negatives=[s for s in calls if 'unexpected acceptance' in s]
        self.assertEqual(len(negatives),7)
        self.assertTrue(all(s.startswith('BEGIN;') and s.endswith(' COMMIT;') for s in negatives))
    def test_race_requires_busy_then_conflict_and_exact_charge(self):
        race=mock.Mock(); calls=[]; h={'_issue':lambda n:'ISSUE;', '_setup':lambda r:'ROLE '+r+';', 'race':race}
        def execute(sql):
            calls.append(sql); return '1|364' if 'SELECT (SELECT count(*)' in sql else ''
        d.run_case(['psql'],execute,'race',h)
        self.assertEqual(race.call_args.kwargs,{'retry_sqlstate':'23505'})
        self.assertIn("repeat('42'",race.call_args.args[1]); self.assertIn("repeat('43'",race.call_args.args[2])
    def test_snapshot_fails_extra_migration(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for name in d.SOURCES:
                p=root/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(b'x')
            with mock.patch.object(d,'ROOT',root):
                before=d.snapshot(); (root/d.EXTRAS[0]).write_bytes(b'changed'); self.assertNotEqual(before,d.snapshot())
                (root/'db/opt-in-migrations/0024_unexpected.sql').write_bytes(b'x')
                with self.assertRaises(ValueError): d.snapshot()
    def test_both_leaf_gates_are_exercised_separately(self):
        for case,leaf in (('product_leaf_lock','11'),('export_leaf_lock','33')):
            with self.subTest(case=case):
                race=mock.Mock(); h={'_issue':lambda n:'ISSUE;', '_setup':lambda r:'ROLE '+r+';', 'race':race}
                def execute(sql): return '1|364' if 'SELECT (SELECT count(*)' in sql else ''
                d.run_case(['psql'],execute,case,h)
                self.assertIn("repeat('"+leaf+"'",race.call_args.args[1])
                self.assertIn('bind_causal_marker_key',race.call_args.args[2])
                self.assertEqual(race.call_args.args[2],race.call_args.args[3])
    def test_ambiguous_create_recovers_only_owned_container_and_fails(self):
        registry={'IMAGE':'pinned','verify_qualified_profile':lambda:None,
                  'cleanup_owned':mock.Mock(),'recover_owned_container':mock.Mock(return_value=None)}
        def command(args,input=None,timeout=30):
            if args[1]=='create': raise TimeoutError('ambiguous')
            return ''
        with mock.patch.object(d.sys,'argv',['driver']), mock.patch.object(d,'snapshot',return_value={'fixed':'hash'}) as snap, \
             mock.patch.dict(d.GEN,{'helpers':lambda:(registry,{'_run':command})}), \
             mock.patch.object(d.signal,'signal',return_value=None), mock.patch.object(d.signal,'setitimer'):
            with self.assertRaises(TimeoutError): d.main()
        registry['recover_owned_container'].assert_called_once()
        registry['cleanup_owned'].assert_not_called()
        self.assertEqual(snap.call_count,2)
    def test_cleanup_failure_is_not_success(self):
        cid='a'*64
        registry={'IMAGE':'pinned','verify_qualified_profile':lambda:None,
                  'cleanup_owned':mock.Mock(side_effect=RuntimeError('cleanup failed')),'recover_owned_container':mock.Mock()}
        def command(args,input=None,timeout=30):
            if args[1]=='create': return cid
            if args[1]=='exec': raise RuntimeError('psql failed')
            return ''
        from types import SimpleNamespace
        with mock.patch.object(d.sys,'argv',['driver']), mock.patch.object(d,'snapshot',side_effect=[{'fixed':'hash'},{'changed':'hash'}]), \
             mock.patch.dict(d.GEN,{'helpers':lambda:(registry,{'_run':command})}), mock.patch.object(d,'checked_source',return_value=b'fixture'), \
             mock.patch.object(d.signal,'signal',return_value=None), mock.patch.object(d.signal,'setitimer'), \
             mock.patch.object(d.subprocess,'run',return_value=SimpleNamespace(returncode=0)):
            with self.assertRaises(BaseExceptionGroup) as caught: d.main()
        self.assertEqual([str(x) for x in caught.exception.exceptions],['psql failed','cleanup failed','qualification source changed'])
        registry['cleanup_owned'].assert_called_once()

    def test_loader_refuses_symlink_before_executing_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); scripts=root/'scripts'; scripts.mkdir()
            marker=root/'executed'; target=root/'target.py'
            target.write_text('from pathlib import Path\nPath('+repr(str(marker))+').touch()\n')
            (scripts/'test-postgres-causal-generation.py').symlink_to(target)
            with self.assertRaisesRegex(ValueError,'source symlink'): d.load_generation(root)
            self.assertFalse(marker.exists())

    def test_existing_other_credentials_have_their_exact_leaf_pairs(self):
        calls=[]; h={'_issue':lambda n:'ISSUE;', '_setup':lambda r:'ROLE '+r+';'}
        def execute(sql):
            calls.append(sql); return '0|92' if 'SELECT (SELECT count(*)' in sql else ''
        d.run_case([],execute,'wrong_identity',h)
        self.assertTrue(any("000000000003'" in sql and "repeat('03',32)" in sql for sql in calls))
        self.assertTrue(any("000000000002'" in sql and "repeat('22',32)" in sql for sql in calls))
    def test_delayed_insert_checks_entry_and_rollback(self):
        calls=[]; h={'_claim':lambda _: 'CLAIM(900000000,10,1024,1024,60)', '_issue':lambda _: '', '_setup':lambda r:'ROLE '+r+';'}
        def execute(sql):
            calls.append(sql)
            if 'is_called::text' in sql: return 'true|1'
            if 'SELECT (SELECT count(*)' in sql: return '0|92'
            return ''
        d.run_case([],execute,'delayed_insert',h)
        self.assertTrue(any('pg_sleep(5)' in sql for sql in calls))
        self.assertTrue(any('check_causal_session' in sql for sql in calls))
        self.assertTrue(any('check_violation' in sql for sql in calls))
        def no_entry(sql):
            if 'is_called::text' in sql: return 'false|1'
            return '0|92' if 'SELECT (SELECT count(*)' in sql else ''
        with self.assertRaisesRegex(AssertionError,'not entered'): d.run_case([],no_entry,'delayed_insert',h)
    def test_policy_changes_precede_duplicate_rejection(self):
        for case,kind in (('disabled_duplicate','disable'),('policy_drift_duplicate','cas')):
            calls=[]; changes=[]
            h={'_issue':lambda n:'ISSUE;', '_setup':lambda r:'ROLE '+r+';', '_policy_change':lambda k:(changes.append(k) or 'POLICY;')}
            def execute(sql):
                calls.append(sql); return '1|364' if 'SELECT (SELECT count(*)' in sql else ''
            d.run_case([],execute,case,h)
            self.assertEqual(changes,[kind])
            self.assertLess(next(i for i,x in enumerate(calls) if 'POLICY;' in x),next(i for i,x in enumerate(calls) if 'unexpected acceptance' in x))

    def test_unknown_case_is_refused(self):
        with self.assertRaises(ValueError): d.run_case([],lambda _:None,'other',{})

if __name__=='__main__': unittest.main()
