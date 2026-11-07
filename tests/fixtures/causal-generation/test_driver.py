"""Offline controls for the SQL-only owned generation driver."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('generation_driver',ROOT/'scripts/test-postgres-causal-generation.py')
driver=importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)

class Driver(unittest.TestCase):
    def test_complete_cases_use_distinct_exact_ledger_clones(self):
        calls=[]; cases=[]
        def execute(db,sql):
            calls.append((db,sql))
            if 'current_database()' in sql: return db+'|{'+','.join(map(str,range(1,23)))+'}|0|0'
            return ''
        def run(argv,callback,case,helper):
            cases.append(case); self.assertIn('generation_case_'+str(len(cases)-1),argv); callback('case sentinel')
        with mock.patch('builtins.print'): driver.qualify_cases('a'*64,execute,run,{})
        self.assertEqual(tuple(cases),driver.CASES)
        self.assertEqual(sum(sql.startswith('CREATE DATABASE') for _,sql in calls),9)
        self.assertEqual(sum(sql.startswith('DROP DATABASE') for _,sql in calls),9)
        for i in range(9): self.assertIn(('generation_case_'+str(i),'case sentinel'),calls)

    def test_failed_case_still_drops_clone_and_stops(self):
        calls=[]
        def execute(db,sql):
            calls.append((db,sql))
            if 'current_database()' in sql: return db+'|{'+','.join(map(str,range(1,23)))+'}|0|0'
            return ''
        def fail(*_): raise RuntimeError('controlled')
        with self.assertRaisesRegex(RuntimeError,'controlled'): driver.qualify_cases('a'*64,execute,fail,{})
        self.assertEqual(sum(sql.startswith('DROP DATABASE') for _,sql in calls),1)
        self.assertEqual(sum(sql.startswith('CREATE DATABASE') for _,sql in calls),1)

    def test_fresh_clone_rejects_wrong_ledger_or_existing_state(self):
        for value in ('wrong|{'+','.join(map(str,range(1,23)))+'}|0|0',
                      'generation_case_0|{'+','.join(map(str,range(1,22)))+'}|0|0',
                      'generation_case_0|{'+','.join(map(str,range(1,23)))+'}|0|1'):
            with self.assertRaises(AssertionError): driver.assert_fresh(lambda *_:value,'generation_case_0')
        for cid,db in [('bad','case'),('a'*64,'../bad')]:
            with self.assertRaises(ValueError): driver.psql_args(cid,db)

    def test_sources_detect_mutation_missing_unknown_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for name in driver.SOURCES:
                p=root/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(b'fixture')
            with mock.patch.object(driver,'ROOT',root):
                before=driver.source_snapshot(); target=root/'db/opt-in-migrations/0022_causal_generation.sql'
                target.write_bytes(b'changed'); self.assertNotEqual(before,driver.source_snapshot())
                target.unlink()
                with self.assertRaises(ValueError): driver.source_snapshot()
                target.write_bytes(b'fixture'); extra=target.parent/'0023_unknown.sql'; extra.write_bytes(b'x')
                with self.assertRaises(ValueError): driver.source_snapshot()
                extra.unlink(); target.unlink(); target.symlink_to(root/'outside')
                with self.assertRaises(ValueError): driver.source_snapshot()

    def test_main_failure_cleans_owned_container_and_rechecks_sources(self):
        cid='a'*64; seen=[]
        def command(args,input=None,timeout=30):
            seen.append(args)
            if args[1]=='create': return cid
            if args[1]=='exec': raise RuntimeError('controlled psql failure')
            return ''
        registry={'IMAGE':'pinned','verify_qualified_profile':lambda:None,
                  'cleanup_owned':mock.Mock(),'recover_owned_container':mock.Mock()}
        session={'_run':command}
        with mock.patch.object(driver.sys,'argv',['driver']), mock.patch.object(driver,'source_snapshot',return_value={'fixed':'hash'}) as snapshot, \
             mock.patch.object(driver,'helpers',return_value=(registry,session)), mock.patch.object(driver.signal,'signal',return_value=None), \
             mock.patch.object(driver.signal,'setitimer'), mock.patch.object(driver.subprocess,'run',return_value=SimpleNamespace(returncode=0)), \
             mock.patch.object(driver,'checked_source',return_value=b'fixture'):
            with self.assertRaisesRegex(RuntimeError,'controlled psql failure'): driver.main()
        self.assertEqual(snapshot.call_count,2)
        registry['cleanup_owned'].assert_called_once()
        self.assertEqual(registry['cleanup_owned'].call_args.args[1],cid)
        registry['recover_owned_container'].assert_not_called()

    def test_race_requires_serialization_conflict_and_single_charge(self):
        calls=[]; race=mock.Mock()
        helper={'_issue':lambda nonce:'ISSUE '+nonce+';', '_setup':lambda role:'ROLE '+role+';', 'race':race}
        def execute(sql):
            calls.append(sql)
            return '1|92' if 'SELECT (SELECT count(*)' in sql else ''
        driver.run_case(['psql'],execute,'race',helper)
        args=race.call_args
        self.assertEqual(args.kwargs['retry_sqlstate'],'23505')
        self.assertIn(driver.GEN,args.args[1]); self.assertIn(driver.OTHER,args.args[2])
        self.assertEqual(args.args[2],args.args[3])
        self.assertTrue(any('causal_generation_claims' in sql for sql in calls))

    def test_delayed_insert_requires_live_precondition_and_rollback_check(self):
        calls=[]
        helper={'_claim':lambda _: 'CLAIM(900000000,10,1024,1024,60)', '_issue':lambda _: '', '_setup':lambda role:'ROLE '+role+';'}
        def execute(sql):
            calls.append(sql)
            if 'is_called::text' in sql: return 'true|1'
            return '0|0' if 'SELECT (SELECT count(*)' in sql else ''
        driver.run_case([],execute,'delayed_insert',helper)
        self.assertIn('nextval(',calls[0]); self.assertIn('pg_sleep(3)',calls[0])
        self.assertIn('2000000,10,1024,1024,60)',calls[1])
        self.assertIn('check_causal_session',calls[2])
        self.assertIn('check_violation',calls[3])
        self.assertIn('is_called::text',calls[4])
        self.assertIn('causal_generation_claims',calls[5])
        for entry in ('false|1','true|2','false|0',''):
            def missing(sql):
                if 'is_called::text' in sql: return entry
                return '0|0' if 'SELECT (SELECT count(*)' in sql else ''
            with self.assertRaisesRegex(AssertionError,'trigger not entered'): driver.run_case([],missing,'delayed_insert',helper)

    def test_ambiguous_create_reconciles_by_owned_identity(self):
        registry={'IMAGE':'pinned','verify_qualified_profile':lambda:None,
                  'cleanup_owned':mock.Mock(),'recover_owned_container':mock.Mock(return_value=None)}
        def command(args,input=None,timeout=30):
            if args[1]=='create': raise TimeoutError('ambiguous')
            return ''
        with mock.patch.object(driver.sys,'argv',['driver']), mock.patch.object(driver,'source_snapshot',return_value={'fixed':'hash'}),              mock.patch.object(driver,'helpers',return_value=(registry,{'_run':command})),              mock.patch.object(driver.signal,'signal',return_value=None), mock.patch.object(driver.signal,'setitimer'):
            with self.assertRaises(TimeoutError): driver.main()
        registry['recover_owned_container'].assert_called_once()
        registry['cleanup_owned'].assert_not_called()

    def test_readiness_command_and_operation_timeouts_remain_bounded(self):
        source=(ROOT/'scripts/test-postgres-causal-generation.py').read_text()
        self.assertIn('signal.setitimer(signal.ITIMER_REAL,600)',source)
        self.assertIn('timeout=120',source)
        self.assertIn('timeout=5',source)
        self.assertEqual(len(driver.CASES),9)

if __name__=='__main__': unittest.main()
