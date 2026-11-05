import json
from pathlib import Path
import runpy
import tempfile
import subprocess
import unittest
from unittest import mock

MODULE = runpy.run_path(str(Path(__file__).resolve().parents[3]/'scripts/test-postgres-causal-inbox.py'))
G = MODULE['main'].__globals__


class InboxDriverTests(unittest.TestCase):
    def test_groups_and_races_use_separate_verified_clones(self):
        active=set(); clones=[]; seen=[]
        def execute(db, sql):
            if sql.startswith('CREATE DATABASE '):
                name=sql.split()[2]; self.assertFalse(active); active.add(name); clones.append(name); return ''
            if sql.startswith('DROP DATABASE IF EXISTS '):
                name=sql.split()[4].rstrip(';'); active.remove(name); return ''
            self.assertIn(db,active)
            if sql.startswith('SELECT current_database()'):
                return db+'|{'+','.join(map(str,range(1,21)))+'}|0|0|0'
            seen.append((db,sql)); return '123.45' if 'causal_inbox_history_work.sql' in sql else db
        def fresh_cases(fresh, n):
            for _ in range(n):
                argv, callback=fresh(); db=argv[-1]; self.assertIn(db,active); self.assertEqual(callback('marker'),db)
        session={'psql_args':lambda _cid,db:['psql','-d',db]}
        with mock.patch.dict(G, {'checked_source':lambda name:name.encode(),
             'run_session_races':lambda fresh:fresh_cases(fresh,16),
             'run_shared_quota_races':lambda fresh,_core:fresh_cases(fresh,2)}), mock.patch('builtins.print'):
            MODULE['qualify_cases']('a'*64,execute,session,Path('/unused'))
        self.assertEqual(len(clones),23)
        self.assertEqual(len(set(clones)),23)
        self.assertFalse(active)
        groups=[sql for _,sql in seen if sql!='marker']
        self.assertEqual(len(groups),5)
        self.assertIn('causal_inbox_stored_parse.sql',groups[1])
        self.assertIn('causal_inbox_history_work.sql',groups[4])

    def test_bad_clone_and_failed_case_drop_owned_clone(self):
        calls=[]
        def execute(db, sql):
            calls.append((db,sql))
            if sql.startswith('SELECT current_database()'): return 'wrong|{20}|0|0|0'
            return ''
        with self.assertRaisesRegex(AssertionError,'clone identity'):
            MODULE['qualify_cases']('a'*64,execute,{'psql_args':lambda *_:[]},Path('/unused'))
        self.assertTrue(any(sql.startswith('DROP DATABASE IF EXISTS inbox_case_1') for _,sql in calls))

    def test_guard_detects_changed_added_missing_and_symlink_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for name in MODULE['SOURCE_PATHS']:
                path=root/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(b'original')
            (root/'crates/core/src').mkdir(parents=True)
            code=root/'crates/core/src/lib.rs'; code.write_text('one')
            with mock.patch.dict(G,{'ROOT':root}):
                before=MODULE['source_snapshot']()
                code.write_text('two'); self.assertNotEqual(before,MODULE['source_snapshot']())
                code.write_text('one'); (root/'crates/core/new.rs').write_text('extra')
                self.assertNotEqual(before,MODULE['source_snapshot']())
                (root/'crates/core/new.rs').unlink()
                target=root/'db/tests/causal_inbox_basic.sql'; target.unlink()
                with self.assertRaisesRegex(ValueError,'missing'): MODULE['source_snapshot']()
                target.write_bytes(b'original')
                directory=root/'db/tests'; moved=root/'moved'; directory.rename(moved); directory.symlink_to(moved,target_is_directory=True)
                with self.assertRaisesRegex(ValueError,'symlink'): MODULE['source_snapshot']()

    def test_extra_migration_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for name in MODULE['SOURCE_PATHS']:
                path=root/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(b'x')
            (root/'db/migrations/9999_extra.sql').write_text('x')
            with mock.patch.dict(G,{'ROOT':root}):
                with self.assertRaisesRegex(ValueError,'source list changed'): MODULE['source_snapshot']()

    def test_build_uses_locked_offline_and_uses_cargo_artifact_path(self):
        with tempfile.TemporaryDirectory() as temp:
            executable=Path(temp)/'custom-target'/'example'; executable.parent.mkdir(); executable.write_text('x')
            calls=[]
            def run(args,**kw):
                calls.append((args,kw)); return json.dumps({'reason':'compiler-artifact','target':{'name':'fixture_v2_canonical'},'executable':str(executable)})
            self.assertEqual(MODULE['build_core'](run),executable)
            self.assertIn('--locked',calls[0][0]); self.assertIn('--offline',calls[0][0])
            self.assertEqual(calls[0][1]['timeout'],300)
            executable.unlink()
            with self.assertRaisesRegex(RuntimeError,'unavailable'): MODULE['build_core'](run)
            with self.assertRaisesRegex(RuntimeError,'invalid Core'): MODULE['build_core'](lambda *_a,**_kw:'not json')

    def test_cleanup_runs_after_failed_create_or_source_change(self):
        cid='a'*64; cleaned=[]
        registry={'verify_qualified_profile':lambda:None,'IMAGE':'pinned',
                  'recover_owned_container':lambda *_:cid,'cleanup_owned':lambda _run,c,*_:cleaned.append(c)}
        def run(args,**_):
            if args[1]=='create': return 'bad-id'
            return ''
        session={'_run':run}
        with mock.patch.dict(G,{'source_snapshot':lambda:{},'verify_vector_sync':lambda:None,'helpers':lambda:(registry,session),'build_core':lambda _run:Path('/unused')}), mock.patch('sys.argv',['driver']):
            with self.assertRaisesRegex(RuntimeError,'invalid container identity'): MODULE['main']()
        self.assertEqual(cleaned,[cid])
        cleaned.clear(); snapshots=iter([{'x':'one'},{'x':'two'}])
        with mock.patch.dict(G,{'source_snapshot':lambda:next(snapshots),'verify_vector_sync':lambda:None,'helpers':lambda:(registry,session),'build_core':lambda _run:Path('/unused')}), mock.patch('sys.argv',['driver']):
            with self.assertRaisesRegex(RuntimeError,'source changed'): MODULE['main']()
        self.assertEqual(cleaned,[cid])

    def test_failure_output_redacts_raw_error_and_preserves_sqlstate(self):
        class Diagnostic(Exception):
            sqlstate='23514'
            category='command failure'
        error=Diagnostic('SECRET SQL AND SERVER DATA')
        message=MODULE['safe_failure'](error)
        self.assertIn('23514',message)
        self.assertIn('command failure',message)
        self.assertNotIn('SECRET',message)
        error.sqlstate='UNSAFE SECRET'; error.category='SECRET'
        self.assertNotIn('SECRET',MODULE['safe_failure'](error))

    def test_final_postgres_pid_required_before_bootstrap(self):
        cid='a'*64; state={'pid':'entrypoint','probes':0}; cleaned=[]
        class BootstrapReached(Exception): pass
        def run(args,**_):
            if args[1]=='create': return cid
            if args[1]=='exec':
                self.assertEqual(state['pid'],'postgres'); raise BootstrapReached()
            return ''
        def probe(args,**_):
            shell=args[-1]
            self.assertIn('cat /proc/1/comm',shell); self.assertIn('pg_isready',shell)
            status=0 if state['pid']=='postgres' else 1
            state['probes']+=1; state['pid']='postgres'
            return subprocess.CompletedProcess(args,status,b'',b'')
        registry={'verify_qualified_profile':lambda:None,'IMAGE':'pinned',
                  'recover_owned_container':lambda *_:self.fail('unexpected recovery'),
                  'cleanup_owned':lambda _run,c,*_:cleaned.append(c)}
        session={'_run':run,'psql_args':lambda c,d:['docker','exec',c,d]}
        with mock.patch.dict(G,{'source_snapshot':lambda:{},'verify_vector_sync':lambda:None,'helpers':lambda:(registry,session),'build_core':lambda _run:Path('/unused'),'checked_source':lambda _name:b'bootstrap'}), mock.patch.object(G['subprocess'],'run',side_effect=probe), mock.patch.object(G['time'],'sleep'), mock.patch('sys.argv',['driver']):
            with self.assertRaises(BootstrapReached): MODULE['main']()
        self.assertEqual(state['probes'],2)
        self.assertEqual(cleaned,[cid])

    def test_skipped_race_phase_cannot_be_reported_as_pass(self):
        active=set()
        def execute(db,sql):
            if sql.startswith('CREATE DATABASE '): active.add(sql.split()[2]); return ''
            if sql.startswith('DROP DATABASE IF EXISTS '): active.remove(sql.split()[4].rstrip(';')); return ''
            if sql.startswith('SELECT current_database()'): return db+'|{'+','.join(map(str,range(1,21)))+'}|0|0|0'
            return '123'
        with mock.patch.dict(G,{'checked_source':lambda _name:b'x','run_session_races':lambda _fresh:None}), mock.patch('builtins.print'):
            with self.assertRaisesRegex(RuntimeError,'incomplete session races'):
                MODULE['qualify_cases']('a'*64,execute,{'psql_args':lambda *_:[]},Path('/unused'))
        self.assertFalse(active)

    def test_checked_vectors_match_normative_fixture(self):
        MODULE['verify_vector_sync']()
        original=G['checked_source']
        def changed(name):
            return b'not the generated vectors' if name.endswith('causal_inbox_vectors.sql') else original(name)
        with mock.patch.dict(G,{'checked_source':changed}):
            with self.assertRaisesRegex(ValueError,'differs'): MODULE['verify_vector_sync']()

    def test_both_core_encodings_have_timeouts_and_timeout_cannot_pass(self):
        class ReachedFixture(Exception): pass
        def fresh(): raise ReachedFixture()
        for fail_at in (None,1,2):
            calls=[]
            def run(args,**kwargs):
                calls.append(kwargs)
                self.assertEqual(kwargs['timeout'],15)
                if len(calls)==fail_at:
                    raise subprocess.TimeoutExpired(args,kwargs['timeout'])
                body=json.loads(kwargs['input'])
                payload=json.dumps({'canonical_hex':json.dumps(body).encode().hex(),'digest':'a'*64}).encode()
                return subprocess.CompletedProcess(args,0,payload,b'')
            with mock.patch.object(G['subprocess'],'run',side_effect=run):
                if fail_at is None:
                    with self.assertRaises(ReachedFixture): MODULE['run_shared_quota_races'](fresh,Path('/fixture'))
                    self.assertEqual(len(calls),2)
                else:
                    with self.assertRaises(subprocess.TimeoutExpired): MODULE['run_shared_quota_races'](fresh,Path('/fixture'))
                    self.assertEqual(len(calls),fail_at)
                    self.assertNotIn('PASS',MODULE['safe_failure'](subprocess.TimeoutExpired(['SECRET'],15)))

    def test_inspection_recovery_accepts_only_exact_known_absence(self):
        name='owned-inbox-123'
        def response(stderr):
            return subprocess.CompletedProcess(['docker'],1,'',stderr)
        for text in ('Error: No such object: '+name+'\n','error: no such object: '+name+'\n',
                     'error: no such object: '+name):
            with mock.patch.object(G['subprocess'],'run',return_value=response(text)):
                self.assertIsNone(MODULE['inspect_owned_name'](name))
        for text in ('error: no such object: '+name+'-other\n',
                     'error: no such object: '+name+'\nextra\n',
                     'error: no such object: '+name+' \n',
                     'Cannot connect to the Docker daemon',
                     'error: no such object: different\n'):
            with mock.patch.object(G['subprocess'],'run',return_value=response(text)):
                with self.assertRaisesRegex(RuntimeError,'inspection failed'):
                    MODULE['inspect_owned_name'](name)
        with mock.patch.object(G['subprocess'],'run',return_value=subprocess.CompletedProcess(['docker'],0,'[{"Id":"abc"}]','')):
            self.assertEqual(MODULE['inspect_owned_name'](name),[{'Id':'abc'}])

    def test_seed_probe_rejects_contamination(self):
        for probe in ('seed|{1,20}|0|0|0','seed|{'+','.join(map(str,range(1,21)))+'}|0|1|0'):
            with self.assertRaisesRegex(AssertionError,'clone identity'):
                MODULE['assert_fresh'](lambda *_:probe,'seed')

    def test_only_explicit_flag_emits_vectors(self):
        with mock.patch.dict(G,{'emit_vectors':lambda:None,'source_snapshot':mock.Mock(side_effect=AssertionError('should not run'))}), mock.patch('sys.argv',['driver','--emit-vectors']):
            MODULE['main']()
        with mock.patch('sys.argv',['driver','--unknown']):
            with self.assertRaises(ValueError): MODULE['main']()


if __name__ == '__main__':
    unittest.main()
