import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest import mock

MODULE = runpy.run_path(str(Path(__file__).resolve().parents[3]/'scripts/test-postgres-causal-sessions.py'))
G = MODULE['main'].__globals__


class SessionDriverTests(unittest.TestCase):
    def test_all_cases_use_fresh_verified_clone_and_matching_callbacks(self):
        active = set()
        runs = []
        clones = []
        cid = 'a'*64
        def execute(database,sql):
            if sql.startswith('CREATE DATABASE '):
                self.assertEqual(database,'postgres')
                name=sql.split()[2]
                self.assertNotIn(name,clones)
                self.assertFalse(active)
                clones.append(name); active.add(name)
                self.assertTrue(sql.endswith(' TEMPLATE contour_local;'))
                return ''
            if sql.startswith('DROP DATABASE '):
                self.assertEqual(database,'postgres')
                active.remove(sql.split()[2].rstrip(';'))
                return ''
            self.assertIn(database,active)
            if sql.startswith('SELECT current_database()'):
                return database+'|{'+','.join(str(x) for x in range(1,20))+'}|0'
            runs.append(('fixture',database,sql))
            return database
        def run_case(argv,callback,name):
            db=argv[argv.index('-d')+1]
            self.assertIn(db,active)
            self.assertEqual(callback('marker'),db)
            runs.append(('race',db,name))
        with mock.patch.dict(G,{'checked_source':lambda name: name.encode()}), mock.patch('builtins.print'):
            result=MODULE['qualify_cases'](cid,execute,run_case)
        self.assertEqual(len(clones),18)
        self.assertEqual(result,('basic','clock')+MODULE['SCENARIOS'])
        self.assertEqual([x[2] for x in runs if x[0]=='race'],list(MODULE['SCENARIOS']))
        self.assertEqual(len([x for x in runs if x[0]=='fixture' and x[2]!='marker']),2)
        self.assertFalse(active)

    def test_missing_or_duplicate_scenario_fails_closed(self):
        with mock.patch.dict(G,{'SCENARIOS':MODULE['SCENARIOS'][:-1]}):
            with self.assertRaisesRegex(RuntimeError,'invalid qualification case list'):
                MODULE['qualify_cases']('a'*64,lambda *_:None,lambda *_:None)
        with mock.patch.dict(G,{'SCENARIOS':MODULE['SCENARIOS'][:-1]+(MODULE['SCENARIOS'][0],)}):
            with self.assertRaisesRegex(RuntimeError,'invalid qualification case list'):
                MODULE['qualify_cases']('a'*64,lambda *_:None,lambda *_:None)

    def test_wrong_clone_or_initial_state_fails_before_case(self):
        seen=[]
        def execute(db,sql):
            if sql.startswith('CREATE DATABASE'): return ''
            return 'wrong|{1}|0'
        with self.assertRaisesRegex(AssertionError,'clone identity'):
            MODULE['qualify_cases']('a'*64,execute,lambda *a: seen.append(a))
        self.assertFalse(seen)

    def test_scenario_failure_is_not_a_pass(self):
        def execute(db,sql):
            if sql.startswith(('CREATE DATABASE','DROP DATABASE')): return ''
            if sql.startswith('SELECT current_database()'):
                return db+'|{'+','.join(str(x) for x in range(1,20))+'}|0'
            return ''
        def fail(*_): raise RuntimeError('scenario failed')
        with mock.patch.dict(G,{'checked_source':lambda _name:b'fixture'}), mock.patch('builtins.print'):
            with self.assertRaisesRegex(RuntimeError,'scenario failed'):
                MODULE['qualify_cases']('a'*64,execute,fail)

    def test_source_snapshot_detects_missing_changed_and_symlink_ancestor(self):
        with tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve())) as temp:
            root=Path(temp)/'repo'; root.mkdir()
            for name in MODULE['SOURCE_PATHS']:
                path=root/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(b'original')
            with mock.patch.dict(G,{'ROOT':root}):
                before=MODULE['source_snapshot']()
                target=root/'db/tests/causal_session_basic.sql'
                target.write_bytes(b'changed')
                self.assertNotEqual(before,MODULE['source_snapshot']())
                target.unlink()
                with self.assertRaisesRegex(ValueError,'missing'): MODULE['source_snapshot']()
                target.write_bytes(b'original')
                tests_dir=root/'db/tests'; moved=root/'moved'; tests_dir.rename(moved); tests_dir.symlink_to(moved,target_is_directory=True)
                with self.assertRaisesRegex(ValueError,'symlink'): MODULE['source_snapshot']()

    def test_temporary_ready_server_cannot_start_bootstrap(self):
        cid='a'*64; stage={'pid':'entrypoint','ready':True,'probes':0,'bootstrap':None}; cleaned=[]
        class BootstrapReached(Exception): pass
        def command(args,**kwargs):
            if args[1]=='create': return cid
            if args[1]=='exec':
                stage['bootstrap']=stage['pid']
                raise BootstrapReached()
            return ''
        def probe(args,**kwargs):
            # Simulate the temporary initialization server answering pg_isready.
            # Only a probe that also checks PID 1 can reject it. The second
            # observation is the final postgres process and remains ready.
            self.assertTrue(stage['ready'])
            shell=args[-1] if len(args)>4 and args[3:5]==['sh','-c'] else ''
            requires_final=('cat /proc/1/comm' in shell and '= postgres' in shell and 'pg_isready' in shell)
            status=0 if stage['pid']=='postgres' or not requires_final else 1
            stage['probes']+=1
            if stage['probes']==1: stage['pid']='postgres'
            return subprocess.CompletedProcess(args,status,b'',b'')
        registry={'verify_qualified_profile':lambda:None,'IMAGE':'pinned',
                  'cleanup_owned':lambda runner,c,n,r:cleaned.append(c),
                  'recover_owned_container':lambda *_:self.fail('unexpected recovery')}
        with mock.patch.dict(G,{'source_snapshot':lambda:{},'registry_helpers':lambda:registry,'_run':command,'checked_source':lambda _name:b'bootstrap'}), \
             mock.patch.object(G['subprocess'],'run',side_effect=probe), mock.patch.object(G['time'],'sleep'), mock.patch('sys.argv',['driver']):
            with self.assertRaises(BootstrapReached): MODULE['main']()
        self.assertEqual(stage['probes'],2)
        self.assertEqual(stage['bootstrap'],'postgres')
        self.assertEqual(cleaned,[cid])

    def test_connection_diagnostics_are_bounded_and_redacted(self):
        diagnose=MODULE['connection_diagnostic']
        secret='SECRET_DATABASE_PASSWORD_SHOULD_NOT_APPEAR'
        samples=[('psql: error: connection failed: FATAL: 3D000: database "'+secret+'" does not exist','database unavailable','3D000'),
                 ('psql: error: connection failed: FATAL: the database system is starting up '+secret,'server starting',None),
                 ('psql: error: connection to server failed: No such file or directory '+secret,'connection socket unavailable',None),
                 ('psql: error: connection failed: Connection refused '+secret,'connection refused',None),
                 ('unrecognized '+secret,'command failure',None)]
        for stderr,category,code in samples:
            error=diagnose(stderr)
            self.assertEqual((error.category,error.sqlstate),(category,code))
            self.assertNotIn(secret,str(error))
            self.assertNotIn(secret,repr(error.__dict__))
            self.assertLess(len(str(error)),120)

    def test_run_raises_sanitized_connection_error(self):
        secret='SECRET_PRIVATE_FIXTURE_TEXT'
        result=subprocess.CompletedProcess(['psql'],2,'','psql: error: connection failed: FATAL: database "'+secret+'" does not exist')
        with mock.patch.object(G['subprocess'],'run',return_value=result):
            with self.assertRaises(MODULE['FixtureCommandError']) as caught:
                MODULE['_run'](['psql'],input='SQL '+secret)
        self.assertEqual(caught.exception.category,'database unavailable')
        self.assertNotIn(secret,str(caught.exception))
        self.assertNotIn(secret,repr(caught.exception.__dict__))

    def test_main_failure_runs_owned_cleanup(self):
        calls=[]; cid='a'*64
        def run(args,**_):
            calls.append(args)
            if args[1]=='create': return cid
            if args[1]=='start': raise RuntimeError('start failed')
            return ''
        registry={'verify_qualified_profile':lambda:None,'IMAGE':'pinned',
                  'cleanup_owned':lambda runner,c,n,r: calls.append(('clean',c,n,r)),
                  'recover_owned_container':lambda *_: self.fail('unexpected recovery')}
        with mock.patch.dict(G,{'source_snapshot':lambda:{},'registry_helpers':lambda:registry,'_run':run}), mock.patch('sys.argv',['driver']):
            with self.assertRaisesRegex(RuntimeError,'start failed'): MODULE['main']()
        self.assertTrue(any(c[0]=='clean' and c[1]==cid for c in calls))

    def test_source_change_during_run_fails_after_cleanup(self):
        calls=[]; cid='e'*64; snapshots=iter([{'source':'before'},{'source':'after'}])
        def run(args,**_):
            if args[1]=='create': return cid
            if args[1]=='start': raise RuntimeError('start failed')
            return ''
        registry={'verify_qualified_profile':lambda:None,'IMAGE':'pinned',
                  'cleanup_owned':lambda runner,c,n,r: calls.append(c),
                  'recover_owned_container':lambda *_:None}
        with mock.patch.dict(G,{'source_snapshot':lambda:next(snapshots),'registry_helpers':lambda:registry,'_run':run}), mock.patch('sys.argv',['driver']):
            with self.assertRaisesRegex(RuntimeError,'source changed'): MODULE['main']()
        self.assertEqual(calls,[cid])

    def test_malformed_create_recovers_before_cleanup(self):
        calls=[]; cid='b'*64
        def run(args,**_):
            if args[1]=='create': return 'truncated'
            return ''
        registry={'verify_qualified_profile':lambda:None,'IMAGE':'pinned',
                  'cleanup_owned':lambda runner,c,n,r: calls.append(('clean',c)),
                  'recover_owned_container':lambda inspect,n,r: cid}
        with mock.patch.dict(G,{'source_snapshot':lambda:{},'registry_helpers':lambda:registry,'_run':run}), mock.patch('sys.argv',['driver']):
            with self.assertRaisesRegex(RuntimeError,'invalid container identity'): MODULE['main']()
        self.assertEqual(calls,[('clean',cid)])

    def test_create_timeout_recovers_owned_container(self):
        calls=[]; cid='c'*64
        def run(args,**_):
            if args[1]=='create': raise subprocess.TimeoutExpired(args,30)
            return ''
        registry={'verify_qualified_profile':lambda:None,'IMAGE':'pinned',
                  'cleanup_owned':lambda runner,c,n,r: calls.append(('clean',c)),
                  'recover_owned_container':lambda inspect,n,r: cid}
        with mock.patch.dict(G,{'source_snapshot':lambda:{},'registry_helpers':lambda:registry,'_run':run}), mock.patch('sys.argv',['driver']):
            with self.assertRaises(subprocess.TimeoutExpired): MODULE['main']()
        self.assertEqual(calls,[('clean',cid)])

    def test_cleanup_error_cannot_report_success(self):
        cid='d'*64
        def run(args,**_):
            if args[1]=='create': return cid
            if args[1]=='start': raise RuntimeError('start failed')
            return ''
        def cleanup(*_): raise RuntimeError('cleanup failed')
        registry={'verify_qualified_profile':lambda:None,'IMAGE':'pinned',
                  'cleanup_owned':cleanup,'recover_owned_container':lambda *_:None}
        with mock.patch.dict(G,{'source_snapshot':lambda:{},'registry_helpers':lambda:registry,'_run':run}), mock.patch('sys.argv',['driver']):
            with self.assertRaisesRegex(RuntimeError,'cleanup failed'): MODULE['main']()

    def test_recovery_requires_matching_identity_and_explicit_absence(self):
        recover=MODULE['registry_helpers']()['recover_owned_container']; cid='a'*64
        self.assertIsNone(recover(lambda _name:None,'owned','id'))
        with self.assertRaises(RuntimeError):
            recover(lambda name:[{'Id':cid,'Name':'/'+name,'Config':{'Labels':{'org.apicontour.registry-run':'foreign'}}}],'owned','id')
        with self.assertRaises(RuntimeError):
            recover(lambda _name: (_ for _ in ()).throw(RuntimeError('inspect failed')),'owned','id')

    def test_seed_validation_rejects_nonzero_rows_or_wrong_ledger(self):
        for bad in ('contour_local|{1,2}|0','contour_local|{'+','.join(str(x) for x in range(1,20))+'}|1'):
            with self.assertRaisesRegex(AssertionError,'clone identity'):
                MODULE['assert_fresh'](lambda _db,_sql:bad,'contour_local')

    def test_registry_cleanup_rejects_foreign_container(self):
        reg=MODULE['registry_helpers'](); calls=[]
        def fake(args):
            calls.append(args)
            return json.dumps([{'Id':'b'*64,'Name':'/foreign','Config':{'Labels':{}}}])
        with self.assertRaises(RuntimeError): reg['cleanup_owned'](fake,'a'*64,'expected','id')
        self.assertEqual(len(calls),1)

    def test_unexpected_source_file_fails_closed(self):
        with tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve())) as temp:
            root=Path(temp)
            for name in MODULE['SOURCE_PATHS']:
                path=root/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(b'x')
            (root/'db/migrations/9999_extra.sql').write_text('unexpected')
            with mock.patch.dict(G,{'ROOT':root}):
                with self.assertRaisesRegex(ValueError,'source list changed'): MODULE['source_snapshot']()


if __name__ == '__main__':
    unittest.main()
