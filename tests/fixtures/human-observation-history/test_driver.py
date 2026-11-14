"""Offline guard checks; no PostgreSQL or HTTP execution."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('observation_history_fixture',ROOT/'scripts/test-human-observation-history.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class DriverTests(unittest.TestCase):
    def test_historical_profile_requires_exact_ledger_and_closed_migrations(self):
        import runpy
        fixture=runpy.run_path(str(ROOT/'scripts/test-human-origin.py'))
        before='{'+','.join(map(str,range(1,18)))+'}'
        after='{'+','.join(map(str,range(1,26)))+'}'
        calls=[]
        def execute(sql):
            calls.append(sql)
            if sql.startswith('SELECT array_agg'): return before if len(calls)==1 else after
        fixture['apply_historical_profile'](execute)
        self.assertEqual(len(calls),10)
        for sql,name in zip(calls[1:-1],fixture['HISTORICAL_MIGRATIONS']):
            self.assertEqual(sql,(ROOT/'db/opt-in-migrations'/(name+'.sql')).read_text())
        bad=mock.Mock(return_value='{1,2}')
        with self.assertRaises(RuntimeError): fixture['apply_historical_profile'](bad)
        bad.assert_called_once()
        bad_after=mock.Mock(side_effect=[before]+[None]*8+['{1,2}'])
        with self.assertRaises(RuntimeError): fixture['apply_historical_profile'](bad_after)
    def test_historical_mode_cannot_be_inherited(self):
        import os,runpy
        environment=runpy.run_path(str(ROOT/'scripts/test-postgres-tls.py'))['fixture_environment']
        with mock.patch.dict(os.environ,{'CONTOUR_HISTORICAL_ORIGIN_FIXTURE':'1'}):
            self.assertNotIn('CONTOUR_HISTORICAL_ORIGIN_FIXTURE',environment('synthetic','/unused'))

    def test_observer_mode_cannot_be_inherited(self):
        import os,runpy
        environment=runpy.run_path(str(ROOT/'scripts/test-postgres-tls.py'))['fixture_environment']
        with mock.patch.dict(os.environ,{'CONTOUR_CAUSAL_OBSERVER_FIXTURE':'1'}):
            self.assertNotIn('CONTOUR_CAUSAL_OBSERVER_FIXTURE',environment('synthetic','/unused'))

    def test_invalid_scope_never_queries_or_launches(self):
        execute=mock.Mock()
        with mock.patch.object(module,'_runner') as run:
            with self.assertRaises(ValueError):module.run_cases(execute,'config','other','environment','normal','unknown',['bad']*4,'bad','target',{})
            execute.assert_not_called();run.assert_not_called()
    def test_unexpected_route_never_launches(self):
        with mock.patch.object(module,'_runner') as run:
            with self.assertRaises(ValueError):module._get('probe','config','token','/other',{})
            run.assert_not_called()
    def test_probe_errors_or_unbounded_output_are_never_success(self):
        for result in (mock.Mock(returncode=1,stderr=b'',stdout=b'{}'),mock.Mock(returncode=0,stderr=b'failure',stdout=b'{}')):
            with mock.patch.object(module,'_runner',return_value=mock.Mock(return_value=result)):
                with self.assertRaises(RuntimeError):module._get('probe','config','token','/v1/observations?operation_id=x',{})
class OwnershipTests(unittest.TestCase):
    def test_historical_receipt_requires_exact_owned_regular_file(self):
        import os, runpy, tempfile
        require=runpy.run_path(str(ROOT/'scripts/test-postgres-submit.py'))['require_historical_receipt']
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory); path=folder/'historical-origin.done'
            with self.assertRaises(OSError): require(folder)
            path.write_bytes(b'wrong')
            with self.assertRaises(AssertionError): require(folder)
            path.write_bytes(b'historical-origin-complete\n'); require(folder)
            alias=folder/'alias'; os.link(path,alias)
            with self.assertRaises(AssertionError): require(folder)
            alias.unlink(); path.unlink(); path.symlink_to(alias)
            with self.assertRaises(OSError): require(folder)
    def test_observer_receipt_requires_exact_owned_regular_file(self):
        import os, runpy, tempfile
        require=runpy.run_path(str(ROOT/'scripts/test-postgres-submit.py'))['require_causal_observer_receipt']
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory); path=folder/'causal-observer.done'
            with self.assertRaises(OSError): require(folder)
            path.write_bytes(b'wrong')
            with self.assertRaises(AssertionError): require(folder)
            path.write_bytes(b'causal-observer-complete\n'); require(folder)
            alias=folder/'alias'; os.link(path,alias)
            with self.assertRaises(AssertionError): require(folder)
            alias.unlink(); path.unlink(); path.symlink_to(alias)
            with self.assertRaises(OSError): require(folder)

    def test_receipt_is_mandatory_and_exact(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'human-observation-history.done'
            with self.assertRaises(OSError): module.require_receipt(directory)
            path.write_bytes(b'wrong')
            with self.assertRaises(ValueError): module.require_receipt(directory)
            path.write_bytes(b'history-fixture-complete\n'); module.require_receipt(directory)
    def test_foreign_container_blocks_all_cleanup(self):
        import json
        calls=[]
        def run(args):
            calls.append(args)
            return json.dumps([{'Id':'foreign'}])
        with self.assertRaises(ValueError): module.cleanup_resources(run,'container','volume','network','owner','image','name','ref','started')
        self.assertEqual(calls,[['docker','inspect','container']])
    def test_unknown_fixture_is_retained(self):
        import shutil
        fixture=module.OwnedFixtureDirectory()
        try:
            with self.assertRaisesRegex(RuntimeError,'unknown'):
                with fixture as folder:
                    fixture.intent('network',{'owner':'test'})
                    raise RuntimeError('unknown')
            self.assertTrue((Path(folder)/'network.intent').is_file())
        finally: shutil.rmtree(fixture.path)

class ProvenanceTests(unittest.TestCase):
    def test_growing_artifact_stream_is_bounded(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder).resolve(); example=target/'debug/examples/example'; example.parent.mkdir(parents=True)
            example.write_bytes(b'x'); example.chmod(0o700)
            with mock.patch('os.read',return_value=b'x'*1_048_576) as read:
                with self.assertRaisesRegex(ValueError,'hash limit'): module.artifact_identity(example,target)
                self.assertEqual(read.call_count,954)
    def test_changed_or_unselected_artifact_rejected_before_launch(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder).resolve(); example=target/'debug/examples/example'; example.parent.mkdir(parents=True)
            example.write_bytes(b'first'); example.chmod(0o700)
            guard=module.artifact_guard(target,{'example':module.artifact_identity(example,target)})
            guard('subprocess.Popen',(str(example),))
            example.write_bytes(b'other')
            with self.assertRaises(ValueError): guard('subprocess.Popen',(str(example),))
            with self.assertRaises(ValueError): guard('subprocess.Popen',(str(example.parent/'foreign'),))
    def test_container_restart_or_network_drift_blocks_cleanup(self):
        import json
        cid='c'*64; nid='n'*64; vol='volume'; owner='owner'
        base={'Id':cid,'Image':'image','Config':{'Image':'ref','Labels':{'org.apicontour.fixture-owner':owner}},'HostConfig':{'Init':True},'Mounts':[{'Destination':'/var/lib/postgresql/data','Name':vol}],'State':{'StartedAt':'first'},'NetworkSettings':{'Networks':{'fixture':{'NetworkID':nid}}}}
        for state,network in [('second',nid),('first','other')]:
            obj=dict(base,State={'StartedAt':state},NetworkSettings={'Networks':{'fixture':{'NetworkID':network}}}); calls=[]
            def run(args): calls.append(args); return json.dumps([obj])
            with self.assertRaises(ValueError): module.cleanup_resources(run,cid,vol,nid,owner,'image','name','ref','first')
            self.assertEqual(len(calls),1)
    def test_dirty_source_rejected_before_history_code_executes(self):
        tls_spec=importlib.util.spec_from_file_location('history_tls',ROOT/'scripts/test-postgres-tls.py')
        tls=importlib.util.module_from_spec(tls_spec);tls_spec.loader.exec_module(tls)
        with mock.patch.object(tls,'bounded_git',return_value=b'dirty'),mock.patch('builtins.exec') as execute:
            with self.assertRaises(ValueError): tls.checked_history_loader()
            execute.assert_not_called()

class CargoSelectionTests(unittest.TestCase):
    def test_exact_package_target_and_executable_required(self):
        import tempfile,json
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder).resolve(); executable=target/'debug/examples/probe'; executable.parent.mkdir(parents=True); executable.write_bytes(b'content'); executable.chmod(0o700)
            event={'reason':'compiler-artifact','target':{'kind':['example'],'name':'probe'},'package_id':'package-exact','executable':str(executable)}
            self.assertEqual(set(module.select_artifacts(json.dumps(event),['probe'],'package-exact',target)),{'probe'})
            for change in ({'package_id':'foreign'},{'executable':str(executable)+'-foreign'}):
                with self.assertRaises(ValueError): module.select_artifacts(json.dumps(dict(event,**change)),['probe'],'package-exact',target)
            with self.assertRaises(ValueError): module.select_artifacts('', ['probe'],'package-exact',target)

if __name__=='__main__':unittest.main()
