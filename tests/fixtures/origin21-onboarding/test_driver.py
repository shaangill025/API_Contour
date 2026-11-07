"""Offline checks for the origin21 qualification driver and deployment factory."""
import tempfile
import copy
import hashlib
import importlib.util
import json
import os
import array
import socket
import threading
import unittest
from unittest import mock
from pathlib import Path
from deploy.local import origin21_products, origin21_sql_runner

spec=importlib.util.spec_from_file_location('origin21_qualification',Path(__file__).resolve().parents[3]/'scripts/test-origin21-onboarding.py')
driver=importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)


class ReadinessTests(unittest.TestCase):
    def test_temporary_acceptance_does_not_count_as_final(self):
        from types import SimpleNamespace
        def run(args,**kwargs):
            text=' '.join(args)
            # A temporary Unix-socket postmaster answers pg_isready but reports
            # listen_addresses empty to the final-server identity query.
            return SimpleNamespace(returncode=0,stdout=b'f\n' if 'current_setting' in text else b'accepting connections\n',stderr=b'')
        self.assertFalse(driver.postgres_ready(run,'a'*64))

    def test_final_server_requires_exact_success_and_bounded_process(self):
        from types import SimpleNamespace
        seen=[]
        def run(args,**kwargs):
            seen.append((args,kwargs)); return SimpleNamespace(returncode=0,stdout=b't\n',stderr=b'')
        self.assertTrue(driver.postgres_ready(run,'a'*64))
        text=seen[0][0][-1]
        for part in ('docker-init','postmaster.pid','pg_isready','current_database()',"current_setting('listen_addresses')","current_setting('ssl')"):
            self.assertIn(part,text)
        self.assertEqual(seen[0][1]['timeout'],5)
        for response in (SimpleNamespace(returncode=1,stdout=b't\n',stderr=b''),SimpleNamespace(returncode=0,stdout=b't',stderr=b''),SimpleNamespace(returncode=0,stdout=b't\nextra\n',stderr=b''),SimpleNamespace(returncode=0,stdout=b't\n',stderr=b'warning')):
            self.assertFalse(driver.postgres_ready(lambda *a,**k:response,'a'*64))
        for error in (TimeoutError('timeout'),RuntimeError('failure')):
            self.assertFalse(driver.postgres_ready(mock.Mock(side_effect=error),'a'*64))


class FactoryTests(unittest.TestCase):
    def test_full_preflight_refuses_existing_complete_artifact_roots_without_mutation(self):
        from deploy.local import origin21_profile,origin21_configs
        from deploy.pilot import origin_credentials
        for kind in ('profile','products'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve(); (root/'.git').write_text('gitdir: synthetic\n'); state=root/'.local-mvp'; state.mkdir(mode=0o700)
                profile=state/'origin21-pilot'; products=state/'origin21-products'
                if kind=='profile':
                    profile.mkdir(mode=0o700)
                    names=origin_credentials._expected() | set(origin21_configs.expected()) | {'setup.lock','setup.json','operator-evidence.json','capture/private/observer-policy.json'}
                    for name in sorted(names,key=len):
                        path=profile/name
                        if name.endswith('/'): path.mkdir(parents=True,exist_ok=True,mode=0o700)
                        else:
                            path.parent.mkdir(parents=True,exist_ok=True,mode=0o700); path.write_bytes(b'synthetic'); path.chmod(0o600)
                    before={str(path.relative_to(profile)):(path.read_bytes(),path.stat().st_ino,path.stat().st_mode) for path in profile.rglob('*') if path.is_file()}
                else:
                    products.mkdir(mode=0o700)
                    for name in ('intent.json','products.json','commitments.json','companions-intent.json','companions.json','products-model.json','companions-model.json'):
                        path=products/name; path.write_bytes(b'synthetic'); path.chmod(0o600)
                    before={path.name:(path.read_bytes(),path.stat().st_ino,path.stat().st_mode) for path in products.iterdir()}
                selected=origin21_profile.PROFILE._replace(state=profile)
                with mock.patch.object(driver,'ROOT',root), mock.patch.object(origin21_profile,'PROFILE',selected), mock.patch.object(origin21_products,'OWNER',products), mock.patch.object(driver.runpy,'run_path') as helper, mock.patch.object(origin21_products,'start_products') as start:
                    with self.assertRaisesRegex(ValueError,'artifact root already exists'): driver.main(['--full-capture','/unused','0'*64])
                    helper.assert_not_called(); start.assert_not_called()
                after={str(path.relative_to(profile)):(path.read_bytes(),path.stat().st_ino,path.stat().st_mode) for path in profile.rglob('*') if path.is_file()} if kind=='profile' else {path.name:(path.read_bytes(),path.stat().st_ino,path.stat().st_mode) for path in products.iterdir()}
                self.assertEqual(before,after); self.assertFalse((state/'ca.crt').exists()); self.assertFalse((state/'ca.key').exists())

    def test_racing_profile_root_is_never_adopted_or_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory).resolve(); folder=parent/('contour-origin21-qual-'+'a'*32); folder.mkdir(mode=0o700); profile=parent/'origin21-pilot'; products=parent/'origin21-products'
            driver.preflight_artifact_roots(profile,products)
            profile.mkdir(mode=0o700); sentinel=profile/'setup.json'; sentinel.write_bytes(b'foreign'); sentinel.chmod(0o600)
            with self.assertRaises(FileExistsError): driver.create_profile_owned(folder,profile)
            self.assertFalse((folder/'profile-owned.json').exists())
            with self.assertRaisesRegex(ValueError,'lacks ownership evidence'): driver.verify_owned_root(folder,'profile',profile)
            self.assertEqual(sentinel.read_bytes(),b'foreign')

    def test_racing_products_root_after_preflight_cannot_gain_cleanup_authority(self):
        from deploy.local import origin21_setup
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory).resolve(); folder=parent/('contour-origin21-qual-'+'a'*32); folder.mkdir(mode=0o700); profile=parent/'origin21-pilot'; products=parent/'origin21-products'
            driver.preflight_artifact_roots(profile,products)
            def raced(**_):
                products.mkdir(mode=0o700); path=products/'intent.json'; path.write_bytes(b'foreign'); path.chmod(0o600)
                raise ValueError('already exists')
            build={'head':'a'*40,'image_id':'sha256:'+'b'*64,'status':'passed'}
            with mock.patch.object(origin21_products,'origin21_profile',SimpleNamespace(PROFILE=SimpleNamespace(state=profile))), mock.patch.object(origin21_products,'OWNER',products), mock.patch.object(origin21_setup,'prepare_identities'), mock.patch.object(origin21_products,'start_products',side_effect=raced):
                with self.assertRaisesRegex(ValueError,'already exists'): driver.full_capture(folder,{},mock.Mock(),build)
            self.assertTrue((folder/'profile-owned.json').exists()); self.assertFalse((folder/'products-owned.json').exists())
            with self.assertRaisesRegex(ValueError,'lacks ownership evidence'): driver.verify_owned_root(folder,'products',products)
            self.assertEqual((products/'intent.json').read_bytes(),b'foreign')

    def test_changed_returned_product_identity_never_gets_ownership_marker(self):
        from deploy.local import origin21_setup,origin21_evidence
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory).resolve(); folder=parent/('contour-origin21-qual-'+'a'*32); folder.mkdir(mode=0o700); profile=parent/'origin21-pilot'; products=parent/'origin21-products'
            build={'head':'a'*40,'image_id':'sha256:'+'b'*64,'status':'passed'}
            with mock.patch.object(origin21_products,'origin21_profile',SimpleNamespace(PROFILE=SimpleNamespace(state=profile))), mock.patch.object(origin21_products,'OWNER',products), mock.patch.object(origin21_setup,'prepare_identities'), mock.patch.object(origin21_products,'start_products',return_value=(b'a'*32,b'b'*32)), mock.patch.object(origin21_products,'inspect_slot',return_value={'slot':1}), mock.patch.object(origin21_evidence,'digest',return_value=b'x'*32):
                with self.assertRaisesRegex(RuntimeError,'commitments changed'): driver.full_capture(folder,{},mock.Mock(),build)
            self.assertFalse((folder/'products-owned.json').exists())

    def test_owned_root_replacement_is_never_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory).resolve(); folder=parent/('contour-origin21-qual-'+'a'*32); folder.mkdir(mode=0o700); profile=parent/'origin21-pilot'
            driver.create_profile_owned(folder,profile)
            original=driver.verify_owned_root(folder,'profile',profile)
            profile.rename(parent/'original'); profile.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError,'ownership drift'): driver.verify_owned_root(folder,'profile',profile)
            self.assertNotEqual(original,(os.lstat(profile).st_dev,os.lstat(profile).st_ino))

    def test_cleanup_refuses_unowned_profile_before_any_tree_removal(self):
        from deploy.local import origin21_profile
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory).resolve(); folder=parent/('contour-origin21-qual-'+'a'*32); folder.mkdir(mode=0o700); profile=parent/'origin21-pilot'; profile.mkdir(mode=0o700); products=parent/'origin21-products'
            sentinel=profile/'setup.json'; sentinel.write_bytes(b'foreign'); sentinel.chmod(0o600)
            with mock.patch.object(origin21_profile,'PROFILE',origin21_profile.PROFILE._replace(state=profile)), mock.patch.object(origin21_products,'OWNER',products), mock.patch.object(driver,'remove_owned_tree') as remove:
                with self.assertRaisesRegex(ValueError,'lacks ownership evidence'): driver.cleanup_full_artifacts(folder)
                remove.assert_not_called()
            self.assertEqual(sentinel.read_bytes(),b'foreign')
    def test_build_evidence_requires_canonical_bytes_digest_and_exact_image_labels(self):
        head='a'*40; token='b'*32; image='sha256:'+'c'*64; tag='apicontour-origin21-build:'+token
        value={'version':1,'head':head,'image_id':image,'status':'passed','owner_token':token,'tag':tag}
        raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        obj={'Id':image,'RepoTags':[tag],'Config':{'Labels':{'org.apicontour.build-owner':token,'org.apicontour.build-head':head}}}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory).resolve()/'receipt'; path.write_bytes(raw); path.chmod(0o600)
            digest=hashlib.sha256(raw).hexdigest(); inspect=mock.Mock(return_value=obj)
            self.assertEqual(driver.verify_build_evidence(path,digest,head,inspect),value)
            with self.assertRaises(ValueError): driver.verify_build_evidence(path,'0'*64,head,inspect)
            with self.assertRaises(ValueError): driver.verify_build_evidence(path,digest,'d'*40,inspect)
            with self.assertRaises(ValueError): driver.verify_build_evidence(path,digest,head,lambda _:dict(obj,Id='sha256:'+'d'*64))
            with self.assertRaises(ValueError): driver.verify_build_evidence(path,digest,head,lambda _:dict(obj,Config={'Labels':{}}))

    def test_exact_owned_artifact_tree_refuses_extra_before_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'state'; root.mkdir(mode=0o700); (root/'nested').mkdir(mode=0o700)
            (root/'nested'/'known').write_bytes(b'synthetic'); os.chmod(root/'nested'/'known',0o600)
            (root/'unexpected').write_bytes(b'x'); os.chmod(root/'unexpected',0o600)
            with self.assertRaisesRegex(ValueError,'inventory drift'): driver.remove_owned_tree(root,{'nested/','nested/known'})
            self.assertTrue((root/'nested'/'known').exists()); (root/'unexpected').unlink()
            driver.remove_owned_tree(root,{'nested/','nested/known'}); self.assertFalse(root.exists())

    def test_missing_topology_record_prevents_any_deletion(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(driver,'verify_owned_root',return_value=(1,2)), mock.patch.object(origin21_products,'OWNER',Path(directory)), mock.patch.object(origin21_products,'_read_record',side_effect=FileNotFoundError), mock.patch.object(origin21_products,'_recorded_products'):
            call=mock.Mock()
            with self.assertRaises(FileNotFoundError): driver.cleanup_topology(call,mock.Mock(),{},directory)
            call.assert_not_called()

    def test_topology_cleanup_refuses_foreign_capture_member_before_deletion(self):
        from deploy.local import origin21_evidence
        token='a'*32; pg='b'*64; net='c'*64; prod=['d'*64,'e'*64]; default='f'*64
        deployment={'name':'contour-origin21-qual-'+token,'id':net,'owner_token':token,'postgres_id':pg}
        services={name:{'id':str(i)*64,'started_at':'fixed'} for i,name in enumerate(origin21_products.COMPANIONS,1)}
        intent={'deployment':deployment,'token':'t','image_id':'image','image_env':[],'image_cmd':None,'image_workdir':'','model_sha256':'a'*64}
        record={'slots':[{'started_at':'fixed'},{'started_at':'fixed'}]}
        commitments={'version':1,'sha256':['1'*64,'1'*64]}
        pending={'images':{name:{} for name in services},'model_sha256':'b'*64}
        records={'intent.json':intent,'products.json':record,'commitments.json':commitments,'companions-intent.json':pending,'companions.json':{'services':services}}
        ids=prod+[item['id'] for item in services.values()]
        call=mock.Mock(return_value=('\n'.join(ids)).encode())
        network={'Name':deployment['name'],'Id':net,'Internal':True,'Labels':{driver.LABEL:token},'Containers':{**{x:{} for x in [pg,services['origin21-capture-ingress']['id'],services['origin21-capture-worker']['id'],services['native-gateway']['id']]},'9'*64:{}}}
        with tempfile.TemporaryDirectory() as directory:
            owner=Path(directory); (owner/'companions-intent.json').touch()
            with mock.patch.object(driver,'verify_owned_root',return_value=(1,2)), mock.patch.object(origin21_products,'OWNER',owner), mock.patch.object(origin21_products,'_read_record',side_effect=lambda name:records[name]), mock.patch.object(origin21_products,'_recorded_products',return_value=prod), mock.patch.object(origin21_products,'_companion_record',return_value=default), mock.patch.object(origin21_evidence,'digest',return_value=bytes.fromhex('1'*64)):
                with self.assertRaisesRegex(RuntimeError,'network identity drift'): driver.cleanup_topology(call,lambda _:network,deployment,directory)
        self.assertFalse(any(args.args[0][:2]==['docker','rm'] for args in call.call_args_list))

    def test_topology_cleanup_removes_only_recorded_containers_in_order(self):
        from deploy.local import origin21_evidence
        token='a'*32; pg='b'*64; net='c'*64; prod=['d'*64,'e'*64]; default='f'*64
        deployment={'name':'contour-origin21-qual-'+token,'id':net,'owner_token':token,'postgres_id':pg}
        services={name:{'id':str(i)*64,'started_at':'fixed'} for i,name in enumerate(origin21_products.COMPANIONS,1)}
        intent={'deployment':deployment,'token':'t','image_id':'image','image_env':[],'image_cmd':None,'image_workdir':'','model_sha256':'a'*64}
        record={'slots':[{'started_at':'fixed'},{'started_at':'fixed'}]}; pending={'images':{name:{} for name in services},'model_sha256':'b'*64}
        records={'intent.json':intent,'products.json':record,'commitments.json':{'version':1,'sha256':['1'*64,'1'*64]},'companions-intent.json':pending,'companions.json':{'services':services}}
        remaining=set(prod+[item['id'] for item in services.values()]); captured={pg,*[services[n]['id'] for n in ('origin21-capture-ingress','origin21-capture-worker','native-gateway')]}; removed=[]
        def call(args):
            if args[:3]==['docker','rm','-f']:
                cid=args[3]; removed.append(cid); remaining.remove(cid); captured.discard(cid); return b''
            if args[:3]==['docker','ps','-aq']: return ('\n'.join(sorted(remaining))).encode()
            return b''
        def inspect(args):
            if args[:3]==['docker','network','inspect']: return {'Name':deployment['name'],'Id':net,'Internal':True,'Labels':{driver.LABEL:token},'Containers':{cid:{} for cid in captured}}
            return {'Id':args[-1]}
        with tempfile.TemporaryDirectory() as directory:
            owner=Path(directory); (owner/'companions-intent.json').touch()
            with mock.patch.object(driver,'verify_owned_root',return_value=(1,2)), mock.patch.object(origin21_products,'OWNER',owner), mock.patch.object(origin21_products,'_read_record',side_effect=lambda name:records[name]), mock.patch.object(origin21_products,'_verify_model'), mock.patch.object(origin21_products,'_recorded_products',return_value=prod), mock.patch.object(origin21_products,'_companion_record',return_value=default), mock.patch.object(origin21_products,'_network',return_value=default), mock.patch.object(origin21_products,'_validate_companion',return_value={'StartedAt':'fixed'}), mock.patch.object(origin21_products,'validate',return_value={'StartedAt':'fixed'}), mock.patch.object(origin21_evidence,'digest',return_value=bytes.fromhex('1'*64)):
                driver.cleanup_topology(call,inspect,deployment,directory)
        self.assertEqual(removed,[services[n]['id'] for n in reversed(origin21_products.COMPANIONS)]+prod)
        self.assertEqual(captured,{pg}); self.assertFalse(remaining)

    def test_dirty_source_is_refused(self):
        call=mock.Mock(side_effect=[b'a'*40,b'?? unexpected'])
        with self.assertRaises(ValueError): driver.clean_head(call)

    def test_full_capture_rechecks_journal_facts_and_requires_capture_only_result(self):
        from deploy.local import origin21_setup,origin21_ready,origin21_evidence
        from types import SimpleNamespace
        commitments=(b'a'*32,b'b'*32); build={'head':'a'*40,'image_id':'sha256:'+'b'*64,'status':'passed'}
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory).resolve(); state=folder/'state'; state.mkdir()
            for name in ('setup.json','operator-evidence.json'):
                path=state/name; path.write_bytes(b'private-synthetic'); path.chmod(0o600)
            runner=mock.Mock(); runner.run.return_value='1'
            with mock.patch.object(driver,'create_profile_owned'), mock.patch.object(driver,'record_owned_root'), mock.patch.object(origin21_evidence,'digest',side_effect=lambda v:commitments[v['slot']-1]), mock.patch.object(origin21_products,'origin21_profile',SimpleNamespace(PROFILE=SimpleNamespace(state=state))), mock.patch.object(origin21_setup,'prepare_identities') as identities, mock.patch.object(origin21_products,'start_products',return_value=commitments), mock.patch.object(origin21_setup,'prepare') as prepare, mock.patch.object(origin21_products,'start_companions') as companions, mock.patch.object(origin21_products,'inspect_slot',side_effect=lambda i:{'slot':i}), mock.patch.object(driver,'fact_snapshot',return_value='[]'), mock.patch.object(origin21_ready,'check',return_value={'product_tls_and_catalog_verified':True,'ui_verified':False}):
                driver.full_capture(folder,{'fixture':'only'},runner,build)
                identities.assert_called_once(); companions.assert_called_once()
                self.assertEqual(prepare.call_count,3)
                self.assertTrue(prepare.call_args_list[-1].kwargs['check_only'])
                self.assertIsNot(prepare.call_args.kwargs['psql'],prepare.call_args.kwargs['sensitive_execute'])
                prepare.call_args.kwargs['psql']('SELECT 1;')
                self.assertEqual(runner.run.call_args.args[1:],('sql','postgres'))
                prepare.call_args.kwargs['authenticate']('contour_local_origin21_ingress','synthetic')
                self.assertEqual(runner.run.call_args.args[1:],('auth','contour_local_origin21_ingress'))

    def test_replay_fact_drift_fails_before_capture_claim(self):
        from deploy.local import origin21_setup,origin21_ready,origin21_evidence
        from types import SimpleNamespace
        commitments=(b'a'*32,b'b'*32); build={'head':'a'*40,'image_id':'sha256:'+'b'*64,'status':'passed'}
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory).resolve(); state=folder/'state'; state.mkdir()
            for name in ('setup.json','operator-evidence.json'):
                path=state/name; path.write_bytes(b'fixture'); path.chmod(0o600)
            with mock.patch.object(driver,'create_profile_owned'), mock.patch.object(driver,'record_owned_root'), mock.patch.object(origin21_evidence,'digest',side_effect=lambda v:commitments[v['slot']-1]), mock.patch.object(origin21_products,'origin21_profile',SimpleNamespace(PROFILE=SimpleNamespace(state=state))), mock.patch.object(origin21_setup,'prepare_identities'), mock.patch.object(origin21_products,'start_products',return_value=commitments), mock.patch.object(origin21_setup,'prepare'), mock.patch.object(origin21_products,'start_companions'), mock.patch.object(origin21_products,'inspect_slot',side_effect=lambda i:{'slot':i}), mock.patch.object(driver,'fact_snapshot',side_effect=['before','after']), mock.patch.object(origin21_ready,'check') as check:
                with self.assertRaisesRegex(RuntimeError,'replay drift'): driver.full_capture(folder,{},mock.Mock(),build)
                check.assert_not_called()

    def test_full_capture_refuses_any_result_that_claims_ui_verification(self):
        from deploy.local import origin21_setup,origin21_ready,origin21_evidence
        from types import SimpleNamespace
        commitments=(b'a'*32,b'b'*32); build={'head':'a'*40,'image_id':'sha256:'+'b'*64,'status':'passed'}
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory).resolve(); state=folder/'state'; state.mkdir()
            for name in ('setup.json','operator-evidence.json'):
                path=state/name; path.write_bytes(b'fixture'); path.chmod(0o600)
            with mock.patch.object(driver,'create_profile_owned'), mock.patch.object(driver,'record_owned_root'), mock.patch.object(origin21_evidence,'digest',side_effect=lambda v:commitments[v['slot']-1]), mock.patch.object(origin21_products,'origin21_profile',SimpleNamespace(PROFILE=SimpleNamespace(state=state))), mock.patch.object(origin21_setup,'prepare_identities'), mock.patch.object(origin21_products,'start_products',return_value=commitments), mock.patch.object(origin21_setup,'prepare'), mock.patch.object(origin21_products,'start_companions'), mock.patch.object(origin21_products,'inspect_slot',side_effect=lambda i:{'slot':i}), mock.patch.object(driver,'fact_snapshot',return_value='same'), mock.patch.object(origin21_ready,'check',return_value={'product_tls_and_catalog_verified':True,'ui_verified':True}):
                with self.assertRaisesRegex(RuntimeError,'capture qualification incomplete'): driver.full_capture(folder,{},mock.Mock(),build)

    def test_guard_rejects_backend_loss_postmaster_restart_and_crash_logs(self):
        child=mock.Mock(); child.poll.return_value=None
        def make():
            guard=driver.ContinuityGuard('a'*64,mock.Mock(return_value='1'),mock.Mock(return_value=(b'boot\n',b'')))
            guard.child=child; guard.identity=(123,456); guard.postmaster_start='100'; guard.logs=(b'boot\n',b'')
            guard.postmaster=mock.Mock(return_value='100')
            return guard
        guard=make(); guard.check()
        guard=make(); guard.execute.return_value='0'
        with self.assertRaisesRegex(RuntimeError,'backend changed'): guard.check()
        guard=make(); guard.postmaster.return_value='101'
        with self.assertRaisesRegex(RuntimeError,'postmaster restarted'): guard.check()
        for line in (b'server process (PID 315) was terminated by signal 15\n',b'all server processes terminated; reinitializing\n',b'database system is not yet accepting connections\n'):
            guard=make(); guard.read_logs.return_value=(b'boot\n',line)
            with self.assertRaisesRegex(RuntimeError,'crash diagnostic'): guard.check()
        guard=make(); guard.read_logs.return_value=(b'rotated\n',b'')
        with self.assertRaisesRegex(RuntimeError,'crash diagnostic'): guard.check()
        guard=make(); guard.logs=(b'boot\n',b'server process (PID 12) was terminated')
        guard.read_logs.return_value=(b'boot\n',b'server process (PID 12) was terminated by signal 15\n')
        with self.assertRaisesRegex(RuntimeError,'crash diagnostic'): guard.check()

    def test_guard_start_captures_one_exact_backend_and_checks_sleep(self):
        import io
        readfd,writefd=os.pipe(); os.write(writefd,b'123|456\n'); os.close(writefd)
        stdout=os.fdopen(readfd,'rb',buffering=0)
        child=mock.Mock(pid=321,stdout=stdout,stdin=io.BytesIO()); child.poll.return_value=None
        def execute(sql): return '100' if 'pg_postmaster_start_time' in sql else '1'
        try:
            with mock.patch.object(driver.subprocess,'Popen',return_value=child):
                guard=driver.ContinuityGuard('a'*64,execute,lambda:(b'boot\n',b'')); guard.start()
            self.assertEqual(guard.identity,(123,456)); self.assertIn(b'pg_sleep(120)',child.stdin.getvalue())
        finally: stdout.close()

    def test_guard_termination_uses_exact_backend_identity_and_waits(self):
        child=mock.Mock(); child.poll.return_value=None; child.stdout.fileno.return_value=44
        def execute(sql):
            if 'pg_terminate_backend' in sql: return 'true'
            if "wait_event='PgSleep'" in sql: return '1'
            return '0'
        guard=driver.ContinuityGuard('a'*64,execute,lambda:(b'boot\n',b'')); guard.child=child; guard.identity=(123,456); guard.postmaster_start='100'; guard.logs=(b'boot\n',b''); guard.postmaster=mock.Mock(return_value='100')
        with mock.patch.object(driver.os,'read',return_value=b''), mock.patch.object(driver.os,'set_blocking'):
            guard.close()
        child.wait.assert_called_once_with(timeout=10)
        self.assertIn('pid=123',guard.predicate()); self.assertIn('456',guard.predicate())
        with self.assertRaisesRegex(RuntimeError,'already attempted'): guard.close()
    def test_failure_diagnostic_excludes_exception_payload(self):
        try: raise RuntimeError('synthetic-private-sql-and-password')
        except RuntimeError as error: diagnostic=driver.failure_location(error)
        self.assertEqual(diagnostic,'unavailable')
        self.assertNotIn('synthetic-private',diagnostic)

    def test_blocked_case_requires_sequence_sleep_and_cleanup_evidence(self):
        observed=threading.Event(); calls=[]
        class Runner:
            target={'container_id':'a'*64,'image_id':'sha256:'+'b'*64,'network_id':'c'*64}
            def run(self,sql,mode,role,**kwargs):
                if b'pg_sleep' in sql:
                    observed.wait(2); raise RuntimeError('timed out')
                return '1'
        def execute(sql):
            calls.append(sql)
            if 'last_value' in sql: return 'true'
            if "wait_event='PgSleep'" in sql: observed.set(); return '1'
            return '0'
        pending={'nonce':'d'*32,'identity':{'pid':123,'pgid':123,'starttime':1}}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(driver,'pending_identity',return_value=pending), mock.patch.object(driver,'assert_group_absent') as group:
            driver.blocked_transaction(Runner(),directory,execute,mock.Mock(),'a'*64,'')
            group.assert_called_once()
        self.assertTrue(any('origin21_qual_rows' in sql for sql in calls))

    def test_blocked_case_rejects_unobserved_query_entry(self):
        class Runner:
            target={}
            def run(self,*args,**kwargs): raise RuntimeError('early failure')
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(driver,'pending_identity',side_effect=FileNotFoundError), mock.patch.object(driver,'assert_group_absent') as group:
            with self.assertRaisesRegex(RuntimeError,'evidence missing'):
                driver.blocked_transaction(Runner(),directory,lambda _: '0',mock.Mock(),'a'*64,'')
            group.assert_not_called()

    def test_private_relay_forwards_payload_and_never_forwards_ack(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); state=root/'.local-mvp'; state.mkdir()
            case=state/('contour-origin21-qual-'+'a'*32)/'ack-case'; case.mkdir(parents=True)
            source,writer=os.pipe(); reader,target=os.pipe()
            control,received=socket.socketpair(type=socket.SOCK_DGRAM)
            control.sendmsg([len(b'private payload').to_bytes(8,'big')],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[target]))]); os.close(target)
            os.write(writer,b'private payloadACK!'); os.close(writer)
            with mock.patch.object(driver,'ROOT',root), mock.patch.object(driver.time,'sleep'):
                driver.relay_case([str(source),str(received.detach()),str(case)])
            control.close()
            self.assertEqual(os.read(reader,1024),b'private payload'); self.assertEqual(os.read(reader,1),b''); os.close(reader)
            marker=json.loads((case/'ack'/'intent.json').read_text())
            self.assertEqual(marker['event'],'ACK-held'); self.assertEqual(marker['pid'],os.getpid())

    def test_ack_timeout_never_claims_success_and_reaps_child(self):
        child=mock.Mock(pid=123); child.poll.return_value=None
        relay=mock.Mock(pid=124); relay.poll.return_value=None
        deployment={'id':'a'*64,'postgres_image_id':'sha256:'+'b'*64}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(driver.subprocess,'Popen',side_effect=[relay,child]), mock.patch.object(driver.time,'monotonic',side_effect=[0,21]), mock.patch.object(driver.time,'sleep'):
            with self.assertRaises(TimeoutError): driver.lost_ack(directory,deployment,mock.Mock(),mock.Mock(),'c'*64,'')
        child.kill.assert_called_once(); child.wait.assert_called_once()
        relay.kill.assert_called_once(); relay.wait.assert_called_once()

    def test_ack_relay_is_reaped_when_case_launch_fails_before_any_marker(self):
        relay=mock.Mock(pid=124); relay.poll.return_value=None
        deployment={'id':'a'*64,'postgres_image_id':'sha256:'+'b'*64}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(driver.subprocess,'Popen',side_effect=[relay,OSError('case launch failed')]):
            with self.assertRaises(OSError): driver.lost_ack(directory,deployment,mock.Mock(),mock.Mock(),'c'*64,'')
        relay.kill.assert_called_once(); relay.wait.assert_called_once()

    def test_real_relay_deadline_bounds_handoff_payload_output_and_ack_waits(self):
        for blocked in ('handoff','payload','output','ack'):
            with self.subTest(blocked=blocked), tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve(); state=root/'.local-mvp'; state.mkdir()
                case=state/('contour-origin21-qual-'+'a'*32)/'ack-case'; case.mkdir(parents=True)
                source,writer=os.pipe(); reader,target=os.pipe()
                control,received=socket.socketpair(type=socket.SOCK_DGRAM)
                try:
                    if blocked=='output':
                        os.set_blocking(target,False)
                        while True:
                            try: os.write(target,b'x'*4096)
                            except BlockingIOError: break
                        os.set_blocking(target,True)
                    if blocked!='handoff':
                        control.sendmsg([(1).to_bytes(8,'big')],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[target]))])
                    os.close(target); target=None
                    if blocked in ('output','ack'): os.write(writer,b'x')
                    if blocked=='output': os.write(writer,b'ACK!')
                    with mock.patch.object(driver,'ROOT',root), mock.patch.object(driver,'RELAY_DEADLINE_SECONDS',.05):
                        with self.assertRaisesRegex(TimeoutError,'absolute deadline'):
                            driver.relay_case([str(source),str(received.detach()),str(case)])
                    source=None
                    self.assertFalse((case/'ack').exists())
                finally:
                    control.close(); received.close()
                    for fd in (source,writer,reader,target):
                        if fd is not None:
                            try: os.close(fd)
                            except OSError: pass

    def test_foreign_identity_is_role_address_and_start_bound(self):
        foreign={'nonce':'a'*32,'pid':123,'start':456}
        predicate=driver.foreign_predicate(foreign,'origin21_qual_foreign')
        for value in ('pid=123','backend_start','456',"usename='origin21_qual_foreign'",'client_addr',"backend_type='client backend'"):
            self.assertIn(value,predicate)
        for bad,role in ((dict(foreign,nonce='bad'),'origin21_qual_foreign'),(dict(foreign,pid=0),'origin21_qual_foreign'),(foreign,'postgres')):
            with self.assertRaises(ValueError): driver.foreign_predicate(bad,role)

    def test_private_child_refuses_unapproved_mode(self):
        with self.assertRaises(ValueError): driver.private_case(['arbitrary','/tmp/example'])

    def test_local_death_requires_rollback_and_exact_reconciliation(self):
        deployment={'id':'a'*64,'postgres_image_id':'sha256:'+'b'*64}; pending={'nonce':'d'*32,'identity':{'pid':123,'pgid':123,'starttime':9}}
        for row_count in ('0','1'):
            child=mock.Mock(pid=321,returncode=-9); child.poll.return_value=-9
            runner=mock.Mock(); runner.run.return_value='1'
            def execute(sql): return row_count if 'public.origin21_qual_rows' in sql else '0'
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(driver.subprocess,'Popen',return_value=child), mock.patch.object(driver,'wait_for_sleep',return_value=pending), mock.patch.object(driver,'pending_identity',return_value=pending), mock.patch.object(driver,'assert_group_absent') as group, mock.patch.object(origin21_sql_runner,'for_deployment',return_value=runner):
                if row_count=='0':
                    driver.crashed_parent(directory,deployment,execute,mock.Mock(),'c'*64,''); group.assert_called_once()
                else:
                    with self.assertRaisesRegex(RuntimeError,'roll back'): driver.crashed_parent(directory,deployment,execute,mock.Mock(),'c'*64,'')
                    group.assert_not_called()
                child.kill.assert_called_once()

    def test_foreign_case_checks_survival_then_terminates_only_exact_backend(self):
        import io
        child=mock.Mock(pid=321); child.stdin=io.BytesIO(); child.poll.return_value=None
        runner=mock.Mock(); runner.launch=mock.Mock(return_value='owned-process')
        queries=[]
        def execute(sql):
            queries.append(sql)
            if 'wait_event' in sql: return '123|456'
            if 'count(*)' in sql: return '0' if any('pg_terminate_backend' in q for q in queries) else '1'
            return ''
        def blocked(runner,*args):
            self.assertEqual(runner.launch('a'*32,'sql','postgres',8),'owned-process')
            self.assertEqual(runner.launch('c'*32,'sql','postgres',8),'owned-process')
        with mock.patch.object(driver.subprocess,'Popen',return_value=child), mock.patch.object(driver,'blocked_transaction',side_effect=blocked):
            driver.foreign_session(runner,'/tmp/unused',execute,mock.Mock(),'b'*64,'')
        kill=next(sql for sql in queries if 'pg_terminate_backend' in sql)
        self.assertIn('pid=123',kill); self.assertIn('456',kill); self.assertIn("usename='origin21_qual_foreign'",kill)
        child.wait.assert_called_once()
    def test_created_container_has_no_live_network_endpoint(self):
        token='a'*32; nid='b'*64; cid='c'*64; image='sha256:'+'d'*64
        name='contour-origin21-qual-'+token
        pg={'Id':cid,'Name':'/'+name+'-postgres','Image':image,
            'State':{'Status':'created','Running':False,'Pid':0},
            'Config':{'Image':driver.IMAGE,'Labels':{driver.LABEL:token}},
            'HostConfig':{'Init':True,'Privileged':False,'PublishAllPorts':False,'PortBindings':{},'NetworkMode':nid},
            'NetworkSettings':{'Networks':{name:{'NetworkID':'','EndpointID':'','Aliases':['postgres']}}}}
        self.assertEqual(driver.validate_postgres(pg,token,cid,image,nid),'created')
        bad=copy.deepcopy(pg); bad['HostConfig']['Init']=False
        with self.assertRaises(RuntimeError): driver.validate_postgres(bad,token,cid,image,nid)
        network={'Name':name,'Id':nid,'Internal':True,'Labels':{driver.LABEL:token},'Containers':{}}
        inspect=mock.Mock(side_effect=[pg,network,network]); call=mock.Mock(return_value=b'')
        driver.cleanup_owned(call,inspect,token,nid,cid,image,True,True)
        self.assertEqual(call.call_args_list[0].args[0],['docker','rm','-f',cid])
        bad=copy.deepcopy(pg); bad['NetworkSettings']['Networks'][name]['NetworkID']=nid
        with self.assertRaises(RuntimeError): driver.validate_postgres(bad,token,cid,image,nid)

    def test_driver_rejects_unapproved_modes(self):
        with self.assertRaises(ValueError): driver.main([])
        with self.assertRaises(ValueError): driver.main(['--unexpected'])

    def test_owned_network_and_container_are_exact(self):
        token='a'*32; network_id='b'*64; cid='c'*64; image='sha256:'+'d'*64
        name='contour-origin21-qual-'+token
        network={'Name':name,'Id':network_id,'Internal':True,'Labels':{driver.LABEL:token},'Containers':{cid:{}}}
        pg={'Id':cid,'Name':'/'+name+'-postgres','Image':image,'Config':{'Image':driver.IMAGE,'Labels':{driver.LABEL:token}},'State':{'Status':'running','Running':True},'HostConfig':{'Init':True,'NetworkMode':network_id,'Privileged':False,'PublishAllPorts':False,'PortBindings':{}},'NetworkSettings':{'Networks':{name:{'NetworkID':network_id,'Aliases':['postgres']}}}}
        driver.validate_network(network,token,network_id,[cid]); driver.validate_postgres(pg,token,cid,image,network_id)
        with self.assertRaises(RuntimeError): driver.validate_postgres(dict(pg,HostConfig=dict(pg['HostConfig'],Init=False)),token,cid,image,network_id)
        for bad in (dict(network,Internal=False),dict(network,Labels={}),dict(network,Containers={})):
            with self.assertRaises(RuntimeError): driver.validate_network(bad,token,network_id,[cid])
        with self.assertRaises(RuntimeError): driver.validate_postgres(dict(pg,Image='sha256:'+'f'*64),token,cid,image,network_id)

    def test_cleanup_requires_exact_ownership_and_refuses_ambiguity(self):
        token='a'*32; net='b'*64; cid='c'*64; image='sha256:'+'d'*64; name='contour-origin21-qual-'+token
        network={'Name':name,'Id':net,'Internal':True,'Labels':{driver.LABEL:token},'Containers':{cid:{}}}
        pg={'Id':cid,'Name':'/'+name+'-postgres','Image':image,'Config':{'Image':driver.IMAGE,'Labels':{driver.LABEL:token}},'State':{'Status':'running','Running':True},'HostConfig':{'Init':True,'NetworkMode':net,'Privileged':False,'PublishAllPorts':False,'PortBindings':{}},'NetworkSettings':{'Networks':{name:{'NetworkID':net,'Aliases':['postgres']}}}}
        inspect=mock.Mock(side_effect=[pg,network,dict(network,Containers={})]); call=mock.Mock(return_value=b'')
        driver.cleanup_owned(call,inspect,token,net,cid,image,True,True)
        self.assertEqual(call.call_args_list[0].args[0],['docker','rm','-f',cid])
        self.assertEqual(call.call_args_list[2].args[0],['docker','network','rm',net])
        inspect=mock.Mock(return_value=dict(pg,Image='sha256:'+'e'*64)); call=mock.Mock()
        with self.assertRaises(RuntimeError): driver.cleanup_owned(call,inspect,token,net,cid,image,True,True)
        call.assert_not_called()
        with self.assertRaises(RuntimeError): driver.cleanup_owned(call,inspect,token,net,None,image,True,True)
        call.assert_not_called()
        inspect=mock.Mock(side_effect=[pg,network]); call=mock.Mock(side_effect=RuntimeError('remove failed'))
        with self.assertRaises(RuntimeError): driver.cleanup_owned(call,inspect,token,net,cid,image,True,True)
        self.assertEqual(call.call_count,1)

    def test_intent_is_durable_exclusive_and_does_not_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            driver.durable_intent(directory,{'owner':'a'*32})
            path=Path(directory)/'intent.json'; before=path.read_bytes()
            self.assertEqual(os.stat(path).st_mode & 0o777,0o600)
            with self.assertRaises(FileExistsError): driver.durable_intent(directory,{'owner':'b'*32})
            self.assertEqual(path.read_bytes(),before)

    def test_factory_rechecks_closed_fixture_network(self):
        token='a'*32
        network={'name':'contour-origin21-qual-'+token,'owner_kind':'fixture','owner_token':token,
                 'id':'b'*64,'postgres_id':'c'*64,'postgres_image_id':'sha256:'+'d'*64,'ca_sha256':'e'*64}
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(origin21_products,'_capture_network') as inspect:
            runner=origin21_sql_runner.for_deployment(Path(folder),network)
            inspect.assert_called_once_with(network)
            network['name']='changed'
            runner.verify_target(runner.target)
            self.assertEqual(inspect.call_args.args[0]['name'],'contour-origin21-qual-'+token)
            with self.assertRaises(RuntimeError): runner.verify_target(dict(runner.target,network_id='f'*64))

    def test_launch_waits_for_setsid_child_and_keeps_payload_out_of_argv(self):
        import subprocess
        token='a'*32
        network={'name':'contour-origin21-qual-'+token,'owner_kind':'fixture','owner_token':token,
                 'id':'b'*64,'postgres_id':'c'*64,'postgres_image_id':'sha256:'+'d'*64,'ca_sha256':'e'*64}
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(origin21_products,'_capture_network'), mock.patch.object(subprocess,'Popen') as popen:
            runner=origin21_sql_runner.for_deployment(Path(folder),network)
            runner.launch('1'*32,'auth','contour_local_origin21_ingress',42)
            args=popen.call_args.args[0]
            self.assertEqual(args[args.index('setsid'):args.index('setsid')+2],['setsid','--wait'])
            self.assertIn(network['postgres_id'],args)
            self.assertNotIn('synthetic-password',repr(args))

    def test_factory_rejects_foreign_or_malformed_deployment_before_inspection(self):
        token='a'*32
        network={'name':'contour-origin21-qual-'+token,'owner_kind':'fixture','owner_token':token,
                 'id':'b'*64,'postgres_id':'c'*64,'postgres_image_id':'sha256:'+'d'*64,'ca_sha256':'e'*64}
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(origin21_products,'_capture_network') as inspect:
            for change in ({'name':'foreign'},{'owner_token':'b'*32},{'owner_kind':'foreign'},{'postgres_id':'bad'}):
                with self.assertRaises(ValueError): origin21_sql_runner.for_deployment(Path(folder),dict(network,**change))
            inspect.assert_not_called()

    def test_factory_refuses_postgres_without_init_before_launch(self):
        import subprocess
        token='a'*32; net='b'*64; cid='c'*64; image='sha256:'+'d'*64; name='contour-origin21-qual-'+token
        deployment={'name':name,'owner_kind':'fixture','owner_token':token,'id':net,'postgres_id':cid,'postgres_image_id':image,'ca_sha256':'e'*64}
        network={'Name':name,'Id':net,'Internal':True,'Labels':{driver.LABEL:token},'Containers':{cid:{}}}
        pg={'Id':cid,'Image':image,'State':{'Running':True},'HostConfig':{'Init':False},'Config':{'Image':driver.IMAGE,'Labels':{driver.LABEL:token}}}
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(origin21_products,'_objects',side_effect=[network,pg]), mock.patch.object(subprocess,'Popen') as launch:
            with self.assertRaises(RuntimeError): origin21_sql_runner.for_deployment(Path(folder),deployment)
            launch.assert_not_called()


if __name__=='__main__': unittest.main()
