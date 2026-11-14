"""Offline managed PostgreSQL initializer boundary checks."""
import hashlib
import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from deploy.local import origin21_managed_init as init

class InitializerTests(unittest.TestCase):
    def test_managed_runtime_state_is_ignored_but_source_is_not(self):
        for path,expected in (('.local-mvp-managed/ca.key',0),('.local-mvp-managed/origin21-pilot/setup.json',0),('deploy/local/origin21_managed_init.py',1),('deploy/local/origin21_managed_cleanup.py',1),('tests/fixtures/managed-origin/test_initializer.py',1)):
            result=subprocess.run(['git','check-ignore','--no-index','-q','--',path],cwd=init.ROOT,timeout=5)
            self.assertEqual(result.returncode,expected,path)

    def test_runtime_target_rejects_generation_change_before_sql(self):
        deployment={'postgres_id':'a'*64,'postgres_image_id':'sha256:'+'b'*64,'id':'c'*64,'name':init.NETWORK}
        records={'initializer.intent':{'version':1,'head':'d'*40,'build_image':'sha256:'+'e'*64,'build_receipt_sha256':'f'*64,'token':'1'*32,'network':init.NETWORK,'volume':init.VOLUME},'postgres.start.result':{'version':1,'id':'a'*64,'started_at':'2026-11-07T01:00:00Z'}}
        def read(path,*args): return init._bytes(records[path.name])
        with mock.patch.object(init.origin_credentials,'_file',side_effect=read),mock.patch.object(init.origin21_products,'_image',return_value={'id':deployment['postgres_image_id']}),mock.patch.object(init,'_postgres',return_value={'StartedAt':'replacement'}),mock.patch.object(init,'_volume') as volume:
            with self.assertRaises(ValueError): init.verify_runtime_target(deployment)
            volume.assert_not_called()

    def test_runner_rechecks_managed_generation_before_every_payload(self):
        from deploy.local import origin21_sql_runner,origin21_profile
        deployment={'postgres_id':'a'*64,'postgres_image_id':'sha256:'+'b'*64,'id':'c'*64,'name':init.NETWORK,'owner_kind':'managed-local','owner_token':init.PROJECT,'ca_sha256':'d'*64}
        with tempfile.TemporaryDirectory() as directory,mock.patch.object(init.origin21_products,'_capture_network'),mock.patch.object(init,'verify_runtime_target',side_effect=[None,ValueError('replacement')]) as verify:
            runner=origin21_sql_runner.for_deployment(Path(directory).resolve(),deployment,selected=origin21_profile.MANAGED)
            runner.launch=mock.Mock()
            with self.assertRaises(ValueError): runner.verify_target(runner.target)
            self.assertEqual(verify.call_count,2); runner.launch.assert_not_called()
            self.assertFalse((Path(directory)/'pending.json').exists())

    def test_source_guard_refuses_unpinned_initializer_before_process(self):
        with mock.patch.object(init.origin21_state,'MANAGED_SOURCE_FILES',()),mock.patch.object(init.origin21_transport,'_run') as run:
            with self.assertRaises(RuntimeError): init._source('a'*40)
            run.assert_not_called()

    def test_unknown_sql_ack_retains_exclusive_phase_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); runner=mock.Mock(); runner.run.side_effect=TimeoutError('unknown')
            with self.assertRaises(TimeoutError): init._phase(root,'migration-0001',runner,'SELECT 1;',lambda:True)
            self.assertTrue((root/'phase-migration-0001.intent').exists()); self.assertFalse((root/'phase-migration-0001.done').exists())
            with self.assertRaises(FileExistsError): init._phase(root,'migration-0001',runner,'SELECT 1;',lambda:True)
            runner.run.assert_called_once()

    def test_unknown_network_create_and_postgres_start_never_retry(self):
        for operation,intent in (('network','network.intent'),('start','postgres.start.intent')):
            with self.subTest(operation=operation),tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve()
                with mock.patch.object(init,'BASE',root),mock.patch.object(init.origin21_products,'_command',side_effect=TimeoutError('unknown')) as command:
                    action=(lambda:init._create_network('a'*32)) if operation=='network' else (lambda:init._start_postgres('b'*64))
                    with self.assertRaises(TimeoutError): action()
                    self.assertTrue((root/intent).is_file())
                    with self.assertRaises(FileExistsError): action()
                    command.assert_called_once()

    def test_source_change_after_sql_keeps_intent_without_done(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); runner=mock.Mock(); checks=iter([True,False])
            with self.assertRaises(ValueError): init._phase(root,'bootstrap',runner,'SELECT 1;',lambda:next(checks))
            self.assertTrue((root/'phase-bootstrap.intent').exists()); self.assertFalse((root/'phase-bootstrap.done').exists())

    def test_build_receipt_requires_six_canonical_fields_and_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            image='sha256:'+'a'*64; head='b'*40; token='c'*32; tag='apicontour-origin21-build:'+token
            value={'version':1,'head':head,'image_id':image,'status':'passed','owner_token':token,'tag':tag}
            raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode(); path=Path(directory).resolve()/'receipt'; path.write_bytes(raw); path.chmod(0o600)
            obj={'Id':image,'RepoTags':[tag],'Config':{'Labels':{'org.apicontour.build-owner':token,'org.apicontour.build-head':head}}}
            with mock.patch.object(init.origin21_products,'_objects',return_value=obj):
                self.assertEqual(init._build(image,head,path,hashlib.sha256(raw).hexdigest()),value)
            with mock.patch.object(init.origin21_products,'_objects',return_value=dict(obj,Id='sha256:'+'d'*64)):
                with self.assertRaises(ValueError): init._build(image,head,path,hashlib.sha256(raw).hexdigest())
            with self.assertRaises(ValueError): init._build(image,head,path,'0'*64)

    def test_db_owner_inventory_rejects_extra_detached_and_missing(self):
        cid='a'*64; token='b'*32
        with mock.patch.object(init.origin21_products,'_command',return_value=cid.encode()) as command:
            init._db_inventory(token,[cid]); self.assertEqual(command.call_args.args[0][-1],'label='+init.LABEL+'='+token)
        for output in (b'',(cid+'\n'+'c'*64).encode(),(cid+'\n'+cid).encode()):
            with mock.patch.object(init.origin21_products,'_command',return_value=output) as command:
                with self.assertRaises(ValueError): init._db_inventory(token,[cid])
                self.assertFalse(any('rm' in call.args[0] for call in command.call_args_list))
        with mock.patch.object(init.origin21_products,'_command',return_value=b''):
            init._db_inventory(token,[])

    def test_postgres_requires_init_and_exact_config(self):
        cid='a'*64; image={'id':'sha256:'+'b'*64,'env':['PATH=/bin'],'entrypoint':['docker-entrypoint.sh'],'workdir':None}; network='c'*64; token='d'*32
        env=['PATH=/bin']+[key+'='+value for key,value in init.PG_ENV.items()]
        obj={'Id':cid,'Name':'/'+init.PROJECT+'-postgres','Image':image['id'],
          'Config':{'Image':init.POSTGRES,'Labels':{init.LABEL:token,'com.docker.compose.project':init.PROJECT,'com.docker.compose.service':'postgres'},'Env':env,'Entrypoint':image['entrypoint'],'Cmd':['sh','-c',init.PG_COMMAND],'WorkingDir':''},
          'HostConfig':{'Init':True,'Privileged':False,'PortBindings':{},'PublishAllPorts':False,'NetworkMode':network,'Memory':512*1024*1024,'NanoCpus':1000000000,'PidsLimit':128,'PidMode':'','IpcMode':'private','UTSMode':'','UsernsMode':'','Devices':None,'DeviceRequests':None,'CapAdd':None},
          'State':{'Running':False,'Status':'created'},'NetworkSettings':{'Networks':{init.NETWORK:{'Aliases':['postgres'],'NetworkID':''}}},
          'Mounts':[{'Type':'volume','Name':init.VOLUME,'Destination':'/var/lib/postgresql/data','RW':True}]}
        with mock.patch.object(init.origin21_products,'_command',return_value=cid.encode()),mock.patch.object(init.origin21_products,'_objects',return_value=obj): init._postgres(cid,image,network,token,running=False)
        for bad in (dict(obj,HostConfig=dict(obj['HostConfig'],Init=False)),dict(obj,Config=dict(obj['Config'],Cmd=['postgres'])),dict(obj,HostConfig=dict(obj['HostConfig'],Privileged=True)),dict(obj,Mounts=[])):
            with mock.patch.object(init.origin21_products,'_command',return_value=cid.encode()),mock.patch.object(init.origin21_products,'_objects',return_value=bad):
                with self.assertRaises(ValueError): init._postgres(cid,image,network,token,running=False)

if __name__=='__main__': unittest.main()
