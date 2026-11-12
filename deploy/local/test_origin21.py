"""Offline v21 foundation controls; no live SQL, credentials or services."""
import os
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from deploy.local import capture_profiles, origin21_cli, origin21_credentials, origin21_evidence, origin21_logins, origin21_products, origin21_profile, origin21_provision, origin21_ready, origin21_runtime, origin21_schema, origin21_setup, origin21_sql_runner, origin21_state, origin21_transport, provision, up


class ManagedContextTests(unittest.TestCase):
    def test_only_two_exact_immutable_contexts_and_descriptors(self):
        profile=origin21_profile
        self.assertIs(profile.context_for_profile(profile.PROFILE),profile.STATIC)
        self.assertIs(profile.context_for_bound(profile.MANAGED_BOUND),profile.MANAGED)
        self.assertIs(profile.context_for_capture(profile.MANAGED_BOUND.capture),profile.MANAGED)
        with self.assertRaises(ValueError): profile.require_context(profile.MANAGED._replace())
        with self.assertRaises(ValueError): profile.context_for_profile(profile.MANAGED_PROFILE._replace())
        with self.assertRaises(ValueError): profile.context_for_bound(profile.MANAGED_BOUND._replace())
        self.assertNotEqual(profile.MANAGED.profile.state,profile.STATIC.profile.state)
        self.assertNotEqual(profile.MANAGED.owner,profile.STATIC.owner)
        self.assertNotEqual(profile.MANAGED.edge.parent,profile.STATIC.profile.state.parent)
        self.assertEqual(profile.MANAGED.profile.ingress_login,profile.STATIC.profile.ingress_login)
        with self.assertRaises(AttributeError): profile.MANAGED.project='other'

    def test_managed_setup_refuses_raw_or_mixed_transport_before_operations(self):
        callback=mock.Mock(); evidence=(b'a'*32,b'b'*32)
        with mock.patch.object(origin21_schema,'require_reference') as refs:
            for selected,transport in ((origin21_profile.MANAGED,None),(origin21_profile.MANAGED,object()),(origin21_profile.STATIC,object()),(origin21_profile.MANAGED._replace(),None)):
                with self.subTest(selected=selected,transport=transport):
                    with self.assertRaises(ValueError): origin21_setup.prepare(psql=callback,sensitive_execute=callback,authenticate=callback,inspect_slot=callback,expected_evidence=evidence,selected=selected,transport=transport)
            refs.assert_not_called(); callback.assert_not_called()

    def test_managed_setup_rejects_every_external_inspector_before_verify(self):
        from deploy.local import origin21_transport
        runner=mock.Mock(); transport=origin21_transport.ManagedTransport(origin21_transport._MANAGED_SEAL,runner,{'id':'fixture'},'image','head','receipt','digest')
        evidence=(b'a'*32,b'b'*32)
        with mock.patch.object(origin21_transport.ManagedTransport,'verify') as verify, mock.patch.object(origin21_schema,'require_reference') as refs, mock.patch.object(origin21_credentials,'Credentials') as creds:
            for inspector in (mock.Mock(),origin21_products.inspect_slot,lambda index:origin21_products.inspect_slot(index,selected=origin21_profile.MANAGED)):
                with self.assertRaises(ValueError):
                    origin21_setup.prepare(transport=transport,inspect_slot=inspector,expected_evidence=evidence,selected=origin21_profile.MANAGED)
            verify.assert_not_called(); refs.assert_not_called(); creds.assert_not_called(); runner.run.assert_not_called()

    def test_managed_credentials_require_exact_managed_ca_paths_without_reads(self):
        from deploy.pilot import origin_credentials
        managed=origin21_profile.MANAGED_PROFILE; root=managed.state.parent
        with mock.patch.object(origin_credentials,'_file') as read:
            for cert,key in ((origin21_profile.STATE.parent/'ca.crt',origin21_profile.STATE.parent/'ca.key'),(root/'other.crt',root/'ca.key'),(root/'ca.crt',root/'other.key'),('ca.crt','ca.key'),(root/'../ca.crt',root/'ca.key')):
                with self.subTest(cert=cert,key=key):
                    with self.assertRaises(ValueError): origin21_credentials.Credentials(managed,cert,key)
            value=origin21_credentials.Credentials(managed,root/'ca.crt',root/'ca.key')
            self.assertEqual((value.ca_cert,value.ca_key),(root/'ca.crt',root/'ca.key'))
            origin21_credentials.Credentials(origin21_profile.PROFILE,'relative','still-relative')
            read.assert_not_called()

    def test_managed_transport_rechecks_receipt_owner_and_target_before_sql(self):
        from deploy.local import origin21_transport
        deployment={'name':'managed','id':'i'}; runner=mock.Mock(); runner.target={'id':'i'}
        transport=origin21_transport.ManagedTransport(origin21_transport._MANAGED_SEAL,runner,deployment,'image','head','receipt','digest')
        record={'deployment':deployment,'app_image_id':'image','build_head':'head','build_receipt_sha256':'digest'}
        with mock.patch.object(origin21_products,'_build_receipt',return_value=deployment), mock.patch.object(origin21_products,'_read_record',return_value=record):
            runner.verify_target.side_effect=RuntimeError('target changed')
            with self.assertRaises(RuntimeError): transport.admin('SELECT 1')
            runner.run.assert_not_called()
        with self.assertRaises(AttributeError): transport._image='other'
        with self.assertRaises(ValueError): origin21_transport.ManagedTransport(object(),runner,deployment,'image','head','receipt','digest')

    def test_managed_source_closure_rejects_symlink_without_touching_static(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); source=root/'source'; source.write_bytes(b'fixture')
            with mock.patch.object(origin21_profile,'ROOT',root),mock.patch.object(origin21_state,'MANAGED_SOURCE_FILES',('source',)):
                self.assertEqual(origin21_state._source_snapshot(origin21_profile.MANAGED),{'source':b'fixture'})
                source.unlink(); source.symlink_to('/dev/null')
                with self.assertRaises(ValueError): origin21_state._source_snapshot(origin21_profile.MANAGED)
                with self.assertRaises(ValueError): origin21_state._source_snapshot(origin21_profile.MANAGED._replace())

    def test_managed_compose_requires_network_and_pins_mounted_sources(self):
        from deploy.local import origin21_state
        text=origin21_profile.MANAGED.compose.read_text()
        self.assertIn('${ORIGIN21_CAPTURE_NETWORK:?managed capture network required}',text)
        self.assertNotIn('apicontour-local_default',text)
        for name in ('deploy/pilot/flows-wrong-name.json','deploy/pilot/flows-wrong-ca.json','deploy/pilot/native_edge_probe.js'):
            self.assertIn(name,origin21_state.MANAGED_SOURCE_FILES)
        self.assertNotIn('deploy/pilot/flows-wrong-name.json',origin21_state.SOURCE_FILES)

    def test_managed_product_mounts_and_network_are_separate_and_closed(self):
        context=origin21_profile.MANAGED
        for index in (1,2):
            mounts=origin21_products._mounts(index,selected=context)
            self.assertEqual(mounts['/pilot/native_edge_probe.js'],str(origin21_profile.ROOT/'deploy/pilot/native_edge_probe.js'))
            self.assertEqual(mounts['/pilot/ca.crt'],str(context.profile.state.parent/'ca.crt'))
            self.assertEqual(mounts['/pilot/tls/client.key'],str(context.profile.state/('replica'+str(index))/'client.key'))
            self.assertNotEqual(mounts['/pilot/ca.crt'],origin21_products._mounts(index)['/pilot/ca.crt'])
        members=['a'*64,'b'*64]; token='c'*64; network_id='d'*64
        network={'Name':context.network,'Id':network_id,'Internal':True,'Labels':{'com.docker.compose.project':context.project,'com.docker.compose.network':'default','org.apicontour.origin21.owner':token},'Containers':{x:{} for x in members}}
        with mock.patch.object(origin21_products,'_objects',return_value=network) as inspect:
            self.assertEqual(origin21_products._network(members,token,selected=context),network_id)
            self.assertEqual(inspect.call_args.args[0],['docker','network','inspect',context.network])
            with self.assertRaises(RuntimeError): origin21_products._network(members[:1],token,selected=context)
        with self.assertRaises(ValueError): origin21_products._mounts(1,selected=context._replace())

    def test_managed_envoy_requires_both_owner_labels_before_start(self):
        context=origin21_profile.MANAGED; cid='a'*64; origin='b'*64; edge='c'*32
        image={'id':'sha256:'+'d'*64,'env':['PATH=/bin'],'cmd':None,'entrypoint':['envoy'],'workdir':None}
        mounts={'/certs':'/private/certs','/run/watch':'/private/watch','/run/forwarder':'/private/forwarder'}
        obj={'Id':cid,'Name':'/'+context.project+'-native-envoy-1','Image':image['id'],
             'Config':{'Image':origin21_products.ENVOY,'Labels':{'com.docker.compose.project':context.project,'com.docker.compose.service':'native-envoy','org.apicontour.origin21.owner':origin,'org.apicontour.managed-edge-owner':edge},'User':str(os.getuid())+':'+str(os.getgid()),'Env':['PATH=/bin'],'Cmd':['-c','/run/forwarder/envoy.json','--log-level','error'],'WorkingDir':'','Entrypoint':['envoy']},
             'HostConfig':{'ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'CapAdd':None,'SecurityOpt':['no-new-privileges:true'],'PidMode':'','IpcMode':'private','UTSMode':'','UsernsMode':'','Devices':None,'Memory':256*1024*1024,'NanoCpus':1000000000,'PidsLimit':128,'PortBindings':{},'Tmpfs':{}},
             'Mounts':[{'Destination':k,'Type':'bind','RW':False,'Source':v} for k,v in mounts.items()],'State':{'Running':False}}
        with mock.patch.object(origin21_products,'_managed_edge_token',return_value=edge), mock.patch.object(origin21_products,'_companion_mounts',return_value=mounts):
            origin21_products._validate_companion(obj,'native-envoy',cid,image,origin,'','','capture',running=False,selected=context)
            changed=dict(obj,Config=dict(obj['Config'],Labels=dict(obj['Config']['Labels'],**{'org.apicontour.managed-edge-owner':'f'*32})))
            with self.assertRaises(RuntimeError): origin21_products._validate_companion(changed,'native-envoy',cid,image,origin,'','','capture',running=False,selected=context)

    def test_managed_edge_token_is_exclusive_durable_and_required_for_model(self):
        with tempfile.TemporaryDirectory() as directory:
            edge=Path(directory)/'edge'; context=origin21_profile.MANAGED._replace(edge=edge)
            token='a'*64
            with mock.patch.object(origin21_profile,'MANAGED',context), mock.patch.object(origin21_products,'_command',return_value=b'{}') as command:
                with self.assertRaises((FileNotFoundError,ValueError)):
                    origin21_products._derive_model('products',token,'image','network',selected=context)
                command.assert_not_called()
                edge_token=origin21_products._reserve_managed_edge(context,token)
                self.assertEqual(len(edge_token),32); self.assertNotEqual(edge_token,token)
                self.assertEqual(origin21_products._managed_edge_token(context,token),edge_token)
                self.assertEqual((edge/'intent.json').stat().st_mode & 0o777,0o600)
                for name in ('state','published','watched'): self.assertEqual((edge/name).stat().st_mode & 0o777,0o700)
                with self.assertRaises(FileExistsError): origin21_products._reserve_managed_edge(context,token)
                with self.assertRaises(ValueError): origin21_products._managed_edge_token(context,'b'*64)
                with self.assertRaises(ValueError): origin21_products._derive_model('products',token,'image','network',selected=context)
                self.assertEqual(command.call_args.kwargs['edge_token'],edge_token)

    def test_managed_policy_cas_requires_exact_sensitive_transport(self):
        from deploy.local import origin21_lease,origin21_transport
        capture=origin21_profile.MANAGED_BOUND.capture
        callback=mock.Mock(); runner=mock.Mock(); runner.run.return_value=''
        transport=origin21_transport.ManagedTransport(origin21_transport._MANAGED_SEAL,runner,{'id':'fixture'},'image','head','receipt','digest')
        args=(b'a',1,b'b',2,'start','end',False,capture)
        with mock.patch.object(origin21_lease.p.base,'psql') as fallback, mock.patch.object(origin21_transport.ManagedTransport,'verify') as verify:
            for executor in (None,callback,origin21_transport.sensitive,transport.admin):
                with self.subTest(executor=executor):
                    with self.assertRaises(ValueError): origin21_lease.locked_transaction(*args,executor=executor)
            callback.assert_not_called(); fallback.assert_not_called(); runner.run.assert_not_called(); verify.assert_not_called()
            origin21_lease.locked_transaction(*args,executor=transport.sensitive)
            runner.run.assert_called_once(); self.assertGreaterEqual(verify.call_count,1)
        with mock.patch.object(origin21_lease.p.base,'psql',return_value='') as static_fallback:
            origin21_lease.locked_transaction(b'a',1,b'b',2,'start','end',False,origin21_profile.BOUND.capture)
            static_fallback.assert_called_once()

    def test_runtime_static_default_and_managed_sds_are_separate(self):
        from deploy.pilot import native_envoy
        from deploy.local import origin21_configs
        default=origin21_runtime.configs()
        self.assertEqual(default,origin21_runtime.configs(origin21_profile.PROFILE))
        self.assertEqual(default['envoy'],native_envoy.config(origin_v2=True))
        managed=origin21_runtime.configs(origin21_profile.MANAGED_PROFILE)
        self.assertEqual(managed['envoy'],native_envoy.config(origin_v2=True,managed_edge=True))
        with self.assertRaises(ValueError): origin21_runtime.configs(origin21_profile.MANAGED_PROFILE._replace())
        self.assertNotEqual(origin21_configs.expected()['native/forwarder/envoy.json'],origin21_configs.expected(origin21_profile.MANAGED_PROFILE)['native/forwarder/envoy.json'])


class Origin21Tests(unittest.TestCase):
    def test_companion_record_reobserves_images_across_profiles(self):
        from deploy.local import origin21_managed_controller
        ids=['sha256:'+c*64 for c in 'abc']; token='1'*32; head='2'*40
        image_values=[{'Id':ident,'Config':{'Env':['A=B'],'Cmd':None,'Entrypoint':None,'WorkingDir':None}} for ident in ids]
        metadata=[origin21_products._image_metadata(value) for value in image_values]
        images={name:metadata[1] if name=='destination' else metadata[2] if name=='native-envoy' else metadata[0] for name in origin21_products.COMPANIONS}
        intent={'token':token,'app_image_id':ids[0],'image_id':ids[1],'build_head':head,'build_receipt_sha256':'3'*64,'deployment':{'name':'network'},'model_sha256':'4'*64}
        pending={'version':1,'token':token,'image_id':ids[0],'build_head':head,'build_receipt_sha256':'3'*64,'capture_network':'capture','images':images,'services':list(origin21_products.COMPANIONS),'model_sha256':'5'*64}
        services={name:{'id':str(i)*64,'started_at':'started'} for i,name in enumerate(origin21_products.COMPANIONS,1)}
        record={'version':1,'services':services}; products=['6'*64,'7'*64]; calls=[]
        def command(args,timeout=30):
            if args[:3]==['docker','image','inspect']:
                calls.append(args); return json.dumps(image_values).encode()
            return ' '.join(products+[services[name]['id'] for name in origin21_products.COMPANIONS]).encode()
        def read(name,**kwargs): return pending if name=='companions-intent.json' else record
        with mock.patch.object(origin21_products,'_read_record',side_effect=read),mock.patch.object(origin21_products,'_verify_model'),mock.patch.object(origin21_products.origin21_transport,'_run',side_effect=lambda args,*a,**k:head if args[1]=='rev-parse' else ''),mock.patch.object(origin21_products,'_capture_network',return_value='capture'),mock.patch.object(origin21_products,'_network',return_value='business'),mock.patch.object(origin21_products,'_objects',return_value={}),mock.patch.object(origin21_products,'_validate_companion',return_value={'StartedAt':'started'}),mock.patch.object(origin21_products,'_command',side_effect=command),mock.patch.object(origin21_managed_controller,'verify_recorded_topology'):
            for selected in (origin21_profile.STATIC,origin21_profile.MANAGED):
                self.assertEqual(origin21_products._companion_record(intent,products,selected=selected),'business')
            image_values[1]['Config']['Env']=['A=changed']
            with self.assertRaises(ValueError): origin21_products._companion_record(intent,products,selected=origin21_profile.MANAGED)
        self.assertEqual(len(calls),3)

    def test_companion_images_reject_ambiguous_or_wrong_roles(self):
        ids=['sha256:'+c*64 for c in 'abc']
        intent={'app_image_id':ids[0],'image_id':ids[1]}
        pending={'images':{name:{'id':ids[1] if name=='destination' else ids[2] if name=='native-envoy' else ids[0]} for name in origin21_products.COMPANIONS}}
        values=[{'Id':ident,'Config':{'Env':['A=B']}} for ident in ids]
        invalid=[[],values[:2],values+[values[0]],[values[1],values[0],values[2]],
                 [values[0],values[0],values[2]],[values[0],None,values[2]],
                 [values[0],{'Id':ids[1],'Config':{'Env':['missing-equals']}},values[2]],
                 [values[0],values[1],{'Id':'sha256:'+'d'*64,'Config':{}}]]
        for payload in invalid:
            with self.subTest(payload=payload), mock.patch.object(origin21_products,'_command',return_value=json.dumps(payload).encode()):
                with self.assertRaises((ValueError,RuntimeError)): origin21_products._companion_images(intent,pending)
        with mock.patch.object(origin21_products,'_command',side_effect=RuntimeError('failed CLI')):
            with self.assertRaisesRegex(RuntimeError,'failed CLI'): origin21_products._companion_images(intent,pending)
        for malformed in ({}, {'images':{}}, {'images':{**pending['images'],'native-envoy':{'id':ids[0]}}}):
            with mock.patch.object(origin21_products,'_command') as command:
                with self.assertRaises(ValueError): origin21_products._companion_images(intent,malformed)
                command.assert_not_called()

    def test_companion_images_one_fresh_ordered_observation(self):
        ids=['sha256:'+c*64 for c in 'abc']
        intent={'app_image_id':ids[0],'image_id':ids[1]}
        images={name:{'id':ids[1] if name=='destination' else ids[2] if name=='native-envoy' else ids[0]} for name in origin21_products.COMPANIONS}
        pending={'images':images}
        def objects():
            return [{'Id':ident,'Config':{'Env':['X=1'],'Cmd':['run'],'Entrypoint':['entry'],'WorkingDir':'/work'}} for ident in ids]
        payload=objects(); calls=[]
        def command(args,timeout=30):
            calls.append((args,timeout)); refs=[ids[0],origin21_evidence.IMAGE,origin21_products.ENVOY]
            return json.dumps([payload[refs.index(ref)] for ref in args[3:]]).encode()
        with mock.patch.object(origin21_products,'_command',side_effect=command):
            app,node,envoy=origin21_products._companion_images(intent,pending)
            self.assertEqual([app['id'],node['id'],envoy['id']],ids)
            self.assertEqual(calls,[(['docker','image','inspect',ids[0],origin21_evidence.IMAGE,origin21_products.ENVOY],30)])
            payload[1]['Config']['Env']=['X=changed']
            self.assertEqual(origin21_products._companion_images(intent,pending)[1]['env'],['X=changed'])
            self.assertEqual(len(calls),2)

    def test_compose_models_close_transitive_dependencies_and_detect_drift(self):
        services={name:{'networks':{'default':{}},'volumes':[{'type':'bind','source':'/private/input','target':'/input','read_only':True}]} for name in origin21_products.PRODUCTS+origin21_products.COMPANIONS}
        services['replica1']['depends_on']={'native-envoy':{'condition':'service_started'}}
        services['replica2']['depends_on']={'native-envoy':{'condition':'service_started'}}
        services['native-envoy']['depends_on']={'native-gateway':{'condition':'service_started'}}
        services['native-gateway']['depends_on']={'destination':{'condition':'service_started'},'origin21-capture-ingress':{'condition':'service_started'}}
        for name in ('origin21-capture-ingress','origin21-capture-worker'): services[name]['networks']={'capture':{}}
        services['native-gateway']['networks']={'default':{},'capture':{}}
        full={'name':origin21_products.PROJECT,'services':services,'networks':{'default':{'internal':True},'capture':{'external':True}}}
        products=origin21_products._select_model(full,'products'); companions=origin21_products._select_model(full,'companions')
        self.assertEqual(set(products['services']),set(origin21_products.PRODUCTS)); self.assertEqual(set(products['networks']),{'default'})
        self.assertNotIn('depends_on',products['services']['replica1']); self.assertIn('depends_on',services['replica1'])
        self.assertEqual(set(companions['services']),set(origin21_products.COMPANIONS)); self.assertEqual(set(companions['networks']),{'default','capture'})
        self.assertEqual(set(companions['services']['native-envoy']['depends_on']),{'native-gateway'})
        bad=dict(full,services=dict(services,replica1=dict(services['replica1'],network_mode='service:native-envoy')))
        with self.assertRaises(ValueError): origin21_products._select_model(bad,'products')
        bad=dict(full,services=dict(services,replica1=dict(services['replica1'],depends_on={'foreign':{}})))
        with self.assertRaises(ValueError): origin21_products._select_model(bad,'products')
        token='a'*64; capture='contour-origin21-qual-'+'b'*32
        configured=dict(full,networks={'default':{'name':origin21_products.NETWORK,'internal':True,'labels':{'org.apicontour.origin21.owner':token}},'capture':{'name':capture,'external':True}})
        with mock.patch.object(origin21_products,'_command',return_value=json.dumps(configured).encode()) as command:
            derived=origin21_products._derive_model('products',token,'sha256:'+'c'*64,capture)
            self.assertEqual(set(json.loads(derived)['services']),set(origin21_products.PRODUCTS))
            self.assertEqual(command.call_args.kwargs['capture_network'],capture)
        wrong=dict(configured,networks=dict(configured['networks'],capture={'name':'foreign','external':True}))
        with mock.patch.object(origin21_products,'_command',return_value=json.dumps(wrong).encode()):
            with self.assertRaisesRegex(ValueError,'network identity drift'): origin21_products._derive_model('products',token,'sha256:'+'c'*64,capture)
        raw=json.dumps(products,sort_keys=True,separators=(',',':')).encode(); digest=hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(origin21_products,'OWNER',Path(directory)):
            origin21_products.origin_credentials._write(Path(directory)/'products-model.json',raw)
            self.assertEqual(origin21_products._verify_model('products',digest),Path(directory)/'products-model.json')
            with self.assertRaises(FileExistsError): origin21_products.origin_credentials._write(Path(directory)/'products-model.json',raw)
            (Path(directory)/'products-model.json').write_bytes(raw+b' ')
            with self.assertRaisesRegex(ValueError,'changed'): origin21_products._verify_model('products',digest)

    def test_owner_inspection_refuses_model_drift_before_docker(self):
        intent={'version':1,'project':origin21_products.PROJECT,'image':origin21_evidence.IMAGE,'image_id':'i','image_env':[],'image_cmd':None,'image_workdir':'','token':'t','app_image_id':'a','build_head':'h','build_receipt_sha256':'r','deployment':{},'services':['replica1','replica2'],'model_sha256':'0'*64}
        with tempfile.TemporaryDirectory() as directory:
            owner=Path(directory); os.chmod(owner,0o700); model=owner/'products-model.json'; model.write_bytes(b'changed'); model.chmod(0o600)
            with mock.patch.object(origin21_products,'OWNER',owner), mock.patch.object(origin21_products,'_read_record',side_effect=[intent,{'version':1,'slots':[{},{}]}]), mock.patch.object(origin21_products,'_capture_network') as inspect:
                with self.assertRaisesRegex(ValueError,'model changed'): origin21_products.inspect_slot(1)
                inspect.assert_not_called()

    def test_postgres_init_overlay_is_opt_in_and_source_bound(self):
        path=origin21_profile.ROOT/'deploy/local/origin21-postgres-init.yaml'
        self.assertEqual(path.read_text(), '# Opt-in for Origin21 only; apply alongside deploy/local/compose.yaml.\nservices:\n  postgres:\n    init: true\n')
        self.assertIn('deploy/local/origin21-postgres-init.yaml',origin21_state.SOURCE_FILES)
        result=subprocess.run(['git','diff','--exit-code','HEAD','--','deploy/local/compose.yaml'],cwd=origin21_profile.ROOT,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0)
    def test_supervisor_identity_must_be_persisted_before_payload(self):
        nonce='a'*32; private=b'private request'
        gate=origin21_sql_runner.Handshake(nonce,private)
        with self.assertRaises(RuntimeError): gate.payload()
        for line in (b'READY '+b'b'*32+b' 123 123 456\n', b'READY '+nonce.encode()+b' 123 124 456\n'):
            with self.assertRaises(ValueError): gate.ready(line)
            with self.assertRaises(RuntimeError): gate.payload()
        identity=gate.ready(b'READY '+nonce.encode()+b' 123 123 456\n')
        with self.assertRaises(RuntimeError): gate.payload()
        with self.assertRaises(ValueError): gate.persisted(dict(identity,pid=999))
        gate.persisted(identity)
        self.assertEqual(gate.payload(),private)

    def test_supervisor_unresolved_intent_blocks_restart_and_persists_identity(self):
        target={'container_id':'a'*64,'image_id':'sha256:'+'b'*64,'network_id':'c'*64}
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory,0o700)
            gate=origin21_sql_runner.Handshake('d'*32,b'secret')
            with origin21_sql_runner.IntentStore(directory,target) as store:
                store.begin(gate,'sql','postgres')
                with self.assertRaises(RuntimeError): store.begin(origin21_sql_runner.Handshake('e'*32,b'another'),'sql','postgres')
                store.ready(gate,b'READY '+b'd'*32+b' 101 101 202\n')
                self.assertEqual(gate.payload(),b'secret')
                self.assertNotIn(b'secret',store.path.read_bytes())
            with origin21_sql_runner.IntentStore(directory,target) as store:
                self.assertEqual(store.read()['identity'],{'pid':101,'pgid':101,'starttime':202})
                with self.assertRaises(RuntimeError): store.begin(origin21_sql_runner.Handshake('e'*32,b'another'),'sql','postgres')
                store.remove()
                self.assertIsNone(store.read())

    def test_supervisor_result_is_exactly_framed_and_status_checked(self):
        nonce='a'*32
        status=b'STATUS '+nonce.encode()+b' 0\n'
        output=b'eWVz\nEND '+nonce.encode()+b'\n'
        self.assertEqual(origin21_sql_runner.decode_result(nonce,output,status),'yes')
        for out,err in ((output,b'STATUS '+nonce.encode()+b' 1\n'),(output+b'extra',status),(b'!'+output,status),(output,b'')):
            with self.assertRaises(RuntimeError): origin21_sql_runner.decode_result(nonce,out,err)

    def test_supervisor_fake_process_requires_ready_and_ack(self):
        target={'container_id':'a'*64,'image_id':'sha256:'+'b'*64,'network_id':'c'*64}
        program=('import os,sys,select,base64; n=sys.argv[1]; s=int(sys.argv[2]); '
                 'assert not select.select([sys.stdin.buffer],[],[],.05)[0]; '
                 'print("READY",n,os.getpid(),os.getpgrp(),1,flush=True); '
                 'data=sys.stdin.buffer.read(s); '
                 'sys.stdout.buffer.write(base64.b64encode(data)+b"\\nEND "+n.encode()+b"\\n"); sys.stdout.flush(); '
                 'print("STATUS",n,0,file=sys.stderr,flush=True); '
                 'assert sys.stdin.buffer.read(4)==b"ACK!"')
        def launch(nonce,mode,role,size):
            return subprocess.Popen([sys.executable,'-u','-c',program,nonce,str(size)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory,0o700)
            cleanup=mock.Mock(return_value=True)
            runner=origin21_sql_runner.Runner(directory,target,lambda _:None,cleanup,launch)
            self.assertEqual(runner.run(b'example','sql','postgres',deadline=5),'example')
            cleanup.assert_not_called()
            self.assertFalse((Path(directory)/'pending.json').exists())

    def test_supervisor_failed_cleanup_keeps_intent_across_restart(self):
        target={'container_id':'a'*64,'image_id':'sha256:'+'b'*64,'network_id':'c'*64}
        program=('import os,sys,time; n=sys.argv[1]; '
                 'print("READY",n,os.getpid(),os.getpgrp(),1,flush=True); '
                 'sys.stdin.buffer.read(int(sys.argv[2])); time.sleep(5)')
        def launch(nonce,mode,role,size):
            return subprocess.Popen([sys.executable,'-u','-c',program,nonce,str(size)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory,0o700)
            cleanup=mock.Mock(return_value=False)
            runner=origin21_sql_runner.Runner(directory,target,lambda _:None,cleanup,launch)
            with self.assertRaises(RuntimeError): runner.run(b'private','sql','postgres',deadline=1)
            self.assertTrue((Path(directory)/'pending.json').exists())
            self.assertEqual(cleanup.call_count,1)
            with self.assertRaisesRegex(RuntimeError,'cleanup unresolved'): runner.run(b'next','sql','postgres',deadline=1)
            self.assertEqual(cleanup.call_count,2)
            cleanup.return_value=True
            with self.assertRaises(RuntimeError): runner.run(b'next','sql','postgres',deadline=1)
            self.assertEqual(cleanup.call_count,4)
            self.assertFalse((Path(directory)/'pending.json').exists())

    def test_supervisor_before_ready_timeout_never_sends_payload_or_retries(self):
        target={'container_id':'a'*64,'image_id':'sha256:'+'b'*64,'network_id':'c'*64}
        def launch(nonce,mode,role,size):
            return subprocess.Popen([sys.executable,'-u','-c','import time; time.sleep(5)'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory,0o700)
            cleanup=mock.Mock(return_value=True)
            runner=origin21_sql_runner.Runner(directory,target,lambda _:None,cleanup,launch)
            with self.assertRaises(RuntimeError): runner.run(b'private','sql','postgres',deadline=1)
            cleanup.assert_not_called()
            with self.assertRaisesRegex(RuntimeError,'pre-READY'): runner.run(b'next','sql','postgres',deadline=1)

    def test_cleanup_refuses_unmatched_process_identity(self):
        if not os.path.exists('/proc/self/stat'): self.skipTest('Linux procfs required')
        process=subprocess.Popen([sys.executable,'-c','import time; time.sleep(5)'],start_new_session=True)
        try:
            result=subprocess.run(['sh','-c',origin21_sql_runner.CLEANUP,'cleanup','a'*32,str(process.pid),str(process.pid),'1','sql','postgres'],capture_output=True,timeout=3)
            self.assertNotEqual(result.returncode,0)
            self.assertIsNone(process.poll())
        finally:
            process.terminate(); process.wait(timeout=3)

    def test_supervisor_rejects_late_output_and_final_drain_timeout(self):
        target={'container_id':'a'*64,'image_id':'sha256:'+'b'*64,'network_id':'c'*64}
        prefix=('import os,sys,time; n=sys.argv[1]; '
                'print("READY",n,os.getpid(),os.getpgrp(),1,flush=True); '
                'sys.stdin.buffer.read(int(sys.argv[2])); '
                'sys.stdout.write("eWVz\\nEND "+n+"\\n"); sys.stdout.flush(); '
                'print("STATUS",n,0,file=sys.stderr,flush=True); sys.stdin.buffer.read(4); ')
        for suffix in ('print("late",flush=True)', 'time.sleep(5)'):
            def launch(nonce,mode,role,size):
                return subprocess.Popen([sys.executable,'-u','-c',prefix+suffix,nonce,str(size)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            with tempfile.TemporaryDirectory() as directory:
                os.chmod(directory,0o700)
                cleanup=mock.Mock(return_value=False)
                runner=origin21_sql_runner.Runner(directory,target,lambda _:None,cleanup,launch)
                with self.assertRaises(RuntimeError): runner.run(b'example','sql','postgres',deadline=1)
                self.assertTrue((Path(directory)/'pending.json').exists())
                cleanup.assert_called_once()

    def test_supervisor_rejects_output_between_validation_and_ack(self):
        import select
        target={'container_id':'a'*64,'image_id':'sha256:'+'b'*64,'network_id':'c'*64}
        release_read,release_write=os.pipe()
        program=('import os,sys; n=sys.argv[1]; '
                 'print("READY",n,os.getpid(),os.getpgrp(),1,flush=True); '
                 'sys.stdin.buffer.read(int(sys.argv[2])); '
                 'print("eWVz\\nEND "+n,flush=True); '
                 'print("STATUS",n,0,file=sys.stderr,flush=True); '
                 'os.read(int(sys.argv[3]),1); print("late",flush=True); sys.stdin.buffer.read(4)')
        current=[]
        def launch(nonce,mode,role,size):
            child=subprocess.Popen([sys.executable,'-u','-c',program,nonce,str(size),str(release_read)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,pass_fds=(release_read,))
            current.append(child); return child
        original=origin21_sql_runner.decode_result
        def release(*args):
            value=original(*args); os.write(release_write,b'x')
            self.assertTrue(select.select([current[0].stdout],[],[],2)[0])
            return value
        try:
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(origin21_sql_runner,'decode_result',side_effect=release):
                os.chmod(directory,0o700); cleanup=mock.Mock(return_value=False)
                with self.assertRaises(RuntimeError): origin21_sql_runner.Runner(directory,target,lambda _:None,cleanup,launch).run(b'example','sql','postgres',deadline=4)
                cleanup.assert_called_once()
                self.assertTrue((Path(directory)/'pending.json').exists())
        finally:
            os.close(release_read); os.close(release_write)

    def test_cleanup_scope_and_recorded_role_are_closed(self):
        for required in ("usename='$role'", "backend_type='client backend'", 'client_addr IS NULL', "'127.0.0.1'::pg_catalog.inet", "'::1'::pg_catalog.inet", 'group_absent'):
            self.assertIn(required,origin21_sql_runner.CLEANUP)
        for mode,role in (('sql','other'),('auth','postgres'),('other',origin21_profile.PROFILE.ingress_login)):
            with self.assertRaises(ValueError): origin21_sql_runner._validate_mode_role(mode,role)

    def test_cleanup_absent_group_and_reused_group_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); proc=root/'proc'; proc.mkdir(); commands=root/'bin'; commands.mkdir()
            log=root/'sql'; killed=root/'killed'
            for name,script in {
                'timeout':'#!/bin/sh\nshift 2\nexec "$@"\n',
                'psql':'#!/bin/sh\nprintf "%s\\n" "$*" >> "$TEST_SQL"\ncase "$*" in *"SELECT count(*)"*) echo 0;; esac\n',
                'kill':'#!/bin/sh\ntouch "$TEST_KILLED"\n',
            }.items():
                path=commands/name; path.write_text(script); path.chmod(0o700)
            script=origin21_sql_runner.CLEANUP.replace('/proc/',str(proc)+'/').replace('/bin/kill',str(commands/'kill'))
            env=dict(os.environ,PATH=str(commands)+':'+os.environ['PATH'],TEST_SQL=str(log),TEST_KILLED=str(killed))
            args=['sh','-c',script,'cleanup','a'*32,'90001','90001','100','sql','postgres']
            result=subprocess.run(args,capture_output=True,env=env,timeout=5)
            self.assertEqual((result.returncode,result.stdout),(0,b'CLEAN\n'))
            self.assertFalse(killed.exists())
            queries=log.read_text(); self.assertIn("usename='postgres'",queries); self.assertIn('client_addr IS NULL',queries)
            log.unlink(); member=proc/'90002'; member.mkdir(); (member/'stat').write_text('90002 (other) S 1 90001 0\n')
            result=subprocess.run(args,capture_output=True,env=env,timeout=5)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(log.exists()); self.assertFalse(killed.exists())

    def test_migration_guard_holds_table_lock_without_preheld_advisory_lock(self):
        for version in range(15,22):
            statements=[]
            with mock.patch.object(origin21_setup,'_guard',return_value='SELECT 42;'):
                origin21_setup.Migration(statements.append,version,b'BEGIN; SELECT 1; COMMIT;',{}).apply()
            self.assertEqual(statements,['BEGIN; LOCK TABLE contour.schema_migrations IN ACCESS EXCLUSIVE MODE; SELECT 42; SELECT 1; COMMIT;'])
            self.assertNotIn('pg_advisory',statements[0])

    def test_capture_qualification_correlates_each_record_and_proof(self):
        p=origin21_profile.PROFILE; slot=p.origins[0]; evidence=b'a'*32; leaf='b'*64; revision=7
        def row(direction):
            shape={'kind':'object','fields':{'probe':{'kind':'boolean'}},'additional':None} if direction=='request' else {'kind':'object','fields':{'result':{'kind':'string'}},'additional':None}
            rid='record-'+direction
            return [rid,p.source,*provision.IDS[1:],p.deployment,direction,None if direction=='request' else '200',shape,leaf,slot.instance,slot.lifecycle,slot.credential,slot.grant,evidence.hex(),rid,'complete','structure',None if direction=='request' else 200,shape,[*provision.IDS,'http',direction,'POST','/pilot'],'proof','proof',*provision.IDS[1:],slot.deployment,slot.instance,*provision.IDS[1:],slot.deployment,'http_json_v1',revision,p.source,*provision.IDS[1:],p.deployment,1,1,1,False,'http_json_v1',revision,[]]
        rows=[row('request'),row('response')]
        self.assertTrue(origin21_ready.validate_fresh(rows,set(),1,leaf,evidence,revision))
        for index,wrong in ((7,'500'),(14,'0'*64),(22,'other-proof'),(28,'other-project'),(44,99)):
            modified=[list(value) for value in rows]; modified[0][index]=wrong
            with self.assertRaises(RuntimeError): origin21_ready.validate_fresh(modified,set(),1,leaf,evidence,revision)
        missing=[list(value) for value in rows]; missing[0][15]=None
        self.assertFalse(origin21_ready.validate_fresh(missing,set(),1,leaf,evidence,revision))
        with self.assertRaises(RuntimeError): origin21_ready.validate_fresh(rows+[row('request')],set(),1,leaf,evidence,revision)

    def test_capture_snapshot_rejects_unbounded_or_duplicate_results(self):
        with self.assertRaises(RuntimeError): origin21_ready.snapshot(lambda _: 'x'*(8*1024*1024+1))
        row=['duplicate']+[None]*45
        with self.assertRaises(RuntimeError): origin21_ready.snapshot(lambda _: json.dumps([row,row]))

    def test_profile_is_distinct_and_fixed(self):
        new=origin21_profile.PROFILE; old=capture_profiles.ORIGIN_PILOT
        self.assertNotEqual(new.state,old.state)
        self.assertNotEqual(new.state,capture_profiles.PILOT.capture)
        self.assertNotIn(new.ingress_login,(old.ingress_login,old.worker_login))
        self.assertNotIn(new.worker_login,(old.ingress_login,old.worker_login,new.ingress_login))
        ids=[new.collector,new.source,new.deployment,new.instance,new.nonce]
        ids += [value for slot in new.origins for value in slot[:5]]
        old_ids=[old.capture.collector,old.capture.source,old.capture.deployment,old.capture.instance,old.capture.nonce]
        old_ids += [value for slot in old.origins for value in slot[:5]]
        self.assertEqual(len(ids),len(set(ids)))
        self.assertTrue(set(ids).isdisjoint(old_ids))
        self.assertTrue(all(slot.leaf_der.is_relative_to(new.state) for slot in new.origins))
        self.assertEqual(len(origin21_state._identity(new)),64)
        with self.assertRaises(ValueError): capture_profiles.select(new.name)

    def test_runtime_configuration_uses_existing_tenant_and_separate_origin(self):
        profile=origin21_profile.PROFILE
        result=origin21_runtime.configs()
        gateway=result['gateway']; ingress=result['capture']['ingress.json']; worker=result['capture']['worker.json']
        from deploy.local import provision
        self.assertEqual(gateway['tenant'],provision.IDS[0])
        self.assertEqual(gateway['workload'],[*provision.IDS[1:],profile.deployment])
        self.assertEqual((gateway['collector'],gateway['source']),(profile.collector,profile.source))
        self.assertEqual(gateway['capture_wire_version'],'v2')
        self.assertEqual(ingress['ingestion_profile'],'origin_v2')
        self.assertEqual((ingress['database_user'],worker['database_user']),(profile.ingress_login,profile.worker_login))
        route=result['envoy']['static_resources']['listeners'][0]['filter_chains'][0]['filters'][0]['typed_config']['route_config']
        self.assertEqual(route['request_headers_to_add'][0]['header']['value'],'%DOWNSTREAM_PEER_FINGERPRINT_256%')
        with self.assertRaises(ValueError): origin21_runtime.configs(capture_profiles.ORIGIN_PILOT)

    def test_versioned_credentials_and_login_adapter_are_closed(self):
        profile=origin21_profile.PROFILE
        credentials=origin21_credentials.Credentials(profile,'/not-read/ca','/not-read/key')
        self.assertIs(credentials.profile,profile)
        with self.assertRaises(ValueError): origin21_credentials.Credentials(capture_profiles.ORIGIN_PILOT,'x','y')
        query=mock.Mock(return_value='EXACT'); secret_executor=mock.Mock(); auth=mock.Mock(return_value=True)
        logins=origin21_logins.Logins(profile,query,secret_executor,auth)
        with mock.patch.object(logins,'_password',side_effect=lambda name: 'synthetic-'+name):
            self.assertEqual(logins.inspect(),origin21_state.EXACT)
            logins.apply()
        self.assertEqual(auth.call_count,2)
        self.assertEqual({call.args[0] for call in auth.call_args_list},{profile.ingress_login,profile.worker_login})
        sql=secret_executor.call_args.args[0]
        self.assertIn(profile.ingress_login,sql); self.assertIn(profile.worker_login,sql)
        self.assertNotIn('contour_local_origin_ingress',sql); self.assertNotIn('contour_local_origin_worker',sql)
        self.assertNotIn('synthetic-ingress',sql); self.assertNotIn('synthetic-worker',sql)
        with self.assertRaises(ValueError): origin21_logins.Logins(capture_profiles.ORIGIN_PILOT,query,secret_executor,auth)
        with self.assertRaises(ValueError): origin21_logins.Logins(profile,query,query,auth)
        auth.return_value=False
        with mock.patch.object(logins,'_password',return_value='synthetic'):
            self.assertEqual(logins.inspect(),origin21_state.DRIFT)

    def test_exact_ledger_and_reference_missing_fail_closed(self):
        for versions in ([],list(range(1,15)),list(range(1,18)),list(range(1,21)),list(range(1,23)),list(range(1,21))+[True]):
            with self.assertRaises(ValueError): origin21_schema.require_ledger(versions)
        origin21_schema.require_ledger(list(range(1,22)))
        with mock.patch.object(origin21_schema,'REFERENCE_SHA256',{(n,'pre'):None for n in range(14,22)} | {(14,'groups'):None,(21,'enrolled'):None}):
            with self.assertRaisesRegex(RuntimeError,'reference and comparator not installed'):
                origin21_schema.require_ready(list(range(1,22)),lambda _:self.fail('SQL must not run'))
            for stage in range(14,22):
                origin21_schema.require_ledger(list(range(1,stage+1)),stage)
                with self.assertRaises(RuntimeError): origin21_schema.require_reference(stage,'pre')
            with self.assertRaises(RuntimeError): origin21_schema.require_reference(14,'groups')
            with self.assertRaises(ValueError): origin21_schema.require_reference(20,'enrolled')
            with self.assertRaises(RuntimeError): origin21_schema.require_reference(21,'enrolled')

    def test_reference_digest_tuple_canonical_and_exact_comparison(self):
        inventory={'version':1,'server_major':16,'items':[{'kind':'role','value':{'name':'contour_owner'}}]}
        def encode(stage,phase):
            return (json.dumps({'stage':stage,'phase':phase,'inventory':inventory},sort_keys=True,separators=(',',':'))+'\n').encode()
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'ref.json'; raw=encode(21,'pre'); path.write_bytes(raw)
            pins={(21,'pre'):hashlib.sha256(raw).hexdigest()}
            with mock.patch.object(origin21_schema,'REFERENCE_SHA256',pins), mock.patch.object(origin21_schema,'reference_path',return_value=path):
                psql=mock.Mock(side_effect=['contour_local',json.dumps(inventory)])
                origin21_schema.require_ready(list(range(1,22)),psql)
                self.assertEqual(psql.call_count,2)
                bad=dict(inventory,items=[])
                with self.assertRaisesRegex(RuntimeError,'catalog drift'):
                    origin21_schema.require_ready(list(range(1,22)),mock.Mock(side_effect=['contour_local',json.dumps(bad)]))
                with self.assertRaisesRegex(RuntimeError,'wrong local database'):
                    origin21_schema.require_ready(list(range(1,22)),mock.Mock(return_value='elsewhere'))
                path.write_bytes(raw+b' ')
                with self.assertRaisesRegex(ValueError,'digest mismatch'): origin21_schema.require_reference()
            raw=encode(20,'pre'); path.write_bytes(raw)
            with mock.patch.object(origin21_schema,'REFERENCE_SHA256',{(21,'pre'):hashlib.sha256(raw).hexdigest()}), mock.patch.object(origin21_schema,'reference_path',return_value=path):
                with self.assertRaisesRegex(ValueError,'reference identity'): origin21_schema.require_reference()

    def test_inventory_is_metadata_only_and_closed(self):
        sql=origin21_schema.inventory_sql()
        for table in ('pg_catalog.pg_class','pg_catalog.pg_attribute','pg_catalog.pg_constraint','pg_catalog.pg_trigger','pg_catalog.pg_policy','pg_catalog.pg_proc','pg_catalog.pg_type','pg_catalog.pg_roles','pg_catalog.pg_auth_members','pg_catalog.pg_db_role_setting','pg_catalog.pg_default_acl','pg_catalog.pg_rewrite'):
            self.assertIn(table,sql)
        for secret in ('rolpassword','pg_authid','signed_envelope','checked_batch'):
            self.assertNotIn(secret,sql)
        self.assertIn("ORDER BY kind,value::text",sql)
        for marker in ('internal_trigger','t.tgenabled','t.tgisinternal','t.tgconstraint','rule','rw.ev_enabled','pg_catalog.pg_get_ruledef','reloptions',"'f','c'","p.prokind='a'",'d.setrole=0 AND d.setdatabase'):
            self.assertIn(marker,sql)
        self.assertNotIn("'name',t.tgname,'enabled',t.tgenabled,'internal'",sql)

    def test_missing_reference_blocks_before_state_or_callbacks(self):
        operations={phase:mock.Mock() for phase in origin21_state.PHASES}
        with mock.patch.object(origin21_schema,'REFERENCE_SHA256',{(n,'pre'):None for n in range(14,22)} | {(14,'groups'):None,(21,'enrolled'):None}), mock.patch.object(origin21_state.capture_renew,'safe_dir') as directory:
            with self.assertRaises(RuntimeError): origin21_state.run(origin21_profile.PROFILE,operations)
            directory.assert_not_called()
        for op in operations.values(): op.inspect.assert_not_called(); op.apply.assert_not_called()
        with self.assertRaises(ValueError): origin21_state.run(capture_profiles.ORIGIN_PILOT,operations)

    def test_journal_rejects_old_descriptor_source_and_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'setup.json'; state=dict(version=1,descriptor='new',source='current',completed=0,pending=None,credential_digest=None,evidence_digest=None)
            origin21_state._initial(path,state)
            self.assertEqual(origin21_state._read(path,'new','current'),state)
            for identity,source in [('old','current'),('new','old')]:
                with self.assertRaises(ValueError): origin21_state._read(path,identity,source)
            state['pending']='migration_15'; path.write_bytes(origin21_state._encode(state)); os.chmod(path,0o600)
            with self.assertRaises(ValueError): origin21_state._read(path,'new','current')
            path.write_bytes(b'{"version":1,"version":1}'); os.chmod(path,0o600)
            with self.assertRaises(ValueError): origin21_state._read(path,'new','current')

    def test_closed_cli_never_accepts_unknown_modes_or_starts_on_invalid_evidence(self):
        with mock.patch.object(origin21_cli.os,'getuid',return_value=1000), mock.patch.object(origin21_cli.os,'umask'), mock.patch.object(origin21_setup,'prepare') as prepare:
            for args in ([],['enroll','bad','bad'],['renew','0'*64],['products'],['other']):
                with self.assertRaises(ValueError): origin21_cli.main(args)
            prepare.assert_not_called()
            self.assertEqual(origin21_cli.main(['enroll','a'*64,'b'*64]),'enroll reconciled')
            self.assertEqual(prepare.call_args.kwargs['expected_evidence'],(bytes.fromhex('a'*64),bytes.fromhex('b'*64)))
            self.assertFalse(prepare.call_args.kwargs['renew'])

    def test_local_transport_keeps_secrets_out_of_process_arguments(self):
        role=origin21_profile.PROFILE.ingress_login; password='s'*32
        runner=mock.Mock(); runner.run.return_value=role
        with mock.patch.object(origin21_sql_runner,'production',return_value=runner):
            self.assertTrue(origin21_transport.authenticate(role,password))
            self.assertEqual(runner.run.call_args.args,(password.encode(),'auth',role))
            self.assertIn('PGSSLMODE=verify-full',origin21_sql_runner.SUPERVISOR)
            self.assertIn('PGSSLROOTCERT=/run/local-ca.crt',origin21_sql_runner.SUPERVISOR)
        runner.run.return_value=''
        with mock.patch.object(origin21_sql_runner,'production',return_value=runner):
            origin21_transport.sensitive('SELECT 1;')
            data,mode,login=runner.run.call_args.args
            self.assertEqual((mode,login),('sql','postgres'))
            self.assertTrue(data.startswith(origin21_transport.GUARD.encode())); self.assertTrue(data.endswith(b'SELECT 1;'))
        with mock.patch.object(origin21_sql_runner,'production') as run:
            with self.assertRaises(ValueError): origin21_transport.authenticate('contour_local_origin_ingress',password)
            with self.assertRaises(ValueError): origin21_transport.authenticate(role,'x:bad')
            run.assert_not_called()

    def test_explicit_business_start_is_readonly_and_reference_gated(self):
        self.assertEqual(up.provision_script([]),origin21_profile.ROOT/'deploy/local/provision.py')
        self.assertEqual(up.provision_script(['--origin21']),origin21_profile.ROOT/'deploy/local/origin21_provision.py')
        with self.assertRaises(ValueError): up.provision_script(['--origin21','extra'])
        with mock.patch.object(origin21_schema,'REFERENCE_SHA256',{(21,'enrolled'):None}), mock.patch.object(origin21_provision.provision,'psql') as sql, mock.patch.object(origin21_provision.provision,'private_file') as private:
            with self.assertRaises(RuntimeError): origin21_provision.main()
            sql.assert_not_called(); private.assert_not_called()

    def test_onboarding_blocks_before_callbacks_when_reference_missing(self):
        psql=mock.Mock(); sensitive=mock.Mock(); authenticate=mock.Mock()
        with mock.patch.object(origin21_schema,'REFERENCE_SHA256',{(n,'pre'):None for n in range(14,22)} | {(14,'groups'):None,(21,'enrolled'):None}), self.assertRaisesRegex(RuntimeError,'reference and comparator not installed'):
            origin21_setup.prepare(psql=psql,sensitive_execute=sensitive,authenticate=authenticate,inspect_slot=mock.Mock(),expected_evidence=(b'a'*32,b'b'*32))
        psql.assert_not_called(); sensitive.assert_not_called(); authenticate.assert_not_called()
        with self.assertRaises(ValueError): origin21_setup.prepare(psql=psql,sensitive_execute=psql,authenticate=authenticate,inspect_slot=mock.Mock(),expected_evidence=(b'a'*32,b'b'*32))

    def test_groups_atomic_guard_and_migration_refusal(self):
        psql=mock.Mock(); context={'login':False}
        with mock.patch.object(origin21_setup,'_guard',return_value='GUARD;'):
            origin21_setup.Groups(psql,context).apply()
        sql=psql.call_args.args[0]
        self.assertEqual(sql.count('BEGIN;'),1); self.assertEqual(sql.count('COMMIT;'),1)
        self.assertIn('GUARD;',sql); self.assertIn('CREATE ROLE contour_v2_ingress',sql); self.assertIn('CREATE ROLE contour_origin_ingress',sql)
        before=psql.call_count
        migration=origin21_setup.Migration(psql,15,b'BEGIN; COMMIT; COMMIT;',context)
        with self.assertRaises(ValueError): migration.apply()
        self.assertEqual(psql.call_count,before)
        with mock.patch.object(origin21_setup,'_ledger',return_value=14), mock.patch.object(origin21_setup,'_check',return_value=False):
            self.assertEqual(origin21_setup.Migration(psql,15,b'BEGIN; COMMIT;',context).inspect(),origin21_state.DRIFT)

    def test_exact_reference_guard_handles_sql_quotes_and_dollar_quotes(self):
        with mock.patch.object(origin21_schema,'require_reference',return_value={'function':"a' $$ b"}), mock.patch.object(origin21_schema,'inventory_sql',return_value='SELECT 1;'):
            sql=origin21_setup._guard(14,'pre')
            self.assertIn("a'' $$ b",sql)
            self.assertIn('$origin21_guard$',sql)
        with mock.patch.object(origin21_schema,'require_reference',return_value={'bad':'$origin21_guard$'}), mock.patch.object(origin21_schema,'inventory_sql',return_value='SELECT 1;'):
            with self.assertRaises(ValueError): origin21_setup._guard(14,'pre')

    def test_versioned_lease_rejects_old_profile_before_executor(self):
        from deploy.local import origin21_lease
        callback=mock.Mock()
        with self.assertRaises(ValueError): origin21_lease.locked_transaction(b'a',1,b'b',2,'start','end',True,capture_profiles.ORIGIN_PILOT.capture,executor=callback)
        callback.assert_not_called()

    def test_product_inspection_requires_owned_exact_runtime(self):
        cid='a'*64; image='sha256:'+'b'*64; token='c'*64; net='d'*64
        obj={'Id':cid,'Name':'/'+origin21_products.PROJECT+'-replica1-1','Image':image,'Config':{'Image':origin21_evidence.IMAGE,
            'Labels':{'com.docker.compose.project':origin21_products.PROJECT,'com.docker.compose.service':'replica1','org.apicontour.origin21.owner':token},
            'User':str(os.getuid())+':'+str(os.getgid()),'Cmd':None,'WorkingDir':'/work','Entrypoint':['node','/usr/src/node-red/node_modules/node-red/red.js','--userDir','/data','--settings','/pilot/settings.js'],
            'Env':['PATH=/bin','PILOT_TARGET=https://pilot-gateway:9443/pilot','PILOT_TLS_TEST=normal']},
            'HostConfig':{'NetworkMode':origin21_products.NETWORK,'ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true'],
            'Privileged':False,'CapAdd':None,'PidMode':'','IpcMode':'private','UTSMode':'','UsernsMode':'','Devices':None,
            'Tmpfs':{'/data':'rw,nosuid,nodev,noexec,size=16m,mode=1777','/tmp':'rw,nosuid,nodev,noexec,size=16m,mode=1777'},
            'Memory':256*1024*1024,'NanoCpus':1_000_000_000,'PidsLimit':128,'PortBindings':{}},
            'State':{'Running':True,'StartedAt':'2026-11-07T12:00:00.123456789Z'},
            'NetworkSettings':{'Networks':{origin21_products.NETWORK:{'NetworkID':net}}},
            'Mounts':[{'Destination':'/pilot/test','Type':'bind','RW':False,'Source':'/private/fixture'}]}
        with mock.patch.object(origin21_products,'_mounts',return_value={'/pilot/test':'/private/fixture'}):
            origin21_products.validate(obj,1,cid,image,['PATH=/bin'],None,'/work',token,running=True)
            for field in ('Id','Image'):
                bad=dict(obj,**{field:'wrong'})
                with self.assertRaises(RuntimeError): origin21_products.validate(bad,1,cid,image,['PATH=/bin'],None,'/work',token,running=True)
            bad=dict(obj,HostConfig=dict(obj['HostConfig'],ReadonlyRootfs=False))
            with self.assertRaises(RuntimeError): origin21_products.validate(bad,1,cid,image,['PATH=/bin'],None,'/work',token,running=True)
            bad=dict(obj,Mounts=[dict(obj['Mounts'][0],RW=True)])
            with self.assertRaises(RuntimeError): origin21_products.validate(bad,1,cid,image,['PATH=/bin'],None,'/work',token,running=True)
            with self.assertRaises(RuntimeError): origin21_products.validate(obj,1,cid,image,['PATH=/bin'],None,'/work','e'*64,running=True)
        network={'Id':net,'Name':origin21_products.NETWORK,'Internal':True,
            'Labels':{'com.docker.compose.project':origin21_products.PROJECT,'com.docker.compose.network':'default','org.apicontour.origin21.owner':token},'Containers':{cid:{}}}
        with mock.patch.object(origin21_products,'_objects',return_value=network):
            self.assertEqual(origin21_products._network([cid],token),net)
            with self.assertRaises(RuntimeError): origin21_products._network([cid,'f'*64],token)
            with self.assertRaises(RuntimeError): origin21_products._network([cid],'e'*64)

    def test_product_creation_rejects_collisions_and_retains_ambiguous_intent(self):
        with tempfile.TemporaryDirectory() as temp:
            owner=Path(temp)/'products'; calls=[]
            def collision(args,*a,**k):
                calls.append(args)
                if args[1:3]==['ps','-aq']: return b'foreign-container'
                return b''
            with mock.patch.object(origin21_products,'OWNER',owner), mock.patch.object(origin21_products,'_identity_ready'), mock.patch.object(origin21_products,'_build_receipt',return_value={'name':'synthetic'}), mock.patch.object(origin21_products,'_capture_network'), mock.patch.object(origin21_products,'_command',side_effect=collision):
                with self.assertRaisesRegex(ValueError,'project already exists'): origin21_products.start_products(app_image_id='sha256:'+'a'*64,build_head='b'*40,build_receipt='/not-read',build_receipt_sha256='c'*64)
                self.assertFalse(owner.exists())
            calls=[]
            def ambiguous(args,*a,**k):
                calls.append(args)
                if args[:2]==['docker','compose']: raise RuntimeError('ambiguous creation')
                return b''
            model=json.dumps({'name':origin21_products.PROJECT,'services':{x:{'networks':{'default':{}}} for x in origin21_products.PRODUCTS},'networks':{'default':{}}},sort_keys=True,separators=(',',':')).encode()
            with mock.patch.object(origin21_products,'OWNER',owner), mock.patch.object(origin21_products,'_identity_ready'), mock.patch.object(origin21_products,'_build_receipt',return_value={'name':'synthetic'}), mock.patch.object(origin21_products,'_capture_network'), mock.patch.object(origin21_products,'_derive_model',return_value=model), mock.patch.object(origin21_products,'_command',side_effect=ambiguous), mock.patch.object(origin21_products,'_image_id',return_value=('sha256:'+'a'*64,[],None,'')):
                with self.assertRaisesRegex(RuntimeError,'ambiguous creation'): origin21_products.start_products(app_image_id='sha256:'+'a'*64,build_head='b'*40,build_receipt='/not-read',build_receipt_sha256='c'*64)
                self.assertTrue((owner/'intent.json').is_file()); self.assertFalse((owner/'products.json').exists())
                create=next(args for args in calls if args[:2]==['docker','compose'])
                self.assertNotIn('--no-deps',create); self.assertEqual(create[-2:],list(origin21_products.PRODUCTS))
                self.assertTrue((owner/'products-model.json').is_file())
                self.assertFalse(any('rm' in args for args in calls))
                count=len(calls)
                with self.assertRaisesRegex(ValueError,'ownership state already exists'): origin21_products.start_products(app_image_id='sha256:'+'a'*64,build_head='b'*40,build_receipt='/not-read',build_receipt_sha256='c'*64)
                self.assertEqual(len(calls),count)

    def test_companion_inspection_requires_exact_fixed_image_and_network(self):
        cid='a'*64; token='c'*64; node='d'*64; cap='e'*64
        image={'id':'sha256:'+'f'*64,'env':['PATH=/bin'],'cmd':None,'entrypoint':None,'workdir':'/work'}
        obj={'Id':cid,'Name':'/'+origin21_products.PROJECT+'-native-gateway-1','Image':image['id'],
            'Config':{'Image':image['id'],'Labels':{'com.docker.compose.project':origin21_products.PROJECT,'com.docker.compose.service':'native-gateway','org.apicontour.origin21.owner':token},
                'User':str(os.getuid())+':'+str(os.getgid()),'Env':['PATH=/bin'],'Cmd':None,'WorkingDir':'/work','Entrypoint':['/usr/local/bin/local_gateway','/run/native/gateway.json']},
            'HostConfig':{'ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'CapAdd':None,'SecurityOpt':['no-new-privileges:true'],
                'PidMode':'','IpcMode':'private','UTSMode':'','UsernsMode':'','Devices':None,'Memory':256*1024*1024,'NanoCpus':1_000_000_000,'PidsLimit':128,'PortBindings':{},'Tmpfs':{}},
            'Mounts':[{'Destination':'/run/native','Type':'bind','RW':False,'Source':'/private/fixture'}],
            'State':{'Running':True,'StartedAt':'2026-11-07T12:00:00Z'},
            'NetworkSettings':{'Networks':{origin21_products.NETWORK:{'NetworkID':node},'apicontour-local_default':{'NetworkID':cap}}}}
        with mock.patch.object(origin21_products,'_companion_mounts',return_value={'/run/native':'/private/fixture'}):
            origin21_products._validate_companion(obj,'native-gateway',cid,image,token,node,cap,'apicontour-local_default',running=True)
            unset=dict(image,workdir=None); empty=dict(obj,Config=dict(obj['Config'],WorkingDir=''))
            origin21_products._validate_companion(empty,'native-gateway',cid,unset,token,node,cap,'apicontour-local_default',running=True)
            for expected,actual in ((None,'/unexpected'),('/work',''),('/work','/other'),(42,'')):
                mismatch=dict(obj,Config=dict(obj['Config'],WorkingDir=actual))
                with self.assertRaises(RuntimeError): origin21_products._validate_companion(mismatch,'native-gateway',cid,dict(image,workdir=expected),token,node,cap,'apicontour-local_default',running=True)
            bad=dict(obj,Image='sha256:'+'1'*64)
            with self.assertRaises(RuntimeError): origin21_products._validate_companion(bad,'native-gateway',cid,image,token,node,cap,'apicontour-local_default',running=True)
            bad=dict(obj,NetworkSettings={'Networks':{origin21_products.NETWORK:{'NetworkID':node}}})
            with self.assertRaises(RuntimeError): origin21_products._validate_companion(bad,'native-gateway',cid,image,token,node,cap,'apicontour-local_default',running=True)
            bad=dict(obj,HostConfig=dict(obj['HostConfig'],Privileged=True))
            with self.assertRaises(RuntimeError): origin21_products._validate_companion(bad,'native-gateway',cid,image,token,node,cap,'apicontour-local_default',running=True)

    def test_incomplete_companion_intent_never_widens_network(self):
        with mock.patch.object(origin21_products,'_read_record',side_effect=[{'version':1},FileNotFoundError()]), mock.patch.object(origin21_products,'_network') as network:
            with self.assertRaises(FileNotFoundError): origin21_products._companion_record({},['a'*64,'b'*64])
            network.assert_not_called()

    def test_selected_network_checks_owner_postgres_alias_and_ca(self):
        token='1'*32; name='contour-origin21-qual-'+token; net='2'*64; cid='3'*64; pgimage='sha256:'+'4'*64; ca=b'synthetic-ca'
        deployment={'name':name,'id':net,'owner_kind':'fixture','owner_token':token,'postgres_id':cid,'postgres_image_id':pgimage,'ca_sha256':hashlib.sha256(ca).hexdigest()}
        network={'Name':name,'Id':net,'Internal':True,'Labels':{'org.apicontour.fixture-owner':token},'Containers':{cid:{}}}
        pg={'Id':cid,'Image':pgimage,'HostConfig':{'Init':True},'State':{'Running':True},'Config':{'Image':'postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4','Labels':{'org.apicontour.fixture-owner':token}},'NetworkSettings':{'Networks':{name:{'NetworkID':net,'Aliases':['postgres']}}}}
        with mock.patch.object(origin21_products,'_objects',side_effect=[network,pg]), mock.patch.object(origin21_products.capture_renew,'read_file',return_value=ca):
            self.assertEqual(origin21_products._capture_network(deployment),net)
        for value in (False,None):
            with mock.patch.object(origin21_products,'_objects',side_effect=[network,dict(pg,HostConfig={'Init':value})]), mock.patch.object(origin21_products.capture_renew,'read_file') as read:
                with self.assertRaises(RuntimeError): origin21_products._capture_network(deployment)
                read.assert_not_called()
        for bad in (dict(network,Internal=False),dict(network,Labels={'org.apicontour.fixture-owner':'wrong'}),dict(network,Containers={})):
            with mock.patch.object(origin21_products,'_objects',return_value=bad):
                with self.assertRaises(RuntimeError): origin21_products._capture_network(deployment)
        badpg=dict(pg,NetworkSettings={'Networks':{name:{'NetworkID':net,'Aliases':['wrong']}}})
        with mock.patch.object(origin21_products,'_objects',side_effect=[network,badpg]):
            with self.assertRaises(RuntimeError): origin21_products._capture_network(deployment)
        with mock.patch.object(origin21_products,'_objects',side_effect=[network,pg]), mock.patch.object(origin21_products.capture_renew,'read_file',return_value=b'wrong'):
            with self.assertRaises(RuntimeError): origin21_products._capture_network(deployment)

    def test_build_receipt_binds_image_head_and_bytes(self):
        image='sha256:'+'a'*64; head='b'*40
        network={'name':'apicontour-local_default','id':'1'*64,'owner_kind':'local','owner_token':'apicontour-local','postgres_id':'2'*64,'postgres_image_id':'sha256:'+'3'*64,'ca_sha256':'4'*64}
        raw=json.dumps({'version':1,'head':head,'image_id':image,'status':'passed','network':network},sort_keys=True,separators=(',',':')).encode()
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'receipt'; path.write_bytes(raw); os.chmod(path,0o600)
            with mock.patch.object(origin21_transport,'_run',side_effect=[head,'']):
                self.assertEqual(origin21_products._build_receipt(image,head,path,hashlib.sha256(raw).hexdigest()),network)
            with self.assertRaises(ValueError): origin21_products._build_receipt(image,head,path,'0'*64)
            with mock.patch.object(origin21_transport,'_run',side_effect=[head,'unexpected change']):
                with self.assertRaises(ValueError): origin21_products._build_receipt(image,head,path,hashlib.sha256(raw).hexdigest())

    def test_companion_start_never_adopts_or_restarts_existing_products(self):
        # Gate must fail before Docker if the operator build identity differs.
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(origin21_products,'OWNER',Path(temp)), mock.patch.object(origin21_products.capture_renew,'safe_dir'), mock.patch.object(origin21_products,'_read_record',side_effect=[{'app_image_id':'wrong','build_head':'wrong','build_receipt_sha256':'wrong'},{}]), mock.patch.object(origin21_products,'_command') as command:
            os.chmod(temp,0o700)
            with self.assertRaisesRegex(ValueError,'app build identity changed'):
                origin21_products.start_companions(app_image_id='sha256:'+'a'*64,build_head='b'*40,build_receipt='/not-read',build_receipt_sha256='c'*64,psql=mock.Mock(),sensitive_execute=mock.Mock(),authenticate=mock.Mock())
            command.assert_not_called()

    def test_companions_refuse_current_fact_or_auth_drift_before_intent(self):
        intent={'app_image_id':'image','build_head':'head','build_receipt_sha256':'digest','deployment':{},'token':'token','model_sha256':'a'*64}
        products={'slots':[{},{}]}; journal={'completed':len(origin21_state.PHASES),'pending':None}
        for reason in ('revoked lifecycle','revoked credential','revoked grant','authentication failed'):
            with tempfile.TemporaryDirectory() as directory:
                os.chmod(directory,0o700)
                with mock.patch.object(origin21_products,'OWNER',Path(directory)), mock.patch.object(origin21_products,'_read_record',side_effect=[intent,products]), mock.patch.object(origin21_products,'_verify_model'), mock.patch.object(origin21_products,'_build_receipt',return_value={}), mock.patch.object(origin21_state,'_read',return_value=journal), mock.patch.object(origin21_state,'_source_identity',return_value='source'), mock.patch.object(origin21_products,'_recorded_products',return_value=['one','two']), mock.patch.object(origin21_products,'_network'), mock.patch.object(origin21_products,'_command',return_value=b'one\ntwo\n') as command, mock.patch.object(origin21_evidence,'digest',return_value=b'a'*32), mock.patch.object(origin21_setup,'prepare',side_effect=ValueError(reason)) as prepare, mock.patch.object(origin21_products,'_write_record') as write:
                    with self.assertRaisesRegex(ValueError,reason):
                        origin21_products.start_companions(app_image_id='image',build_head='head',build_receipt='receipt',build_receipt_sha256='digest',psql=mock.Mock(),sensitive_execute=mock.Mock(),authenticate=mock.Mock())
                    self.assertTrue(prepare.call_args.kwargs['check_only'])
                    self.assertFalse(prepare.call_args.kwargs.get('renew',False))
                    write.assert_not_called()
                    self.assertFalse(any('create' in call.args[0] for call in command.call_args_list))

    def test_check_only_requires_complete_and_rechecks_each_completed_phase(self):
        class Operation:
            def __init__(self): self.value=origin21_state.EXACT
            def inspect(self): return self.value
            def apply(self): raise AssertionError('check-only must never apply')
            def commitment(self): return 'a'*64
        operations={phase:Operation() for phase in origin21_state.PHASES}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'setup.json'
            state=dict(version=1,descriptor='identity',source='source',completed=len(origin21_state.PHASES)-1,pending=None,credential_digest='a'*64,evidence_digest='a'*64)
            origin21_state._initial(path,state)
            with self.assertRaisesRegex(ValueError,'committed setup required'):
                origin21_state._reconcile(path,'identity','source',operations,require_complete=True)
            state['completed']=len(origin21_state.PHASES); path.write_bytes(origin21_state._encode(state)); os.chmod(path,0o600)
            for phase in ('origin_1_lifecycle','origin_1_credential','origin_1_grant','logins'):
                operations[phase].value=origin21_state.DRIFT
                with self.assertRaisesRegex(ValueError,'completed phase drift'):
                    origin21_state._reconcile(path,'identity','source',operations,require_complete=True)
                operations[phase].value=origin21_state.EXACT

    def test_login_inspection_rejects_failed_current_tls_authentication(self):
        psql=mock.Mock(return_value=origin21_state.EXACT)
        authenticate=mock.Mock(return_value=False)
        login=origin21_logins.Logins(origin21_profile.PROFILE,psql,mock.Mock(),authenticate)
        with mock.patch.object(login,'_password',return_value='x'*32):
            self.assertEqual(login.inspect(),origin21_state.DRIFT)
        authenticate.assert_called_once()

    def test_identities_prefix_reconciles_only_first_phase(self):
        class Credential:
            def __init__(self): self.done=False
            def inspect(self): return origin21_state.EXACT if self.done else origin21_state.ABSENT
            def apply(self): self.done=True
            def commitment(self): return 'a'*64
        credential=Credential()
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(origin21_state,'_source_identity',return_value='source'):
            path=Path(temp)/'setup.json'
            origin21_state._reconcile(path,'identity','source',{'credentials':credential},phases=origin21_state.PHASES[:1])
            record=origin21_state._read(path,'identity','source')
            self.assertEqual(record['completed'],1); self.assertEqual(record['credential_digest'],'a'*64)
            origin21_state._reconcile(path,'identity','source',{'credentials':credential},phases=origin21_state.PHASES[:1])
            with self.assertRaises(ValueError):
                origin21_state._reconcile(path,'identity','source',{'credentials':credential},phases=origin21_state.PHASES[:1],require_complete=True)

    def test_operator_evidence_is_exact_and_bound_to_two_real_inspections(self):
        # Synthetic test data only; no Docker inspection or credential read.
        leaves=[b'synthetic-leaf-one',b'synthetic-leaf-two']
        values=[dict(container_id=str(i)*64,image_id='sha256:'+'a'*64,image_ref=origin21_evidence.IMAGE,
                     namespace='owned-network',service_label='replica'+str(i),app_image_id='sha256:'+'f'*64,build_head='e'*40,build_receipt_sha256='d'*64,deployment_sha256='c'*64,
                     leaf_sha256=hashlib.sha256(leaves[i-1]).hexdigest(),started_at='2026-11-07T12:00:00.123456789Z') for i in (1,2)]
        expected=tuple(origin21_evidence.digest(v) for v in values)
        def read_leaf(path): return leaves[0] if 'replica1' in str(path) else leaves[1]
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(origin21_evidence.origin_credentials,'_file',side_effect=read_leaf):
            op=origin21_evidence.Evidence(origin21_profile.PROFILE,lambda i:dict(values[i-1]),expected)
            op.path=Path(temp)/'operator-evidence.json'
            self.assertEqual(op.inspect(),origin21_state.ABSENT); op.apply()
            self.assertEqual(op.inspect(),origin21_state.EXACT)
            self.assertEqual(op.slot_digest(origin21_profile.PROFILE.origins[0]),expected[0].hex())
            values[0]['container_id']='3'*64
            self.assertEqual(op.inspect(),origin21_state.DRIFT)
            with self.assertRaises(ValueError): op.slot_digest(origin21_profile.PROFILE.origins[0])
        bad=dict(values[0],service_label='replica2')
        with self.assertRaises(ValueError): origin21_evidence.descriptor(bad,1,bad['leaf_sha256'])
        with self.assertRaises(ValueError): origin21_evidence.Evidence(origin21_profile.PROFILE,lambda _:None,(b'x'*32,b'y'))

    def test_journal_reconciles_lost_ack_and_refuses_unplanned_state(self):
        class Operation:
            def __init__(self): self.exists=False; self.fail=False; self.calls=0
            def inspect(self): return origin21_state.EXACT if self.exists else origin21_state.ABSENT
            def apply(self):
                self.calls+=1; self.exists=True
                if self.fail: self.fail=False; raise RuntimeError('lost acknowledgement')
            def commitment(self): return 'a'*64
        operations={phase:Operation() for phase in origin21_state.PHASES}
        operations['migration_16'].fail=True
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(origin21_state,'_source_identity',return_value='source'):
            path=Path(temp)/'setup.json'
            with self.assertRaisesRegex(RuntimeError,'lost acknowledgement'):
                origin21_state._reconcile(path,'identity','source',operations)
            journal=origin21_state._read(path,'identity','source')
            self.assertEqual(journal['pending'],'migration_16')
            origin21_state._reconcile(path,'identity','source',operations)
            self.assertEqual(operations['migration_16'].calls,1)
            self.assertEqual(origin21_state._read(path,'identity','source')['completed'],len(origin21_state.PHASES))
            operations['credentials'].commitment=lambda:'b'*64
            with self.assertRaisesRegex(ValueError,'credential commitment drift'):
                origin21_state._reconcile(path,'identity','source',operations)
        operations={phase:Operation() for phase in origin21_state.PHASES}
        operations['groups'].exists=True
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(origin21_state,'_source_identity',return_value='source'):
            with self.assertRaisesRegex(ValueError,'unplanned setup state'):
                origin21_state._reconcile(Path(temp)/'setup.json','identity','source',operations)
            self.assertEqual(operations['groups'].calls,0)

    def test_existing_legacy_bound_sources_not_modified(self):
        from deploy.pilot import origin_setup_state
        root=origin21_profile.ROOT
        result=subprocess.run(['git','diff','--exit-code','HEAD','--',*origin_setup_state.SOURCE_FILES],cwd=root,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0)


if __name__=='__main__': unittest.main()
