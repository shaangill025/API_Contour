"""Offline controls for managed-Origin prepublication identity checks."""
import json
import os
import unittest
from contextlib import ExitStack
from unittest import mock
from deploy.gateway.managed_edge import ManagedEdge,NativeDirectoryPublisher,NativeReplicaPeer
from deploy.local import origin21_managed_controller as controller,origin21_managed_init as init,origin21_profile as profiles,origin21_state


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        p=controller.products; self.ctx=profiles.MANAGED
        self.ids=['%064x'%i for i in range(1,10)]; self.node='sha256:'+'a'*64; self.app='sha256:'+'b'*64; self.envoy='sha256:'+'c'*64
        self.intent={'project':self.ctx.project,'token':'d'*64,'image_id':self.node,'app_image_id':self.app,'build_head':'e'*40,'build_receipt_sha256':'f'*64,'model_sha256':'1'*64,'deployment':{'name':'managed-net','postgres_id':self.ids[7],'postgres_image_id':'sha256:'+'9'*64,'id':'capture-id'}}
        self.slots=[{'container_id':self.ids[0],'started_at':'start-one','leaf_sha256':'2'*64},{'container_id':self.ids[1],'started_at':'start-two','leaf_sha256':'3'*64}]
        self.recorded={'version':1,'slots':self.slots}
        self.services={name:{'id':self.ids[i+2],'started_at':None if name=='native-envoy' else 'start-'+name} for i,name in enumerate(p.COMPANIONS)}
        node={'id':self.node}; app={'id':self.app}; envoy={'id':self.envoy}
        self.images={name:(node if name=='destination' else envoy if name=='native-envoy' else app) for name in p.COMPANIONS}
        self.pending={'version':1,'token':self.intent['token'],'image_id':self.app,'build_head':self.intent['build_head'],'build_receipt_sha256':self.intent['build_receipt_sha256'],'capture_network':'capture-id','images':self.images,'services':list(p.COMPANIONS),'model_sha256':'4'*64}
        self.peer=object.__new__(NativeReplicaPeer); self.peer.cid=self.ids[0]; self.peer.image_id=self.node; self.peer.network_id='business-id'; self.peer.mounts={'fixture':'product'}; self.peer.envoy_cid=self.services['native-envoy']['id']; self.peer.envoy_image_id=self.envoy; self.peer.envoy_mounts={'fixture':'envoy'}
        self.publisher=object.__new__(NativeDirectoryPublisher); self.publisher.cid=self.ids[8]; self.publisher.token='5'*32; self.publisher.watched=str(self.ctx.edge/'watched')
    def run_snapshot(self,extra_capture=False,extra_publisher=False,extra_db=False,pg_changed=False,receipt_changed=False):
        p=controller.products
        records={'intent.json':self.intent,'products.json':self.recorded,'companions-intent.json':self.pending,'companions-created.json':{'version':1,'services':self.services}}
        capture={self.ids[7],self.services['native-gateway']['id'],self.services['origin21-capture-ingress']['id'],self.services['origin21-capture-worker']['id']}
        if extra_capture: capture.add('f'*64)
        def objects(args):
            if args[:3]==['docker','network','inspect']: return {'Containers':{cid:{} for cid in capture}}
            cid=args[-1]; service=next(name for name,item in self.services.items() if item['id']==cid)
            return {'fixture':service}
        def validate(obj,service,*args,**kwargs): return {'StartedAt':self.services[service]['started_at']}
        def image(ref):
            return {'id':self.node if ref==p.origin21_evidence.IMAGE else self.envoy if ref==p.ENVOY else 'sha256:'+'9'*64 if ref==init.POSTGRES else self.app}
        db_intent={'version':1,'head':self.intent['build_head'],'build_image':self.app,'build_receipt_sha256':'8'*64,'token':'6'*32,'network':self.intent['deployment']['name'],'volume':init.VOLUME}
        def fixed_file(path,*args):
            value=db_intent if path.name=='initializer.intent' else {'version':1,'id':self.ids[7],'started_at':'pg-start'} if path.name=='postgres.start.result' else {'version':1,'receipt_sha256':('0'*64 if receipt_changed else self.intent['build_receipt_sha256']),'postgres_id':self.ids[7],'started_at':'pg-start'} if path.name=='initializer.done' else {'publisher':'fixed'}
            return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        def command(args,*a,**k):
            if 'label=org.apicontour.managed-edge-owner=' in args[-1]: values=[self.services['native-envoy']['id'],self.publisher.cid]+(['f'*64] if extra_publisher else [])
            elif 'label='+init.LABEL+'=' in args[-1]: values=[self.ids[7]]+(['f'*64] if extra_db else [])
            else: values=self.ids[:7]
            return ('\n'.join(values)).encode()
        patches=[
            mock.patch.object(p,'_read_record',side_effect=lambda name,**kw:records[name]),
            mock.patch.object(p,'_command',side_effect=command),
            mock.patch.object(p,'_verify_model'),
            mock.patch.object(p,'_recorded_products',return_value=self.ids[:2]),
            mock.patch.object(p,'_network',return_value='business-id'),
            mock.patch.object(p,'_capture_network',return_value='capture-id'),
            mock.patch.object(p,'_objects',side_effect=objects),
            mock.patch.object(p,'_image',side_effect=image),
            mock.patch.object(p,'_validate_companion',side_effect=validate),
            mock.patch.object(p,'_mounts',return_value=self.peer.mounts),
            mock.patch.object(p,'_companion_mounts',return_value=self.peer.envoy_mounts),
            mock.patch.object(p,'_managed_edge_token',return_value=self.publisher.token),
            mock.patch.multiple(init,_postgres=mock.Mock(return_value={'StartedAt':'changed' if pg_changed else 'pg-start'}),_volume=mock.Mock()),
            mock.patch.object(origin21_state,'MANAGED_SOURCE_FILES',(init.SOURCE,)),
            mock.patch.object(origin21_state,'_source_identity',return_value='source'),
            mock.patch.object(origin21_state,'_read',return_value={'completed':len(origin21_state.PHASES),'pending':None}),
            mock.patch.object(controller.origin_credentials,'_file',side_effect=fixed_file),
            mock.patch.object(NativeDirectoryPublisher,'identity',return_value={'publisher':'fixed'}),
            mock.patch.object(NativeDirectoryPublisher,'verify'),
            mock.patch.object(NativeReplicaPeer,'identity',return_value={'peer':'fixed'}),
            mock.patch.object(NativeReplicaPeer,'verify_existing_before_publication')
        ]
        with ExitStack() as stack:
            for patch in patches: stack.enter_context(patch)
            return controller.verify_before_publication(self.peer,self.publisher)
    def test_both_product_generations_and_all_members_bound(self):
        record=self.run_snapshot(); self.assertEqual(record['products'],self.slots); self.assertEqual(record['postgres_id'],self.ids[7])
        with self.assertRaises(ValueError): self.run_snapshot(extra_capture=True)
        with self.assertRaises(ValueError): self.run_snapshot(extra_publisher=True)
        with self.assertRaises(ValueError): self.run_snapshot(extra_db=True)
        with self.assertRaises(ValueError): self.run_snapshot(pg_changed=True)
        with self.assertRaises(ValueError): self.run_snapshot(receipt_changed=True)
    def test_publisher_is_verified_before_start_and_rejects_drift(self):
        from deploy.gateway.managed_edge import _PUBLISH_CLEAR,_PUBLISH_WARM
        cid=self.ids[8]; token='5'*32; watched=self.ctx.edge/'watched'; image={'id':self.node,'env':['PATH=/bin']}
        env=['PATH=/bin']+[key+'=' for key in _PUBLISH_CLEAR]
        obj={'Id':cid,'Name':'/'+self.ctx.project+'-edge-publisher','Image':self.node,
            'Config':{'Image':controller.products.origin21_evidence.IMAGE,'Labels':{'org.apicontour.managed-edge-owner':token},'User':str(os.getuid())+':'+str(os.getgid()),'Entrypoint':['/usr/local/bin/node'],'Cmd':['-e',_PUBLISH_WARM],'Env':env},
            'State':{'Running':False,'Status':'created','StartedAt':'0001-01-01T00:00:00Z'},
            'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'CapAdd':None,'SecurityOpt':['no-new-privileges'],'PidMode':'','IpcMode':'private','UTSMode':'','UsernsMode':'','Devices':None,'DeviceRequests':None,'DeviceCgroupRules':None,'PortBindings':{}},
            'Mounts':[{'Type':'bind','Source':str(watched),'Destination':'/watch','RW':True}]}
        with mock.patch.object(controller.products,'_objects',return_value=obj): controller._verify_created_publisher(cid,token,image,watched)
        for replacement in (dict(obj,Config=dict(obj['Config'],Cmd=['-e','evil'])),dict(obj,HostConfig=dict(obj['HostConfig'],NetworkMode='host')),dict(obj,HostConfig=dict(obj['HostConfig'],Privileged=True)),dict(obj,Mounts=[])):
            with mock.patch.object(controller.products,'_objects',return_value=replacement):
                with self.assertRaises(ValueError): controller._verify_created_publisher(cid,token,image,watched)

    def test_stopped_publisher_requires_same_generation_and_no_live_exec(self):
        from deploy.gateway.managed_edge import _PUBLISH_CLEAR,_PUBLISH_WARM
        cid=self.ids[8]; token='5'*32; watched=self.ctx.edge/'watched'; image={'id':self.node,'env':['PATH=/bin']}; started='2026-11-07T01:00:00Z'
        obj={'Id':cid,'Name':'/'+self.ctx.project+'-edge-publisher','Image':self.node,'Config':{'Image':controller.products.origin21_evidence.IMAGE,'Labels':{'org.apicontour.managed-edge-owner':token},'User':str(os.getuid())+':'+str(os.getgid()),'Entrypoint':['/usr/local/bin/node'],'Cmd':['-e',_PUBLISH_WARM],'Env':['PATH=/bin']+[key+'=' for key in _PUBLISH_CLEAR]},'State':{'Running':False,'Status':'exited','StartedAt':started,'Pid':0,'Restarting':False},'HostConfig':{'RestartPolicy':{'Name':'no'},'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'CapAdd':None,'SecurityOpt':['no-new-privileges'],'PidMode':'','IpcMode':'private','UTSMode':'','UsernsMode':'','Devices':None,'DeviceRequests':None,'DeviceCgroupRules':None,'PortBindings':{}},'Mounts':[{'Type':'bind','Source':str(watched),'Destination':'/watch','RW':True}],'ExecIDs':[]}
        with mock.patch.object(controller.products,'_objects',return_value=obj): controller._verify_created_publisher(cid,token,image,watched,stopped_at=started)
        for replacement in (dict(obj,ExecIDs=['live']),dict(obj,State=dict(obj['State'],Pid=4)),dict(obj,State=dict(obj['State'],Restarting=True)),dict(obj,State=dict(obj['State'],StartedAt='other')),dict(obj,HostConfig=dict(obj['HostConfig'],RestartPolicy={'Name':'always'}))):
            with mock.patch.object(controller.products,'_objects',return_value=replacement):
                with self.assertRaises(ValueError): controller._verify_created_publisher(cid,token,image,watched,stopped_at=started)

    def test_envoy_start_requires_intent_and_then_binding_and_confirmation(self):
        owner=object.__new__(ManagedEdge); owner.peer=self.peer; owner.publisher=self.publisher; owner.qualification=None; owner.state=self.ctx.edge/'state'
        record={'companions':{'native-envoy':{'id':self.peer.envoy_cid}}}; raw=json.dumps(record,sort_keys=True,separators=(',',':')).encode()
        order=[]
        def command(args,timeout):
            self.assertEqual(order,['intent']); order.append('start'); return self.peer.envoy_cid.encode()
        with mock.patch.object(ManagedEdge,'_load',return_value={'current':None,'binding':None,'pending':{'phase':'staged'}}),mock.patch('deploy.gateway.managed_edge._regular',return_value=raw),mock.patch.object(controller,'verify_before_publication',return_value=record),mock.patch.object(ManagedEdge,'_begin_existing_start',side_effect=lambda *args:(order.append('intent') or object())),mock.patch.object(p:=controller.products,'_command',side_effect=command),mock.patch.object(ManagedEdge,'_bind_initial_existing_origin',side_effect=lambda capability:order.append('bind')),mock.patch.object(ManagedEdge,'reconcile',side_effect=lambda:order.append('confirm')):
            controller.start_envoy_once(owner)
        self.assertEqual(order,['intent','start','bind','confirm'])

    def test_wrong_live_peer_is_rejected(self):
        self.peer.cid='f'*64
        with self.assertRaises(ValueError): self.run_snapshot()

if __name__=='__main__': unittest.main()
