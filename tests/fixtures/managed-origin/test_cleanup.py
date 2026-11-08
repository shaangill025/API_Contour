"""Offline exact-resource cleanup controls; no Docker or SQL execution."""
import tempfile
import hashlib
import json
import unittest
from pathlib import Path
from unittest import mock
from contextlib import ExitStack
from deploy.local import origin21_managed_cleanup as cleanup

class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name).resolve(); self.state=self.root/'state'; self.state.mkdir(); (self.state/'existing-origin.intent').write_bytes(b'fixture')
        self.ids=['%064x'%i for i in range(1,10)]; self.names=cleanup.products.COMPANIONS
        self.services={name:{'id':self.ids[i+2],'started_at':'start-'+name} for i,name in enumerate(self.names)}
        self.slots=[{'container_id':self.ids[i],'started_at':'start-'+str(i+1),'namespace':'business'} for i in range(2)]
        self.deployment={'postgres_id':self.ids[7],'postgres_image_id':'sha256:'+'a'*64,'id':'capture','name':cleanup.init.NETWORK}
        self.intent={'deployment':self.deployment,'token':'b'*64,'model_sha256':'c'*64,'image_id':'sha256:'+'d'*64,'image_env':[],'image_cmd':None,'image_workdir':''}
        self.records={'intent.json':self.intent,'products.json':{'slots':self.slots},'companions-intent.json':{'images':{name:{} for name in self.names},'model_sha256':'e'*64},'companions.json':{'services':self.services}}
        self.receipt=json.dumps({'version':1,'head':'1'*40,'image_id':'sha256:'+'2'*64,'status':'passed','network':self.deployment},sort_keys=True,separators=(',',':')).encode()
        self.initial={'initializer.intent':{'version':1,'head':'1'*40,'build_image':'sha256:'+'2'*64,'build_receipt_sha256':'3'*64,'token':'f'*32,'network':cleanup.init.NETWORK,'volume':cleanup.init.VOLUME},'initializer.done':{'version':1,'receipt_sha256':hashlib.sha256(self.receipt).hexdigest(),'postgres_id':self.ids[7],'started_at':'pg-start'},'postgres.start.result':{'version':1,'id':self.ids[7],'started_at':'pg-start'}}
        self.current=set(self.ids[:7]); self.publisher_live=True; self.commands=[]; self.writes=[]; self.extra=False; self.fail_remove=False
    def tearDown(self): self.temp.cleanup()
    def command(self,args,*unused,**kwargs):
        self.commands.append(args)
        if args[:3]==['docker','rm','-f']:
            if self.fail_remove: raise TimeoutError('unknown')
            cid=args[3]; self.current.discard(cid)
            if cid==self.ids[8]: self.publisher_live=False
            return cid.encode()
        if args[:3]==['docker','ps','-aq']:
            filt=args[-1]
            if filt.startswith('label=com.docker.compose.project='): return '\n'.join(sorted(self.current)).encode()
            if filt.startswith('label=org.apicontour.managed-edge-owner='):
                edge=([self.services['native-envoy']['id']] if self.services['native-envoy']['id'] in self.current else [])+([self.ids[8]] if self.publisher_live else [])+(['f'*64] if self.extra else [])
                return '\n'.join(edge).encode()
            return b''
        if args[:3]==['docker','network','rm']: return args[3].encode()
        return b''
    def exercise(self):
        owner=mock.MagicMock(); owner.state=self.state; owner.publisher.cid=self.ids[8]
        context=mock.MagicMock(); context.__enter__.return_value=owner
        def record(path): return self.initial[path.name]
        def read(name,**kwargs): return self.records[name]
        def companion(obj,name,*args,**kwargs): return {'StartedAt':self.services[name]['started_at']}
        def product(obj,index,*args,**kwargs): return {'StartedAt':self.slots[index-1]['started_at']}
        def write(path,value): self.writes.append((path.name,value))
        files=(cleanup.SOURCE,cleanup.init.SOURCE)
        with mock.patch.object(cleanup.origin21_state,'MANAGED_SOURCE_FILES',files),mock.patch.object(cleanup.init,'_source',return_value='source'),mock.patch.object(cleanup.origin_credentials,'_file',return_value=self.receipt),mock.patch.object(cleanup,'_record',side_effect=record),mock.patch.object(cleanup,'_write',side_effect=write),mock.patch.object(cleanup.controller,'open_edge',return_value=context),mock.patch.object(cleanup.products,'_read_record',side_effect=read),mock.patch.object(cleanup.products,'_image',return_value={'id':self.deployment['postgres_image_id']}),mock.patch.object(cleanup.products,'_managed_edge_token',return_value='1'*32),mock.patch.object(cleanup.products,'_verify_model'),mock.patch.object(cleanup.products,'_network'),mock.patch.object(cleanup.products,'_objects',return_value={}),mock.patch.object(cleanup.products,'validate',side_effect=product),mock.patch.object(cleanup.products,'_validate_companion',side_effect=companion),mock.patch.object(cleanup.products,'_command',side_effect=self.command),mock.patch.object(cleanup.init,'_network'),mock.patch.object(cleanup.init,'_db_inventory'),mock.patch.object(cleanup.init,'_volume'),mock.patch.object(cleanup.init,'_postgres',return_value={'StartedAt':'pg-start'}):
            cleanup.teardown()
    def exercise_lost(self,*,extra=False,stopped_error=False):
        from deploy.gateway import managed_edge
        from deploy.local import origin21_managed_qualification as q,origin21_managed_qualification_cleanup as qc
        proof=object.__new__(q.OwnedManagedQualification); object.__setattr__(proof,'_token','a'*32)
        self.initial['initializer.intent']['volume']=proof.volume
        owner=object.__new__(managed_edge.ManagedEdge); owner.state=self.state; owner.watched=self.root/'watched'; owner.identity='owner'; owner.closed=False; owner.uncertain=True; owner.qualification=proof
        publisher=mock.MagicMock(); publisher.cid=self.ids[8]; publisher.token='1'*32; publisher.started='publisher-start'; publisher.identity.return_value={'identity':'publisher'}; owner.publisher=publisher
        original={'version':1,'token':proof.token}; sha=hashlib.sha256(json.dumps(original,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        containers=[self.ids[0],self.ids[1]]+[self.services[name]['id'] for name in self.names]+[self.ids[8],self.ids[7]]
        topology={'version':1,'token':proof.token,'intent_sha256':sha,'containers':containers,'networks':['business','capture']}
        publication={'publisher':publisher.identity(),'document_sha256':'b'*64,'nonce':'c'*32}; raw=json.dumps(publication,sort_keys=True,separators=(',',':')).encode()
        journal=json.dumps({'identity':'owner','pending':{'phase':'staged'}},sort_keys=True,separators=(',',':')).encode()
        def regular(path,*args):
            return raw if path.name=='publication.exec.intent' else journal if path.name=='journal.json' else ('b'*64+'\n').encode()
        def qread(path): return topology if path.name=='topology.intent' else original
        def record(path): return self.initial[path.name]
        def read(name,**kwargs): return self.records[name]
        def companion(obj,name,*args,**kwargs): return {'StartedAt':self.services[name]['started_at']}
        def product(obj,index,*args,**kwargs): return {'StartedAt':self.slots[index-1]['started_at']}
        def write(path,value): self.writes.append((path.name,value))
        self.extra=extra
        with ExitStack() as stack:
            for patch in (
                mock.patch.object(q.OwnedManagedQualification,'verify',return_value=proof),mock.patch.object(q.OwnedManagedQualification,'verify_owner',return_value=proof),
                mock.patch.object(cleanup.origin21_state,'MANAGED_SOURCE_FILES',(cleanup.SOURCE,cleanup.init.SOURCE)),mock.patch.object(cleanup.init,'_source',return_value='source'),mock.patch.object(cleanup.origin_credentials,'_file',return_value=self.receipt),mock.patch.object(cleanup,'_record',side_effect=record),mock.patch.object(qc,'_read',side_effect=qread),mock.patch.object(managed_edge,'_regular',side_effect=regular),mock.patch.object(cleanup,'_write',side_effect=write),mock.patch.object(cleanup.products,'_read_record',side_effect=read),mock.patch.object(cleanup.products,'_image',return_value={'id':self.deployment['postgres_image_id'],'env':[]}),mock.patch.object(cleanup.products,'_managed_edge_token',return_value='1'*32),mock.patch.object(cleanup.products,'_verify_model'),mock.patch.object(cleanup.products,'_network'),mock.patch.object(cleanup.products,'_objects',return_value={}),mock.patch.object(cleanup.products,'validate',side_effect=product),mock.patch.object(cleanup.products,'_validate_companion',side_effect=companion),mock.patch.object(cleanup.products,'_command',side_effect=self.command),mock.patch.object(cleanup.init,'_network'),mock.patch.object(cleanup.init,'_db_inventory'),mock.patch.object(cleanup.init,'_volume'),mock.patch.object(cleanup.init,'_postgres',return_value={'StartedAt':'pg-start'}),mock.patch.object(cleanup.controller,'_verify_created_publisher',side_effect=ValueError('changed') if stopped_error else None)):
                stack.enter_context(patch)
            cleanup.dispose_after_lost_ack(proof,owner)

    def test_lost_ack_disposal_removes_only_recorded_resources(self):
        self.exercise_lost()
        self.assertEqual(set(cmd[3] for cmd in self.commands if cmd[:3]==['docker','rm','-f']),set(self.ids))
        self.assertEqual(self.writes[-1][0],'topology.cleaned')
        self.assertFalse(any(cmd[:3]==['docker','volume','rm'] for cmd in self.commands))

    def test_lost_ack_disposal_rejects_extra_publisher_or_changed_stopped_identity(self):
        for kwargs in ({'extra':True},{'stopped_error':True}):
            with self.subTest(kwargs=kwargs):
                self.commands.clear(); self.writes.clear()
                with self.assertRaises(ValueError): self.exercise_lost(**kwargs)
                self.assertFalse(any(cmd[:3]==['docker','rm','-f'] for cmd in self.commands)); self.assertFalse(self.writes)

    def test_lost_ack_disposal_rejects_raw_proof_before_mutation(self):
        with mock.patch.object(cleanup.products,'_command') as command,mock.patch.object(cleanup,'_teardown') as teardown:
            with self.assertRaises(ValueError): cleanup.dispose_after_lost_ack(object(),object())
            command.assert_not_called(); teardown.assert_not_called()

    def test_unpinned_cleanup_stops_before_any_record_access(self):
        with mock.patch.object(cleanup.origin21_state,'MANAGED_SOURCE_FILES',()),mock.patch.object(cleanup,'_record') as read,mock.patch.object(cleanup.products,'_command') as command:
            with self.assertRaises(RuntimeError): cleanup.teardown()
            read.assert_not_called(); command.assert_not_called()

    def test_runtime_receipt_mismatch_prevents_any_mutation(self):
        self.initial['initializer.done']['receipt_sha256']='0'*64
        with self.assertRaises(ValueError): self.exercise()
        self.assertFalse(self.commands); self.assertFalse(self.writes)

    def test_teardown_removes_only_exact_nine_containers_and_two_networks(self):
        self.exercise()
        removed=[cmd[3] for cmd in self.commands if cmd[:3]==['docker','rm','-f']]
        self.assertEqual(set(removed),set(self.ids)); self.assertEqual(len(removed),9)
        networks=[cmd[3] for cmd in self.commands if cmd[:3]==['docker','network','rm']]
        self.assertEqual(networks,['business','capture'])
        self.assertFalse(any(cmd[:3]==['docker','volume','rm'] for cmd in self.commands))
        self.assertEqual(self.writes[-1][0],'cleanup.done')
    def test_extra_detached_publisher_blocks_before_mutation(self):
        self.extra=True
        with self.assertRaises(ValueError): self.exercise()
        self.assertFalse(any(cmd[:3]==['docker','rm','-f'] for cmd in self.commands)); self.assertFalse(self.writes)
    def test_unknown_removal_stops_and_retains_exclusive_intent(self):
        self.fail_remove=True
        with self.assertRaises(TimeoutError): self.exercise()
        self.assertIn('cleanup.intent',[name for name,_ in self.writes]); self.assertIn('cleanup-native-envoy.intent',[name for name,_ in self.writes])
        self.assertNotIn('cleanup-native-envoy.done',[name for name,_ in self.writes])
        self.assertEqual(sum(cmd[:3]==['docker','rm','-f'] for cmd in self.commands),1)

if __name__=='__main__': unittest.main()
