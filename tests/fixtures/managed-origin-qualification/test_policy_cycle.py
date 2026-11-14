"""Policy cycle fails closed before allowing another held stream."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('cycle_driver',ROOT/'scripts/test-managed-origin-qualification.py')
d=importlib.util.module_from_spec(spec); spec.loader.exec_module(d)


class PolicyCycleTests(unittest.TestCase):
    def test_renewal_ambiguity_retains_qualification(self):
        from deploy.local import origin21_setup,origin21_renewal
        proof=mock.Mock(); transport=mock.Mock(); history=mock.Mock(count=1,head=b'head',head_policy={'revision':1})
        try:
            with mock.patch.object(origin21_renewal,'artifacts',return_value=(set(),None)), mock.patch.object(origin21_renewal,'history',return_value=history), mock.patch.object(d.products,'require_current_policy',return_value=1), mock.patch.object(d.origin21_ready,'snapshot',return_value=[]), mock.patch.object(d,'_immutable_capture',return_value={}), mock.patch.object(origin21_setup,'prepare',side_effect=TimeoutError('unknown')):
                with self.assertRaises(TimeoutError): d._policy_cycle(transport,proof,(b'a'*32,b'b'*32),({'leaf_sha256':'a'},{'leaf_sha256':'b'}))
            self.assertTrue(any(item[0] is proof for item in d._RETAINED))
        finally: d._RETAINED[:]=[x for x in d._RETAINED if x[0] is not proof]

    def test_adoption_and_immutable_evidence_are_required(self):
        from deploy.local import origin21_setup,origin21_renewal,provision
        from collections import namedtuple
        H=namedtuple('H','count initial head head_policy')
        old=H(1,b'initial',b'old',{'revision':1}); new=H(2,b'initial',b'new',{'revision':2})
        expected=(b'a'*32,b'b'*32); leaves=['a'*64,'b'*64]
        original=tuple({'leaf_sha256':leaf} for leaf in leaves)
        profile=d.profiles.MANAGED.profile
        def row(index,direction,ident):
            slot=profile.origins[index-1]; r=[None]*46
            shape=({'kind':'object','fields':{'probe':{'kind':'boolean'}},'additional':None} if direction=='request' else {'kind':'object','fields':{'result':{'kind':'string'}},'additional':None})
            r[0]=ident; r[1:6]=[profile.source,*provision.IDS[1:],profile.deployment]
            r[6:9]=[direction,None if direction=='request' else '200',shape]
            r[9:15]=[leaves[index-1],slot.instance,slot.lifecycle,slot.credential,slot.grant,expected[index-1].hex()]
            r[15:20]=[ident,'complete','structure',None if direction=='request' else 200,shape]
            r[20]=[*provision.IDS,'http',direction,'POST','/pilot']; r[21:23]=['proof','proof']
            r[23:27]=[*provision.IDS[1:],slot.deployment]; r[27:32]=[slot.instance,*provision.IDS[1:],slot.deployment]
            r[32:34]=['http_json_v1',2]; r[34:39]=[profile.source,*provision.IDS[1:],profile.deployment]
            r[39:46]=[1,1,1,False,'http_json_v1',2,[]]
            return r
        fresh=[row(i,direction,f'{i}-{direction}') for i in (1,2) for direction in ('request','response')]
        prior=row(1,'request','prior'); prior[33]=1; prior[44]=1
        for failure in ('none','wrong_head','old_changed','immutable_changed','missing_adoption','wrong_revision','pending'):
            with self.subTest(failure=failure):
                proof=mock.Mock(); transport=mock.Mock(); transport.sensitive.return_value='true'; events=[]
                post=[list(prior),*fresh]
                if failure=='old_changed': post[0][7]='changed'
                if failure=='missing_adoption': post=post[:-1]
                if failure=='wrong_revision': post[-1]=list(post[-1]); post[-1][33]=1
                histories=[old,new if failure!='wrong_head' else H(3,b'initial',b'new',{'revision':3})]
                pending=(set(),object()) if failure=='pending' else (set(),None)
                try:
                    with mock.patch.object(origin21_renewal,'artifacts',side_effect=[(set(),None),pending]), mock.patch.object(origin21_renewal,'history',side_effect=histories), mock.patch.object(d.products,'require_current_policy',side_effect=[1,2,2]), mock.patch.object(d.origin21_ready,'snapshot',side_effect=[[prior],[prior],post]), mock.patch.object(d,'_immutable_capture',side_effect=[{'prior':'unchanged'}, {'prior':'changed'} if failure=='immutable_changed' else {'prior':'unchanged'}]), mock.patch.object(origin21_setup,'prepare',side_effect=lambda **kw:events.append('renew')), mock.patch.object(d.origin21_ready,'check',side_effect=lambda *a,**kw:events.append('ready')):
                        if failure=='none':
                            d._policy_cycle(transport,proof,expected,original)
                            self.assertEqual(events,['renew','ready'])
                            self.assertFalse(any(x[0] is proof for x in d._RETAINED))
                        else:
                            with self.assertRaises((ValueError,RuntimeError)): d._policy_cycle(transport,proof,expected,original)
                            self.assertTrue(any(x[0] is proof for x in d._RETAINED))
                            if failure in ('wrong_head','pending'): self.assertEqual(events,['renew'])
                finally: d._RETAINED[:]=[x for x in d._RETAINED if x[0] is not proof]

    def test_cycle_occurs_after_second_case_and_blocks_third_on_failure(self):
        from deploy.local.origin21_managed_qualification import OwnedManagedQualification
        from deploy.local.origin21_transport import ManagedTransport
        proof=object.__new__(OwnedManagedQualification); transport=object.__new__(ManagedTransport)
        products=({'leaf_sha256':'a'},{'leaf_sha256':'b'}); expected=(b'a'*32,b'b'*32)
        for fails in (False,True):
            events=[]; pairs=iter([('x','y'),('y','x'),('x','y'),('y','x')])
            def stream(*args): events.append(('stream',args[0],args[1])); return next(pairs)
            def ready(*args,**kwargs): events.append(('ready',))
            def cycle(*args):
                events.append(('cycle',))
                if fails: raise RuntimeError('injected')
                ready()
            with mock.patch.object(OwnedManagedQualification,'verify'), mock.patch.object(ManagedTransport,'verify'), mock.patch.object(d,'_source_guard',return_value='fixed'), mock.patch.object(d,'_helper',return_value={}), mock.patch.object(d,'_destination',return_value='destination'), mock.patch.object(d,'_products',return_value=products), mock.patch.object(d,'_commitments',return_value=expected), mock.patch.object(d.origin21_ready,'snapshot',return_value=[]), mock.patch.object(d.origin21_ready,'check',side_effect=ready), mock.patch.object(d.products,'require_current_policy',return_value=1), mock.patch.object(d,'_stream',side_effect=stream), mock.patch.object(d,'_wait_capture'), mock.patch.object(d,'_policy_cycle',side_effect=cycle), mock.patch.object(d,'_set_phase'):
                if fails:
                    with self.assertRaises(RuntimeError): d.qualify_positive_streams(transport,proof)
                else: d.qualify_positive_streams(transport,proof)
            streams=[i for i,v in enumerate(events) if v[0]=='stream']
            cycle_pos=events.index(('cycle',))
            self.assertEqual(len(streams),2 if fails else 4)
            self.assertLess(streams[1],cycle_pos)
            if not fails:
                self.assertLess(cycle_pos,streams[2])
                self.assertEqual(sum(v[0]=='ready' for v in events),5) # initial plus four cases

    def test_immutable_capture_rejects_missing_duplicate_and_unsafe_ids(self):
        import json
        ident='12345678-1234-1234-1234-123456789abc'; transport=mock.Mock()
        row=[ident,{'raw':'metadata'},{'raw':'batch'},{'checked_batch':'binary'}, {'canonical_proof':'binary'}]
        transport.admin.return_value=json.dumps([row])
        self.assertEqual(d._immutable_capture(transport,{ident}),{ident:row})
        for rows in ([],[row,row]):
            transport.admin.return_value=json.dumps(rows)
            with self.assertRaises(ValueError): d._immutable_capture(transport,{ident})
        transport.admin.reset_mock()
        with self.assertRaises(ValueError): d._immutable_capture(transport,{"not-a-uuid'"})
        transport.admin.assert_not_called()
