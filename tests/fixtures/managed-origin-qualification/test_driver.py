"""Offline guard tests for the real managed stream qualification component."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock
from contextlib import ExitStack

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('managed_origin_qualification',ROOT/'scripts/test-managed-origin-qualification.py')
driver=importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)

class QualificationDriverTests(unittest.TestCase):
    def test_incomplete_source_closure_stops_before_source_or_process(self):
        with mock.patch.object(driver.origin21_state,'MANAGED_SOURCE_FILES',()),mock.patch.object(driver.origin21_state,'_source_identity') as source,mock.patch.object(driver.products,'_command') as command:
            with self.assertRaises(RuntimeError): driver._source_guard()
            source.assert_not_called(); command.assert_not_called()
    def test_control_rejects_unbounded_or_unexpected_destination_before_exec(self):
        with mock.patch.object(driver.products,'_command') as command:
            for cid,nonce,action in [('a'*64,'bad','status'),('bad','b'*32,'status'),('a'*64,'b'*32,'send-payload')]:
                with self.assertRaises(ValueError): driver._control(cid,nonce,action)
            command.assert_not_called()
    def test_nonqualification_destination_fails_before_stream(self):
        cid='a'*64; record={'services':{'destination':{'id':cid}}}
        obj={'Mounts':[{'Destination':'/pilot/destination.js','Type':'bind','RW':False,'Source':str(ROOT/'deploy/pilot/destination.js')}]}
        with mock.patch.object(driver.products,'_read_record',return_value=record),mock.patch.object(driver.products,'_objects',return_value=obj):
            with self.assertRaises(ValueError): driver._destination()

    def test_publication_wait_ignores_visible_partial_intent_and_preexec_work(self):
        clock=[0.0]; proof=mock.Mock(); proof.exists.return_value=True
        proof.publication_exec_ready.side_effect=lambda:None if clock[0]<3.0 else {'started':3.0}
        with mock.patch.object(driver.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(driver.time,'sleep',side_effect=lambda x:clock.__setitem__(0,clock[0]+x)):
            ready=driver._wait_publication_intent(proof,setup_timeout=4.0)
        self.assertGreaterEqual(clock[0],3.0); self.assertEqual(ready,{'started':3.0})
    def test_publication_wait_rejects_exec_readiness_after_setup_deadline(self):
        clock=[0.0]; proof=mock.Mock(); proof.exists.return_value=True
        proof.publication_exec_ready.side_effect=lambda:None if clock[0]<5.0 else {'started':5.0}
        with mock.patch.object(driver.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(driver.time,'sleep',side_effect=lambda x:clock.__setitem__(0,clock[0]+x)):
            with self.assertRaises(TimeoutError): driver._wait_publication_intent(proof,setup_timeout=4.0)

    def test_cancel_before_readiness_fails_without_observation(self):
        import threading
        proof=mock.Mock(); proof.publication_exec_ready.return_value=None; cancel=threading.Event(); cancel.set()
        with self.assertRaises(RuntimeError): driver._wait_publication_intent(proof,setup_timeout=4,cancel=cancel)
        proof.publication_exec_ready.assert_not_called()

    def test_reserved_candidate_never_counts_as_publisher_ack(self):
        owner=mock.Mock(); owner.peer.envoy_cid='a'*64; owner._load.return_value={'pending':{'phase':'reserved'},'binding':{'envoy_started':'fixed'}}; owner.renew.side_effect=[ValueError('staging failed'),RuntimeError('blocked')]; owner.rollback.side_effect=RuntimeError('blocked')
        with mock.patch.object(driver.products,'_command',return_value=b'a'*64),mock.patch.object(driver.products,'_objects',return_value={'State':{'Running':True,'Paused':True,'StartedAt':'fixed'}}):
            with self.assertRaises(ValueError): driver._pause_and_reconcile(owner)
        owner.reconcile.assert_not_called()

    def test_staged_pending_requires_fresh_exact_publisher_ack(self):
        import hashlib
        for changed in (False,True):
            with self.subTest(changed=changed):
                owner=mock.Mock(); owner.peer.envoy_cid='a'*64
                before={'pending':None,'binding':{'envoy_started':'fixed'}}; pending={'phase':'staged','candidate':'v-fixed','commitment':{'fixed':'value'}}
                owner._load.side_effect=[before,{'pending':pending}]; owner._document.return_value=b'exact document'; owner.publisher.identity.return_value={'publisher':'exact'}
                owner.renew.side_effect=[TimeoutError('unconfirmed'),RuntimeError('blocked')]; owner.rollback.side_effect=RuntimeError('blocked')
                receipt={'sequence':2,'publisher':{'publisher':'exact'},'document_sha256':hashlib.sha256(b'exact document').hexdigest(),'nonce':'b'*32}
                if changed: receipt['document_sha256']='0'*64
                proof=mock.Mock(); proof.publication_ack.side_effect=[{'sequence':1},receipt]
                with mock.patch.object(driver.products,'_command',return_value=b'a'*64),mock.patch.object(driver.products,'_objects',return_value={'State':{'Running':True,'Paused':True,'StartedAt':'fixed'}}):
                    if changed:
                        with self.assertRaises(ValueError): driver._pause_and_reconcile(owner,proof)
                        owner.reconcile.assert_not_called()
                    else:
                        driver._pause_and_reconcile(owner,proof); owner.reconcile.assert_called_once()

    def test_unknown_pause_always_attempts_exact_unpause(self):
        owner=mock.Mock(); owner.peer.envoy_cid='a'*64; calls=[]
        def command(args,*unused):
            calls.append(args)
            if args[1]=='pause': raise TimeoutError('unknown')
            return owner.peer.envoy_cid.encode()
        with mock.patch.object(driver.products,'_command',side_effect=command):
            with self.assertRaises(TimeoutError): driver._pause_and_reconcile(owner)
        self.assertEqual(calls,[['docker','pause','a'*64],['docker','unpause','a'*64]])
        owner.reconcile.assert_not_called()

    def test_unexpected_renewal_and_watcher_failures_are_both_retained(self):
        import tempfile
        from deploy.local.origin21_managed_qualification import OwnedManagedQualification
        proof=object.__new__(OwnedManagedQualification); owner=mock.Mock(); owner.renew.side_effect=ValueError('primary')
        context=mock.MagicMock(); context.__enter__.return_value=owner
        with tempfile.TemporaryDirectory() as directory:
            owner.state=Path(directory)
            with mock.patch.object(OwnedManagedQualification,'verify',return_value=proof),mock.patch.object(OwnedManagedQualification,'bind_topology'),mock.patch.object(OwnedManagedQualification,'arm_ack_loss'),mock.patch.object(driver,'_source_guard',return_value='source'),mock.patch.object(driver.controller,'open_edge',return_value=context),mock.patch.object(driver,'_wait_publication_intent',side_effect=RuntimeError('watcher')):
                with self.assertRaises(BaseExceptionGroup) as caught: driver.qualify_lost_publication_ack(proof)
        self.assertTrue(any(isinstance(e,ValueError) for e in caught.exception.exceptions))
        self.assertTrue(any(isinstance(e,RuntimeError) for e in caught.exception.exceptions))

    def test_live_observer_blocks_private_cleanup(self):
        import tempfile,threading
        from deploy.local import origin21_managed_cleanup
        from deploy.local.origin21_managed_qualification import OwnedManagedQualification
        proof=object.__new__(OwnedManagedQualification); owner=mock.Mock(); owner.renew.side_effect=TimeoutError('expected')
        context=mock.MagicMock(); context.__enter__.return_value=owner
        watcher=mock.Mock(); watcher.is_alive.return_value=True
        with tempfile.TemporaryDirectory() as directory:
            owner.state=Path(directory)
            with mock.patch.object(OwnedManagedQualification,'verify',return_value=proof),mock.patch.object(OwnedManagedQualification,'bind_topology'),mock.patch.object(OwnedManagedQualification,'arm_ack_loss'),mock.patch.object(driver,'_source_guard',return_value='source'),mock.patch.object(driver.controller,'open_edge',return_value=context),mock.patch.object(threading,'Thread',return_value=watcher),mock.patch.object(origin21_managed_cleanup,'dispose_after_lost_ack') as cleanup:
                with self.assertRaises(BaseExceptionGroup): driver.qualify_lost_publication_ack(proof)
                cleanup.assert_not_called()
        watcher.join.assert_called_once_with(45)

    def test_main_orders_real_boundaries_and_stops_before_cleanup_on_unknown_failure(self):
        from deploy.local import origin21_managed_qualification as q,origin21_managed_init as init,origin21_managed_cli as cli,origin21_managed_cleanup as cleanup,origin21_managed_qualification_cleanup as disposal
        proof=mock.MagicMock(); context=mock.MagicMock(); context.__enter__.return_value=proof; order=[]
        def call(name,result=None,fail=False):
            def invoke(*args,**kwargs):
                order.append(name)
                if fail: raise RuntimeError('unknown')
                return result
            return invoke
        def run(fail):
            order.clear()
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(driver,'_source_guard',return_value='source'))
                stack.enter_context(mock.patch.object(q,'begin',side_effect=call('begin',context)))
                stack.enter_context(mock.patch.object(init,'initialize',side_effect=call('initialize',(Path('/private/receipt'),'digest'))))
                stack.enter_context(mock.patch.object(cli,'main',side_effect=call('up')))
                stack.enter_context(mock.patch.object(driver.origin21_transport,'managed_transport',side_effect=call('transport',object())))
                stack.enter_context(mock.patch.object(driver,'qualify_positive_streams',side_effect=call('streams',{})))
                stack.enter_context(mock.patch.object(driver,'qualify_wrong_name_and_pending',side_effect=call('negative',{})))
                stack.enter_context(mock.patch.object(driver,'qualify_lost_publication_ack',side_effect=call('unknown',{},fail)))
                stack.enter_context(mock.patch.object(cleanup,'dispose_after_lost_ack',side_effect=call('teardown')))
                stack.enter_context(mock.patch.object(disposal,'dispose_synthetic_volume',side_effect=call('volume')))
                if fail:
                    with self.assertRaises(RuntimeError): driver.main(['image','head','/receipt','digest'])
                else: self.assertTrue(driver.main(['image','head','/receipt','digest'])['cleanup'])
            return list(order)
        self.assertEqual(run(False),['begin','initialize','up','transport','streams','negative','unknown','volume'])
        self.assertEqual(run(True),['begin','initialize','up','transport','streams','negative','unknown'])

if __name__=='__main__': unittest.main()
