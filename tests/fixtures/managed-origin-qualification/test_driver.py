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
    def test_readiness_timing_is_bounded_redacted_and_best_effort(self):
        from deploy.local.origin21_managed_qualification import OwnedManagedQualification
        ready=driver.origin21_ready; proof=object.__new__(OwnedManagedQualification); lines=[]
        with mock.patch.object(OwnedManagedQualification,'verify'):
            diag=ready._QualificationDiagnostics(proof,lines.append,clock=iter([1_000_000,9_000_000]).__next__)
        with diag.measure('setup'): pass
        self.assertEqual(lines,['managed-ready name=setup event=start ms=0 count=1','managed-ready name=setup event=end ms=8 count=2'])
        diag.emit('secret','end',1); diag.emit('setup','end',-1); diag.emit('setup','end',True)
        self.assertEqual(len(lines),2)
        with mock.patch.object(OwnedManagedQualification,'verify'):
            broken=ready._QualificationDiagnostics(proof,lambda _: (_ for _ in ()).throw(RuntimeError('secret')),clock=lambda: (_ for _ in ()).throw(RuntimeError('clock')))
        with self.assertRaisesRegex(ValueError,'primary'):
            with broken.measure('setup'): raise ValueError('primary')
        for _ in range(200): diag.emit('probe','start',0)
        self.assertEqual(len(lines),160); self.assertEqual(diag.lines,160)
        self.assertNotIn('secret',' '.join(lines))
    def test_readiness_diagnostics_reject_unowned_proof(self):
        with self.assertRaises(ValueError): driver.origin21_ready._QualificationDiagnostics(object(),lambda _:None)

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
        context=owner
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
        context=owner
        watcher=mock.Mock(); watcher.is_alive.return_value=True
        with tempfile.TemporaryDirectory() as directory:
            owner.state=Path(directory)
            with mock.patch.object(OwnedManagedQualification,'verify',return_value=proof),mock.patch.object(OwnedManagedQualification,'bind_topology'),mock.patch.object(OwnedManagedQualification,'arm_ack_loss'),mock.patch.object(driver,'_source_guard',return_value='source'),mock.patch.object(driver.controller,'open_edge',return_value=context),mock.patch.object(threading,'Thread',return_value=watcher),mock.patch.object(origin21_managed_cleanup,'dispose_after_lost_ack') as cleanup:
                with self.assertRaises(BaseExceptionGroup): driver.qualify_lost_publication_ack(proof)
                cleanup.assert_not_called()
        watcher.join.assert_called_once_with(45)
        owner.close.assert_not_called()
        driver._RETAINED[:]=[item for item in driver._RETAINED if item[0] is not owner]

    def test_lost_ack_join_exception_retains_owner_and_proof_in_main(self):
        import tempfile
        from deploy.local import origin21_managed_qualification as q,origin21_managed_init as init,origin21_managed_cli as cli,origin21_managed_qualification_cleanup as disposal
        proof=object.__new__(q.OwnedManagedQualification); owner=mock.Mock(); watcher=mock.Mock()
        watcher.join.side_effect=KeyboardInterrupt('join'); owner.renew.side_effect=TimeoutError('expected')
        try:
            with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                owner.state=Path(directory)
                for obj,name,value in ((driver,'_source_guard','source'),(q,'begin',proof),(init,'initialize',(Path('/receipt'),'digest')),(cli,'main',None),(driver.origin21_transport,'managed_transport',object()),(driver,'qualify_positive_streams',{}),(driver,'qualify_wrong_name_and_pending',{}),(driver.controller,'open_edge',owner),(driver.threading,'Thread',watcher),(disposal,'dispose_synthetic_volume',None)):
                    stack.enter_context(mock.patch.object(obj,name,return_value=value))
                stack.enter_context(mock.patch.object(q.OwnedManagedQualification,'verify',return_value=proof))
                stack.enter_context(mock.patch.object(q.OwnedManagedQualification,'bind_topology'))
                stack.enter_context(mock.patch.object(q.OwnedManagedQualification,'arm_ack_loss'))
                close=stack.enter_context(mock.patch.object(q.OwnedManagedQualification,'close'))
                with self.assertRaises(BaseExceptionGroup): driver.main(['image','head','receipt','digest'])
                owner.close.assert_not_called(); close.assert_not_called(); disposal.dispose_synthetic_volume.assert_not_called()
                self.assertTrue(any(item[0] is owner for item in driver._RETAINED))
        finally:
            driver._RETAINED[:]=[item for item in driver._RETAINED if item[0] is not owner and item[0] is not proof]

    def test_main_orders_real_boundaries_and_stops_before_cleanup_on_unknown_failure(self):
        from deploy.local import origin21_managed_qualification as q,origin21_managed_init as init,origin21_managed_cli as cli,origin21_managed_cleanup as cleanup,origin21_managed_qualification_cleanup as disposal
        proof=mock.MagicMock(); context=proof; order=[]
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

class HeldDiagnosticsTests(unittest.TestCase):
    def test_closed_status_buckets_and_legacy_status(self):
        import runpy,threading
        helper=runpy.run_path(str(ROOT/'scripts/test-managed-native-edge.py'))
        for status in ('408','429','500','502','503','504','OTHER'):
            monitor=object.__new__(helper['Monitor']); monitor.lock=threading.Lock(); monitor.out=bytearray(); monitor.err=bytearray(('DIAG STATUS_'+status+'\n').encode()); monitor.overflow=False; monitor.read_error=False
            with self.assertRaises(helper['HeldStatus'+('Other' if status=='OTHER' else status)]): monitor.lines()
        monitor.err=bytearray(b'DIAG STATUS\n')
        with self.assertRaises(helper['HeldStatusError']): monitor.lines()
        monitor.err=bytearray(b'DIAG STATUS_501 secret\n')
        with self.assertRaises(RuntimeError) as error: monitor.lines()
        self.assertNotIn('secret',str(error.exception))

class StreamOwnerSetupTests(unittest.TestCase):
    def test_real_publication_method_runs_pre_and_post_gates_around_barrier(self):
        from deploy.gateway.managed_edge import ManagedEdge
        events=[]; current=['a'*64]; owner=mock.Mock()
        data={'pending':{'phase':'staged','candidate':'candidate','commitment':{}},'binding':{},'current':'old','current_commitment':{}}
        owner._managed_gate.side_effect=lambda _:events.append('gate')
        owner._publish.side_effect=lambda *a:events.append('publish')
        owner._confirm.side_effect=lambda *a:events.append('confirm')
        owner._save.side_effect=lambda _:events.append('save')
        owner._load.side_effect=lambda:{'current_commitment':{'cert_sha256':current[0]}}
        def renew():
            ManagedEdge._publish_and_confirm(owner,data); current[0]='b'*64
        owner.renew.side_effect=renew
        class Monitor:
            def __init__(self,args): events.append('client'); self.proc=mock.Mock()
            def lines(self): return [b'PID 7']
            def wait(self,value,**kwargs): events.append('prefix' if value==b'CLIENT_WRITTEN' else 'pass')
            def send(self,value): events.append('release')
            def finish(self,expected): pass
            def reap(self): pass
        with mock.patch.object(driver.controller,'open_edge',return_value=owner),mock.patch.object(driver,'_wait_status'):
            driver._stream('request',1,'renew','d'*64,{'container_id':'c'*64},{'Monitor':Monitor,'remote_absent':lambda *a:None},object())
        self.assertEqual(events.count('gate'),2)
        self.assertLess(events.index('gate'),events.index('client'))
        self.assertLess(events.index('prefix'),events.index('publish'))
        self.assertLess(events.index('confirm'),events.index('release'))
        self.assertLess(events.index('save'),len(events))

    def test_real_publication_postgate_failure_never_succeeds(self):
        from deploy.gateway.managed_edge import ManagedEdge
        owner=mock.Mock(); gates=[]
        data={'pending':{'phase':'staged','candidate':'candidate','commitment':{}},'binding':{},'current':'old','current_commitment':{}}
        def gate(_):
            gates.append(True)
            if len(gates)==2: raise ValueError('postgate')
        owner._managed_gate.side_effect=gate
        owner._load.return_value={'current_commitment':{'cert_sha256':'a'*64}}
        owner.renew.side_effect=lambda:ManagedEdge._publish_and_confirm(owner,data)
        monitor=mock.Mock(); monitor.lines.return_value=[b'PID 7']
        with mock.patch.object(driver.controller,'open_edge',return_value=owner),mock.patch.object(driver,'_wait_status'):
            with self.assertRaises(BaseExceptionGroup): driver._stream('request',1,'renew','d'*64,{'container_id':'c'*64},{'Monitor':lambda _:monitor,'remote_absent':lambda *a:None},object())
        self.assertEqual(len(gates),2); owner._save.assert_not_called()

    def test_owner_validation_precedes_starting_idle_bounded_request(self):
        events=[]; current=['a'*64]
        owner=mock.Mock()
        owner._load.side_effect=lambda:{'current_commitment':{'cert_sha256':current[0]}}
        owner._confirm.side_effect=lambda:events.append('confirm')
        def publish():
            events.append('publish'); owner._confirm(); current[0]='b'*64
        owner._publish.side_effect=publish
        owner.renew.side_effect=lambda:owner._publish()
        owner.close.side_effect=lambda:events.append('owner-exit')
        class Monitor:
            def __init__(self,args): events.append('client'); self.proc=mock.Mock()
            def lines(self): return [b'PID 7']
            def wait(self,value,**kwargs): events.append('prefix' if value==b'CLIENT_WRITTEN' else 'pass')
            def send(self,value): events.append('release')
            def finish(self,expected): events.append('finish')
            def reap(self): events.append('reap')
        helper={'Monitor':Monitor,'remote_absent':lambda *a:events.append('remote-absent')}
        with mock.patch.object(driver.controller,'open_edge',return_value=owner),mock.patch.object(driver,'_wait_status'):
            self.assertEqual(driver._stream('request',1,'renew','d'*64,{'container_id':'c'*64},helper,object()),('a'*64,'b'*64))
        self.assertLess(events.index('prefix'),events.index('publish'))
        self.assertLess(events.index('confirm'),events.index('release'))
        self.assertLess(events.index('reap'),events.index('owner-exit'))

class StreamOwnerFailureTests(unittest.TestCase):
    def test_deadline_crossed_during_finish_or_absence_fails(self):
        import time
        for slow in ('finish','absence'):
            with self.subTest(slow=slow):
                owner=mock.Mock(); current=['a'*64]
                owner._load.side_effect=lambda:{'current_commitment':{'cert_sha256':current[0]}}
                def publish(): owner._confirm(); current[0]='b'*64
                owner._publish.side_effect=publish; owner.renew.side_effect=lambda:owner._publish()
                monitor=mock.Mock(); monitor.lines.return_value=[b'PID 7']
                absent=mock.Mock()
                if slow=='finish': monitor.finish.side_effect=lambda *a:time.sleep(.12)
                else: absent.side_effect=lambda *a:time.sleep(.12)
                with mock.patch.object(driver.controller,'open_edge',return_value=owner),mock.patch.object(driver,'_wait_status'),mock.patch.object(driver,'_STREAM_DEADLINE',.08):
                    with self.assertRaises(BaseExceptionGroup): driver._stream('request',1,'renew','d'*64,{'container_id':'c'*64},{'Monitor':lambda _:monitor,'remote_absent':absent},object())
                owner.close.assert_called_once()

    def test_already_set_prefix_cannot_publish_after_deadline(self):
        import threading,time
        real_event=threading.Event; count=[0]; published=[]
        class DelayedEvent:
            def __init__(self): self.event=real_event()
            def set(self): self.event.set()
            def is_set(self): return self.event.is_set()
            def wait(self,timeout=None):
                result=self.event.wait(timeout)
                if result: time.sleep(.12)
                return result
        def event():
            count[0]+=1
            return DelayedEvent() if count[0]==2 else real_event()
        owner=mock.Mock(); owner._load.return_value={'current_commitment':{'cert_sha256':'a'*64}}
        owner._publish.side_effect=lambda:published.append(True)
        owner.renew.side_effect=lambda:owner._publish()
        monitor=mock.Mock(); monitor.lines.return_value=[b'PID 7']
        with mock.patch.object(driver.controller,'open_edge',return_value=owner),mock.patch.object(driver,'_wait_status'),mock.patch.object(driver,'_STREAM_DEADLINE',.08),mock.patch.object(driver.threading,'Event',side_effect=event):
            with self.assertRaises(BaseExceptionGroup): driver._stream('request',1,'renew','d'*64,{'container_id':'c'*64},{'Monitor':lambda _:monitor,'remote_absent':mock.Mock()},object())
        self.assertFalse(published)
        for item in list(driver._RETAINED):
            if item[0] is owner: item[1].join(2); driver._RETAINED.remove(item); owner.close()

    def test_launch_and_join_exceptions_retain_owner_and_proof(self):
        import threading
        from deploy.local import origin21_managed_qualification as q,origin21_managed_init as init,origin21_managed_cli as cli,origin21_managed_qualification_cleanup as disposal
        real_thread=threading.Thread
        for failure in ('start','join'):
            with self.subTest(failure=failure):
                release=threading.Event(); entered=threading.Event(); threads=[]
                owner=mock.Mock(); proof=mock.Mock(); original_publish=owner._publish; original_confirm=owner._confirm
                owner._load.return_value={'current_commitment':{'cert_sha256':'a'*64}}
                def publish():
                    owner._confirm(); entered.set(); release.wait(2)
                original_publish.side_effect=publish
                owner.renew.side_effect=lambda:owner._publish()
                class ThreadProxy:
                    def __init__(self,**kwargs): self.thread=real_thread(**kwargs); threads.append(self.thread)
                    def start(self):
                        self.thread.start()
                        if failure=='start': raise KeyboardInterrupt('start interrupted')
                    def join(self,timeout):
                        if failure=='join': raise KeyboardInterrupt('join interrupted')
                        self.thread.join(timeout)
                    def is_alive(self): return self.thread.is_alive()
                monitor=mock.Mock(); monitor.lines.return_value=[b'PID 7']
                helper={'Monitor':mock.Mock(return_value=monitor),'remote_absent':mock.Mock()}
                def streams(*unused):
                    return driver._stream('request',1,'renew','d'*64,{'container_id':'c'*64},helper,proof)
                try:
                    with ExitStack() as stack:
                        for obj,name,value in ((driver.threading,'Thread',ThreadProxy),(driver.controller,'open_edge',owner),(driver,'_wait_status',None),(driver,'_source_guard','source'),(q,'begin',proof),(init,'initialize',(Path('/receipt'),'digest')),(cli,'main',None),(driver.origin21_transport,'managed_transport',object()),(driver,'qualify_positive_streams',None),(disposal,'dispose_synthetic_volume',None)):
                            if name=='Thread': stack.enter_context(mock.patch.object(obj,name,side_effect=ThreadProxy))
                            elif name=='qualify_positive_streams': stack.enter_context(mock.patch.object(obj,name,side_effect=streams))
                            else: stack.enter_context(mock.patch.object(obj,name,return_value=value))
                        with self.assertRaises(BaseExceptionGroup) as raised: driver.main(['image','head','receipt','digest'])
                        self.assertTrue(any(isinstance(e,KeyboardInterrupt) for e in raised.exception.exceptions),repr(raised.exception))
                        owner.close.assert_not_called(); proof.close.assert_not_called(); disposal.dispose_synthetic_volume.assert_not_called()
                        self.assertIsNot(owner._publish,original_publish); self.assertIsNot(owner._confirm,original_confirm)
                        self.assertTrue(any(item[0] is owner for item in driver._RETAINED))
                finally:
                    release.set()
                    for thread in threads: thread.join(2)
                    driver._RETAINED[:]=[item for item in driver._RETAINED if item[0] is not owner and item[0] is not proof]

    def exercise_failure(self,kind):
        import threading,time
        owner=mock.Mock(); current=['a'*64]; release=threading.Event(); published=[]
        owner._load.side_effect=lambda:{'current_commitment':{'cert_sha256':current[0]}}
        def confirm():
            if kind=='confirm': raise ValueError('confirm')
        def publish():
            published.append(True); owner._confirm()
            if kind=='postgate': raise ValueError('postgate')
            if kind=='live': release.wait(2)
            current[0]='b'*64
        owner._confirm.side_effect=confirm; owner._publish.side_effect=publish
        owner.renew.side_effect=lambda:owner._publish()
        monitor=mock.Mock(); monitor.lines.return_value=[b'PID 7']
        if kind=='client': monitor.wait.side_effect=ValueError('client')
        if kind=='barrier': monitor.wait.side_effect=lambda *a,**k:time.sleep(.15)
        helper={'Monitor':mock.Mock(return_value=monitor),'remote_absent':mock.Mock()}
        try:
            with mock.patch.object(driver.controller,'open_edge',return_value=owner),mock.patch.object(driver,'_wait_status'),mock.patch.object(driver,'_STREAM_DEADLINE',.1 if kind in ('live','barrier') else 2):
                with self.assertRaises(BaseExceptionGroup): driver._stream('request',1,'renew','d'*64,{'container_id':'c'*64},helper,object())
            if kind in ('client','barrier'): self.assertFalse(published)
            if kind=='confirm': monitor.send.assert_not_called()
            if kind=='live':
                owner.close.assert_not_called(); self.assertTrue(any(item[0] is owner for item in driver._RETAINED))
            else: owner.close.assert_called_once()
        finally:
            release.set()
            for item in list(driver._RETAINED):
                if item[0] is owner:
                    item[1].join(2); driver._RETAINED.remove(item); owner.close()

    def test_confirmation_failure(self): self.exercise_failure('confirm')
    def test_post_activation_gate_or_save_failure(self): self.exercise_failure('postgate')
    def test_client_failure_before_prefix(self): self.exercise_failure('client')
    def test_barrier_expiry(self): self.exercise_failure('barrier')
    def test_live_writer_retains_owner(self): self.exercise_failure('live')

    def test_owner_failure_never_constructs_stream_client(self):
        helper={'Monitor':mock.Mock()}
        with mock.patch.object(driver.controller,'open_edge',side_effect=RuntimeError('owner unavailable')):
            with self.assertRaises(RuntimeError): driver._stream('request',1,'renew','d'*64,{'container_id':'c'*64},helper,object())
        helper['Monitor'].assert_not_called()

    def test_renewal_and_monitor_cleanup_failures_survive_owner_close(self):
        primary=RuntimeError('rotation failed'); cleanup=OSError('reap failed')
        owner=mock.Mock();owner._load.return_value={'current_commitment':{'cert_sha256':'a'*64}}
        owner.renew.side_effect=lambda:owner._publish()
        owner._publish.side_effect=primary
        monitor=mock.Mock();monitor.lines.return_value=[b'PID 7'];monitor.reap.side_effect=cleanup
        helper={'Monitor':mock.Mock(return_value=monitor),'remote_absent':mock.Mock()}
        with mock.patch.object(driver.controller,'open_edge',return_value=owner),mock.patch.object(driver,'_wait_status'):
            with self.assertRaises(BaseExceptionGroup) as raised:
                driver._stream('request',1,'renew','d'*64,{'container_id':'c'*64},helper,object())
        self.assertIn(primary,raised.exception.exceptions);self.assertIn(cleanup,raised.exception.exceptions)
        owner.close.assert_called_once();helper['remote_absent'].assert_not_called()

if __name__=='__main__': unittest.main()
