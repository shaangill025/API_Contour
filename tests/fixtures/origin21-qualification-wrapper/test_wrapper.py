import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import time
import os
import signal
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('origin21_wrapper',ROOT/'scripts/qualify-origin21-onboarding.py')
w=importlib.util.module_from_spec(spec); spec.loader.exec_module(w)


class WrapperTests(unittest.TestCase):
    def test_child_diagnostics_are_closed_and_never_emit_raw_values(self):
        allowed=b'fixture failure phase=full-capture type=RuntimeError location=test-origin21-onboarding.py:123,origin21_sql_runner.py:45'
        raw=b'private-key-and-business-data\n'+allowed+b'\n'+allowed+b'\n'
        raw+=b'fixture failure phase=secret type=RuntimeError location=unavailable\n'
        raw+=b'fixture failure phase=full-capture type=SecretClass location=unavailable\n'
        raw+=b'fixture failure phase=full-capture type=ValueError location=private-secret.py:2\n'
        raw+=allowed+b' trailing-secret\n'
        self.assertEqual(w.public_child_failure_lines(raw),[allowed.decode()])
        cleanup=b'fixture failure phase=owned-cleanup type=CleanupFailure'
        self.assertEqual(w.public_child_failure_lines(cleanup),[cleanup.decode()])
        self.assertEqual(w.public_failure_locations(RuntimeError('secret')),[])
        try: exec(compile('raise RuntimeError("secret")',str(w.__file__),'exec'))
        except RuntimeError as error:
            result=w.public_failure_locations(error)
        self.assertEqual(result,['FAIL: Origin21 wrapper location=qualify-origin21-onboarding.py:1'])

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name).resolve(); self.owner=self.root/'owner'; self.owner.mkdir(mode=0o700); self.owned=w.OwnedDirectory(self.owner)
        self.head='a'*40; self.sources={'file':'c'*64}; self.token='b'*32; self.image='sha256:'+'d'*64; self.calls=[]
    def tearDown(self): self.owned.close(); self.temp.cleanup()
    def run_command(self,args,*,cwd,timeout,log=None):
        self.calls.append((args,cwd,timeout))
        if args[:3]==['git','worktree','add']:
            child=Path(args[-2]); child.mkdir(); (child/'.git').write_text('gitdir: owned')
        if args[:3]==['git','worktree','remove']: shutil.rmtree(args[-1])
        if args[:3]==['docker','image','ls']: return b''
        return b''
    def exercise(self,run=None,snapshot=None,image=None):
        snap=snapshot or mock.Mock(return_value=(self.head,self.sources))
        ident=image or mock.Mock(return_value=self.image)
        with mock.patch.object(w,'snapshot',snap), mock.patch.object(w,'require_registration') as reg, mock.patch.object(w,'image_identity',ident):
            w.qualify(run or self.run_command,self.root,self.owned,self.token)
        return snap,ident,reg
    def test_success_build_receipt_is_real_result_and_exact_worktree_removed(self):
        self.assertEqual((w.GLOBAL_SECONDS,w.BUILD_SECONDS,w.FULL_SECONDS,w.OUTPUT_LIMIT),(3000,1800,810,16777216))
        self.exercise(); calls=[x[0] for x in self.calls]
        build=next(x for x in calls if x[:2]==['docker','build'])
        self.assertEqual(next(x[2] for x in self.calls if x[0][:2]==['docker','build']),1800)
        self.assertEqual(next(x[2] for x in self.calls if '--full-capture' in x[0]),810)
        self.assertIn('org.apicontour.build-owner='+self.token,build); self.assertIn('org.apicontour.build-head='+self.head,build)
        invocation=next(x for x in calls if '--full-capture' in x)
        receipt=Path(invocation[-2]); raw=receipt.read_bytes(); value=json.loads(raw)
        self.assertEqual(value,{'version':1,'head':self.head,'image_id':self.image,'status':'passed','owner_token':self.token,'tag':'apicontour-origin21-build:'+self.token})
        self.assertEqual(invocation[-1],hashlib.sha256(raw).hexdigest())
        remove=next(x for x in calls if x[:3]==['git','worktree','remove']); self.assertNotIn('--force',remove)
        self.assertFalse((self.owner/'worktree').exists())
        self.assertEqual(receipt.stat().st_mode & 0o777,0o600)
    def test_source_change_stops_before_full_and_retains_intent(self):
        snap=mock.Mock(side_effect=[(self.head,self.sources),(self.head,self.sources),(self.head,{'file':'changed'})])
        with self.assertRaises(ValueError): self.exercise(snapshot=snap)
        self.assertTrue((self.owner/'intent.json').exists()); self.assertTrue((self.owner/'worktree').exists())
        self.assertFalse(any('--full-capture' in x[0] for x in self.calls)); self.assertFalse(any(x[0][:3]==['docker','image','rm'] for x in self.calls))
    def test_build_failure_retains_worktree_and_never_creates_receipt(self):
        def run(args,**kw):
            if args[:2]==['docker','build']: raise TimeoutError('unknown build outcome')
            return self.run_command(args,**kw)
        with self.assertRaises(TimeoutError): self.exercise(run=run)
        self.assertTrue((self.owner/'intent.json').exists()); self.assertTrue((self.owner/'worktree').exists()); self.assertFalse((self.owner/'build-receipt.json').exists())
    def test_drifted_image_refuses_cleanup(self):
        image=mock.Mock(side_effect=[self.image,'sha256:'+'e'*64])
        with self.assertRaises(ValueError): self.exercise(image=image)
        self.assertTrue((self.owner/'worktree').exists()); self.assertFalse(any(x[0][:3]==['docker','image','rm'] for x in self.calls))
    def test_cleanup_failure_retains_worktree(self):
        def run(args,**kw):
            if args[:3]==['docker','image','rm']: raise RuntimeError('cleanup failure')
            return self.run_command(args,**kw)
        with self.assertRaises(RuntimeError): self.exercise(run=run)
        self.assertTrue((self.owner/'worktree').exists()); self.assertTrue((self.owner/'intent.json').exists())
    def test_preexisting_path_is_never_adopted(self):
        (self.owner/'worktree').mkdir(); sentinel=self.owner/'worktree'/'sentinel'; sentinel.write_text('foreign')
        with self.assertRaises(ValueError): self.exercise()
        self.assertEqual(sentinel.read_text(),'foreign'); self.assertFalse(self.calls)
    def test_ignored_state_blocks_worktree_removal(self):
        def run(args,**kw):
            if args[:3]==['git','ls-files','--others']: return b'.local-mvp/private\0'
            return self.run_command(args,**kw)
        with self.assertRaises(RuntimeError): self.exercise(run=run)
        self.assertTrue((self.owner/'worktree').exists())
        self.assertFalse(any(x[0][:3]==['git','worktree','remove'] for x in self.calls))
    def test_bounded_runner_records_private_output_on_failure(self):
        log=self.owner/'build.log'; runner=w.Runner(time.monotonic()+5,self.owned)
        with self.assertRaises(RuntimeError):
            runner([sys.executable,'-c',"import sys;print('private');sys.exit(3)"],cwd=self.root,timeout=3,log=log)
        self.assertIn(b'private',log.read_bytes()); self.assertEqual(log.stat().st_mode & 0o777,0o600)
    def test_full_failure_retains_image_and_worktree(self):
        def run(args,**kw):
            if '--full-capture' in args: raise RuntimeError('qualification failed')
            return self.run_command(args,**kw)
        with self.assertRaises(RuntimeError): self.exercise(run=run)
        self.assertTrue((self.owner/'build-receipt.json').exists()); self.assertTrue((self.owner/'worktree').exists())
        self.assertFalse(any(x[0][:3]==['docker','image','rm'] for x in self.calls))

    def test_replaced_owner_never_written_or_removed(self):
        moved=self.root/'original'; self.owner.rename(moved); self.owner.mkdir(mode=0o700)
        sentinel=self.owner/'sentinel'; sentinel.write_text('foreign')
        with self.assertRaises(ValueError): self.owned.write('intent.json',b'owned')
        with self.assertRaises(ValueError): self.owned.remove()
        self.assertEqual(sentinel.read_text(),'foreign'); self.assertFalse((self.owner/'intent.json').exists())

    def test_unsupported_interpreter_refuses_before_process_or_owner_creation(self):
        with mock.patch.object(w.os,'waitid',None,create=True),mock.patch.object(w.subprocess,'Popen') as spawn,mock.patch.object(w.tempfile,'mkdtemp') as create,mock.patch.object(w.sys,'argv',['qualifier']):
            with self.assertRaises(w.ProcessRuntimeUnavailable):w.Runner(time.monotonic()+5,self.owned)
            with self.assertRaises(w.ProcessRuntimeUnavailable):w.main()
            spawn.assert_not_called();create.assert_not_called()

    def test_wait_exit_rejects_already_exited_after_deadline(self):
        observed=type('Exit',(),{'si_code':os.CLD_EXITED,'si_status':0})()
        with mock.patch.object(w,'observe_exit',return_value=observed) as inspect,mock.patch.object(w.time,'monotonic',return_value=2):
            with self.assertRaises(TimeoutError):w.wait_exit(object(),1)
            inspect.assert_not_called()
        with mock.patch.object(w,'observe_exit',return_value=observed),mock.patch.object(w.time,'monotonic',side_effect=[0,2]):
            with self.assertRaises(TimeoutError):w.wait_exit(object(),1)

    def test_leader_is_unreaped_until_the_group_signal(self):
        original_popen=subprocess.Popen; original_killpg=os.killpg; processes=[]
        def popen(*args,**kw):
            child=original_popen(*args,**kw);processes.append(child);return child
        def killpg(group,signal_number):
            if signal_number==signal.SIGKILL and group==processes[0].pid:
                self.assertIsNone(processes[0].returncode,'leader was reaped before group signal')
            return original_killpg(group,signal_number)
        with mock.patch.object(w.subprocess,'Popen',side_effect=popen), mock.patch.object(w.os,'killpg',side_effect=killpg):
            self.assertEqual(w.Runner(time.monotonic()+10,self.owned)([sys.executable,'-c',"print('ok')"],cwd=self.root,timeout=3),b'ok\n')

    def test_leader_exit_descendant_holding_pipe_is_killed(self):
        child_code="import time;time.sleep(60)"
        parent_code="import os,subprocess,sys;subprocess.Popen([sys.executable,'-c',sys.argv[1]]);print(os.getpgrp(),flush=True)"
        runner=w.Runner(time.monotonic()+10,self.owned)
        start=time.monotonic()
        with self.assertRaises((TimeoutError,BaseExceptionGroup)):
            runner([sys.executable,'-c',parent_code,child_code],cwd=self.root,timeout=.4,log=self.owner/'build.log')
        self.assertLess(time.monotonic()-start,7)
        group=int((self.owner/'build.log').read_bytes().splitlines()[0])
        with self.assertRaises(ProcessLookupError): os.killpg(group,0)

    def test_exited_permission_requires_eventual_esrch_and_only_one_group_stop(self):
        original=os.killpg;calls=[];denied=False
        def killpg(group,number):
            nonlocal denied
            calls.append(number)
            if number==signal.SIGKILL: raise PermissionError('zombie observation')
            if not denied: denied=True;raise PermissionError('transient absence observation')
            return original(group,number)
        with mock.patch.object(w.os,'killpg',side_effect=killpg):
            self.assertEqual(w.Runner(time.monotonic()+5,self.owned)([sys.executable,'-c',"print('ok')"],cwd=self.root,timeout=2),b'ok\n')
        self.assertEqual(calls.count(signal.SIGKILL),1);self.assertTrue(denied)

    def test_process_group_parses_documented_bsd_memory_status(self):
        real_popen=subprocess.Popen
        def inspect(raw):
            def fake_ps(args,**kwargs):
                self.assertEqual(args,['/bin/ps','-axo','pid=,pgid=,stat='])
                return real_popen([sys.executable,'-c','import sys;sys.stdout.buffer.write('+repr(raw)+')'],**kwargs)
            with mock.patch.object(w.subprocess,'Popen',side_effect=fake_ps):
                return w.group_members(100,time.monotonic()+3)
        self.assertEqual(inspect(b'100 100 S>\n101 100 R>+\n200 200 S<\n'),{100,101})
        self.assertEqual(inspect(b'100 100 ?\n101 100 ?E\n200 200 S<\n'),{100,101})
        for raw in (b'100 100 S!\n',b'100 100 S\x01\n',b'100 100 S\n100 100 R\n',b'101 100 S\n'):
            with self.subTest(raw=raw),self.assertRaises((ValueError,RuntimeError)):
                inspect(raw)

    def test_observed_extra_member_is_failure_even_when_output_and_exit_are_valid(self):
        with mock.patch.object(w,'group_members',side_effect=lambda group,deadline:{group,group+1}):
            with self.assertRaisesRegex(RuntimeError,'descendant survived'):
                w.Runner(time.monotonic()+5,self.owned)([sys.executable,'-c',"print('ok')"],cwd=self.root,timeout=2)

    def test_inspection_failure_still_stops_owned_group_before_reap(self):
        original=os.killpg;stops=[]
        def killpg(group,number):
            if number==signal.SIGKILL:stops.append(group)
            return original(group,number)
        with mock.patch.object(w,'group_members',side_effect=ValueError('untrusted observation')),mock.patch.object(w.os,'killpg',side_effect=killpg):
            with self.assertRaisesRegex(ValueError,'untrusted observation'):
                w.Runner(time.monotonic()+5,self.owned)([sys.executable,'-c','pass'],cwd=self.root,timeout=2)
        self.assertEqual(len(stops),1)

    def test_primary_and_persistent_permission_failures_are_both_retained(self):
        with mock.patch.object(w.os,'killpg',side_effect=PermissionError('denied')):
            with self.assertRaises(BaseExceptionGroup) as caught:
                w.Runner(time.monotonic()+.3,self.owned)([sys.executable,'-c','raise SystemExit(3)'],cwd=self.root,timeout=.2)
        self.assertTrue(any(isinstance(e,RuntimeError) for e in caught.exception.exceptions))
        self.assertTrue(any(isinstance(e,PermissionError) for e in caught.exception.exceptions))

    def test_denied_group_signal_is_failure(self):
        runner=w.Runner(time.monotonic()+5,self.owned)
        with mock.patch.object(w.os,'killpg',side_effect=PermissionError('denied')):
            with self.assertRaises((PermissionError,BaseExceptionGroup)):
                runner([sys.executable,'-c','pass'],cwd=self.root,timeout=3)

    def test_label_mismatch_is_rejected(self):
        image={'Id':self.image,'RepoTags':['tag'],'Config':{'Labels':{w.OWNER_LABEL:'other',w.HEAD_LABEL:self.head}}}
        with self.assertRaises(ValueError): w.image_identity(lambda *a,**k:json.dumps([image]).encode(),self.root,'tag',self.token,self.head)

if __name__=='__main__': unittest.main()
