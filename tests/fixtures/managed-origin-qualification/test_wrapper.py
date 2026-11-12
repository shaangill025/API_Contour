"""Offline owner/resource boundaries for the portable managed wrapper."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('managed_qualification_wrapper',ROOT/'scripts/qualify-managed-origin.py')
wrapper=importlib.util.module_from_spec(spec); spec.loader.exec_module(wrapper)


class ManagedWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.child=Path(self.temp.name)/'worktree'; self.child.mkdir(mode=0o700)
        self.base=self.child/'.local-mvp-managed'; self.base.mkdir(mode=0o700)
        self.token='a'*32; self.head='b'*40; self.volume='contour-managed-origin21-qual-'+self.token+'-data'
        self.folder=self.base/'qualification'/self.token; self.folder.mkdir(mode=0o700,parents=True)
        (self.base/'qualification').chmod(0o700); self.folder.chmod(0o700)
        edge=self.base/'managed-edge'; state=edge/'state'; state.mkdir(mode=0o700,parents=True); edge.chmod(0o700); state.chmod(0o700)
        self.record(state/'publication.exec.intent',{'publisher':'fixture'})
        fixture=self.child/'tests/fixtures/managed-origin-qualification/destination.js'; fixture.parent.mkdir(parents=True); fixture.write_bytes(b'fixed')
        self.intent={'version':1,'kind':'synthetic','token':self.token,'head':self.head,'volume':self.volume,'destination':'tests/fixtures/managed-origin-qualification/destination.js','destination_sha256':hashlib.sha256(b'fixed').hexdigest(),'source_identity':'f'*64,'build_image':'sha256:'+'1'*64,'build_receipt_sha256':'2'*64}
        digest=hashlib.sha256(json.dumps(self.intent,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.containers=['%064x'%i for i in range(1,10)]; self.networks=['%064x'%i for i in range(10,12)]
        self.record(self.folder/'qualification.intent',self.intent)
        self.record(self.folder/'topology.intent',{'version':1,'token':self.token,'intent_sha256':digest,'containers':self.containers,'networks':self.networks})
        self.record(self.folder/'topology.cleaned',{'version':1,'token':self.token,'intent_sha256':digest,'containers_removed':self.containers,'networks_removed':self.networks})
        self.record(self.folder/'volume-dispose.done',{'version':1,'token':self.token,'volume':self.volume})
        self.record(self.base/'initializer.intent',{'version':1,'head':self.head,'token':'c'*32,'volume':self.volume,'build_image':'sha256:'+'1'*64,'build_receipt_sha256':'2'*64,'network':'fixed'})
        self.record(edge/'intent.json',{'version':1,'origin_token':'0'*64,'edge_token':'d'*32})
        self.owner=mock.Mock(); self.calls=[]; self.survives=False
    def tearDown(self): self.temp.cleanup()
    def record(self,path,value):
        path.write_bytes(json.dumps(value,sort_keys=True,separators=(',',':')).encode()); path.chmod(0o600)
    def command(self,args,**kwargs):
        self.calls.append(args)
        return b'owned' if self.survives and args[-1]=='id='+self.containers[0] else b''
    def test_exact_absence_removes_only_synthetic_tree(self):
        sentinel=self.child/'keep'; sentinel.write_text('foreign')
        wrapper.cleanup_private(self.command,self.child,self.owner,self.head)
        self.assertFalse(self.base.exists()); self.assertEqual(sentinel.read_text(),'foreign')
    def test_readiness_component_requires_no_lost_ack_intent(self):
        with self.assertRaises(ValueError): wrapper.cleanup_private(self.command,self.child,self.owner,self.head,profile_readiness=True)
        self.assertTrue(self.base.exists())
        (self.base/'managed-edge'/'state'/'publication.exec.intent').unlink()
        wrapper.cleanup_private(self.command,self.child,self.owner,self.head,profile_readiness=True)
        self.assertFalse(self.base.exists())

    def test_surviving_resource_or_unsafe_entry_retains_state(self):
        self.survives=True
        with self.assertRaises(ValueError): wrapper.cleanup_private(self.command,self.child,self.owner,self.head)
        self.assertTrue(self.base.exists()); self.survives=False
        (self.base/'foreign-link').symlink_to(self.child/'outside')
        with self.assertRaises(ValueError): wrapper.cleanup_private(self.command,self.child,self.owner,self.head)
        self.assertTrue((self.base/'foreign-link').is_symlink())
    def test_outer_build_failure_retains_worktree_and_never_runs_inner(self):
        owner_path=self.child.parent/'owner'; owner_path.mkdir(mode=0o700); calls=[]
        class Owner:
            path=owner_path
            def verify(self): pass
            def write(self,name,data):
                path=self.path/name; path.write_bytes(data); return path
        def run(args,**kwargs):
            calls.append(args)
            if args[:3]==['git','worktree','add']:
                path=Path(args[-2]); path.mkdir(); (path/'.git').write_text('gitdir: owned')
            if args[:2]==['docker','build']: raise TimeoutError('unknown build')
            return b''
        h={'snapshot':lambda *_:('b'*40,{'source':'fixed'}),'require_registration':lambda *a,**k:None,'encode':lambda x:json.dumps(x,sort_keys=True,separators=(',',':')).encode(),'OWNER_LABEL':'owner','HEAD_LABEL':'head'}
        with self.assertRaises(TimeoutError): wrapper.qualify(run,Owner(),'a'*32,h)
        self.assertTrue((owner_path/'intent.json').exists()); self.assertTrue((owner_path/'worktree').exists()); self.assertFalse((owner_path/'build-receipt.json').exists())
        self.assertFalse(any('scripts/test-managed-origin-qualification.py' in cmd for cmd in calls))

    def test_outer_refuses_preexisting_worktree_without_adoption(self):
        owner_path=self.child.parent/'owner'; owner_path.mkdir(mode=0o700); foreign=owner_path/'worktree'; foreign.mkdir(); sentinel=foreign/'keep'; sentinel.write_text('foreign')
        owner=mock.Mock(); owner.path=owner_path
        h={'snapshot':lambda *_:('b'*40,{'source':'fixed'})}
        with self.assertRaises(ValueError): wrapper.qualify(mock.Mock(),owner,'a'*32,h)
        self.assertEqual(sentinel.read_text(),'foreign')

    def test_dirty_helper_is_rejected_before_loading_code(self):
        with mock.patch.object(wrapper.subprocess,'run',return_value=mock.Mock(returncode=1)),mock.patch.object(wrapper.runpy,'run_path') as load:
            with self.assertRaises(ValueError): wrapper.helper()
            load.assert_not_called()

    def test_shared_capability_refusal_precedes_owner_creation(self):
        with mock.patch.object(wrapper.sys,'argv',['qualify-managed-origin.py']),mock.patch.object(wrapper,'helper',return_value={'require_process_primitives':mock.Mock(side_effect=RuntimeError('missing'))}),mock.patch.object(wrapper.tempfile,'mkdtemp') as create:
            with self.assertRaises(RuntimeError): wrapper.main()
            create.assert_not_called()

    def test_missing_waitid_refuses_before_helper_or_owner(self):
        with mock.patch.object(wrapper.sys,'argv',['qualify-managed-origin.py']),mock.patch.object(wrapper.os,'waitid',None,create=True),mock.patch.object(wrapper,'helper') as helper,mock.patch.object(wrapper.tempfile,'mkdtemp') as create:
            with self.assertRaises(RuntimeError): wrapper.main()
            helper.assert_not_called(); create.assert_not_called()

    def test_budgets_are_separate_from_legacy(self):
        self.assertEqual((wrapper.GLOBAL_SECONDS,wrapper.BUILD_SECONDS,wrapper.QUALIFY_SECONDS),(3600,1800,1200))


class DiagnosticTests(unittest.TestCase):
    def test_bad_cli_arguments_report_type_and_phase_without_argument(self):
        import subprocess,sys
        result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/qualify-managed-origin.py'),'secret-argument'],capture_output=True,text=True,timeout=10)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('managed-failure phase=arguments role=primary type=ValueError',result.stderr)
        self.assertNotIn('secret-argument',result.stderr)
    def test_inner_bad_arguments_report_type_without_value(self):
        import subprocess,sys
        result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/test-managed-origin-qualification.py'),'secret-argument'],capture_output=True,text=True,timeout=10)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('managed-failure phase=arguments role=primary type=ValueError',result.stderr)
        self.assertNotIn('secret-argument',result.stderr)
    def test_nested_failures_are_bounded_and_redacted(self):
        class SecretError(Exception): pass
        error=BaseExceptionGroup('secret group',[ValueError('secret primary'),BaseExceptionGroup('secret nested',[OSError('secret cleanup'),SecretError('secret unknown')])]+[RuntimeError('secret')]*40)
        lines=wrapper.failure_lines(error,'build')
        self.assertLessEqual(len(lines),16)
        self.assertTrue(any('role=primary type=ValueError' in line for line in lines))
        self.assertTrue(any('role=cleanup type=OSError' in line for line in lines))
        self.assertTrue(any('type=OtherError' in line for line in lines))
        self.assertNotIn('secret',' '.join(lines))
    def test_private_log_timing_grammar_rejects_untrusted_and_bounds_count(self):
        with tempfile.TemporaryDirectory() as directory:
            owner=mock.Mock(); owner.path=Path(directory)
            valid=b'managed-ready name=setup event=end ms=12 count=2'
            bad=[b'managed-ready name=secret event=end ms=12 count=2',b'managed-ready name=setup event=end ms=1000000000 count=2',b'managed-ready name=setup event=end ms=1 count=161',b'managed-ready name=setup event=end ms=1 count=1 secret']
            (owner.path/'qualification.log').write_bytes(b'\n'.join([valid]*170+bad))
            lines=wrapper.child_failure_lines(owner)
            self.assertEqual(lines,[valid.decode()]*160)

    def test_stream_timings_are_closed_and_bounded(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            owner=mock.Mock(); owner.path=Path(directory)
            valid=b'managed-stream name=publish ms=12 count=2'
            bad=[b'managed-stream name=secret ms=1 count=1',b'managed-stream name=publish ms=1000000000 count=1',b'managed-stream name=publish ms=1 count=6',b'managed-stream name=publish ms=1 count=1 secret']
            (owner.path/'qualification.log').write_bytes(b'\n'.join([valid]*25+bad))
            self.assertEqual(wrapper.child_failure_lines(owner),[valid.decode()]*20)

    def test_private_log_accepts_only_closed_child_diagnostics(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            owner=mock.Mock(); owner.path=Path(directory)
            (owner.path/'qualification.log').write_bytes(b'managed-failure phase=stream-prefix role=primary type=TimeoutError location=scripts/test-managed-origin-qualification.py:123\nmanaged-failure phase=secret role=primary type=ValueError location=unavailable\nsecret data\n')
            self.assertEqual(wrapper.child_failure_lines(owner),['managed-failure phase=stream-prefix role=primary type=TimeoutError location=scripts/test-managed-origin-qualification.py:123'])

class ProgressTests(unittest.TestCase):
    def test_progress_is_closed_and_flushed_without_untrusted_value(self):
        import contextlib,io,runpy
        inner=runpy.run_path(str(ROOT/'scripts/test-managed-origin-qualification.py'))
        output=io.StringIO()
        with contextlib.redirect_stderr(output):
            inner['_set_phase']('initial-readiness')
            with self.assertRaises(ValueError): inner['_set_phase']('secret-value')
        self.assertEqual(output.getvalue(),'managed-progress phase=initial-readiness\n')

if __name__=='__main__': unittest.main()
