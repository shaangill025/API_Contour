import contextlib
import json
import tempfile
import importlib.util
import threading
from pathlib import Path
import unittest
from unittest import mock
from contextlib import ExitStack

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('readiness_driver',ROOT/'scripts/test-managed-origin-qualification.py')
driver=importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)
spec=importlib.util.spec_from_file_location('readiness_wrapper',ROOT/'scripts/qualify-managed-origin.py')
wrapper=importlib.util.module_from_spec(spec); spec.loader.exec_module(wrapper)
from deploy.local import origin21_readiness_profile as profile,origin21_managed_qualification as q


class ProfilingTests(unittest.TestCase):
    def proof(self): return object.__new__(q.OwnedManagedQualification)

    def test_wrap_preserves_object_arguments_results_and_exact_errors(self):
        p=profile.Profile(self.proof(),clock=iter([1_000_000,3_000_000,5_000_000,9_000_000]).__next__)
        token=object(); result=object(); error=ValueError('private-canary'); seen=[]
        def original(*args,**kwargs):
            seen.append((args,kwargs))
            if len(seen)==2: raise error
            return result
        wrapped=p._wrap('products_command',original)
        self.assertIs(wrapped(token,key=token),result)
        with self.assertRaises(ValueError) as caught: wrapped(token,key=token)
        self.assertIs(caught.exception,error); self.assertIs(seen[0][0][0],token); self.assertIs(seen[0][1]['key'],token)
        line=p.lines()[1]; self.assertEqual(line,'managed-profile name=products_command calls=2 inclusive_ms=6 max_ms=4')
        self.assertNotIn('private-canary',' '.join(p.lines()))

    def test_clock_failure_and_threads_never_change_original(self):
        p=profile.Profile(self.proof(),clock=lambda:float('nan'))
        wrapped=p._wrap('transport_run',lambda x:x)
        threads=[threading.Thread(target=lambda:[wrapped('private-canary') for _ in range(100)]) for _ in range(4)]
        for t in threads:t.start()
        for t in threads:t.join()
        self.assertEqual(p.counts['transport_run'],[400,0,0]); self.assertNotIn('private-canary',' '.join(p.lines()))
        failure=RuntimeError('original')
        def bad(): raise failure
        with self.assertRaises(RuntimeError) as caught: p._wrap('transport_run',bad)()
        self.assertIs(caught.exception,failure)

    def test_hooks_restore_on_exception(self):
        from deploy.local import origin21_products
        p=profile.Profile(self.proof()); original=origin21_products._command
        with mock.patch.object(q.OwnedManagedQualification,'verify'):
            with self.assertRaisesRegex(ValueError,'failure'):
                with p:
                    self.assertIsNot(origin21_products._command,original)
                    raise ValueError('failure')
        self.assertIs(origin21_products._command,original)

    def test_component_runs_one_readiness_then_owned_cleanup(self):
        from deploy.local import origin21_managed_init as init,origin21_managed_cli as cli,origin21_managed_cleanup as cleanup,origin21_managed_qualification_cleanup as disposal
        proof=mock.MagicMock(); events=[]; transport=object(); expected=(b'a'*32,b'b'*32)
        def call(name,value=None):
            def fn(*_a,**_k): events.append(name); return value
            return fn
        class Profiler:
            def __init__(self,argument): self.argument=argument
            def __enter__(self): events.append('profile-enter'); return self
            def __exit__(self,*_): events.append('profile-exit')
            def lines(self): return ('fixed line',)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(driver,'_source_guard',return_value='source'))
            stack.enter_context(mock.patch.object(q,'begin',side_effect=call('begin',proof)))
            stack.enter_context(mock.patch.object(init,'initialize',side_effect=call('initialize',(Path('/receipt'),'digest'))))
            stack.enter_context(mock.patch.object(cli,'main',side_effect=call('up')))
            stack.enter_context(mock.patch.object(driver.origin21_transport,'managed_transport',side_effect=call('transport',transport)))
            stack.enter_context(mock.patch.object(driver,'_commitments',return_value=expected))
            ready=stack.enter_context(mock.patch.object(driver.origin21_ready,'check',side_effect=call('ready',{'product_tls_and_catalog_verified':True,'ui_verified':False})))
            stack.enter_context(mock.patch.object(profile,'Profile',Profiler))
            stack.enter_context(mock.patch.object(cleanup,'teardown',side_effect=call('teardown')))
            stack.enter_context(mock.patch.object(disposal,'dispose_synthetic_volume',side_effect=call('volume')))
            positive=stack.enter_context(mock.patch.object(driver,'qualify_positive_streams'))
            negative=stack.enter_context(mock.patch.object(driver,'qualify_wrong_name_and_pending'))
            unknown=stack.enter_context(mock.patch.object(driver,'qualify_lost_publication_ack'))
            with mock.patch('builtins.print'): result=driver.main(['image','head','receipt','digest','--profile-readiness'])
        self.assertEqual(result,{'scope':'single-full-readiness-diagnostic','component':True})
        self.assertEqual(events,['begin','initialize','up','transport','profile-enter','ready','profile-exit','teardown','volume'])
        ready.assert_called_once_with(expected,selected=driver.profiles.MANAGED,transport=transport)
        positive.assert_not_called(); negative.assert_not_called(); unknown.assert_not_called(); proof.close.assert_called_once()

    def test_closed_output_and_default_deadline(self):
        self.assertEqual(wrapper._PROFILE_LABELS,profile.LABELS)
        lines=['managed-profile totals=inclusive-overlap-not-additive']+[
            'managed-profile name='+name+' calls=1 inclusive_ms=1 max_ms=1' for name in wrapper._PROFILE_LABELS]
        raw=('\n'.join(lines+['managed-component scope=single-full-readiness-diagnostic result=pass'])+'\n').encode()
        self.assertEqual(wrapper.profile_lines(raw),tuple(lines)); self.assertEqual(wrapper.QUALIFY_SECONDS,1200)
        with self.assertRaises(ValueError): wrapper.profile_lines(raw+b'private-canary\n')
        with self.assertRaises(ValueError): wrapper.profile_lines(raw.replace(b'calls=1',b'calls=9999999',1))
        self.assertIn('deploy/local/origin21_readiness_profile.py',driver.origin21_state.MANAGED_SOURCE_FILES)

class FlagAndFailureTests(unittest.TestCase):
    def test_flag_grammar_before_any_proof(self):
        for args in (['--profile-readiness','--profile-readiness'],['--profile-readiness','--unknown']):
            with mock.patch.object(wrapper.sys,'argv',['wrapper',*args]),mock.patch.object(wrapper,'helper') as helper:
                with self.assertRaises(ValueError): wrapper.main()
                helper.assert_not_called()
        with mock.patch.object(driver,'_source_guard') as guard:
            with self.assertRaises(ValueError): driver.main(['a','b','c','d','--profile-readiness','--profile-readiness'])
            guard.assert_not_called()

    def test_outer_forwards_closed_flag_combinations(self):
        for fresh,diagnostic in ((False,False),(True,False),(False,True),(True,True)):
            with self.subTest(fresh=fresh,diagnostic=diagnostic), tempfile.TemporaryDirectory() as d:
                folder=Path(d); calls=[]
                class Owner:
                    path=folder
                    def verify(self): pass
                    def write(self,name,data):
                        p=self.path/name; p.write_bytes(data); return p
                def run(args,**_kwargs):
                    calls.append(args)
                    if args[:3]==['git','worktree','add']:
                        child=Path(args[-2]); child.mkdir(); (child/'.git').write_text('gitdir: owned')
                    if len(args)>1 and args[1]=='scripts/test-managed-origin-qualification.py':
                        raise RuntimeError('stop before execution')
                    return b''
                helper={'snapshot':lambda *_:('b'*40,{'fixed':'hash'}),'require_registration':lambda *_a,**_k:None,
                        'encode':lambda x:json.dumps(x,sort_keys=True,separators=(',',':')).encode(),
                        'OWNER_LABEL':'owner','HEAD_LABEL':'head','image_identity':lambda *_:'sha256:'+'c'*64}
                with self.assertRaisesRegex(RuntimeError,'stop before execution'):
                    wrapper.qualify(run,Owner(),'a'*32,helper,fresh_metadata=fresh,profile_readiness=diagnostic)
                argv=next(a for a in calls if len(a)>1 and a[1]=='scripts/test-managed-origin-qualification.py')
                self.assertEqual('--fresh-metadata' in argv,fresh); self.assertEqual('--profile-readiness' in argv,diagnostic)

    def test_inner_accepts_both_flag_orders_and_binds_scope_after_proof(self):
        from deploy.local import origin21_managed_init as init
        for flags in (['--fresh-metadata','--profile-readiness'],['--profile-readiness','--fresh-metadata']):
            proof=mock.MagicMock(); order=[]
            @contextlib.contextmanager
            def scope(value):
                self.assertIs(value,proof); order.append('scope'); yield
            def begin(**_): order.append('begin'); return proof
            def stop(**_): order.append('initialize'); raise RuntimeError('stop')
            with mock.patch.object(driver,'_source_guard',return_value='source'),mock.patch.object(q,'begin',side_effect=begin), \
                 mock.patch.object(driver.docker_metadata,'qualification_scope',side_effect=scope),mock.patch.object(init,'initialize',side_effect=stop):
                with self.assertRaisesRegex(RuntimeError,'stop'): driver.main(['image','head','receipt','digest',*flags])
            self.assertEqual(order,['begin','scope','initialize']); proof.close.assert_called_once()

    def test_failed_readiness_does_not_teardown_or_claim_success(self):
        from deploy.local import origin21_managed_init as init,origin21_managed_cli as cli,origin21_managed_cleanup as cleanup,origin21_managed_qualification_cleanup as disposal
        proof=mock.MagicMock()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(driver,'_source_guard',return_value='source'))
            stack.enter_context(mock.patch.object(q,'begin',return_value=proof))
            stack.enter_context(mock.patch.object(init,'initialize',return_value=(Path('/receipt'),'digest')))
            stack.enter_context(mock.patch.object(cli,'main'))
            stack.enter_context(mock.patch.object(driver.origin21_transport,'managed_transport',return_value=object()))
            stack.enter_context(mock.patch.object(driver,'_commitments',return_value=(b'a'*32,b'b'*32)))
            stack.enter_context(mock.patch.object(profile,'Profile',return_value=contextlib.nullcontext()))
            stack.enter_context(mock.patch.object(driver.origin21_ready,'check',side_effect=RuntimeError('not ready')))
            teardown=stack.enter_context(mock.patch.object(cleanup,'teardown'))
            volume=stack.enter_context(mock.patch.object(disposal,'dispose_synthetic_volume'))
            with self.assertRaisesRegex(RuntimeError,'not ready'):
                driver.main(['image','head','receipt','digest','--profile-readiness'])
        teardown.assert_not_called(); volume.assert_not_called(); proof.close.assert_called_once()


if __name__=='__main__':unittest.main()
