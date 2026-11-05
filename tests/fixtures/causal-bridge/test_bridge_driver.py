import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

MODULE=runpy.run_path(str(Path(__file__).resolve().parents[3]/'scripts/test-postgres-causal-bridge.py'))
G=MODULE['main'].__globals__


class DriverTests(unittest.TestCase):
    def test_all_probe_cases_and_persisted_effects(self):
        calls=[]; state={'stages':[]}; work=Path('/synthetic'); base=['probe']+['original']*23
        expected=[('untrusted_tls_ca',4,'/synthetic/untrusted.crt','fixture issuer TLS failed'),
                  ('wrong_issuer_role',5,'causal_inbox_login','Identity'),
                  ('mixed_issuer_role',5,'causal_mixed_login','Identity'),
                  ('wrong_grant_key',7,'/synthetic/policy.pub','Signature'),
                  ('wrong_policy_key',8,'/synthetic/grant.pub','Signature'),
                  ('invalid_grant_signature',9,'/synthetic/grant-invalid.json','Signature'),
                  ('invalid_policy_signature',10,'/synthetic/policy-invalid.json','Signature'),
                  ('wrong_peer_pin',12,'44'*32,'Scope'),
                  ('wrong_source',16,'f7000000-0000-4000-8000-000000000003','Identity'),
                  ('wrong_inbox_role',6,'causal_issuer_login','Identity'),
                  ('mixed_inbox_role',6,'causal_mixed_login','Identity')]
        def runner(args,**kwargs):
            index=len(calls); calls.append(list(args))
            self.assertEqual(kwargs['timeout'],40)
            if index<len(expected):
                _,pos,value,result=expected[index]
                self.assertEqual(args[pos],value)
                self.assertEqual([i for i in range(len(args)) if args[i]!=base[i]],[pos])
                return subprocess.CompletedProcess(args,1,b'',result.encode())
            self.assertEqual(args,base)
            return subprocess.CompletedProcess(args,0,b'PASS: causal issue and exact committed batch retry\n',b'')
        def counts():
            n=len(calls)
            if n<=9: return '0|0|0|0|0|0'
            if n<=11: return '1|0|0|0|0|0'
            return '1|1|1|339|339|1'
        with mock.patch.dict(G,{'run_process':runner}):
            MODULE['run_probe_cases'](base,work,{},counts,state)
        self.assertEqual(len(calls),12)
        self.assertEqual(state['stages'],[x[0] for x in expected]+['positive_commit_and_exact_duplicate'])
        self.assertEqual(state['receipt_counts'],{'sessions':1,'batches':1,'events':1,'distinct_receipts':1,'used_bytes':339})
        self.assertEqual(state['status'],'passed')

    def test_negative_that_writes_is_rejected(self):
        def runner(args,**kwargs): return subprocess.CompletedProcess(args,1,b'',b'fixture issuer TLS failed')
        n=iter(['0|0|0|0|0|0','1|0|0|0|0|0'])
        state={'stages':[]}
        with mock.patch.dict(G,{'run_process':runner}):
            with self.assertRaisesRegex(AssertionError,'negative caused durable writes'):
                MODULE['run_probe_cases'](['p']+['x']*23,Path('/synthetic'),{},lambda:next(n),state)
        self.assertNotEqual(state.get('status'),'passed')

    def test_cargo_artifact_selection_and_target_isolation(self):
        with tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve())) as temp:
            root=Path(temp); target=root/'chosen'; target.mkdir(); exe=target/'probe'; exe.write_bytes(b'fixture'); exe.chmod(0o700)
            source=root/'crates/contour-postgres/examples/causal_bridge_probe.rs'
            item={'reason':'compiler-artifact','target':{'name':'causal_bridge_probe','kind':['example'],'src_path':str(source)},'profile':{'test':False},'executable':str(exe)}
            line=lambda obj:json.dumps(obj).encode()
            with mock.patch.dict(G,{'ROOT':root}):
                self.assertEqual(MODULE['resolve_cargo_artifact']([line(item)],target),exe)
                with self.assertRaisesRegex(RuntimeError,'ambiguous'): MODULE['resolve_cargo_artifact']([line(item),line(item)],target)
                with self.assertRaisesRegex(RuntimeError,'ambiguous'): MODULE['resolve_cargo_artifact']([line(item|{'target':item['target']|{'src_path':'/other'}})],target)
                (root/'outside').write_bytes(b'foreign'); (root/'outside').chmod(0o700)
                with self.assertRaisesRegex(RuntimeError,'outside target'): MODULE['resolve_cargo_artifact']([line(item|{'executable':str(root/'outside')})],target)
                sibling=root/'sibling'; sibling.write_bytes(b'foreign'); sibling.chmod(0o700)
                with self.assertRaisesRegex(RuntimeError,'invalid cargo executable'): MODULE['resolve_cargo_artifact']([line(item|{'executable':str(target/'..'/'sibling')})],target)
                with self.assertRaisesRegex(RuntimeError,'invalid cargo artifact'): MODULE['resolve_cargo_artifact']([b'not-json'],target)
                with self.assertRaisesRegex(RuntimeError,'missing cargo executable'): MODULE['resolve_cargo_artifact']([line(item|{'executable':None})],target)

    def test_outside_cargo_artifact_is_not_read_before_rejection(self):
        with tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve())) as temp:
            root=Path(temp); target=root/'target'; target.mkdir()
            foreign=root/'foreign'; foreign.write_bytes(b'foreign'); foreign.chmod(0o700)
            inside=target/'probe'; inside.write_bytes(b'owned'); inside.chmod(0o700)
            source=root/'crates/contour-postgres/examples/causal_bridge_probe.rs'
            event={'reason':'compiler-artifact','target':{'name':'causal_bridge_probe','kind':['example'],'src_path':str(source)},'profile':{'test':False},'executable':str(foreign)}
            digest=mock.Mock(return_value='digest')
            with mock.patch.dict(G,{'ROOT':root,'digest_file':digest}):
                with self.assertRaisesRegex(RuntimeError,'outside target'):
                    MODULE['resolve_cargo_artifact']([json.dumps(event).encode()],target)
                digest.assert_not_called()
                event['executable']=str(inside)
                self.assertEqual(MODULE['resolve_cargo_artifact']([json.dumps(event).encode()],target),inside)
                digest.assert_called_once_with(inside)

    def test_build_uses_locked_offline_and_configured_fresh_target(self):
        with tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve())) as temp:
            root=Path(temp); target=root/'chosen'; target.mkdir(); exe=target/'probe';exe.write_bytes(b'x');exe.chmod(0o700)
            event={'reason':'compiler-artifact','target':{'name':'causal_bridge_probe','kind':['example'],'src_path':str(root/'crates/contour-postgres/examples/causal_bridge_probe.rs')},'profile':{'test':False},'executable':str(exe)}
            def run(args,**kwargs):
                self.assertIn('--locked',args);self.assertIn('--offline',args)
                self.assertEqual(kwargs['cwd'],root);self.assertEqual(kwargs['env']['CARGO_TARGET_DIR'],str(target))
                return [(json.dumps(event)+'\n').encode()]
            with mock.patch.dict(G,{'ROOT':root,'bounded_process_output':run}):
                self.assertEqual(MODULE['build_probe'](target),exe)

    def test_cargo_process_output_and_time_are_bounded(self):
        import sys
        output=MODULE['bounded_process_output']([sys.executable,'-c','print("one");print("two")'],cwd=G['ROOT'],env=os.environ.copy(),timeout=5,limit=100)
        self.assertEqual(output,[b'one',b'two'])
        with self.assertRaisesRegex(RuntimeError,'output limit'):
            MODULE['bounded_process_output']([sys.executable,'-c','print("x"*10000)'],cwd=G['ROOT'],env=os.environ.copy(),timeout=5,limit=100)
        with self.assertRaises(TimeoutError):
            MODULE['bounded_process_output']([sys.executable,'-c','import time; time.sleep(10)'],cwd=G['ROOT'],env=os.environ.copy(),timeout=.1,limit=100)

    def test_noisy_child_group_is_killed_on_output_limit(self):
        import sys,time
        with tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve())) as temp:
            marker=Path(temp)/'survived'
            child="import pathlib,time; time.sleep(0.7); pathlib.Path("+repr(str(marker))+").write_text('survived')"
            parent="import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',"+repr(child)+"]); print('x'*100000,flush=True); time.sleep(10)"
            with self.assertRaisesRegex(RuntimeError,'output limit'):
                MODULE['run_process']([sys.executable,'-c',parent],cwd=G['ROOT'],env=os.environ.copy(),timeout=5,limit=1024)
            time.sleep(1.0)
            self.assertFalse(marker.exists(),'a child survived process-group cleanup')

    def test_command_and_probe_calls_cannot_accumulate_noisy_output(self):
        import sys
        code="import sys,time; sys.stdout.write('x'*2000000); sys.stdout.flush(); time.sleep(5)"
        with self.assertRaisesRegex(RuntimeError,'output limit') as caught:
            MODULE['command']([sys.executable,'-c',code],timeout=5)
        self.assertNotIn(code,str(caught.exception))
        state={'stages':[]}; base=[sys.executable,'-c',code]+['x']*21
        with self.assertRaisesRegex(RuntimeError,'output limit') as caught:
            MODULE['run_probe_cases'](base,Path('/synthetic'),os.environ.copy(),lambda:'0|0|0|0|0|0',state)
        self.assertEqual(state['current_case'],'untrusted_tls_ca')
        self.assertNotIn(code,str(caught.exception))
        self.assertNotEqual(state.get('status'),'passed')

    def test_bounded_runner_does_not_expose_command_arguments(self):
        import sys
        secret='SYNTHETIC_PRIVATE_ARGUMENT'
        result=MODULE['run_process']([sys.executable,'-c','print("ok")',secret],cwd=G['ROOT'],env=os.environ.copy(),timeout=5)
        self.assertNotIn(secret,repr(result));self.assertIsNone(result.args)
        with self.assertRaises(TimeoutError) as caught:
            MODULE['run_process']([sys.executable,'-c','import time; time.sleep(10)',secret],cwd=G['ROOT'],env=os.environ.copy(),timeout=.1)
        self.assertNotIn(secret,str(caught.exception));self.assertNotIn(secret,repr(caught.exception))

    def test_process_input_is_bounded_before_spawn(self):
        with mock.patch.object(G['subprocess'],'Popen') as popen:
            with self.assertRaisesRegex(ValueError,'input limit'):
                MODULE['run_process'](['never'],data=b'x'*11,input_limit=10)
        popen.assert_not_called()

    def test_renamed_owned_resource_is_removed_by_verified_id(self):
        cid='a'*64; name='original'; run='owner'; removed=[]
        owned={'Id':cid,'Name':'/renamed','Config':{'Labels':{MODULE['LABEL']:run}}}
        def inspect(kind,selector,**_kwargs):
            if selector==cid and not removed: return owned
            return None
        def command(args,**_kwargs): removed.append(args)
        with mock.patch.dict(G,{'inspect_resource':inspect,'command':command,'require_empty_label_inventory':lambda *_:None}):
            MODULE['cleanup']('container',name,run,known_id=cid)
        self.assertEqual(removed,[['docker','rm','-f',cid]])

    def test_foreign_replacement_is_never_removed(self):
        cid='a'*64; name='original'; run='owner'; removed=[]
        owned={'Id':cid,'Name':'/renamed','Config':{'Labels':{MODULE['LABEL']:run}}}
        foreign={'Id':'b'*64,'Name':'/original','Config':{'Labels':{MODULE['LABEL']:'foreign'}}}
        def inspect(kind,selector,**_kwargs):
            if selector==cid: return None if removed else owned
            if selector==name: return foreign
            raise AssertionError('unexpected selector')
        with mock.patch.dict(G,{'inspect_resource':inspect,'command':lambda args,**_kwargs:removed.append(args)}):
            with self.assertRaisesRegex(RuntimeError,'name occupied'):
                MODULE['cleanup']('container',name,run,known_id=cid)
        self.assertEqual(removed,[['docker','rm','-f',cid]])

    def test_malformed_id_recovery_uses_only_exact_owned_name(self):
        cid='a'*64;name='owned';run='owner';removed=[]
        owned={'Id':cid,'Name':'/owned','Config':{'Labels':{MODULE['LABEL']:run}}}
        def inspect(kind,selector,**_kwargs):
            return owned if selector==name and not removed else None
        with mock.patch.dict(G,{'inspect_resource':inspect,'command':lambda args,**_kwargs:removed.append(args),'require_empty_label_inventory':lambda *_:None}):
            MODULE['cleanup']('container',name,run)
        self.assertEqual(removed,[['docker','rm','-f',cid]])

    def test_missing_id_and_renamed_labeled_resource_fails_without_removal(self):
        cid='c'*64; calls=[]; name='original'; run='owner'
        def inventory(args,**kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(None,0,(cid+'\n').encode(),b'')
        with mock.patch.dict(G,{'inspect_resource':lambda *_a,**_k:None,'run_process':inventory,
                               'command':lambda *_a,**_k:self.fail('inventory must not delete')}):
            with self.assertRaisesRegex(RuntimeError,'inventory not empty'):
                MODULE['cleanup']('container',name,run,known_id=None)
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0],['docker','ps','-aq','--no-trunc','--filter','label='+MODULE['LABEL']+'='+run])

    def test_label_inventory_ambiguous_foreign_and_errors_fail_closed(self):
        label=MODULE['LABEL']; run='owner'
        for kind in ('container','network'):
            for code,output,category in [(0,b'partial-id\n','ambiguous'),
                                         (0,b'\xff\n','ambiguous'),
                                         (0,(('f'*64)+'\n').encode(),'not empty'),
                                         (1,b'','failed')]:
                calls=[]
                def inventory(args,**kwargs):
                    calls.append(args)
                    return subprocess.CompletedProcess(None,code,output,b'ignored')
                with mock.patch.dict(G,{'run_process':inventory}):
                    with self.assertRaisesRegex(RuntimeError,category): MODULE['require_empty_label_inventory'](kind,run)
                self.assertEqual(calls[0][-2:],['--filter','label='+label+'='+run])
                self.assertNotIn('rm',calls[0])
            with mock.patch.dict(G,{'run_process':lambda *_a,**_k:subprocess.CompletedProcess(None,0,b'',b'')}):
                self.assertIsNone(MODULE['require_empty_label_inventory'](kind,run))

    def test_cleanup_recognizes_only_exact_absence(self):
        name='contour-causal-bridge-test'
        for msg in ('Error: No such object: '+name,'error: no such object: '+name):
            with mock.patch.dict(G,{'run_process':lambda *_a,**_k:subprocess.CompletedProcess([],1,b'',msg.encode())}):
                self.assertIsNone(MODULE['inspect_owned']('container',name,'run',allow_absent=True))
        for msg in ('daemon unavailable','error: no such object: '+name+'-other','error: no such object: '+name+'\nextra'):
            with mock.patch.dict(G,{'run_process':lambda *_a,**_k:subprocess.CompletedProcess([],1,b'',msg.encode())}):
                with self.assertRaises(RuntimeError): MODULE['inspect_owned']('container',name,'run',allow_absent=True)

    def test_foreign_ownership_and_cleanup_failure_fail_closed(self):
        cid='a'*64; name='owned'; run_id='id'
        foreign={'Id':cid,'Name':'/foreign','Config':{'Labels':{MODULE['LABEL']:run_id}}}
        calls=[]
        def runner(args,**kwargs): calls.append(args); return subprocess.CompletedProcess(args,0,json.dumps([foreign]).encode(),b'')
        with mock.patch.dict(G,{'run_process':runner}):
            with self.assertRaisesRegex(RuntimeError,'foreign'): MODULE['cleanup']('container',name,run_id)
        self.assertEqual(len(calls),1)
        owned={'Id':cid,'Name':'/owned','Config':{'Labels':{MODULE['LABEL']:run_id}}}
        with mock.patch.dict(G,{'inspect_owned':lambda *_a,**_k:owned,'command':lambda *_a,**_k: (_ for _ in ()).throw(RuntimeError('remove failed'))}):
            with self.assertRaisesRegex(RuntimeError,'remove failed'): MODULE['cleanup']('container',name,run_id)

    def test_failed_network_creation_still_cleans_and_records_failure(self):
        calls=[]
        def fake_command(args,**kwargs):
            if args[:3]==['docker','network','create']:
                raise RuntimeError('fixture command failed')
            if args[:2]==['openssl','pkey']:
                return bytes.fromhex('302a300506032b6570032100')+bytes([7])*32
            if args[:2]==['openssl','pkeyutl']:
                return bytes(64)
            return b''
        def clean(kind,name,run_id,**_kwargs): calls.append((kind,name,run_id))
        def fake_build(target):
            self.assertEqual(target.parent,Path(temp).resolve())
            return target/'synthetic-probe'
        old_umask=os.umask(0o077);os.umask(old_umask)
        with tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve())) as temp:
            with mock.patch.dict(G,{'snapshot':lambda:{},'digest_file':lambda _path:'hash','command':fake_command,'cleanup':clean,'require_empty_label_inventory':lambda *_a:None,'build_probe':fake_build}), \
                 mock.patch.dict(os.environ,{'CARGO_TARGET_DIR':temp}),mock.patch('sys.argv',['driver']),mock.patch('builtins.print') as printed:
                try:
                    with self.assertRaisesRegex(RuntimeError,'fixture command failed'): MODULE['main']()
                finally:
                    os.umask(old_umask)
            result_path=Path(printed.call_args_list[0].args[1]);state=json.loads(result_path.read_text())
            try:
                self.assertEqual(state['current_case'],'network_create')
                self.assertEqual(state['failure_category'],'fixture_command_failed')
                self.assertEqual(state['status'],'failed')
                self.assertTrue(state['cleanup_network'] and state['cleanup_container'] and state['cleanup_build'] and state['source_unchanged'])
                self.assertEqual([x[0] for x in calls],['network'])
                self.assertNotIn('password',result_path.read_text().lower())
            finally:
                shutil.rmtree(result_path.parent)

    def test_main_keeps_cleanup_false_for_renamed_resource_after_no_id(self):
        def fake_command(args,**kwargs):
            if args[:3]==['docker','network','create']: raise RuntimeError('fixture command failed')
            if args[:2]==['openssl','pkey']: return bytes.fromhex('302a300506032b6570032100')+bytes([7])*32
            if args[:2]==['openssl','pkeyutl']: return bytes(64)
            if args[:2]==['docker','rm'] or args[:3]==['docker','network','rm']:
                self.fail('unknown inventory member must not be removed')
            return b''
        def inventory(args,**kwargs):
            output=(('c'*64)+'\n').encode() if args[:3]==['docker','network','ls'] else b''
            return subprocess.CompletedProcess(None,0,output,b'')
        old_umask=os.umask(0o077);os.umask(old_umask)
        with tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve())) as temp:
            overrides={'snapshot':lambda:{},'digest_file':lambda _path:'hash','command':fake_command,
                       'inspect_resource':lambda *_a,**_k:None,'run_process':inventory,'build_probe':lambda target:target/'synthetic-probe'}
            with mock.patch.dict(G,overrides),mock.patch.dict(os.environ,{'CARGO_TARGET_DIR':temp}),mock.patch('sys.argv',['driver']),mock.patch('builtins.print') as printed:
                try:
                    with self.assertRaisesRegex(RuntimeError,'inventory not empty'): MODULE['main']()
                finally: os.umask(old_umask)
            result_path=Path(printed.call_args_list[0].args[1]);state=json.loads(result_path.read_text())
            try:
                self.assertFalse(state['cleanup_network'])
                self.assertEqual(state['network_cleanup_failure'],'label_inventory_not_empty')
                self.assertEqual(state['status'],'failed')
            finally: shutil.rmtree(result_path.parent)

    def test_source_mutation_is_recorded_even_after_failure_and_cleanup(self):
        snapshots=iter([{'source':'before'},{'source':'after'}]);cleaned=[]
        def fake_command(args,**kwargs):
            if args[:3]==['docker','network','create']: raise RuntimeError('fixture command failed')
            if args[:2]==['openssl','pkey']: return bytes.fromhex('302a300506032b6570032100')+bytes([7])*32
            if args[:2]==['openssl','pkeyutl']: return bytes(64)
            return b''
        old_umask=os.umask(0o077);os.umask(old_umask)
        with tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve())) as temp:
            overrides={'snapshot':lambda:next(snapshots),'digest_file':lambda _path:'hash','command':fake_command,
                       'cleanup':lambda kind,*_args,**_kwargs:cleaned.append(kind),'require_empty_label_inventory':lambda *_a:None,'build_probe':lambda target:target/'synthetic-probe'}
            with mock.patch.dict(G,overrides),mock.patch.dict(os.environ,{'CARGO_TARGET_DIR':temp}),mock.patch('sys.argv',['driver']),mock.patch('builtins.print') as printed:
                try:
                    with self.assertRaises(RuntimeError): MODULE['main']()
                finally: os.umask(old_umask)
            result_path=Path(printed.call_args_list[0].args[1]);state=json.loads(result_path.read_text())
            try:
                self.assertFalse(state['source_unchanged'])
                self.assertEqual(state['status'],'failed')
                self.assertEqual(cleaned,['network'])
                self.assertTrue(state['cleanup_network'] and state['cleanup_build'])
            finally: shutil.rmtree(result_path.parent)

    def test_source_guard_missing_mutated_and_symlink(self):
        with tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve())) as temp:
            root=Path(temp)/'repo';root.mkdir()
            for crate in ('contour-postgres','contour-core','contour-auth'): (root/'crates'/crate/'src').mkdir(parents=True)
            with mock.patch.dict(G,{'ROOT':root}):
                for path in MODULE['source_paths']():
                    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'original')
                before=MODULE['snapshot']()
                target=root/'db/opt-in-migrations/0021_origin_admission.sql';target.write_bytes(b'mutated')
                self.assertNotEqual(before,MODULE['snapshot']())
                target.unlink()
                with self.assertRaisesRegex(ValueError,'source list changed'): MODULE['snapshot']()
                target.write_bytes(b'original')
                extra=target.parent/'0099_unknown.sql'; extra.write_bytes(b'extra')
                with self.assertRaisesRegex(ValueError,'source list changed'): MODULE['snapshot']()
                extra.unlink()
                moved=root/'db/moved';parent=target.parent;parent.rename(moved);parent.symlink_to(moved,target_is_directory=True)
                with self.assertRaisesRegex(ValueError,'symlink'): MODULE['snapshot']()

    def test_source_guard_rejects_symlinked_source_directory(self):
        with tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve())) as temp:
            root=Path(temp)/'repo';source=root/'crates/contour-core/src'
            for crate in ('contour-postgres','contour-core','contour-auth'): (root/'crates'/crate/'src').mkdir(parents=True)
            external=Path(temp)/'elsewhere';external.mkdir();(source/'redirect').symlink_to(external,target_is_directory=True)
            with mock.patch.dict(G,{'ROOT':root}):
                with self.assertRaisesRegex(ValueError,'symlink'): MODULE['source_paths']()

    def test_topology_and_safe_diagnostics(self):
        cid='a'*64;nid='b'*64; validate=MODULE['network_valid']
        net={'Id':nid,'Internal':False,'Driver':'bridge','Options':{'com.docker.network.bridge.enable_ip_masquerade':'false'},'Containers':{cid:{}}}
        self.assertTrue(validate(net,nid,(cid,)))
        for key,value in [('Internal',True),('Driver','host'),('Options',{}),('Containers',{cid:{},'c'*64:{}})]:
            self.assertFalse(validate(net|{key:value},nid,(cid,)))
        secret='SYNTHETIC_PASSWORD_NEVER_LOG'
        self.assertEqual(MODULE['failure_category'](subprocess.TimeoutExpired(['--password='+secret],1)),'subprocess_timeout')
        self.assertNotIn(secret,MODULE['failure_category'](RuntimeError(secret)))


if __name__=='__main__': unittest.main()
