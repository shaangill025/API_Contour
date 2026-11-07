"""Offline driver controls; no Docker, database, certificate or listener."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('permit_driver',ROOT/'scripts/test-postgres-causal-permits.py')
driver=importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)

class Driver(unittest.TestCase):
    def test_artifact_requires_exact_source_target_and_containment(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp).resolve()/'target'; target.mkdir(); binary=target/'probe'; binary.write_text('x'); binary.chmod(0o700)
            bridge={'digest_file':lambda p:hashlib.sha256(p.read_bytes()).hexdigest()}
            def item(path,source=str(driver.EXAMPLE)):
                return json.dumps({'reason':'compiler-artifact','target':{'name':'causal_permit_probe','kind':['example'],'src_path':source},'profile':{'test':False},'executable':str(path)}).encode()
            self.assertEqual(driver.artifact([item(binary)],target,bridge),binary)
            with self.assertRaises(RuntimeError): driver.artifact([item(binary),item(binary)],target,bridge)
            with self.assertRaises(RuntimeError): driver.artifact([item(binary,'/wrong')],target,bridge)
            outside=Path(tmp).resolve()/'outside'; outside.write_text('x'); outside.chmod(0o700)
            with self.assertRaises(ValueError): driver.artifact([item(outside)],target,bridge)
            link=target/'alias'; link.symlink_to(binary)
            with self.assertRaises(ValueError): driver.artifact([item(link)],target,bridge)

    def test_node_version_must_be_exact_and_errors_never_pass(self):
        def result(output=b'v24.22.1\n',code=0,err=b''):
            return {'run_process':lambda *a,**kw:SimpleNamespace(returncode=code,stdout=output,stderr=err)}
        self.assertEqual(driver.node_version(result()),'v24.22.1')
        for value in (result(b'v24.22.1 extra\n'),result(b'v24.22.1\n',1),result(err=b'warning'),result(b'v24.22.1')):
            with self.assertRaises(RuntimeError): driver.node_version(value)

    def test_fixed_stage_validation_rejects_extra_or_error_output(self):
        m=SimpleNamespace(lock=threading.Lock(),buffers={'out':bytearray(b'ACTIVE\n'),'err':bytearray()},overflow=False,child=SimpleNamespace(poll=lambda:None))
        driver.line(m,0,b'ACTIVE',timeout=.1)
        with self.assertRaises(RuntimeError): driver.line(m,0,b'WRONG',timeout=.1)
        m.buffers['err'].extend(b'not safe')
        with self.assertRaises(RuntimeError): driver.line(m,0,b'ACTIVE',timeout=.1)

    def test_source_snapshot_rejects_missing_unknown_or_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); example=root/'crates/contour-ingress/examples/causal_permit_probe.rs'; node=root/'collectors/nodered/error-integration/private-owner-permit.js'; marker=node.with_name('causal-marker.js')
            paths=[example,node,marker,root/'scripts/test-postgres-causal-permits.py',root/'tests/fixtures/causal-permits/test_driver.py',root/'crates/contour-ingress/Cargo.toml',root/'scripts/test-postgres-causal-https.py',root/'tests/fixtures/causal-https/test_https_driver.py']
            paths += [root/'db/opt-in-migrations'/(n+'.sql') for n in driver.OPT]
            for path in paths: path.parent.mkdir(parents=True,exist_ok=True); path.write_text('fixture')
            for crate in ('contour-ingress','contour-delivery','contour-platform','contour-abi','contour-wasm'): (root/'crates'/crate/'src').mkdir(parents=True,exist_ok=True)
            bridge={'source_paths':lambda:[], 'digest_file':lambda p:hashlib.sha256(p.read_bytes()).hexdigest()}
            with mock.patch.multiple(driver,ROOT=root,EXAMPLE=example,NODE=node,MARKER=marker):
                before=driver.snapshot(bridge); node.write_text('changed'); self.assertNotEqual(before,driver.snapshot(bridge))
                node.unlink()
                with self.assertRaises(ValueError): driver.snapshot(bridge)
                node.write_text('fixture'); extra=root/'db/opt-in-migrations/0023_unknown.sql'; extra.write_text('x')
                with self.assertRaises(ValueError): driver.snapshot(bridge)
                extra.unlink(); node.unlink(); node.symlink_to(root/'other')
                with self.assertRaises(ValueError): driver.snapshot(bridge)
                node.unlink(); node.write_text('fixture')
                helper=root/'scripts/test-postgres-causal-https.py'; helper.write_text('changed')
                self.assertNotEqual(before,driver.snapshot(bridge))

    def test_build_failure_checks_cleanup_and_source(self):
        inventory=mock.Mock(); snapshots=mock.Mock(return_value={'source':'hash'})
        bridge={'bounded_process_output':mock.Mock(side_effect=TimeoutError('build')), 'command':mock.Mock(),
                'require_empty_label_inventory':inventory,'cleanup':mock.Mock()}
        with mock.patch.object(driver.sys,'argv',['driver']), mock.patch.object(driver,'helpers',return_value=(bridge,{})), \
             mock.patch.object(driver,'snapshot',snapshots), mock.patch.object(driver,'node_version',return_value='v24.22.1'), \
             mock.patch.object(driver.signal,'signal',return_value=None), mock.patch.object(driver.signal,'setitimer'):
            with self.assertRaisesRegex(TimeoutError,'build'): driver.main()
        self.assertEqual(snapshots.call_count,2)
        self.assertEqual([x.args[0] for x in inventory.call_args_list],['container','network'])
        bridge['cleanup'].assert_not_called()

    def test_fixture_cleanup_failure_preserves_original_build_failure(self):
        bridge={'bounded_process_output':mock.Mock(side_effect=TimeoutError('build')), 'command':mock.Mock(),
                'require_empty_label_inventory':mock.Mock(side_effect=[RuntimeError('cleanup'),None]),'cleanup':mock.Mock()}
        with mock.patch.object(driver.sys,'argv',['driver']), mock.patch.object(driver.sys,'stderr'), mock.patch.object(driver,'helpers',return_value=(bridge,{})), \
             mock.patch.object(driver,'snapshot',return_value={'source':'hash'}), mock.patch.object(driver,'node_version',return_value='v24.22.1'), \
             mock.patch.object(driver.signal,'signal',return_value=None), mock.patch.object(driver.signal,'setitimer'):
            with self.assertRaises(BaseExceptionGroup) as caught: driver.main()
        self.assertEqual([type(e) for e in caught.exception.exceptions],[TimeoutError,RuntimeError])

    def test_exercise_builds_real_modes_and_distinct_journals(self):
        events=[]; starts=[]; counts=iter(['1|1|92','1|1|92','2|2|184','4|4|368','5|5|460','6|6|552','6|6|552'])
        class Input:
            def write(self,data): events.append(('send',data))
            def flush(self): pass
        class Monitor:
            def __init__(self,args,env):
                self.args=args; self.lock=threading.Lock(); self.buffers={'out':bytearray(b'ACTIVE\n'),'err':bytearray()}; self.overflow=False; self.child=SimpleNamespace(stdin=Input(),poll=lambda:None); starts.append(args)
            def stop(self,_): events.append(('stop',self.args[25]))
        logs_seen=[]
        def process(args,**kw):
            events.append(('process',args))
            if args[:2]==['docker','logs']:
                logs_seen.append(True)
                out=b'causal_rival_login SELECT contour.claim_causal_generation\ncausal_rival_login generation conflict\n'
                if len(logs_seen)>=3: out+=b'causal_revocation_login contour.issue_causal_session\ncausal_revocation_login 23514 session unavailable\n'
                return SimpleNamespace(returncode=0,stdout=out,stderr=b'')
            return SimpleNamespace(returncode=0,stdout=b'CLAIM_REJECTED\n',stderr=b'')
        def execute(sql):
            events.append(('sql',sql))
            if 'count(*) FROM contour.causal_sessions' in sql: return next(counts)
            if 'check_causal_session' in sql or 'expires_at>clock_timestamp()' in sql: return 'true'
            return ''
        def line(m,index,expected,timeout=15): events.append(('line',m.args[25],expected,timeout))
        def finish(m,expected): events.append(('finish',m.args[25],expected))
        bridge={'IDS':tuple('id'+str(i) for i in range(10)),'run_process':process}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(driver,'line',side_effect=line), mock.patch.object(driver,'finish',side_effect=finish):
            base=['probe','localhost','5432','db','ca','causal_issuer_login','unused','grant.pub','policy.pub','grant.json','policy.json','batch','33'*32,*bridge['IDS'],'placeholder']
            driver.exercise(base,Path(tmp),{'PATH':'/bin'},execute,bridge,{'ProbeProcess':Monitor},'owned')
        self.assertEqual([args[25] for args in starts],['eof','expiry','normal','claim-only','normal','normal'])
        dirs=[args[24] for args in starts]; self.assertEqual(len(set(dirs)),6)
        commands=[e[1] for e in events if e[0]=='process' and e[1][:2]!=['docker','logs']]
        self.assertEqual(len(commands),2)
        self.assertEqual(commands[1][5],'causal_rival_login')
        self.assertNotEqual(commands[1][24],starts[-2][24]); self.assertEqual(commands[1][23],starts[-2][23]); self.assertEqual(starts[-1][5],'causal_revocation_login')
        revocation=next(i for i,e in enumerate(events) if e[0]=='sql' and 'export_revoked' in e[1])
        stopped=next(i for i,e in enumerate(events[revocation:],revocation) if e[0]=='line' and e[2]==b'STOPPED')
        self.assertGreater(stopped,revocation)

    def test_authority_evidence_requires_role_query_and_sqlstate(self):
        query=b'causal_revocation_login contour.issue_causal_session\n'
        denial=b'causal_revocation_login 23514 session unavailable\n'
        self.assertTrue(driver.authority_rejection_observed(query+denial))
        for bad in (b'',query,denial,query+denial.replace(b'23514',b'40001'),query+denial.replace(b'causal_revocation_login',b'other')):
            self.assertFalse(driver.authority_rejection_observed(bad))

    def test_stale_stop_and_trailing_output_or_stderr_fail(self):
        child=SimpleNamespace(poll=lambda:None,wait=lambda timeout:None,returncode=0)
        monitor=SimpleNamespace(lock=threading.Lock(),buffers={'out':bytearray(b'ACTIVE\n'),'err':bytearray()},overflow=False,child=child,stop=lambda _:None)
        driver.assert_active(monitor)
        monitor.buffers['out'].extend(b'STOPPED\n')
        with self.assertRaises(AssertionError): driver.assert_active(monitor)
        monitor.buffers['out'].extend(b'extra\n')
        with self.assertRaises(RuntimeError): driver.finish(monitor,b'ACTIVE\nSTOPPED\n')
        monitor.buffers['out']=bytearray(b'ACTIVE\nSTOPPED\n'); monitor.buffers['err']=bytearray(b'error')
        with self.assertRaises(RuntimeError): driver.finish(monitor,b'ACTIVE\nSTOPPED\n')
        monitor.buffers['err'].clear(); monitor.overflow=True
        with self.assertRaises(RuntimeError): driver.finish(monitor,b'ACTIVE\nSTOPPED\n')

    def test_no_child_inherits_issuer_password(self):
        text=(ROOT/'crates/contour-ingress/examples/causal_permit_probe.rs').read_text()
        self.assertIn('.env_remove("CONTOUR_CAUSAL_ISSUER_PASSWORD")',text)
        self.assertLess(text.index('CausalPermitOwner::claim'),text.index('command.spawn()'))
        self.assertIn('flags & !libc::FD_CLOEXEC',text)

    def test_cooperative_stop_drains_and_reaps_local_descendant(self):
        helper=runpy.run_path(str(ROOT/'scripts/test-postgres-causal-https.py'))['ProbeProcess']
        descendant='import sys; print("ACTIVE",flush=True); sys.stdin.buffer.read(); print("STOPPED",flush=True)'
        parent=('import subprocess,sys; child=subprocess.Popen([sys.executable,"-u","-c",sys.argv[1]],stdin=subprocess.PIPE); '
                'assert sys.stdin.buffer.readline()==b"STOP\\n"; child.stdin.close(); assert child.wait(timeout=3)==0')
        monitor=helper([sys.executable,'-u','-c',parent,descendant],dict(os.environ))
        with driver.owned_probe(monitor,'competition'):
            driver.line(monitor,0,b'ACTIVE',timeout=5)
            monitor.child.stdin.write(b'STOP\n'); monitor.child.stdin.flush()
            driver.line(monitor,1,b'STOPPED',timeout=5)
            driver.finish(monitor,b'ACTIVE\nSTOPPED\n')
        self.assertEqual(monitor.child.returncode,0)
        self.assertTrue(monitor.group_absent)

    def test_local_cooperative_process_trailing_output_is_fatal(self):
        helper=runpy.run_path(str(ROOT/'scripts/test-postgres-causal-https.py'))['ProbeProcess']
        child='import sys; print("ACTIVE",flush=True); sys.stdin.buffer.readline(); print("STOPPED\\nEXTRA",flush=True)'
        monitor=helper([sys.executable,'-u','-c',child],dict(os.environ))
        with self.assertRaises(RuntimeError):
            with driver.owned_probe(monitor,'competition'):
                driver.line(monitor,0,b'ACTIVE',timeout=5)
                monitor.child.stdin.write(b'STOP\n'); monitor.child.stdin.flush()
                driver.line(monitor,1,b'STOPPED',timeout=5)
                driver.finish(monitor,b'ACTIVE\nSTOPPED\n')
        self.assertTrue(monitor.group_absent)

    def test_primary_and_cleanup_errors_are_both_preserved(self):
        monitor=SimpleNamespace(child=SimpleNamespace(pid=123),stop=mock.Mock(side_effect=RuntimeError('cleanup')))
        with mock.patch.object(driver.sys,'stderr') as stderr:
            with self.assertRaises(BaseExceptionGroup) as caught:
                with driver.owned_probe(monitor,'competition'):
                    raise ValueError('primary')
        self.assertEqual([type(e) for e in caught.exception.exceptions],[ValueError,RuntimeError])
        self.assertIn('phase=competition pid=123',str(stderr.write.call_args_list))

    def test_competition_commands_cooperative_stop(self):
        text=(ROOT/'scripts/test-postgres-causal-permits.py').read_text()
        section=text.split("with owned_probe(monitor,'competition'):",1)[1].split("five=args('revocation'",1)[0]
        self.assertIn("stdin.write(b'STOP\\n')",section)
        self.assertIn("line(monitor,1,b'STOPPED',3)",section)

if __name__=='__main__': unittest.main()
