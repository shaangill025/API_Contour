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
import time
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('permit_driver',ROOT/'scripts/test-postgres-causal-permits.py')
driver=importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)

class Driver(unittest.TestCase):
    def test_revocation_retries_only_confirmed_busy_before_original_deadline(self):
        now=[0.0]; outcomes=iter(['busy','committed']); attempts=[]
        def attempt(remaining): attempts.append(remaining); return next(outcomes)
        with mock.patch.object(driver.time,'monotonic',side_effect=lambda:now[0]),mock.patch.object(driver.time,'sleep',side_effect=lambda t:now.__setitem__(0,now[0]+t)):
            driver.revoke_until(attempt,1.0)
        self.assertEqual(len(attempts),2); self.assertLess(attempts[1],attempts[0])

    def test_revocation_terminal_outcomes_and_deadline_do_not_retry(self):
        for outcome in ('unknown','generic40001','transport','cleanup'):
            calls=[]
            def attempt(_): calls.append(True); raise RuntimeError(outcome)
            with self.assertRaises(RuntimeError): driver.revoke_until(attempt,time.monotonic()+1)
            self.assertEqual(len(calls),1)
        now=[0.0]; calls=[]
        with mock.patch.object(driver.time,'monotonic',side_effect=lambda:now[0]),mock.patch.object(driver.time,'sleep',side_effect=lambda t:now.__setitem__(0,now[0]+t)):
            with self.assertRaises(TimeoutError): driver.revoke_until(lambda _:(calls.append(True) or 'busy'),.05)
        self.assertTrue(calls); self.assertLessEqual(now[0],.05)

    def test_revocation_attempt_requires_closed_ack_and_clean_session_exit(self):
        tenant='11111111-1111-4111-8111-111111111111'; runtime='22222222-2222-4222-8222-222222222222'; calls=[]
        def process(args,**kwargs):
            calls.append((args,kwargs)); return SimpleNamespace(returncode=0,stdout=b'REVOCATION_ROLLED_BACK\n',stderr=b'')
        bridge={'run_process':process}
        self.assertEqual(driver.revocation_attempt(bridge,'container',tenant,runtime,.5),'busy')
        script=calls[0][1]['data']; self.assertIn(b"detail NOT IN ('origin gate busy','credential gate busy','collector gate busy')",script)
        self.assertIn(b'ROLLBACK;\n\\echo REVOCATION_ROLLED_BACK',script); self.assertIn(b'COMMIT;\n\\echo REVOCATION_COMMITTED',script)
        self.assertEqual(calls[0][1]['timeout'],.5)
        for value in (SimpleNamespace(returncode=1,stdout=b'REVOCATION_ROLLED_BACK\n',stderr=b''),SimpleNamespace(returncode=0,stdout=b'REVOCATION_ROLLED_BACK\n',stderr=b'error'),SimpleNamespace(returncode=0,stdout=b'40001\n',stderr=b''),SimpleNamespace(returncode=0,stdout=b'REVOCATION_ROLLED_BACK\nextra',stderr=b'')):
            with self.subTest(value=value), self.assertRaises(RuntimeError): driver.revocation_attempt({'run_process':lambda *a,**k:value},'container',tenant,runtime,.5)
        with self.assertRaises(TimeoutError): driver.revocation_attempt({'run_process':mock.Mock(side_effect=TimeoutError('uncertain'))},'container',tenant,runtime,.5)
        cleanup=BaseExceptionGroup('cleanup',[RuntimeError('primary'),OSError('cleanup')])
        with self.assertRaises(BaseExceptionGroup) as raised: driver.revocation_attempt({'run_process':mock.Mock(side_effect=cleanup)},'container',tenant,runtime,.5)
        self.assertIs(raised.exception,cleanup)
        self.assertEqual(driver.revocation_attempt({'run_process':lambda *a,**k:SimpleNamespace(returncode=0,stdout=b'REVOCATION_COMMITTED\n',stderr=b'')},'container',tenant,runtime,.5),'committed')

    def test_committed_proof_is_required(self):
        for result in ('0','2','unknown'):
            with self.assertRaises(AssertionError): driver.require_revocation_proof(lambda _:result,'tenant','runtime')
        driver.require_revocation_proof(lambda _:'1','tenant','runtime')
    def test_failure_lines_emit_only_exact_sanitized_sqlstate(self):
        error=RuntimeError('fixture command failed SQLSTATE 40001')
        group=BaseExceptionGroup('qualification',[BaseExceptionGroup('primary',[error])])
        self.assertEqual(driver.failure_lines(group),['FAIL primary RuntimeError unknown:0 SQLSTATE 40001'])
        for text in ('fixture command failed SQLSTATE 40001 secret','SQLSTATE 40001','fixture command failed SQLSTATE 40001\n','fixture command failed SQLSTATE abcde'):
            self.assertEqual(driver.failure_lines(RuntimeError(text)),['FAIL primary RuntimeError unknown:0'])
        self.assertEqual(driver.failure_lines(ValueError('fixture command failed SQLSTATE 40001')),['FAIL primary ValueError unknown:0'])

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
            paths += [root/'db/opt-in-migrations'/(n+'.sql') for n in driver.OPT + driver.EXTRA_SOURCE_MIGRATIONS]
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
        self.assertIsInstance(caught.exception.exceptions[0].exceptions[0],TimeoutError)
        self.assertIsInstance(caught.exception.exceptions[1].exceptions[0],RuntimeError)

    def test_exercise_builds_real_modes_and_distinct_journals(self):
        events=[]; starts=[]; counts=iter(['1|1|92','1|1|92','2|2|184','4|4|368','5|5|460','6|6|552','6|6|552','6|6|552','7|7|644','7|7|644','8|7|644','8|8|736','9|9|828','9|9|828'])
        class Input:
            def write(self,data): events.append(('send',data))
            def flush(self): pass
        class Monitor:
            def __init__(self,args,env):
                self.args=args; self.lock=threading.Lock(); self.buffers={'out':bytearray(b'ACTIVE\n'),'err':bytearray()}; self.overflow=False; self.child=SimpleNamespace(stdin=Input(),poll=lambda:None); starts.append(args)
            def stop(self,_): events.append(('stop',self.args[25] if len(self.args)>25 else 'gate'))
        logs_seen=[]
        def process(args,**kw):
            events.append(('process',args))
            if args[:2]==['docker','logs']:
                logs_seen.append(True)
                out=b'causal_rival_login SELECT contour.claim_causal_generation\ncausal_rival_login generation conflict\n'
                out+=b'causal_contention_login 40001 origin gate busy\n'*len(logs_seen)
                disabled=next((i for i,e in enumerate(events) if e[0]=='send' and b'UPDATE contour.collector_authorization SET enabled=false' in e[1]),None)
                if disabled is not None and any(e[0]=='send' and e[1].startswith(b'COMMIT') for e in events[disabled+1:]): out+=b'causal_contention_login 23514 session unavailable\n'
                if any(e[0]=='sql' and 'export_revoked' in e[1] for e in events): out+=b'causal_revocation_login contour.issue_causal_session\ncausal_revocation_login 23514 session unavailable\n'
                return SimpleNamespace(returncode=0,stdout=out,stderr=b'')
            return SimpleNamespace(returncode=0,stdout=b'CLAIM_REJECTED\n',stderr=b'')
        def execute(sql):
            events.append(('sql',sql))
            if 'causal_runtime_terminal_events' in sql: return '1'
            if 'count(*) FROM contour.causal_sessions' in sql: return next(counts)
            if 'count(*) FILTER (WHERE enabled=false)' in sql: return '1|0'
            if 'check_causal_session' in sql or 'expires_at>clock_timestamp()' in sql: return 'true'
            return ''
        def line(m,index,expected,timeout=15): events.append(('line',m.args[25] if len(m.args)>25 else 'gate',expected,timeout))
        def finish(m,expected): events.append(('finish',m.args[25] if len(m.args)>25 else 'gate',expected))
        bridge={'IDS':tuple('id'+str(i) for i in range(10)),'run_process':process}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(driver,'line',side_effect=line), mock.patch.object(driver,'finish',side_effect=finish):
            base=['probe','localhost','5432','db','ca','causal_issuer_login','unused','grant.pub','policy.pub','grant.json','policy.json','batch','33'*32,*bridge['IDS'],'placeholder']
            def revoker(_): events.append(('sql','export_revoked')); return 'committed'
            driver.exercise(base,Path(tmp),{'PATH':'/bin'},execute,bridge,{'ProbeProcess':Monitor},'owned',revoker)
        starts=[args for args in starts if len(args)>25]
        self.assertEqual([args[25] for args in starts],['eof','expiry','normal','claim-only','normal','normal','normal','claim-busy','normal'])
        dirs=[args[24] for args in starts]; self.assertEqual(len(set(dirs)),9)
        commands=[e[1] for e in events if e[0]=='process' and e[1][:2]!=['docker','logs']]
        self.assertEqual(len(commands),2)
        self.assertEqual(commands[1][5],'causal_rival_login')
        self.assertNotEqual(commands[1][24],starts[4][24]); self.assertEqual(commands[1][23],starts[4][23]); self.assertEqual(starts[-1][5],'causal_revocation_login')
        revocation=next(i for i,e in enumerate(events) if e[0]=='sql' and 'export_revoked' in e[1])
        stopped=next(i for i,e in enumerate(events[revocation:],revocation) if e[0]=='line' and e[2]==b'STOPPED')
        self.assertGreater(stopped,revocation)

    def test_authority_evidence_requires_role_query_and_sqlstate(self):
        query=b'causal_revocation_login contour.issue_causal_session\n'
        denial=b'causal_revocation_login 23514 session unavailable\n'
        self.assertTrue(driver.authority_rejection_observed(query+denial))
        for bad in (b'',query,denial,query+denial.replace(b'23514',b'40001'),query+denial.replace(b'causal_revocation_login',b'other')):
            self.assertFalse(driver.authority_rejection_observed(bad))

    def test_contention_evidence_requires_role_sqlstate_and_message_on_same_line(self):
        line=b'causal_contention_login 40001 origin gate busy\n'
        self.assertEqual(driver.contention_diagnostics(line,b'40001',b'origin gate busy'),1)
        for bad in (line.replace(b'causal_contention_login',b'other'),line.replace(b'40001',b'23514'),line.replace(b'origin gate busy',b'other'),line.replace(b'busy',b'busy extra'),b'causal_contention_login\n40001 origin gate busy\n'):
            self.assertEqual(driver.contention_diagnostics(bad,b'40001',b'origin gate busy'),0)
        with self.assertRaises(ValueError): driver.contention_diagnostics(line,b'40001',b'other')

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
        monitor=SimpleNamespace(child=SimpleNamespace(pid=123,poll=lambda:0),stop=mock.Mock(side_effect=RuntimeError('secret cleanup')))
        with self.assertRaises(BaseExceptionGroup) as caught:
            with driver.owned_probe(monitor,'competition'):
                raise ValueError('secret primary')
        self.assertEqual([type(e) for e in caught.exception.exceptions],[ValueError,RuntimeError])
        rendered='\n'.join(driver.failure_lines(caught.exception))
        self.assertIn('FAIL primary ValueError ',rendered)
        self.assertIn('FAIL cleanup RuntimeError ',rendered)
        self.assertNotIn('secret',rendered)

    def test_failure_cooperatively_reaps_owner_and_child(self):
        helper=runpy.run_path(str(ROOT/'scripts/test-postgres-causal-https.py'))['ProbeProcess']
        descendant='import sys; print("ACTIVE",flush=True); sys.stdin.buffer.read(); print("STOPPED",flush=True)'
        parent=('import subprocess,sys; child=subprocess.Popen([sys.executable,"-u","-c",sys.argv[1]],stdin=subprocess.PIPE); '
                'assert sys.stdin.buffer.readline()==b"STOP\\n"; child.stdin.close(); assert child.wait(timeout=3)==0')
        monitor=helper([sys.executable,'-u','-c',parent,descendant],dict(os.environ))
        with self.assertRaisesRegex(ValueError,'primary'):
            with driver.owned_probe(monitor,'contention'):
                driver.line(monitor,0,b'ACTIVE',timeout=5)
                raise ValueError('primary')
        self.assertEqual(monitor.child.returncode,0)
        self.assertTrue(monitor.group_absent)
        self.assertEqual(bytes(monitor.buffers['out']),b'ACTIVE\nSTOPPED\n')

    def test_failure_cooperative_modes_and_strict_cleanup(self):
        for phase,expected in [('gate',b'ROLLBACK;\n\\q\n'),('claim-busy',b''),('epoch-new',b'')]:
            with self.subTest(phase=phase):
                code='import sys; data=sys.stdin.buffer.read(); sys.exit(0 if data=='+repr(expected)+' else 42)'
                helper=runpy.run_path(str(ROOT/'scripts/test-postgres-causal-https.py'))['ProbeProcess']
                monitor=helper([sys.executable,'-u','-c',code],dict(os.environ))
                with self.assertRaisesRegex(ValueError,'primary'):
                    with driver.owned_probe(monitor,phase): raise ValueError('primary')
                self.assertEqual(monitor.child.returncode,0)
                self.assertTrue(monitor.group_absent)

    def test_cooperative_failure_still_runs_strict_stop(self):
        monitor=SimpleNamespace(child=SimpleNamespace(poll=lambda:None,stdin=SimpleNamespace(write=mock.Mock(side_effect=OSError('secret')),close=mock.Mock(),closed=False),wait=mock.Mock(side_effect=TimeoutError('secret'))),stop=mock.Mock(side_effect=PermissionError('secret')))
        with self.assertRaises(BaseExceptionGroup) as caught:
            with driver.owned_probe(monitor,'contention'): raise ValueError('secret')
        monitor.stop.assert_called_once_with(False)
        lines=driver.failure_lines(caught.exception)
        self.assertTrue(any('primary ValueError' in line for line in lines))
        self.assertTrue(any('cleanup PermissionError' in line for line in lines))
        self.assertNotIn('secret',' '.join(lines))

    def test_competition_commands_cooperative_stop(self):
        text=(ROOT/'scripts/test-postgres-causal-permits.py').read_text()
        section=text.split("with owned_probe(monitor,'competition'):",1)[1].split("five=args('revocation'",1)[0]
        self.assertIn("stdin.write(b'STOP\\n')",section)
        self.assertIn("line(monitor,1,b'STOPPED',3)",section)

    def test_released_contention_observation_exceeds_prior_permit_lifetime(self):
        now=[0.0]; seen=[]
        def sleep(duration): now[0]+=duration
        with mock.patch.object(driver.time,'monotonic',side_effect=lambda:now[0]), mock.patch.object(driver.time,'sleep',side_effect=sleep), mock.patch.object(driver,'assert_active',side_effect=lambda _:seen.append(now[0])):
            driver.confirm_post_contention(object())
        self.assertGreaterEqual(seen[-1],1.2)
        now[0]=0.0
        def closes(_):
            if now[0]>=.7: raise AssertionError('closed')
        with mock.patch.object(driver.time,'monotonic',side_effect=lambda:now[0]), mock.patch.object(driver.time,'sleep',side_effect=sleep), mock.patch.object(driver,'assert_active',side_effect=closes):
            with self.assertRaises(AssertionError): driver.confirm_post_contention(object())

if __name__=='__main__': unittest.main()
