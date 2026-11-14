import json
import hashlib
import io
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
M=runpy.run_path(str(ROOT/'scripts/test-postgres-causal-https.py'))
G=M['main'].__globals__
B=runpy.run_path(str(ROOT/'scripts/test-postgres-causal-bridge.py'))
BG=B['main'].__globals__


class HttpsDriverTests(unittest.TestCase):
    def test_complete_ordered_scenarios_required(self):
        expected=M['EXPECTED_STAGES']
        self.assertEqual(len(expected),28)
        self.assertEqual(len(set(expected)),28)
        M['require_scenarios'](expected)
        for bad in (expected[:-1],expected[1:],expected[:-1]+(expected[0],),tuple(reversed(expected))):
            with self.assertRaisesRegex(RuntimeError,'incomplete HTTPS'): M['require_scenarios'](bad)
        for name in ('actual_trailer','streamed_global_bound','declared_event_bound','declared_byte_bound',
                     'unread_committed_response','inflight_shutdown_cancellation','collector_revocation',
                     'revoked_exact_replay','revoked_new_batch'):
            self.assertIn(name,expected)

    def test_negative_requires_redacted_error_and_unchanged_durable_state(self):
        body={'code':'not_authorized','message':'Request could not be completed',
              'request_id':'00000000-0000-4000-8000-000000000001','retryable':False}
        state={'stages':[]}
        M['negative_case']('deny',lambda:(403,body),403,'not_authorized','before',lambda:'before',state)
        self.assertEqual(state['stages'],['deny'])
        for call,count in ((lambda:(200,body),lambda:'before'),(lambda:(403,dict(body,secret='x')),lambda:'before'),
                           (lambda:(403,body),lambda:'after')):
            state={'stages':[]}
            with self.assertRaises(AssertionError): M['negative_case']('deny',call,403,'not_authorized','before',count,state)
            self.assertEqual(state['stages'],[])
        with self.assertRaises(ValueError): M['unique_pairs']([('x',1),('x',2)])

    def test_all_mandatory_scenarios_execute_with_simulated_boundaries(self):
        import datetime,hashlib,ssl
        from contextlib import contextmanager
        state={'stages':[],'container_id':'a'*64,'_https_peer':'b'*64}
        ledger=[]; lock={'held':True}; requests=[]; probe_args=[]
        identity=('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001','f6000000-0000-4000-8000-000000000001','f7000000-0000-4000-8000-000000000001','f1000000-0000-4000-8000-000000000001','f2000000-0000-4000-8000-000000000001','f3000000-0000-4000-8000-000000000001','f4000000-0000-4000-8000-000000000001','f5000000-0000-4000-8000-000000000001','f9000000-0000-4000-8000-000000000001')
        base=['probe','localhost','5432','contour_fixture','ca','issuer','inbox','gpub','ppub','grant','policy','batch','synthetic',*identity,'00000000-0000-4000-8000-000000000001']
        class Child:
            def __init__(self): self.stdin=mock.Mock();self.returncode=0
            def wait(self,timeout=None): return 0
        class Monitor:
            def __init__(self,args,env):
                self.child=Child()
                if args and args[0]=='probe': probe_args.append(args)
            def ready(self):return (1,1)
            def stop(self,graceful):
                if state.get('current_case')=='inflight_shutdown_cancellation' and graceful:lock['held']=False
        class Stream:
            def __enter__(self):return self
            def __exit__(self,*_):return False
            def sendall(self,data):
                if state.get('current_case')=='unread_committed_response':
                    payload=data.split(b'\r\n\r\n',1)[1];ledger.append((payload,'00000000-0000-4000-8000-000000000002'))
        @contextmanager
        def connect(*_a,**_k):yield Stream()
        class Context:
            def __init__(self,ca):self.ca=ca
            def wrap_socket(self,plain,server_hostname):
                if self.ca=='untrusted.crt' or server_hostname!='localhost':raise ssl.SSLCertVerificationError('simulated')
                return plain
        def context(_work,client='client',ca='ca.crt'):return Context(ca)
        def error(code):return {'code':code,'message':'Request could not be completed','request_id':'00000000-0000-4000-8000-000000000001','retryable':False}
        failures={'unknown_client_certificate':(403,'not_authorized'),'wrong_method':(405,'method_not_allowed'),
                  'query_string':(404,'not_found'),'wrong_media':(415,'unsupported_media_type'),
                  'content_encoding':(415,'unsupported_encoding'),'declared_trailer':(415,'unsupported_encoding'),
                  'declared_event_bound':(422,'invalid_batch'),'declared_byte_bound':(422,'invalid_batch'),
                  'noncanonical':(422,'invalid_batch'),'unknown_body_field':(422,'invalid_batch'),
                  'wrong_tenant':(403,'not_authorized'),'wrong_runtime':(403,'not_authorized'),'wrong_epoch':(403,'not_authorized'),
                  'revoked_exact_replay':(403,'not_authorized'),'revoked_new_batch':(403,'not_authorized'),
                  'collector_revocation':(403,'not_authorized')}
        def receipt(raw,rid,status):
            body=json.loads(raw);return {'batch_id':body['batch_id'],'runtime_id':identity[1],'session_epoch':1,
                'batch_digest':hashlib.sha256(b'apicontour/causal-events/1\n'+raw).hexdigest(),'receipt_id':rid,
                'accepted_at':'1970-01-01T00:00:01Z','status':status}
        def http(_work,_port,raw,**kwargs):
            phase=state['current_case'];requests.append(phase)
            if phase=='missing_client_certificate':raise ssl.SSLError('simulated')
            if phase in failures:
                status,code=failures[phase];return status,error(code)
            if phase=='accepted_and_duplicate':
                if not ledger:ledger.append((raw,'00000000-0000-4000-8000-000000000001'));return 200,receipt(*ledger[0],'accepted')
                return 200,receipt(*ledger[0],'duplicate')
            if phase=='incomplete_client_eof':return 200,receipt(*ledger[0],'duplicate')
            if phase=='unread_committed_response':return 200,receipt(*ledger[1],'duplicate')
            if phase=='inflight_shutdown_cancellation':
                ledger.append((raw,'00000000-0000-4000-8000-000000000003'));return 200,receipt(*ledger[2],'accepted')
            raise AssertionError('unexpected HTTP case '+phase)
        def command(_args,*,data=None,**_kwargs):
            text=data.decode()
            if 'NOT granted' in text:return b'1' if lock['held'] else b'0'
            if 'pg_try_advisory_xact_lock' in text:return b'false' if lock['held'] else b'true'
            if '(SELECT count(*) FROM contour.causal_sessions)' in text:
                return ('1|%d|%d|%d'%(len(ledger),len(ledger),sum(len(raw) for raw,_ in ledger))).encode()
            if 'SELECT receipt_id::text' in text:
                for raw,rid in ledger:
                    if json.loads(raw)['batch_id'] in text:
                        if "encode(batch_digest" in text:return (rid+'|1000000|'+hashlib.sha256(b'apicontour/causal-events/1\n'+raw).hexdigest()+'|'+raw.hex()).encode()
                        return (rid+'|1000000').encode()
                raise AssertionError('receipt lookup missing')
            return b''
        def rawcall(_work,_port,wire):
            phase=state['current_case'];requests.append(phase)
            return (400,error('unsupported_trailers')) if phase=='actual_trailer' else (413,error('batch_too_large'))
        with mock.patch.dict(G,{'IDS':identity,'ProbeProcess':Monitor,'command':command,'client_context':context,
              'http_call':http,'raw_call':rawcall,'streamed_limit_call':lambda *_:(413,error('batch_too_large'))}), \
             mock.patch.object(G['socket'],'create_connection',side_effect=connect),mock.patch.object(G['time'],'sleep'):
            M['run_https_cases'](base,Path('/unused'),{},lambda:None,state)
        self.assertEqual(tuple(state['stages']),M['EXPECTED_STAGES'])
        self.assertEqual(state['status'],'passed')
        self.assertEqual(len(ledger),3)
        self.assertEqual(requests.count('collector_revocation'),2)
        self.assertEqual(len(probe_args),4)
        self.assertTrue(all(len(args)==24 and args[11]=='b'*64 and args[-1]=='/unused' for args in probe_args))
        self.assertEqual(probe_args[2][3],'contour_clone')

    def test_helper_mutation_during_import_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();scripts=root/'scripts';scripts.mkdir()
            for name in ('test-postgres-causal-bridge.py','test-postgres-causal-inbox.py'):(scripts/name).write_text('original')
            def load(path):
                if path.endswith('test-postgres-causal-inbox.py'):(scripts/'test-postgres-causal-bridge.py').write_text('changed')
                return {}
            with mock.patch.dict(G,{'ROOT':root}),mock.patch.object(G['runpy'],'run_path',side_effect=load):
                with self.assertRaisesRegex(RuntimeError,'changed while loading'):M['load_helpers']()

    def test_second_fixed_probe_build_and_artifact_containment(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); target=root/'target';target.mkdir();exe=target/'probe';exe.write_bytes(b'x');exe.chmod(0o700)
            src=root/'crates/contour-ingress/examples/causal_https_probe.rs'
            event={'reason':'compiler-artifact','target':{'name':'causal_https_probe','kind':['example'],'src_path':str(src)},'profile':{'test':False},'executable':str(exe)}
            calls=[]
            def output(args,**kwargs): calls.append((args,kwargs));return [json.dumps(event).encode()]
            with mock.patch.dict(BG,{'ROOT':root,'bounded_process_output':output}):
                self.assertEqual(B['build_probe'](target,'contour-ingress','causal_https_probe'),exe)
                args,kwargs=calls[0];self.assertIn('--locked',args);self.assertIn('--offline',args)
                self.assertEqual(args[args.index('-p')+1],'contour-ingress');self.assertEqual(kwargs['env']['CARGO_TARGET_DIR'],str(target))
                event['executable']=str(root/'outside')
                with self.assertRaises(RuntimeError): B['build_probe'](target,'contour-ingress','causal_https_probe')
                with self.assertRaises(ValueError): B['build_probe'](target,'other','other')

    def test_monitor_graceful_shutdown_and_bounded_output(self):
        program="import sys; print('READY 4321 1',flush=True); sys.stdin.readline(); print('STOPPED',flush=True)"
        process=M['ProbeProcess']([sys.executable,'-c',program],os.environ.copy())
        self.assertEqual(process.ready(),(4321,1));process.stop(True)
        self.assertIsNotNone(process.child.returncode)
        self.assertFalse(any(t.is_alive() for t in process.threads))
        noisy="import sys,time; print('x'*100000,flush=True); time.sleep(10)"
        process=M['ProbeProcess']([sys.executable,'-c',noisy],os.environ.copy())
        try:
            with self.assertRaises(RuntimeError):process.ready()
        finally:process.stop(False)
        self.assertIsNotNone(process.child.returncode)
        self.assertLessEqual(sum(map(len,process.buffers.values())),32768)

    def test_overflow_and_stop_serialize_one_group_signal(self):
        monitor=M['ProbeProcess'].__new__(M['ProbeProcess'])
        monitor.child=mock.Mock(pid=424242)
        monitor.kill_lock=threading.Lock(); monitor.group_terminated=False; monitor.group_absent=False; monitor.group_signal_failure=False
        calls=[]; errors=[]; start=threading.Barrier(3)
        def signal_group(pid,sig):
            calls.append((pid,sig))
            if len(calls)==1: time.sleep(.03); return
            raise PermissionError('simulated repeated signal denial')
        def worker():
            start.wait()
            try:monitor._kill_group()
            except BaseException as error:errors.append(error)
        with mock.patch.object(G['os'],'killpg',side_effect=signal_group):
            threads=[threading.Thread(target=worker) for _ in range(2)]
            for thread in threads:thread.start()
            start.wait()
            for thread in threads:thread.join(timeout=2)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors,[])
        self.assertEqual(calls,[(424242,G['signal'].SIGKILL)])

    def test_overflow_reader_racing_stop_leaves_no_group(self):
        class Stream:
            def __init__(self):self.closed=False
            def fileno(self):return 9
            def close(self):self.closed=True
        class Child:
            def __init__(self):self.pid=424242;self.returncode=None;self.stdin=Stream();self.stdout=Stream();self.stderr=Stream()
            def poll(self):return self.returncode
            def wait(self,timeout=None):return self.returncode
        monitor=M['ProbeProcess'].__new__(M['ProbeProcess']);monitor.child=Child()
        monitor.buffers={'out':bytearray(),'err':bytearray()};monitor.lock=threading.Lock();monitor.overflow=False
        monitor.kill_lock=threading.Lock();monitor.group_terminated=False;monitor.group_absent=False;monitor.group_signal_failure=False
        signal_started=threading.Event();calls=[];chunks=iter([b'x'*4096]*4+[b'x'])
        def signal_group(pid,sig):
            calls.append((pid,sig))
            if sig==0:raise ProcessLookupError('absent')
            signal_started.set();time.sleep(.03);monitor.child.returncode=-9
        with mock.patch.object(G['os'],'read',side_effect=lambda *_:next(chunks)),mock.patch.object(G['os'],'killpg',side_effect=signal_group):
            reader=threading.Thread(target=monitor._drain,args=('out',monitor.child.stdout));monitor.threads=[reader];reader.start()
            self.assertTrue(signal_started.wait(2))
            monitor.stop(False)
        self.assertFalse(reader.is_alive())
        self.assertTrue(monitor.overflow and monitor.group_absent)
        self.assertEqual(calls,[(424242,G['signal'].SIGKILL),(424242,0)])

    def test_group_permission_error_requires_observed_absence(self):
        def monitor():
            value=M['ProbeProcess'].__new__(M['ProbeProcess']);value.child=mock.Mock(pid=424242)
            value.kill_lock=threading.Lock();value.group_terminated=False;value.group_absent=False;value.group_signal_failure=False
            return value
        value=monitor()
        with mock.patch.object(G['os'],'killpg',side_effect=[PermissionError('signal denied'),ProcessLookupError('group absent')]) as signal_group:
            value._kill_group();value._kill_group()
            self.assertTrue(value.group_absent)
            self.assertEqual(signal_group.call_count,2)
        value=monitor()
        with mock.patch.object(G['os'],'killpg',side_effect=[PermissionError('signal denied'),None]) as signal_group:
            with self.assertRaises(PermissionError):value._kill_group()
            with self.assertRaisesRegex(RuntimeError,'signal denied'):value._kill_group()
            self.assertEqual(signal_group.call_count,2)
        value=monitor()
        with mock.patch.object(G['os'],'killpg',side_effect=[PermissionError('signal denied'),PermissionError('probe denied')]) as signal_group:
            with self.assertRaises(PermissionError):value._kill_group()
            with self.assertRaisesRegex(RuntimeError,'signal denied'):value._kill_group()
            self.assertEqual(signal_group.call_count,2)

    def test_denied_signal_fails_and_closes_local_streams_without_retry(self):
        class Child:
            def __init__(self):self.pid=424242;self.stdin=io.BytesIO();self.stdout=io.BytesIO();self.stderr=io.BytesIO();self.returncode=0
            def poll(self):return self.returncode
        value=M['ProbeProcess'].__new__(M['ProbeProcess']);value.child=Child();value.threads=[]
        value.kill_lock=threading.Lock();value.group_terminated=False;value.group_absent=False;value.group_signal_failure=False
        with mock.patch.object(G['os'],'killpg',side_effect=[PermissionError('signal denied'),None]) as call:
            with self.assertRaisesRegex(RuntimeError,'signal denied'):value.stop(False)
        self.assertEqual(call.call_args_list,[mock.call(424242,G['signal'].SIGKILL),mock.call(424242,0)])
        self.assertTrue(value.child.stdin.closed and value.child.stdout.closed and value.child.stderr.closed)

    def test_group_must_be_observed_absent_after_signal(self):
        value=M['ProbeProcess'].__new__(M['ProbeProcess']);value.child=mock.Mock(pid=424242)
        value.group_absent=False
        with mock.patch.object(G['os'],'killpg',side_effect=ProcessLookupError('absent')) as check:
            value._require_group_absent();self.assertTrue(value.group_absent);check.assert_called_once_with(424242,0)
        value.group_absent=False
        with mock.patch.object(G['os'],'killpg',side_effect=PermissionError('not observable')):
            with self.assertRaisesRegex(RuntimeError,'status denied'):value._require_group_absent()
        value.group_absent=False;ticks=iter([0,6])
        with mock.patch.object(G['os'],'killpg',return_value=None),mock.patch.object(G['time'],'monotonic',side_effect=lambda:next(ticks)):
            with self.assertRaisesRegex(RuntimeError,'still exists'):value._require_group_absent()

    def test_descendant_cannot_survive_group_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            marker=Path(temp)/'escaped'
            child="import pathlib,time;time.sleep(0.8);pathlib.Path("+repr(str(marker))+").write_text('bad')"
            parent="import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',"+repr(child)+"]);print('READY 4321 1',flush=True);time.sleep(10)"
            process=M['ProbeProcess']([sys.executable,'-c',parent],os.environ.copy())
            try:self.assertEqual(process.ready(),(4321,1))
            finally:process.stop(False)
            time.sleep(1)
            self.assertFalse(marker.exists())
            self.assertFalse(any(t.is_alive() for t in process.threads))

    def test_source_snapshot_binds_both_drivers_and_ingress_inputs(self):
        bridge=runpy.run_path(str(ROOT/'scripts/test-postgres-causal-bridge.py'))
        inbox={'source_snapshot':lambda:{'Cargo.toml':'baseline'}}
        bg=bridge['main'].__globals__
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            names=('scripts/test-postgres-causal-https.py','tests/fixtures/causal-https/test_https_driver.py',
                   'scripts/test-postgres-causal-bridge.py','tests/fixtures/causal-bridge/test_bridge_driver.py',
                   'crates/contour-ingress/examples/causal_https_probe.rs','crates/contour-ingress/CAUSAL-HTTPS.md',
                   'crates/contour-ingress/src/causal_service.rs','crates/contour-ingress/src/pool.rs',
                   'crates/contour-postgres/tests/fixtures/causal_bridge.json')
            for name in names:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'original')
            with mock.patch.dict(G,{'ROOT':root}),mock.patch.dict(bg,{'ROOT':root}):
                bridge['snapshot']=lambda:{'bridge-input':'stable'}
                helper='scripts/test-postgres-causal-bridge.py'
                expected={helper:hashlib.sha256((root/helper).read_bytes()).hexdigest()}
                M['install_helpers'](bridge,inbox,expected)
                before=bg['snapshot']()
                (root/helper).write_bytes(b'changed')
                with self.assertRaisesRegex(RuntimeError,'helper changed after loading'):bg['snapshot']()
                (root/helper).write_bytes(b'original')
                target=root/'crates/contour-ingress/src/causal_service.rs';target.write_bytes(b'changed')
                self.assertNotEqual(before,bg['snapshot']())
                target.unlink()
                with self.assertRaisesRegex(ValueError,'unavailable'):bg['snapshot']()
                target.write_bytes(b'original');target.unlink();target.symlink_to(root/'Cargo.toml')
                with self.assertRaisesRegex(ValueError,'symlink'):bg['snapshot']()

    def test_installed_scenario_runs_only_https_protocol_and_propagates_failures(self):
        bridge=runpy.run_path(str(ROOT/'scripts/test-postgres-causal-bridge.py'))
        bg=bridge['main'].__globals__; calls=[]
        base=['https-probe']; work=Path('/synthetic'); env={}; counts=object(); state={'stages':[]}; execute=object()
        def cases(*args): calls.append(args)
        with mock.patch.dict(G,{'run_https_cases':cases}), mock.patch.dict(bg,{'inbox_context_unknown':mock.Mock(side_effect=AssertionError('foreign protocol'))}):
            context=M['install_helpers'](bridge,{'source_snapshot':lambda:{}})
            context.update(work=work,tls_ready=True,peer='ab'*32)
            bg['run_scenario'](base,work,env,counts,state,execute)
            self.assertEqual(calls,[(base,work,env,counts,state)])
            self.assertEqual(state['_https_peer'],'ab'*32)
            self.assertIn('synthetic HTTPS',state['boundary'])
            self.assertFalse(bg['inbox_context_unknown'].called)
            with mock.patch.dict(G,{'run_https_cases':mock.Mock(side_effect=RuntimeError('HTTPS scenario failure'))}):
                with self.assertRaisesRegex(RuntimeError,'HTTPS scenario failure'):
                    bg['run_scenario'](base,work,env,counts,state,execute)

    def test_readiness_timeout_cannot_pass(self):
        sleeper="import time;time.sleep(10)"
        process=M['ProbeProcess']([sys.executable,'-c',sleeper],os.environ.copy())
        ticks=iter([0,31])
        try:
            with mock.patch.object(G['time'],'monotonic',side_effect=lambda:next(ticks)):
                with self.assertRaises(TimeoutError):process.ready()
        finally:process.stop(False)
        self.assertIsNotNone(process.child.returncode)

    def test_adapters_refuse_wrong_hba_and_use_actual_leaf(self):
        bridge=runpy.run_path(str(ROOT/'scripts/test-postgres-causal-bridge.py'))
        bg=bridge['main'].__globals__;calls=[];signed=[]
        def cmd(args,**kwargs):
            calls.append((args,kwargs))
            if args[:2]==['openssl','x509'] and '-outform' in args: return b'synthetic-der'
            if args[:2]==['openssl','pkcs8']:return b'key-der'
            return b''
        def read(path):return b"SELECT decode(repeat('33',32),'hex');"
        def sign(template,domain,*_):signed.append((template,domain));return b'signed'
        bridge['command']=cmd;bridge['checked']=read;bridge['signed_payload']=sign
        # Captured original callables are exercised by the proxies; bridge main
        # remains mocked so no container or listener can be started.
        inbox={'source_snapshot':lambda:{}}
        context=M['install_helpers'](bridge,inbox)
        with tempfile.TemporaryDirectory() as temp:
            work=Path(temp).resolve()
            for name in ('ca.crt','ca.key','server.crt','server.key'): (work/name).write_bytes(b'x')
            bg['command'](['openssl','req','-keyout',str(work/'server.key')])
            decoded=bg['checked'](ROOT/'db/tests/causal_session_setup.sql')
            self.assertNotIn(b"repeat('33'",decoded)
            self.assertIn(context['peer'].encode(),decoded)
            bg['signed_payload']({},b'apicontour/causal-grant/1\n',None,None,None)
            self.assertEqual((signed[0][0]['max_batch_events'],signed[0][0]['max_batch_bytes']),(2,700))
            with self.assertRaisesRegex(RuntimeError,'HBA marker'):
                bg['command'](['docker','exec','-i','x','sh','cat > /var/lib/postgresql/data/pg_hba.conf'],data=b'wrong')


if __name__=='__main__': unittest.main()
