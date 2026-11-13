"""Offline transport tests with local synthetic processes; no Docker or database."""
import importlib.util
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import threading
import unittest
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('transport', ROOT/'scripts/fixture_psql_transport.py')
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
CID = 'a'*64
OWNER = 'b'*32
SQL = ['docker','exec','-i',CID,'psql','-XAtq','-v','ON_ERROR_STOP=1','-U','postgres','-d','contour_fixture']

submit_spec = importlib.util.spec_from_file_location('submit_fixture', ROOT/'scripts/test-postgres-submit.py')
submit = importlib.util.module_from_spec(submit_spec); submit_spec.loader.exec_module(submit)

class ReceiverInboxDiagnosticTests(unittest.TestCase):
    def test_closed_stage_and_redaction(self):
        text=mod._OBSERVER_PREFIX.decode()+'fixed'
        output=base64.b64encode(b'receiver29-step=migration28\nreceiver29-step=migration29\nreceiver29-step=observer-regression\nreceiver29-step=seed\nreceiver29-step=cases\nreceiver-case=parser\nreceiver-case=observer-first\n')
        error=b'psql:<stdin>:321: ERROR:  42702: SECRET_SENTINEL\nCONTEXT:  PL/pgSQL function contour.accept_causal_receiver(secret) line 9 at SECRET_SENTINEL\n'
        values=mod._receiver_inbox_failure(text,output,error)
        self.assertEqual(values,('cases','observer-first','42702','contour.accept_causal_receiver',9,321))
        self.assertNotIn('SECRET_SENTINEL',str(mod.ReceiverInboxQueryError(*values)))
        malformed=base64.b64encode(b'receiver29-step=SECRET_SENTINEL\nreceiver-case=SECRET_SENTINEL\n')
        self.assertEqual(mod._receiver_inbox_failure(text,malformed,error)[:2],('unavailable','unavailable'))
        self.assertEqual(mod._receiver_inbox_failure('untrusted',output,error),('unavailable',)*4+(None,None))
        self.assertEqual(mod._receiver_inbox_failure(text,output,error+error)[2],'unavailable')
        bad_uuid=error.replace(b'42702',b'22P02')
        self.assertEqual(mod._receiver_inbox_failure(text,output,bad_uuid)[2],'22P02')
        self.assertNotIn('SECRET_SENTINEL',str(mod._receiver_inbox_failure(text,output,bad_uuid)))
        post='\\set VERBOSITY verbose\n\\echo receiver-case=revoked-product\nfixed'
        postout=base64.b64encode(b'receiver-case=revoked-product\n')
        self.assertEqual(mod._receiver_inbox_failure(post,postout,error),('unavailable','revoked-product','42702','contour.accept_causal_receiver',9,321))
        self.assertNotIn('SECRET_SENTINEL',str(mod._receiver_inbox_failure(post,postout,error)))

class ExpiryOverlap(unittest.TestCase):
    def run_cases(self, fail_initial=None, wrong_receipt=False):
        events=[]; clock=[100]; expiries=[]
        def future():
            clock[0]+=1
            value=clock[0]+15; expiries.append(value); events.append(('expiry',value))
            return value
        def setup(name, change=None):
            body={'scope':name,'records':[{}]}
            policy={}
            if change: change(policy); body['policy_expiry']=policy['expires_at']
            events.append(('setup',name))
            return body,None,None
        def check(body, wanted='Accepted', status=None):
            scope=body['scope']; events.append(('check',scope,wanted,status,clock[0]))
            if fail_initial==scope and wanted=='Accepted' and status is None:
                raise RuntimeError('initial failed')
            expiry=body['records'][0].get('expires_at',body.get('policy_expiry'))
            if wanted=='Accepted' and status is None: self.assertLess(clock[0],expiry)
            if status=='duplicate' or wanted=='Policy': self.assertGreaterEqual(clock[0],expiry)
            if status=='duplicate': return 'wrong' if wrong_receipt else 'receipt'
            return 'receipt'
        def wait(value):
            events.append(('wait',value)); clock[0]=max(clock[0],value)
        def pairs(body,count): events.append(('pairs',body['scope'],count))
        def run(): submit.check_expiry_retries(setup,check,pairs,future,wait)
        return run,events,expiries

    def test_independent_expiry_windows_overlap_and_assert(self):
        run,events,expiries=self.run_cases(); run()
        self.assertEqual(len(expiries),2); self.assertNotEqual(*expiries)
        checks=[e for e in events if e[0]=='check']; waits=[e for e in events if e[0]=='wait']
        self.assertEqual([e[1] for e in checks[:2]],['submit_expired_retry','submit_lease_retry'])
        self.assertLess(events.index(checks[1]),events.index(waits[0]))
        self.assertEqual(waits,[('wait',expiries[0]),('wait',expiries[1])])
        self.assertEqual([(e[1],e[2],e[3]) for e in checks[2:]], [('submit_expired_retry','Accepted','duplicate'),('submit_lease_retry','Policy',None)])
        self.assertIn(('pairs','submit_lease_retry',1),events)

    def test_initial_failure_aborts_before_wait(self):
        for scope in ('submit_expired_retry','submit_lease_retry'):
            run,events,_=self.run_cases(fail_initial=scope)
            with self.assertRaisesRegex(RuntimeError,'initial failed'): run()
            self.assertFalse(any(e[0]=='wait' for e in events))

    def test_changed_duplicate_receipt_fails(self):
        run,events,_=self.run_cases(wrong_receipt=True)
        with self.assertRaisesRegex(AssertionError,'committed retry'): run()
        self.assertEqual(len([e for e in events if e[0]=='wait']),1)

class ReceiverDiagnostics(unittest.TestCase):
    def test_closed_state_and_function_with_untrusted_messages(self):
        err=(b'psql:<stdin>:123: ERROR:  23514: secret-canary\n'
             b'CONTEXT:  PL/pgSQL function contour.enroll_causal_receiver(secret-canary) line 44 at secret-canary\n')
        fields=mod._receiver_failure(err)
        self.assertEqual(fields,('23514','contour.enroll_causal_receiver',44,123,'unavailable'))
        safe=str(mod.ReceiverQueryError(*fields))
        self.assertIn('state=23514',safe); self.assertIn('function=contour.enroll_causal_receiver',safe); self.assertIn('line=44',safe)
        self.assertNotIn('secret-canary',safe)
    def test_receiver_ordered_case_tags_and_continuation_alias(self):
        out=base64.b64encode(b'receiver-case=vector\nreceiver-case=setup\nreceiver-case=profile\n')
        err=(b'ERROR:  23505: secret\nCONTEXT:  SQL statement secret\n'
             b'PL/pgSQL function register_causal_profile(uuid,uuid,bytea) line 34 at secret\n')
        fields=mod._receiver_failure(err,out)
        self.assertEqual(fields,('23505','contour.register_causal_profile',34,None,'profile'))
        self.assertNotIn('secret',str(mod.ReceiverQueryError(*fields)))
        for body in (b'receiver-case=profile\n',b'receiver-case=vector\nreceiver-case=secret-canary\n',b'receiver-case=vector\nreceiver-case=vector\n'):
            self.assertEqual(mod._receiver_failure(err,base64.b64encode(body))[-1],'unavailable')
        bad=err.replace(b'register_causal_profile',b'evil_secret')
        self.assertEqual(mod._receiver_failure(bad,out)[1],'unavailable')

    def test_untrusted_codes_names_and_multiple_errors_are_closed(self):
        err=b'ERROR:  99999: secret-canary\nCONTEXT:  PL/pgSQL function attacker.secret_canary() line 3 at secret-canary\n'
        fields=mod._receiver_failure(err)
        self.assertEqual(fields,('unavailable','unavailable',None,None,'unavailable'))
        self.assertNotIn('secret',str(mod.ReceiverQueryError(*fields)))
        self.assertEqual(mod._receiver_failure(err+err),('unavailable','unavailable',None,None,'unavailable'))
        self.assertNotIn('secret',str(mod.ReceiverQueryError('secret','secret',True,9999999)))

class Transport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); folder = Path(self.temp.name)
        (folder/'timeout').write_text('#!/bin/sh\nshift 3\nexec "$@"\n')
        (folder/'psql').write_text('''#!/usr/bin/env python3
import os, sys, time
s=sys.stdin.read()
if s == 'FAIL': sys.stderr.write('secret-sentinel'); sys.exit(3)
if s == 'SLOW': time.sleep(2)
if s == 'BIG': sys.stdout.write('x' * 10000); sys.exit(0)
if s == 'DIE': os._exit(7)
print(str(os.getpid()) + ':' + s, end='')
''')
        for name in ('timeout','psql'): (folder/name).chmod(0o755)
        self.env = dict(os.environ, PATH=str(folder)+os.pathsep+os.environ['PATH'])
        self.calls = []
        self.valid = True
        def run(args, **kwargs):
            self.calls.append(args)
            if args[1] == 'inspect' and '--format' not in args:
                obj={'Id':CID,'Config':{'Image':mod.IMAGE,'Labels':{mod.LABEL: OWNER if self.valid else 'wrong'},'Env':['POSTGRES_DB=contour_fixture']}}
                return SimpleNamespace(returncode=0,stdout=json.dumps([obj]))
            return SimpleNamespace(returncode=0,stdout='false')
        def popen(args, **kwargs):
            return subprocess.Popen(['sh','-c',mod.SHELL], **kwargs)
        self.transport = mod.FreshPsqlTransport(SQL,self.env,OWNER,popen=popen,run=run)
    def tearDown(self):
        try: self.transport.close()
        except mod.TransportError: pass
        self.temp.cleanup()
    def test_multiple_fresh_processes_and_literal_sql(self):
        first = self.transport.execute(" secret-sentinel $(touch forbidden) \n")
        second = self.transport.execute(" secret-sentinel $(touch forbidden) \n")
        p1, body1 = first.split(':',1); p2, body2 = second.split(':',1)
        self.assertNotEqual(p1,p2); self.assertEqual(body1,body2)
        self.assertEqual(body1, ' secret-sentinel $(touch forbidden)')
        self.assertFalse(self.calls)
    def test_nonzero_is_completed_error_and_next_query_is_new(self):
        with self.assertRaisesRegex(RuntimeError, 'authority fixture command failed') as caught: self.transport.execute('FAIL')
        self.assertNotIn('secret-sentinel',str(caught.exception))
        self.assertIn(':OK', self.transport.execute('OK')); self.assertFalse(self.calls)
    def test_observer_parser_redacts_and_rejects_untrusted_markers(self):
        text=mod._OBSERVER_PREFIX.decode()+'SELECT fixture;'
        frame=lambda data:base64.b64encode(data)
        good=frame(b'observer-step=runtime-source\nobserver-step=profile\n')
        unavailable=('unavailable','unavailable','unavailable','unavailable',None)
        failure=(b'psql:<stdin>:77: ERROR:  42702: column reference "epoch" is ambiguous\n'
                 b'CONTEXT:  PL/pgSQL function contour.accept_causal_observer(bytea,contour.verified_observer_claim) line 93 at SQL statement\n'
                 b'DETAIL: secret-sentinel\n')
        parsed=mod._observer_failure(text,good,failure)
        self.assertEqual(parsed,('profile','42702','epoch','contour.accept_causal_observer',93))
        error=mod.ObserverQueryError(*parsed)
        self.assertNotIn('secret-sentinel',str(error)); self.assertEqual(set(vars(error)),{'phase','sqlstate','column','function','line'})
        for out in (b'not-base64',frame(b'observer-step=profile\n'),frame(b'observer-step=runtime-source\nobserver-step=secret-sentinel\n'),frame(b'observer-step=runtime-source\nobserver-step=runtime-source\n')):
            self.assertEqual(mod._observer_failure(text,out,failure),unavailable)
        self.assertEqual(mod._observer_failure('other',good,failure),unavailable)
        invalid=('profile','unavailable','unavailable','unavailable',None)
        self.assertEqual(mod._observer_failure(text,good,b'ERROR:  42702: secret\nERROR:  42501: another\n'),invalid)
        self.assertEqual(mod._observer_failure(text,good,b'prefix ERROR: 42702: secret-sentinel\n'),invalid)
        self.assertEqual(mod._observer_failure(text,good,b'42702\n'),invalid)
        inline=b'ERROR:  42702: column reference "raw" is ambiguous\nCONTEXT:  PL/pgSQL function inline_code_block line 3 at SQL statement\n'
        self.assertEqual(mod._observer_failure(text,good,inline),('profile','42702','raw','inline_code_block',3))
        spoof=b'ERROR:  42702: column reference "secret_sentinel" is ambiguous\nCONTEXT:  PL/pgSQL function evil(secret) line 10 at SQL statement\n'
        self.assertEqual(mod._observer_failure(text,good,spoof),('profile','42702','unavailable','unavailable',None))
        self.assertNotIn('secret-sentinel',str(mod.ObserverQueryError('secret-sentinel','secret-sentinel','secret-sentinel','secret-sentinel',99999)))

    def test_observer_failure_remains_definite_and_generic_other_modes(self):
        self.transport.diagnostic_context='observer-v1'
        out=base64.b64encode(b'observer-step=runtime-source\n')
        def exchange(worker,request,nonce,deadline):
            return out,b'ERROR:  23514: secret-sentinel\n'+nonce.encode()+b' STATUS 3\n'
        self.transport._exchange=exchange
        with self.assertRaises(mod.ObserverQueryError) as caught:self.transport.execute(mod._OBSERVER_PREFIX.decode()+'SELECT fixture;')
        self.assertEqual((caught.exception.phase,caught.exception.sqlstate),('runtime-source','23514'))
        self.assertNotIn('secret-sentinel',str(caught.exception));self.assertFalse(self.calls)

    def test_receiver_diagnostics_opt_in_and_default_failure_unchanged(self):
        def exchange(worker,request,nonce,deadline):
            return b'',b'psql:<stdin>:42: ERROR:  23505: secret-canary\nCONTEXT:  PL/pgSQL function contour.enroll_causal_receiver(secret-canary) line 12 at secret-canary\n'+nonce.encode()+b' STATUS 3\n'
        self.transport._exchange=exchange
        with self.assertRaises(RuntimeError) as caught: self.transport.execute('SELECT fixture;')
        self.assertEqual(str(caught.exception),'authority fixture command failed')
        self.transport.diagnostic_context='receiver-v1'
        with self.assertRaises(mod.ReceiverQueryError) as caught: self.transport.execute('SELECT fixture;')
        self.assertIn('state=23505',str(caught.exception)); self.assertIn('input_line=42',str(caught.exception))
        self.assertNotIn('secret-canary',str(caught.exception)); self.assertFalse(self.calls)

    def test_timeout_contains_and_never_replays(self):
        with self.assertRaises(mod.TransportError): self.transport.execute('SLOW',timeout=.1)
        self.assertTrue(any(cmd[1]=='kill' for cmd in self.calls))
        with self.assertRaises(mod.TransportError): self.transport.execute('OK')
    def test_ownership_mismatch_never_kills(self):
        self.valid = False
        with self.assertRaises(mod.TransportError): self.transport.execute('SLOW',timeout=.1)
        self.assertFalse(any(cmd[1]=='kill' for cmd in self.calls))
    def test_bounded_output_contains(self):
        old = mod.LIMIT; mod.LIMIT = 1024
        try:
            with self.assertRaises(mod.TransportError): self.transport.execute('BIG')
            self.assertTrue(any(cmd[1]=='kill' for cmd in self.calls))
        finally: mod.LIMIT = old
    def test_large_bidirectional_request_does_not_deadlock(self):
        payload = 'q' * 250000
        self.assertEqual(self.transport.execute(payload, timeout=5).split(':',1)[1], payload)
        self.assertFalse(self.calls)
    def test_untrusted_command_and_ownership_are_rejected(self):
        with self.assertRaises(ValueError): mod.FreshPsqlTransport(SQL[:-1]+['other'], self.env, OWNER)
        with self.assertRaises(ValueError): mod.FreshPsqlTransport(SQL, self.env, 'not-a-nonce')
        self.assertFalse(self.calls)

    def test_stdout_cannot_forge_a_control_frame(self):
        value = self.transport.execute('\n0123456789abcdef0123456789abcdef END\nsecret-sentinel')
        self.assertTrue(value.endswith('0123456789abcdef0123456789abcdef END\nsecret-sentinel'))
        self.assertFalse(self.calls)
    def test_known_idle_helper_death_restarts_only_on_new_query(self):
        self.transport.execute('first')
        worker = self.transport.local.worker
        worker.kill(); worker.wait()
        self.assertTrue(self.transport.execute('second').endswith(':second'))
        self.assertFalse(self.calls)
    def test_eof_before_response_contains(self):
        def dead(_args, **kwargs):
            return subprocess.Popen(['sh','-c','exit 0'], **kwargs)
        self.transport.popen = dead
        with self.assertRaises(mod.TransportError): self.transport.execute('never replay')
        self.assertTrue(any(cmd[1]=='kill' for cmd in self.calls))
        with self.assertRaises(mod.TransportError): self.transport.execute('new')

    def test_deadline_includes_waiting_for_idle_reap(self):
        thread=threading.Thread(target=lambda: self.transport.execute('initial'))
        thread.start(); thread.join(5); self.assertFalse(thread.is_alive())
        worker=self.transport.workers[0]
        entered=threading.Event(); release=threading.Event(); waiter_done=threading.Event()
        original_wait=worker.wait; requests=[]; original_exchange=self.transport._exchange
        def stalled_wait(*args, **kwargs):
            entered.set(); release.wait(3); return original_wait(*args, **kwargs)
        def exchange(process, request, nonce, timeout):
            requests.append(request); return original_exchange(process, request, nonce, timeout)
        worker.wait=stalled_wait; self.transport._exchange=exchange
        errors=[]
        def first():
            try: self.transport.execute('first',timeout=3)
            except Exception as exc: errors.append(exc)
        def waiter():
            try: self.transport.execute('waiter',timeout=.1)
            except Exception as exc: errors.append(exc)
            finally: waiter_done.set()
        reaper=threading.Thread(target=first); reaper.start()
        self.assertTrue(entered.wait(2))
        waiting=threading.Thread(target=waiter); started=time.monotonic(); waiting.start()
        finished_in_time=waiter_done.wait(.5)
        elapsed=time.monotonic()-started
        release.set(); reaper.join(5); waiting.join(5)
        self.assertTrue(finished_in_time, 'waiter exceeded deadline behind idle reaper')
        self.assertLess(elapsed,.5)
        self.assertFalse(any(b'd2FpdGVy' in request for request in requests))
        self.assertEqual(len(errors),1)

    def test_inflight_interruption_still_contains(self):
        def interrupt(*unused): raise SystemExit('interrupted')
        self.transport._exchange = interrupt
        with self.assertRaises(SystemExit): self.transport.execute('ambiguous')
        self.assertTrue(any(cmd[1]=='kill' for cmd in self.calls))
        with self.assertRaises(mod.TransportError): self.transport.execute('new')

    def test_close_reaps_dead_completed_helper_without_container_kill(self):
        self.transport.execute('completed')
        worker=self.transport.local.worker
        worker.kill(); worker.wait()
        self.transport.close()
        self.assertFalse(self.calls)

    def test_sequential_short_lived_threads_release_helpers(self):
        results=[]; errors=[]
        def run_query(i):
            try: results.append(self.transport.execute(str(i)))
            except Exception as exc: errors.append(exc)
        for i in range(20):
            thread=threading.Thread(target=run_query,args=(i,)); thread.start(); thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(results),20)
        self.transport.close()
        self.assertFalse(self.calls)

    def test_dead_idle_other_thread_is_reaped_without_containment(self):
        thread=threading.Thread(target=lambda: self.transport.execute('first'))
        thread.start(); thread.join(5); self.assertFalse(thread.is_alive())
        worker=self.transport.workers[0]
        worker.kill(); worker.wait()
        self.assertTrue(self.transport.execute('second').endswith(':second'))
        self.transport.close()
        self.assertFalse(self.calls)

    def test_parallel_threads_have_independent_helpers(self):
        gate = threading.Barrier(3); results=[]
        def do(value):
            gate.wait(); results.append(self.transport.execute(value))
        threads=[threading.Thread(target=do,args=(value,)) for value in ('one','two')]
        for thread in threads: thread.start()
        gate.wait()
        for thread in threads: thread.join(5); self.assertFalse(thread.is_alive())
        self.assertEqual({r.split(':')[1] for r in results}, {'one','two'})
        self.assertEqual(len(self.transport.workers),2); self.assertFalse(self.calls)

if __name__ == '__main__': unittest.main()
