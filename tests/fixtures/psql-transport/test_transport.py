"""Offline transport tests with local synthetic processes; no Docker or database."""
import importlib.util
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
