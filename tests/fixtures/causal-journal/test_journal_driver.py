import runpy
import tempfile
import signal
import threading
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
M=runpy.run_path(str(ROOT/'scripts/test-postgres-causal-journal.py'))
G=M['run_cases'].__globals__


class JournalDriverTests(unittest.TestCase):
    def test_scenarios_and_cleanup_are_mandatory(self):
        stages=[]; db=['0']; active=[]
        class Child:
            def __init__(self,mode): self.mode=mode
        class Monitor:
            def __init__(self,args,env):
                self.mode=args[-1]; self.child=Child(self.mode); self.stopped=False; active.append(self)
            def stop(self,graceful): self.stopped=True
        def line(m,index,pattern):
            if index==1 and m.mode in ('normal','later'): db[0]='2' if m.mode=='later' else '1'
            return b'SESSION 1 123 456' if index==2 else b''
        def process(args,**kwargs):
            return mock.Mock(returncode=1,stdout=b'',stderr=(b'BUSY\n' if args[-1]=='normal' else b'MISMATCH\n'))
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(G,{'ProbeProcess':Monitor,'line':line,'send':lambda m:None,'run_process':process,'command':lambda *a,**k:b'true' if k['data'].startswith(b'SELECT (expires_at') else b'1 123 456','stop':lambda m,p:m.stop(False)}):
            state={'stages':stages,'container_id':'fixture'}
            M['run_cases'](['probe'],Path(d),{},lambda:db[0]+'|0|0|0|0|0',state)
        self.assertEqual(state['status'],'passed')
        self.assertEqual(stages,['killed_after_prepared','refuse_nonce','refuse_envelope','refuse_source','refuse_config','locked_after_error','locked_after_success','killed_after_confirmed_issue','exact_reopen','current_key_rejection','separate_later_intent','old_epoch_rejected'])
        self.assertTrue(all(m.stopped for m in active))

    def test_refusal_must_be_exact_and_no_output(self):
        class Monitor:
            def __init__(self,*a): pass
            def stop(self,*a): pass
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(G,{'ProbeProcess':Monitor,'line':lambda *a:b'','run_process':lambda *a,**k:mock.Mock(returncode=0,stdout=b'',stderr=b''),'stop':lambda m,p:m.stop(False)}):
            with self.assertRaises(AssertionError): M['run_cases'](['probe'],Path(d),{},lambda:'0|0|0|0|0|0',{'stages':[]})

    def test_helper_hash_change_rejected(self):
        bridge,https,inbox,hashes=M['load_helpers']()
        M['install_helpers'](bridge,https,inbox,dict(hashes,**{'scripts/test-postgres-causal-https.py':'0'*64}))
        with self.assertRaises(RuntimeError): bridge['main'].__globals__['snapshot']()


    def test_stage_failure_still_stops_started_process(self):
        active=[]
        class Monitor:
            def __init__(self,*args): self.stopped=False; active.append(self)
            def stop(self,*args): self.stopped=True
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(G,{'ProbeProcess':Monitor,'line':mock.Mock(side_effect=RuntimeError('stage failed')),'stop':lambda m,p:m.stop(False)}):
            with self.assertRaisesRegex(RuntimeError,'stage failed'):
                M['run_cases'](['probe'],Path(d),{},lambda:'0|0|0|0|0|0',{'stages':[]})
        self.assertEqual(len(active),1)
        self.assertTrue(active[0].stopped)

    def test_complete_output_and_controlled_kill_are_required(self):
        class Monitor:
            def __init__(self,out=b'PREPARED\n',err=b'',overflow=False,code=-signal.SIGKILL):
                self.lock=threading.Lock(); self.buffers={'out':out,'err':err}; self.overflow=overflow
                self.child=SimpleNamespace(returncode=code); self.stopped=False
            def stop(self,graceful): self.stopped=True
        monitor=Monitor(); M['stop'](monitor,rb'PREPARED\n'); self.assertTrue(monitor.stopped)
        for kwargs in ({'out':b'PREPARED\nEXTRA\n'},{'err':b'late error'},{'overflow':True},{'code':0}):
            with self.subTest(kwargs=kwargs):
                monitor=Monitor(**kwargs)
                with self.assertRaises(RuntimeError): M['stop'](monitor,rb'PREPARED\n')
                self.assertTrue(monitor.stopped)


if __name__=='__main__': unittest.main()
