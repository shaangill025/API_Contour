"""Offline checks for the owned receiver deployment qualifier's closed gates."""
import json
import runpy
from pathlib import Path
import unittest

Q=runpy.run_path(str(Path(__file__).resolve().parents[3]/'scripts/qualify-receiver-deployment.py'))

class QualifierTests(unittest.TestCase):
    def test_cli_reports_one_json_and_preserves_failure_cleanup(self):
        import contextlib, io
        report=Q['report']
        cases=[({'status':'fail','phase':'image','cleanup':'complete'},1),({'status':'pass','phase':None,'cleanup':'complete'},0)]
        for value,code in cases:
            output=io.StringIO()
            with contextlib.redirect_stdout(output): actual=report(lambda: value)
            self.assertEqual(actual,code)
            lines=output.getvalue().splitlines();self.assertEqual(len(lines),1)
            self.assertEqual(json.loads(lines[0]),value)
        def fail(): raise RuntimeError('private diagnostic')
        output=io.StringIO()
        with contextlib.redirect_stdout(output): actual=report(fail)
        self.assertEqual(actual,1)
        lines=output.getvalue().splitlines();self.assertEqual(len(lines),1)
        value=json.loads(lines[0])
        self.assertEqual(value['status'],'fail');self.assertEqual(value['phase'],'input');self.assertEqual(value['cleanup'],'unknown')
        self.assertEqual(value['failure_type'],'RuntimeError')
        self.assertTrue(len(value['source_frames'])<=4 and all(set(frame)=={'file','line'} and type(frame['line']) is int for frame in value['source_frames']))
        self.assertNotIn('private diagnostic',output.getvalue())
        self.assertNotIn(__file__,output.getvalue())
    def test_diagnostics_allow_only_fixed_messages_and_paths(self):
        diagnostic=Q['failure_diagnostic']
        code=compile('raise ValueError("process deadline")','/unapproved/private-secret.py','exec')
        try: exec(code,{})
        except ValueError as error: kind,frames,mapped=diagnostic(error)
        self.assertEqual(kind,'ValueError');self.assertEqual(mapped,'process_deadline')
        self.assertFalse(any('private-secret' in str(frame) for frame in frames))
        try: raise ValueError('process deadline secret-key-contents')
        except ValueError as error: kind,frames,mapped=diagnostic(error)
        self.assertIsNone(mapped)
        self.assertNotIn('secret',str((kind,frames,mapped)))
        code=compile('raise RuntimeError("private secret")',str(Path(Q['ROOT'])/'scripts/qualify-origin21-onboarding.py'),'exec')
        try: exec(code,{})
        except RuntimeError as error: kind,frames,mapped=diagnostic(error)
        self.assertEqual(frames[-1],{'file':'qualify-origin21-onboarding.py','line':1})
        self.assertIsNone(mapped)
    def test_duplicate_and_oversize_json_rejected(self):
        with self.assertRaises(ValueError): Q['parse'](b'{"x":1,"x":2}')
        with self.assertRaises(ValueError): Q['parse'](b' '*32769)
    def test_probe_output_is_closed_and_image_associated(self):
        config='sha256:'+'a'*64
        value=('receiver504_image_config='+config+'\nreceiver504_deployment=pass\n').encode()
        self.assertEqual(Q['probe_result'](value+b'\n'),(('pass',None),config))
        for bad in (b'receiver504_deployment=pass\n\n',value+b'extra\n\n',value+value+b'\n',b'receiver504_deployment=fail phase=other\n\n'):
            with self.assertRaises(ValueError): Q['probe_result'](bad)
    def test_probe_exit_and_containment_fail_closed(self):
        import tempfile
        from types import SimpleNamespace
        good=b'receiver504_image_config=sha256:'+b'a'*64+b'\nreceiver504_deployment=pass\n'
        fail=b'receiver504_deployment=fail phase=image\n'
        with tempfile.TemporaryDirectory() as directory:
            owner=SimpleNamespace(path=Path(directory).resolve())
            def result(stdout, code, stderr=b''):
                def run(args,**kwargs):
                    path=kwargs['log'];path.write_bytes(stdout+b'\nreceiver504_probe_exit='+str(code).encode()+b'\n\n'+stderr);path.chmod(0o600)
                return run
            execute=Q['execute_probe']
            self.assertEqual(execute(result(good,0),'/probe','/input',owner,1)[0],('pass',None))
            self.assertEqual(execute(result(fail,1),'/probe','/input',owner,1)[0],('fail','image'))
            for runner in (result(good,1),result(fail,0),result(good,0,b'error'),result(good,999)):
                with self.assertRaises(ValueError): execute(runner,'/probe','/input',owner,1)
            def failed(*args,**kwargs): raise RuntimeError('containment')
            with self.assertRaises(RuntimeError): execute(failed,'/probe','/input',owner,1)
    def test_runner_rejects_surviving_same_group_descendant(self):
        import runpy, sys, time
        root=Path(__file__).resolve().parents[3]
        helper=runpy.run_path(str(root/'scripts/qualify-origin21-onboarding.py'))
        try: runner=helper['Runner'](time.monotonic()+15)
        except helper['ProcessRuntimeUnavailable']: self.skipTest('qualified interpreter with waitid/WNOWAIT required')
        code=('import subprocess,sys;subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);print("receiver504_deployment=pass",flush=True)')
        with self.assertRaises(BaseException) as captured:
            runner([sys.executable,'-c',code],cwd=root,timeout=10)
        self.assertIn('descendant survived leader',str(captured.exception))
    def test_runner_enforces_combined_stderr_output_bound(self):
        import runpy, sys, time
        root=Path(__file__).resolve().parents[3]
        helper=runpy.run_path(str(root/'scripts/qualify-origin21-onboarding.py'))
        try: runner=helper['Runner'](time.monotonic()+15)
        except helper['ProcessRuntimeUnavailable']: self.skipTest('qualified interpreter with waitid/WNOWAIT required')
        namespace=helper['Runner'].__call__.__globals__; original=namespace['OUTPUT_LIMIT'];namespace['OUTPUT_LIMIT']=64
        try:
            with self.assertRaises(BaseException) as captured:
                runner([sys.executable,'-c','import sys;sys.stderr.write("x"*1000)'],cwd=root,timeout=10)
            self.assertIn('process output bound',str(captured.exception))
        finally: namespace['OUTPUT_LIMIT']=original
    def test_journal_requires_exact_correlated_image_and_network(self):
        prefix=b'apicontour/local-create-intent/1\n'; image=bytes([2])*32; net=bytes([3])*32
        intent=prefix+bytes([1])*32+image+net+bytes([4])*64
        cid=b'CCI-CID1\n'+bytes([5])*32
        self.assertEqual(Q['journal_records'](intent,cid,image.hex(),net.hex()),('01'*32,'05'*32))
        for bad in (intent[:-1],intent[:len(prefix)]+bytes(32)+intent[len(prefix)+32:]):
            with self.assertRaises(ValueError): Q['journal_records'](bad,cid,image.hex(),net.hex())
        with self.assertRaises(ValueError): Q['journal_records'](intent,cid,image.hex(),'ff'*32)
        with self.assertRaises(ValueError): Q['journal_records'](intent,cid+b'x',image.hex(),net.hex())
    def test_network_and_container_ownership_must_match(self):
        cid='1'*64; token='2'*64; image='3'*64; network='4'*64; name='owned'
        descriptor={'digest':'sha256:'+'5'*64,'mediaType':'application/vnd.oci.image.manifest.v1+json','size':1234,'platform':{'os':'linux','architecture':'arm64'}}
        net={'Id':network,'Name':name,'Internal':True,'Driver':'bridge','Labels':{Q['LABEL']:token},'Containers':{}}
        Q['validate_network'](net,network,name,token,[])
        for key,value in [('Internal',False),('Id','0'*64),('Containers',{cid:{}})]:
            bad=dict(net);bad[key]=value
            with self.assertRaises(ValueError): Q['validate_network'](bad,network,name,token,[])
        c={'Id':cid,'Name':'/contour-causal-'+token,'Image':'sha256:'+image,'ImageManifestDescriptor':descriptor,'Config':{'Image':'sha256:'+image,'Labels':{'org.apicontour.causal.owner':token}},'HostConfig':{'NetworkMode':name},'NetworkSettings':{'Networks':{name:{'NetworkID':''}}},'State':{'Status':'created','Running':False,'Pid':0,'StartedAt':'0001-01-01T00:00:00Z'}}
        Q['validate_container'](c,cid,token,image,name,network,descriptor)
        for key,value in [('Id','0'*64),('Image','sha256:'+'6'*64),('Name','/wrong'),('ImageManifestDescriptor',None)]:
            bad=dict(c);bad[key]=value
            with self.assertRaises(ValueError): Q['validate_container'](bad,cid,token,image,name,network,descriptor)
        import copy
        for field,value in [('digest','sha256:'+'6'*64),('size',True)]:
            bad=copy.deepcopy(c);bad['ImageManifestDescriptor'][field]=value
            with self.assertRaises(ValueError): Q['validate_container'](bad,cid,token,image,name,network,descriptor)
        bad=copy.deepcopy(c);bad['ImageManifestDescriptor']['platform']['architecture']='amd64'
        with self.assertRaises(ValueError): Q['validate_container'](bad,cid,token,image,name,network,descriptor)
        bad=copy.deepcopy(c);bad['Config']['Image']='sha256:'+'6'*64
        with self.assertRaises(ValueError): Q['validate_container'](bad,cid,token,image,name,network,descriptor)
        selected={'Id':descriptor['digest'],'Os':'linux','Architecture':'arm64','Descriptor':descriptor}
        self.assertEqual(Q['selected_descriptor'](selected,'arm64'),descriptor)
        for mutate in ('digest','arch','missing','size'):
            bad=copy.deepcopy(selected)
            if mutate=='digest': bad['Descriptor']['digest']='sha256:'+'7'*64
            elif mutate=='arch': bad['Descriptor']['platform']['architecture']='amd64'
            elif mutate=='missing': del bad['Descriptor']
            else: bad['Descriptor']['size']=True
            with self.assertRaises(ValueError): Q['selected_descriptor'](bad,'arm64')

if __name__=='__main__': unittest.main()
