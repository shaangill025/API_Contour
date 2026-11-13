import importlib.util
import json
import hashlib
import gc
import sys
import threading
import contextvars
import tempfile
import os
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('docker_metadata',ROOT/'deploy/local/docker_metadata.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
IDENT = 'a'*64


def exchange(response, path=None):
    req_r, req_w = os.pipe(); res_r, res_w = os.pipe()
    os.write(res_w,response); os.close(res_w)
    process = SimpleNamespace(stdin=os.fdopen(req_w,'wb',buffering=0), stdout=os.fdopen(res_r,'rb',buffering=0))
    try:
        value = m._request(process,path or '/v1.56/containers/'+IDENT+'/json',time.monotonic()+1)
        request = os.read(req_r,4096)
        return value, request
    finally:
        process.stdin.close(); process.stdout.close(); os.close(req_r)


def http(body, headers=b'', status=b'200 OK'):
    return b'HTTP/1.1 '+status+b'\r\nContent-Type: application/json\r\n'+headers+b'\r\n'+body


class Framing(unittest.TestCase):
    def test_framing_content_length_and_types(self):
        body=b'{"n":1,"b":true,"null":null,"list":[1,false]}'
        value, request = exchange(http(body,b'Content-Length: '+str(len(body)).encode()+b'\r\n'))
        self.assertEqual(value,{'n':1,'b':True,'null':None,'list':[1,False]})
        self.assertIs(type(value['n']),int); self.assertNotIn('missing',value)
        self.assertTrue(request.startswith(b'GET /v1.56/containers/'+IDENT.encode()+b'/json HTTP/1.1\r\n'))

    def test_chunked_response(self):
        body=b'3\r\n{"a\r\n4\r\n":1}\r\n0\r\n\r\n'
        value,_=exchange(http(body,b'Transfer-Encoding: chunked\r\n'))
        self.assertEqual(value,{'a':1})

    def test_rejects_ambiguous_truncated_and_oversized(self):
        cases = [http(b'{}',b'Content-Length: 2\r\nContent-Length: 2\r\n'),
                 http(b'{}',b'Content-Length: 9\r\n'),
                 http(b'',b'Content-Length: 2097153\r\n'),
                 http(b'0\r\n\r\n',b'Transfer-Encoding: chunked\r\nContent-Length: 0\r\n'),
                 http(b'3\r\n{',b'Transfer-Encoding: chunked\r\n'),
                 http(b'{}',b'Content-Length: 2\r\n',b'404 Not Found'),
                 http(b'{}',b'Content-Length: 2\r\nContent-Encoding: gzip\r\n'),
                 http(b'{}',b'Content-Length: 2\r\nConnection: upgrade\r\n')]
        for case in cases:
            with self.subTest(case=case[:50]), self.assertRaises(Exception): exchange(case)

    def test_duplicate_nonfinite_and_invalid_json(self):
        for body in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}',b'{"x":1e400}',b'{"x":-1e400}',b'\xff'):
            with self.subTest(body=body), self.assertRaises(Exception):
                exchange(http(body,b'Content-Length: '+str(len(body)).encode()+b'\r\n'))

    def test_network_route_and_cleanup_never_unraisable(self):
        route = m._route(['docker','network','inspect',IDENT])
        self.assertEqual(route,'/v1.56/networks/'+IDENT)
        value,request = exchange(http(b'{}',b'Content-Length: 2\r\n'),route)
        self.assertEqual(value,{})
        self.assertTrue(request.startswith(('GET '+route+' HTTP/1.1\r\n').encode()))
        failures=[]; previous=sys.unraisablehook
        try:
            sys.unraisablehook=lambda error: failures.append(error)
            for _ in range(5):
                with self.assertRaises(Exception): exchange(http(b'{',b'Content-Length: 4\r\n'))
            gc.collect()
        finally: sys.unraisablehook=previous
        self.assertEqual(failures,[])

    def test_headers_and_deadline_bounded(self):
        with self.assertRaises(Exception):
            exchange(http(b'{}',b'X-Fill: '+b'x'*8200+b'\r\nContent-Length: 2\r\n'))
        r,w=os.pipe()
        try:
            with self.assertRaises(TimeoutError): m._Stream(r,time.monotonic()-1).read(1)
        finally: os.close(r); os.close(w)

    def test_exact_exec_inspection_is_fresh_typed_get(self):
        route = m._route(['docker','inspect','--type','exec',IDENT])
        self.assertEqual(route,'/v1.56/exec/'+IDENT+'/json')
        payload=b'{"Running":true,"ContainerID":"'+IDENT.encode()+b'"}'
        value,request=exchange(http(payload,b'Content-Length: '+str(len(payload)).encode()+b'\r\n'),route)
        self.assertIs(value['Running'],True)
        self.assertEqual(value['ContainerID'],IDENT)
        self.assertTrue(request.startswith(('GET '+route+' HTTP/1.1\r\n').encode()))
        for argv in (['docker','inspect','--type','exec',IDENT[:12]],
                     ['docker','inspect','--type','exec',IDENT+'?x=1'],
                     ['docker','inspect','--type','container',IDENT],
                     ['docker','inspect','--type','exec',IDENT,IDENT],
                     ['docker','exec','inspect',IDENT]):
            self.assertIsNone(m._route(argv))

    def test_strict_routes(self):
        for argv in (['docker','inspect',IDENT], ['docker','container','inspect',IDENT],
                     ['docker','network','inspect',IDENT], ['docker','image','inspect','sha256:'+IDENT]):
            self.assertIsNotNone(m._route(argv))
        for argv in (['docker','inspect',IDENT[:12]], ['docker','inspect',IDENT,IDENT],
                     ['docker','volume','inspect',IDENT], ['docker','image','inspect','name'],
                     ['docker','image','inspect',IDENT+'?x=1'], ['docker','inspect','../../x'],
                     ['docker','rm',IDENT]):
            self.assertIsNone(m._route(argv))


class ProtectedPaths(unittest.TestCase):
    def test_sibling_changes_do_not_mask_ancestor_identity_or_mode_drift(self):
        with tempfile.TemporaryDirectory(prefix='metadata-parent-',dir=Path.home()) as d:
            parent=Path(d); parent.chmod(0o700)
            child=parent/'private'; child.mkdir(mode=0o700)
            original=m._config(child)
            (parent/'sibling').write_bytes(b'private log')
            self.assertEqual(m._config(child),original)
            parent.chmod(0o755)
            try: self.assertNotEqual(m._config(child),original)
            finally: parent.chmod(0o700)
            child.rename(parent/'old'); child.mkdir(mode=0o700)
            self.assertNotEqual(m._config(child),original)

    def test_tool_and_empty_config_enforce_private_identity(self):
        with tempfile.TemporaryDirectory(prefix='metadata-test-',dir=Path.home()) as d:
            parent=Path(d); parent.chmod(0o700)
            tool=parent/'tool'; tool.write_bytes(b'synthetic executable'); tool.chmod(0o500)
            digest=hashlib.sha256(b'synthetic executable').hexdigest()
            with patch.object(m,'DOCKER_SHA256',digest):
                initial=m._tool(tool,True); self.assertEqual(initial,m._tool(tool))
                tool.chmod(0o700)
                with self.assertRaises(m.MetadataError): m._tool(tool)
                tool.chmod(0o500)
                hard=parent/'hard'; os.link(tool,hard)
                with self.assertRaises(m.MetadataError): m._tool(tool)
                hard.unlink()
                link=parent/'link'; link.symlink_to(tool)
                with self.assertRaises((m.MetadataError,OSError)): m._tool(link)
            config=parent/'config'; config.mkdir(mode=0o700)
            m._config(config)
            (config/'unexpected').write_text('x')
            with self.assertRaises(m.MetadataError): m._config(config)
            (config/'unexpected').unlink(); config.chmod(0o755)
            with self.assertRaises(m.MetadataError): m._config(config)
            config.chmod(0o700)
            parent.chmod(0o777)
            try:
                with self.assertRaises(m.MetadataError): m._config(config)
            finally: parent.chmod(0o700)


class Process:
    def __init__(self): self.stdin = None; self.stdout = None; self.waits = 0; self.killed = False
    def wait(self,timeout): self.waits += 1; return 0
    def poll(self): return None
    def kill(self): self.killed = True


class Lifecycle(unittest.TestCase):
    def setup_session(self, req):
        proc = Process()
        patches = [patch.object(m,'_tool',return_value=('tool',)),patch.object(m,'_socket',return_value=('socket',)),
                   patch.object(m,'_config',return_value=('config',)),
                   patch.object(m,'_version',return_value={'Client':{'ApiVersion':'1.56'},'Server':{'ApiVersion':'1.56'}}),
                   patch.object(m.subprocess,'Popen',return_value=proc),patch.object(m,'_request',side_effect=req)]
        for p in patches: p.start(); self.addCleanup(p.stop)
        return m.Session(docker=m.DOCKER,sha256=m.DOCKER_SHA256,socket=m.SOCKET,config='/private/config'),proc

    def test_fresh_calls_and_unsupported_no_send(self):
        calls=[]
        def request(_process,path,_deadline):
            calls.append(path)
            return {'ApiVersion':'1.56'} if path=='/version' else {'count':len(calls),'null':None}
        session,proc = self.setup_session(request)
        with session:
            self.assertIsNone(session.read(['docker','rm',IDENT]))
            first=session.read(['docker','inspect',IDENT]); second=session.read(['docker','inspect',IDENT])
            self.assertNotEqual(first,second); self.assertIsNone(first[0]['null'])
            self.assertEqual(calls.count('/v1.56/containers/'+IDENT+'/json'),2)
        self.assertEqual(proc.waits,1)
        with self.assertRaises(m.MetadataError): session.read(['docker','inspect',IDENT])

    def test_version_disagreement_and_failure_reap(self):
        session,proc = self.setup_session(lambda *_:{'ApiVersion':'1.55'})
        with self.assertRaises(m.MetadataError): session.__enter__()
        self.assertEqual(proc.waits,1)
        self.assertFalse(session.active)

    def test_request_error_closes_and_redacts(self):
        def request(_p,path,_d):
            if path=='/version': return {'ApiVersion':'1.56'}
            raise ValueError('private-canary')
        session,proc = self.setup_session(request)
        with session:
            with self.assertRaisesRegex(m.MetadataError,'^metadata session failed$'):
                session.read(['docker','inspect',IDENT])
            self.assertFalse(session.active)
        self.assertEqual(proc.waits,1)

    def test_cancellation_closes_and_propagates(self):
        def request(_p,path,_d):
            if path=='/version': return {'ApiVersion':'1.56'}
            raise KeyboardInterrupt()
        session,proc = self.setup_session(request)
        with session:
            with self.assertRaises(KeyboardInterrupt): session.read(['docker','inspect',IDENT])
        self.assertEqual(proc.waits,1)

    def test_context_drift_and_call_bound(self):
        session,proc = self.setup_session(lambda _p,path,_d:{'ApiVersion':'1.56'} if path=='/version' else {})
        with session:
            session.calls=m.MAX_CALLS
            with self.assertRaises(m.MetadataError): session.read(['docker','inspect',IDENT])
        self.assertEqual(proc.waits,1)

    def test_identity_drift_closes_and_reaps(self):
        session,proc = self.setup_session(lambda _p,path,_d:{'ApiVersion':'1.56'} if path=='/version' else {})
        with session:
            with patch.object(m,'_tool',return_value=('replaced',)):
                with self.assertRaises(m.MetadataError): session.read(['docker','inspect',IDENT])
                self.assertFalse(session.active)
        self.assertEqual(proc.waits,1)

    def test_expired_idle_cleanup_checks_identity_and_reaps(self):
        session,proc=self.setup_session(lambda *_:{'ApiVersion':'1.56'})
        session.__enter__(); session.deadline=time.monotonic()-1
        session.__exit__(None,None,None)
        self.assertFalse(session.active); self.assertEqual(proc.waits,1)

    def test_expired_read_cannot_return_or_request(self):
        paths=[]
        session,proc=self.setup_session(lambda _p,path,_d:(paths.append(path) or {'ApiVersion':'1.56'}))
        session.__enter__(); session.deadline=time.monotonic()-1
        with self.assertRaises(m.MetadataError): session.read(['docker','inspect',IDENT])
        self.assertEqual(paths,['/version']); self.assertEqual(proc.waits,1)

    def test_expired_cleanup_still_rejects_identity_drift_and_reaps(self):
        session,proc=self.setup_session(lambda *_:{'ApiVersion':'1.56'})
        session.__enter__(); session.deadline=time.monotonic()-1
        with patch.object(m,'_tool',return_value=('replaced',)):
            with self.assertRaises(m.MetadataError): session.__exit__(None,None,None)
        self.assertEqual(proc.waits,1); self.assertFalse(session.active)

    def test_timeout_cleanup_kills_only_owned_process(self):
        class Slow(Process):
            def wait(self,timeout):
                self.waits += 1
                if self.waits == 1: raise m.subprocess.TimeoutExpired('child',timeout)
                return -9
        proc = Slow(); m._stop(proc)
        self.assertTrue(proc.killed); self.assertEqual(proc.waits,2)

    def test_concurrent_reads_fail_closed_without_response_reuse(self):
        entered,release=threading.Event(),threading.Event(); paths=[]
        def request(_p,path,_d):
            paths.append(path)
            if path=='/version': return {'ApiVersion':'1.56'}
            entered.set(); self.assertTrue(release.wait(2)); return {'value':1}
        session,proc=self.setup_session(request); session.__enter__(); errors=[]
        def first():
            try: session.read(['docker','inspect',IDENT])
            except BaseException as e: errors.append(e)
        thread=threading.Thread(target=first); thread.start(); self.assertTrue(entered.wait(2))
        with self.assertRaises(m.MetadataError): session.read(['docker','inspect',IDENT])
        self.assertEqual(proc.waits,0); release.set(); thread.join(2); self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors),1); self.assertIsInstance(errors[0],m.MetadataError)
        self.assertEqual(paths.count('/v1.56/containers/'+IDENT+'/json'),1)
        self.assertEqual(proc.waits,1)
        with self.assertRaises(m.MetadataError): session.__exit__(None,None,None)

    def test_exit_waits_for_inflight_read_before_closing(self):
        entered,release=threading.Event(),threading.Event()
        def request(_p,path,_d):
            if path=='/version': return {'ApiVersion':'1.56'}
            entered.set(); self.assertTrue(release.wait(2)); return {'value':1}
        session,proc=self.setup_session(request); session.__enter__(); errors=[]
        def reading():
            try: session.read(['docker','inspect',IDENT])
            except BaseException as e: errors.append(e)
        def exiting():
            try: session.__exit__(None,None,None)
            except BaseException as e: errors.append(e)
        reader=threading.Thread(target=reading); reader.start(); self.assertTrue(entered.wait(2))
        exiter=threading.Thread(target=exiting); exiter.start()
        self.assertTrue(session._cancel.wait(2)); self.assertEqual(proc.waits,0)
        release.set(); reader.join(2); exiter.join(2)
        self.assertFalse(reader.is_alive()); self.assertFalse(exiter.is_alive())
        self.assertEqual(len(errors),2); self.assertTrue(all(isinstance(x,m.MetadataError) for x in errors))
        self.assertEqual(proc.waits,1)

    def test_constructor_pins_endpoint(self):
        with self.assertRaises(m.MetadataError): m.Session(docker='/unapproved',sha256=m.DOCKER_SHA256,socket=m.SOCKET,config='/x')
        with self.assertRaises(m.MetadataError): m.Session(docker=m.DOCKER,sha256='0'*64,socket=m.SOCKET,config='/x')
        with self.assertRaises(m.MetadataError): m.Session(docker=m.DOCKER,sha256=m.DOCKER_SHA256,socket='/tmp/socket',config='/x')


class Integration(unittest.TestCase):
    class FakeSession:
        created = []
        def __init__(self,**kwargs):
            self.kwargs=kwargs; self.calls=0; self.deadline=time.monotonic()+300
            self.active=False; self.closed=0; self._guard=threading.Lock(); self._cancel=threading.Event()
            self.fail=False; self.context_checks=0; self.created.append(self)
        def __enter__(self): self.active=True; return self
        def start(self,deadline=None): self.active=True; return self
        def __exit__(self,*_): self.closed+=1; self.active=False
        def _context(self,deadline=None):
            self.context_checks+=1
            if not self.active: raise m.MetadataError('metadata session failed')
        def read(self,args,deadline=None):
            self.calls+=1
            if self.fail: raise m.MetadataError('metadata session failed')
            return [{'count':self.calls,'null':None}]

    def setUp(self): self.FakeSession.created=[]

    def test_default_off_preserves_original_cli(self):
        from deploy.local import origin21_products as products
        with patch.object(products.shutil,'which',return_value='/original/docker'), \
             patch.object(products.origin21_transport,'_run',return_value='result') as run:
            self.assertEqual(products._command(['docker','inspect',IDENT],17),b'result')
            self.assertEqual(run.call_args.args[0],['/original/docker','inspect',IDENT])
            self.assertEqual(run.call_args.kwargs['deadline'],17)
            self.assertNotIn('DOCKER_CONFIG',run.call_args.kwargs['env'])

    def test_exec_route_is_opt_in_and_each_read_is_fresh(self):
        from deploy.local import docker_metadata as bound, origin21_products as products
        args=['docker','inspect','--type','exec',IDENT]
        with patch.object(products.shutil,'which',return_value='/original/docker'), \
             patch.object(products.origin21_transport,'_run',return_value='ordinary') as run:
            self.assertEqual(products._command(args),b'ordinary')
            self.assertEqual(run.call_args.args[0],['/original/docker',*args[1:]])
        pool=bound._Pool(None,Path('/private/config')); token=bound._ACTIVE.set(pool)
        try:
            with patch.object(bound,'Session',self.FakeSession), patch.object(products.origin21_transport,'_run') as run:
                first=json.loads(products._command(args)); second=json.loads(products._command(args))
                self.assertNotEqual(first,second); self.assertEqual(self.FakeSession.created[0].calls,2)
                run.assert_not_called()
        finally:
            bound._ACTIVE.reset(token); pool.close()

    def test_scoped_supported_fresh_and_unsupported_preserves_timeout_environment(self):
        from deploy.local import docker_metadata as bound, origin21_products as products
        pool=bound._Pool(None,Path('/private/config')); token=bound._ACTIVE.set(pool)
        try:
            with patch.object(bound,'Session',self.FakeSession), patch.object(products.shutil,'which') as which, \
                 patch.object(products.origin21_transport,'_run',return_value='cli') as run:
                a=json.loads(products._command(['docker','inspect',IDENT])); b=json.loads(products._command(['docker','inspect',IDENT]))
                self.assertNotEqual(a,b); self.assertIsNone(a[0]['null']); run.assert_not_called(); which.assert_not_called()
                self.assertEqual(products._command(['docker','rm',IDENT],23,token='t'),b'cli')
                call=run.call_args
                self.assertEqual(call.args[0],[bound.DOCKER,'--config','/private/config','--host','unix://'+bound.SOCKET,'rm',IDENT])
                self.assertGreater(call.kwargs['deadline'],0); self.assertLessEqual(call.kwargs['deadline'],23)
                self.assertEqual(call.kwargs['env']['ORIGIN21_OWNER_TOKEN'],'t')
                self.assertIn('HOME',call.kwargs['env']); self.assertNotIn('DOCKER_CONFIG',call.kwargs['env'])
                fake=self.FakeSession.created[0]; fake.fail=True; run.reset_mock()
                with self.assertRaises(m.MetadataError): products._command(['docker','inspect',IDENT])
                run.assert_not_called(); self.assertGreaterEqual(fake.context_checks,2)
        finally:
            bound._ACTIVE.reset(token); pool.close()

    def test_rotation_and_thread_session_separation(self):
        pool=m._Pool(None,Path('/private/config')); runner=lambda *_a,**_k:''
        with patch.object(m,'Session',self.FakeSession):
            first=json.loads(pool.command(['docker','inspect',IDENT],30,{},runner))
            session=self.FakeSession.created[0]; session.calls=m.MAX_CALLS-1
            again=json.loads(pool.command(['docker','inspect',IDENT],30,{},runner))
            self.assertEqual(first,again); self.assertEqual(session.closed,1)
            other=self.FakeSession.created[1]; other.deadline=time.monotonic()+1
            pool.command(['docker','inspect',IDENT],30,{},runner); self.assertEqual(other.closed,1)
            token=m._ACTIVE.set(pool)
            try:
                ctx=contextvars.copy_context(); values=[]
                t=threading.Thread(target=lambda:ctx.run(lambda:values.append(m.dispatch(['docker','inspect',IDENT],30,{},runner))))
                t.start(); t.join(2); self.assertFalse(t.is_alive()); self.assertEqual(len(values),1)
                self.assertEqual(len(pool.sessions),2)
            finally: m._ACTIVE.reset(token)
            pool.close()
            self.assertTrue(all(s.closed==1 for s in self.FakeSession.created))

    def test_scope_restores_context_and_removes_empty_config(self):
        from deploy.local import origin21_managed_qualification as qualification
        with tempfile.TemporaryDirectory(prefix='metadata-scope-',dir=Path.home()) as d:
            folder=Path(d); folder.chmod(0o700)
            class Proof:
                def __init__(self): self.folder=folder; self.checks=0
                def verify(self): self.checks+=1
            proof=Proof()
            with patch.object(qualification,'OwnedManagedQualification',Proof):
                with self.assertRaisesRegex(ValueError,'primary'):
                    with m.qualification_scope(proof):
                        self.assertIsNotNone(m._ACTIVE.get()); self.assertTrue((folder/'docker-metadata-config').is_dir())
                        raise ValueError('primary')
                self.assertIsNone(m._ACTIVE.get()); self.assertFalse((folder/'docker-metadata-config').exists())
                self.assertGreaterEqual(proof.checks,3)

    def test_fallback_encoding_cannot_return_after_deadline(self):
        now=[10.0]; calls=[]
        class SlowEncoding(str):
            def encode(self,*args,**kwargs):
                now[0]=12.0
                return super().encode(*args,**kwargs)
        def runner(*args,**kwargs):
            calls.append((args,kwargs)); return SlowEncoding('not-a-receipt')
        pool=m._Pool(None,Path('/private/config'))
        with patch.object(m,'Session',self.FakeSession), patch.object(m.time,'monotonic',side_effect=lambda:now[0]):
            with self.assertRaises(m.MetadataError): pool.command(['docker','rm',IDENT],1,{},runner)
            self.assertEqual(len(calls),1)
            pool.close()

    def test_short_deadline_bounds_real_pipe_read(self):
        req_r,req_w=os.pipe(); res_r,res_w=os.pipe()
        class PipeProcess(Process):
            def __init__(self):
                super().__init__(); self.stdin=os.fdopen(req_w,'wb',buffering=0); self.stdout=os.fdopen(res_r,'rb',buffering=0)
        proc=PipeProcess(); session=m.Session(docker=m.DOCKER,sha256=m.DOCKER_SHA256,socket=m.SOCKET,config='/private/config')
        session.tool=('tool',); session.endpoint=('socket',); session.directory=('config',)
        session.deadline=time.monotonic()+10; session.process=proc; session.active=True
        def late():
            time.sleep(.15)
            try: os.write(res_w,http(b'{}',b'Content-Length: 2\r\n'))
            except BrokenPipeError: pass
            finally: os.close(res_w)
        writer=threading.Thread(target=late); writer.start(); start=time.monotonic()
        try:
            with patch.object(m,'_tool',return_value=('tool',)), patch.object(m,'_socket',return_value=('socket',)), patch.object(m,'_config',return_value=('config',)):
                with self.assertRaises(m.MetadataError): session.read(['docker','inspect',IDENT],deadline=start+.04)
            self.assertLess(time.monotonic()-start,.4); self.assertEqual(proc.waits,1)
        finally:
            writer.join(1); os.close(req_r)
        self.assertFalse(writer.is_alive())

    def test_short_deadline_cold_start_and_pool_lock(self):
        pool=m._Pool(None,Path('/private/config')); runner=Mock()
        def version(_argv,_env,deadline):
            while time.monotonic()<deadline: time.sleep(.002)
            raise TimeoutError()
        with patch.object(m,'_tool',return_value=('tool',)), patch.object(m,'_socket',return_value=('socket',)), \
             patch.object(m,'_config',return_value=('config',)), patch.object(m,'_version',side_effect=version), \
             patch.object(m.subprocess,'Popen') as spawn:
            start=time.monotonic()
            with self.assertRaises(m.MetadataError): pool.command(['docker','inspect',IDENT],.04,{},runner)
            self.assertLess(time.monotonic()-start,.4); spawn.assert_not_called(); runner.assert_not_called()
        pool.lock.acquire()
        try:
            start=time.monotonic()
            with self.assertRaises(TimeoutError): pool.command(['docker','inspect',IDENT],.04,{},runner)
            self.assertLess(time.monotonic()-start,.4); runner.assert_not_called()
        finally: pool.lock.release()

    def test_strict_flags_and_unchanged_deadlines(self):
        wrapper_spec=importlib.util.spec_from_file_location('fresh_wrapper',ROOT/'scripts/qualify-managed-origin.py')
        wrapper=importlib.util.module_from_spec(wrapper_spec); wrapper_spec.loader.exec_module(wrapper)
        driver_spec=importlib.util.spec_from_file_location('fresh_driver',ROOT/'scripts/test-managed-origin-qualification.py')
        driver=importlib.util.module_from_spec(driver_spec); driver_spec.loader.exec_module(driver)
        self.assertEqual(wrapper.QUALIFY_SECONDS,1200); self.assertEqual(driver._STREAM_DEADLINE,180)
        for module in (wrapper,driver):
            self.assertIn('deploy/local/docker_metadata.py',module._ALLOWED_FRAMES)
        for extra in (['--fresh-metadata','--fresh-metadata'],['--other']):
            with patch.object(wrapper.sys,'argv',['wrapper',*extra]), patch.object(wrapper,'helper') as helper:
                with self.assertRaises(ValueError): wrapper.main()
                helper.assert_not_called()
        for args in ([1,2,3,4,'--other'],[1,2,3,4,'--fresh-metadata','--fresh-metadata']):
            with patch.object(driver,'_source_guard') as source:
                with self.assertRaises(ValueError): driver.main(args)
                source.assert_not_called()

    def test_explicit_flag_propagates_only_when_selected(self):
        spec=importlib.util.spec_from_file_location('fresh_wrapper_forward',ROOT/'scripts/qualify-managed-origin.py')
        wrapper=importlib.util.module_from_spec(spec); spec.loader.exec_module(wrapper)
        for enabled in (False,True):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory(dir=Path.home()) as d:
                folder=Path(d); calls=[]
                class Owner:
                    path=folder
                    def verify(self): pass
                    def write(self,name,data):
                        path=self.path/name; path.write_bytes(data); return path
                def run(args,**_kwargs):
                    calls.append(args)
                    if args[:3]==['git','worktree','add']:
                        child=Path(args[-2]); child.mkdir(); (child/'.git').write_text('gitdir: owned')
                    if len(args)>1 and args[1]=='scripts/test-managed-origin-qualification.py':
                        raise RuntimeError('stop before execution')
                    return b''
                h={'snapshot':lambda *_:('b'*40,{'fixed':'hash'}),'require_registration':lambda *_a,**_k:None,
                   'encode':lambda value:json.dumps(value,sort_keys=True,separators=(',',':')).encode(),
                   'OWNER_LABEL':'owner','HEAD_LABEL':'head','image_identity':lambda *_:'sha256:'+'c'*64}
                with self.assertRaisesRegex(RuntimeError,'stop before execution'):
                    wrapper.qualify(run,Owner(),'a'*32,h,fresh_metadata=enabled)
                inner=next(a for a in calls if len(a)>1 and a[1]=='scripts/test-managed-origin-qualification.py')
                self.assertEqual(inner[-1]=='--fresh-metadata',enabled)

    def test_source_closure_pins_transport(self):
        from deploy.local import origin21_state
        self.assertIn('deploy/local/docker_metadata.py',origin21_state.SOURCE_FILES)
        self.assertIn('tests/fixtures/docker-metadata/test_metadata.py',origin21_state.MANAGED_SOURCE_FILES)



if __name__ == '__main__': unittest.main()
