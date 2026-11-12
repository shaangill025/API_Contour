import importlib.util
import json
import hashlib
import gc
import sys
import threading
import tempfile
import os
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

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


if __name__ == '__main__': unittest.main()
