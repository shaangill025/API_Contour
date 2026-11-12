"""Private, bounded, fresh Docker metadata reads for opt-in qualification dispatch.

This transport returns observations only, never authority. Its use requires
independent CLI equality checks and current-context/source binding.
"""
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import time
import threading

DOCKER = '/Users/shaanjotgill/Library/Caches/APIContour/tools/docker-29.8.2-31ae2d64/docker'
DOCKER_SHA256 = '31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f'
SOCKET = '/Users/shaanjotgill/.docker/run/docker.sock'
API = '1.56'
MAX_BODY = 2 * 1024 * 1024
MAX_HEADER = 32768
MAX_CALLS = 128
OP_SECONDS = 8
SESSION_SECONDS = 300
ID = re.compile(r'^[0-9a-f]{64}$')


class MetadataError(RuntimeError):
    """A closed failure; raw daemon output and exceptions are not exposed."""


def _fail(): raise MetadataError('metadata session failed')


def _identity(st):
    return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns)


def _path(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or not path.name: _fail()
    chain = []
    for component in reversed((path,*path.parents)):
        st = os.lstat(component)
        if stat.S_ISLNK(st.st_mode): _fail()
        if component != path:
            if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0,os.geteuid()) or st.st_mode & 0o022: _fail()
        chain.append(_identity(st) if component == path else
                     (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid))
    return chain


def _tool(path, full=False):
    chain = _path(path)
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o500
                or st.st_nlink != 1 or not 0 < st.st_size <= 256*1024*1024 or _identity(st) != chain[-1]): _fail()
        if full:
            h = hashlib.sha256(); remaining = st.st_size
            while remaining:
                chunk = os.read(fd,min(1048576,remaining))
                if not chunk: _fail()
                h.update(chunk); remaining -= len(chunk)
            if h.hexdigest() != DOCKER_SHA256: _fail()
        if _identity(os.fstat(fd)) != _identity(st) or _path(path) != chain: _fail()
        return tuple(chain)
    finally: os.close(fd)


def _config(path):
    chain = _path(path); st = os.lstat(path)
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700): _fail()
    fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        if _identity(os.fstat(fd)) != _identity(st) or os.listdir(fd): _fail()
        if _path(path) != chain or _identity(os.fstat(fd)) != _identity(st): _fail()
    finally: os.close(fd)
    return tuple(chain)


def _socket(path):
    chain = _path(path); st = os.lstat(path)
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid not in (0,os.geteuid()): _fail()
    return tuple(chain)


def _pairs(items):
    obj = {}
    for k,v in items:
        if k in obj: _fail()
        obj[k] = v
    return obj


def _float(value):
    result = float(value)
    if not math.isfinite(result): _fail()
    return result


def _parse(data):
    try:
        return json.loads(data.decode('utf-8'),object_pairs_hook=_pairs,parse_float=_float,parse_constant=lambda _: _fail())
    except (UnicodeError,ValueError,RecursionError): _fail()


def _route(args):
    if type(args) not in (list,tuple) or len(args) not in (3,4) or any(type(x) is not str for x in args): return None
    args = list(args)
    if len(args) == 3 and args[:2] == ['docker','inspect']:
        family, ident = 'containers', args[2]
    elif len(args) == 4 and args[0] == 'docker' and args[2] == 'inspect' and args[1] in ('container','network','image'):
        family, ident = {'container':'containers','network':'networks','image':'images'}[args[1]], args[3]
    else: return None
    raw = ident[7:] if family == 'images' and ident.startswith('sha256:') else ident
    if not ID.fullmatch(raw): return None
    return '/v'+API+'/'+family+'/'+ident+('' if family == 'networks' else '/json')


class _Stream:
    def __init__(self, fd, deadline): self.fd, self.deadline, self.header = fd, deadline, 0
    def _ready(self, write=False):
        remaining = self.deadline-time.monotonic()
        if remaining <= 0: raise TimeoutError()
        readable,writable,_ = select.select([] if write else [self.fd],[self.fd] if write else [],[],remaining)
        if not (writable if write else readable): raise TimeoutError()
    def read(self,n=-1):
        if type(n) is not int or n < 0 or n > MAX_BODY+1: _fail()
        chunks = bytearray()
        while len(chunks) < n:
            self._ready(); part = os.read(self.fd,min(n-len(chunks),65536))
            if not part: raise EOFError()
            chunks.extend(part)
        return bytes(chunks)
    def readline(self,limit=-1):
        out = bytearray()
        while True:
            out.extend(self.read(1)); self.header += 1
            if self.header > MAX_HEADER or len(out) > 8192: _fail()
            if out[-1] == 10 or (limit >= 0 and len(out) >= limit): return bytes(out)
    def close(self): pass
    def flush(self): pass


class _Adapter:
    def __init__(self,stream): self.stream = stream
    def makefile(self,*_args,**_kwargs): return self.stream


def _send(fd, payload, deadline):
    view = memoryview(payload)
    while view:
        left = deadline-time.monotonic()
        if left <= 0 or not select.select([],[fd],[],left)[1]: raise TimeoutError()
        n = os.write(fd,view)
        if n <= 0: _fail()
        view = view[n:]


def _request(process, path, deadline):
    valid = (r'/version|/v1\.56/containers/[0-9a-f]{64}/json|'
             r'/v1\.56/networks/[0-9a-f]{64}|/v1\.56/images/(?:sha256:)?[0-9a-f]{64}/json')
    if not re.fullmatch(valid,path): _fail()
    payload = ('GET '+path+' HTTP/1.1\r\nHost: docker\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n').encode('ascii')
    _send(process.stdin.fileno(),payload,deadline)
    stream = _Stream(process.stdout.fileno(),deadline)
    response = http.client.HTTPResponse(_Adapter(stream))
    try:
        response.begin()
        headers = response.getheaders()
        def all_values(key): return [v.strip() for k,v in headers if k.lower() == key]
        lengths, transfers = all_values('content-length'), all_values('transfer-encoding')
        encoding, types, connections = all_values('content-encoding'), all_values('content-type'), all_values('connection')
        if (response.status != 200 or response.version != 11 or response.will_close or
            len(encoding) > 1 or (encoding and encoding[0].lower() != 'identity') or
            len(types) != 1 or types[0].split(';',1)[0].strip().lower() != 'application/json' or
            len(connections) > 1 or (connections and connections[0].lower() != 'keep-alive')): _fail()
        if transfers:
            if len(transfers) != 1 or transfers[0].lower() != 'chunked' or lengths or not response.chunked: _fail()
            body = response.read(MAX_BODY+1)
        else:
            if len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,8}',lengths[0]): _fail()
            length = int(lengths[0])
            if not 0 < length <= MAX_BODY or response.length != length: _fail()
            body = response.read(length)
            if len(body) != length: _fail()
        if not 0 < len(body) <= MAX_BODY: _fail()
        return _parse(body)
    finally:
        response.close()


def _stop(process):
    if process is None: return
    try:
        if process.stdin: process.stdin.close()
    except OSError: pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait(timeout=3)
    finally:
        if process.stdout: process.stdout.close()


def _version(argv, env, deadline):
    process = subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                               env=env,close_fds=True,bufsize=0)
    data = bytearray()
    try:
        fd = process.stdout.fileno()
        while True:
            left = deadline-time.monotonic()
            if left <= 0 or not select.select([fd],[],[],left)[0]: raise TimeoutError()
            chunk = os.read(fd,65536)
            if not chunk: break
            data.extend(chunk)
            if len(data) > MAX_BODY: _fail()
        left = deadline-time.monotonic()
        if left <= 0 or process.wait(timeout=left) != 0: _fail()
        return _parse(bytes(data))
    finally: _stop(process)


class Session:
    def __init__(self, *, docker, sha256, socket, config):
        if docker != DOCKER or sha256 != DOCKER_SHA256 or socket != SOCKET: _fail()
        if not isinstance(config,str) or not Path(config).is_absolute(): _fail()
        self.docker,self.socket,self.config = docker,socket,config
        self.process = None; self.active = False; self.calls = 0; self.deadline = None
        self.tool = self.endpoint = self.directory = None
        self._guard = threading.Lock(); self._cancel = threading.Event()

    def _context(self, deadline=None):
        limit = min(self.deadline,deadline) if deadline is not None and self.deadline is not None else (deadline or self.deadline)
        if limit is not None and time.monotonic() >= limit: raise TimeoutError()
        if _tool(self.docker) != self.tool or _socket(self.socket) != self.endpoint or _config(self.config) != self.directory: _fail()
        if limit is not None and time.monotonic() >= limit: raise TimeoutError()
        if self.process is not None and self.process.poll() is not None: _fail()

    def __enter__(self):
        return self.start()

    def start(self, deadline=None):
        if not self._guard.acquire(blocking=False):
            self._cancel.set()
            raise MetadataError('metadata session failed') from None
        try:
            if self._cancel.is_set() or self.active or self.process is not None or self.deadline is not None: _fail()
            self.deadline = time.monotonic()+SESSION_SECONDS
            limit = min(self.deadline, deadline) if deadline is not None else self.deadline
            if time.monotonic() >= limit: raise TimeoutError()
            self.tool = _tool(self.docker,True); self.endpoint = _socket(self.socket); self.directory = _config(self.config)
            env = {'PATH':'/usr/bin:/bin','DOCKER_CONFIG':self.config}
            if 'HOME' in os.environ: env['HOME'] = os.environ['HOME']
            prefix = [self.docker,'--config',self.config,'--host','unix://'+self.socket]
            if time.monotonic() >= limit: raise TimeoutError()
            version = _version(prefix+['version','--format','{{json .}}'],env,min(limit,time.monotonic()+OP_SECONDS))
            if not isinstance(version,dict) or not isinstance(version.get('Client'),dict) or not isinstance(version.get('Server'),dict): _fail()
            if version['Client'].get('ApiVersion') != API or version['Server'].get('ApiVersion') != API: _fail()
            self._context(limit)
            if self._cancel.is_set(): _fail()
            self.process = subprocess.Popen(prefix+['system','dial-stdio'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL,env=env,close_fds=True,bufsize=0)
            server = _request(self.process,'/version',min(limit,time.monotonic()+OP_SECONDS))
            if not isinstance(server,dict) or server.get('ApiVersion') != API or self._cancel.is_set(): _fail()
            self._context(limit); self.active = True
            return self
        except BaseException as error:
            self._close()
            if isinstance(error,(KeyboardInterrupt,SystemExit)): raise
            raise MetadataError('metadata session failed') from None
        finally:
            self._guard.release()

    def read(self,args,deadline=None):
        route = _route(args)
        if route is None: return None
        if not self._guard.acquire(blocking=False):
            self._cancel.set()
            raise MetadataError('metadata session failed') from None
        try:
            if self._cancel.is_set() or not self.active or self.calls >= MAX_CALLS: _fail()
            limit = min(self.deadline,deadline) if deadline is not None else self.deadline
            self._context(limit); self.calls += 1
            item = _request(self.process,route,min(limit,time.monotonic()+OP_SECONDS))
            if self._cancel.is_set() or not isinstance(item,dict): _fail()
            self._context(limit)
            if self._cancel.is_set() or time.monotonic() >= limit: _fail()
            return [item]
        except BaseException as error:
            self._close()
            if isinstance(error,(KeyboardInterrupt,SystemExit)): raise
            raise MetadataError('metadata session failed') from None
        finally:
            self._guard.release()

    def _close(self):
        self.active = False
        p, self.process = self.process, None
        try: _stop(p)
        except BaseException: raise MetadataError('metadata session cleanup failed') from None

    def __exit__(self,exc_type,exc,tb):
        acquired = self._guard.acquire(blocking=False)
        if not acquired:
            self._cancel.set()
            acquired = self._guard.acquire(timeout=2*OP_SECONDS+2)
        if not acquired: raise MetadataError('metadata session cleanup failed') from None
        try:
            try:
                if self.active and not self._cancel.is_set(): self._context()
            finally: self._close()
            if self._cancel.is_set(): _fail()
        except BaseException:
            raise MetadataError('metadata session failed') from None
        finally:
            self._guard.release()
        return False


# Qualification-only dispatch scope. Each participating thread owns a separate
# proxy; sharing one response stream across threads is prohibited.
import contextlib
import contextvars

_ACTIVE = contextvars.ContextVar('apicontour_fresh_metadata', default=None)


class _Pool:
    def __init__(self, proof, config):
        self.proof = proof; self.config = config; self.sessions = {}
        self.lock = threading.Lock(); self.closed = False

    def _session(self,timeout,deadline):
        current = threading.current_thread()
        remaining = deadline-time.monotonic()
        if remaining <= 0 or not self.lock.acquire(timeout=remaining): raise TimeoutError('metadata deadline')
        try:
            if self.closed: _fail()
            if time.monotonic() >= deadline: raise TimeoutError('metadata deadline')
            session = self.sessions.get(current)
            if session is not None and (session.calls >= MAX_CALLS-1 or time.monotonic()+max(2*OP_SECONDS+2,timeout+2) >= session.deadline):
                session.__exit__(None,None,None); del self.sessions[current]; session = None
                if time.monotonic() >= deadline: raise TimeoutError('metadata deadline')
            if session is None:
                session = Session(docker=DOCKER,sha256=DOCKER_SHA256,socket=SOCKET,config=str(self.config))
                session.start(deadline); self.sessions[current] = session
            if time.monotonic() >= deadline:
                session.__exit__(None,None,None); del self.sessions[current]
                raise TimeoutError('metadata deadline')
            return session
        finally: self.lock.release()

    def command(self,args,timeout,env,runner,deadline=None):
        if deadline is None: deadline = time.monotonic()+timeout
        if time.monotonic() >= deadline: raise TimeoutError('metadata deadline')
        session = self._session(timeout,deadline)
        route = _route(args)
        if route is not None:
            value = session.read(args,deadline=deadline)
            encoded = json.dumps(value,separators=(',',':'),allow_nan=False).encode('utf-8')
            if time.monotonic() >= deadline: raise TimeoutError('metadata deadline')
            return encoded
        if not session._guard.acquire(blocking=False):
            session._cancel.set(); _fail()
        try:
            if session._cancel.is_set() or not session.active: _fail()
            session._context(deadline)
            try:
                remaining = deadline-time.monotonic()
                if remaining <= 0: raise TimeoutError('metadata deadline')
                result = runner([DOCKER,'--config',str(self.config),'--host','unix://'+SOCKET,*args[1:]],'',deadline=remaining,env=env)
            finally:
                session._context(deadline)
            if session._cancel.is_set() or time.monotonic() >= deadline: _fail()
            encoded = result.encode('utf-8')
            if session._cancel.is_set() or time.monotonic() >= deadline: _fail()
            return encoded
        finally:
            session._guard.release()
            if self.closed and session.active: session.__exit__(None,None,None)

    def close(self):
        with self.lock:
            self.closed = True; sessions = list(self.sessions.values()); self.sessions.clear()
        failures = []
        for session in sessions:
            try: session.__exit__(None,None,None)
            except BaseException as error: failures.append(error)
        if failures: raise BaseExceptionGroup('metadata pool cleanup failed',failures)


def dispatch(args,timeout,env,runner):
    """Return None when no private scope is bound; never retry a failed read."""
    started = time.monotonic()
    pool = _ACTIVE.get()
    return None if pool is None else pool.command(args,timeout,env,runner,started+timeout)


@contextlib.contextmanager
def qualification_scope(proof):
    from deploy.local import origin21_managed_qualification as qualification
    if type(proof) is not qualification.OwnedManagedQualification or _ACTIVE.get() is not None: _fail()
    proof.verify()
    config = proof.folder/'docker-metadata-config'
    os.mkdir(config,0o700)
    pool = _Pool(proof,config); token = None; error = None
    try:
        proof.verify(); _config(str(config))
        token = _ACTIVE.set(pool)
        yield
    except BaseException as exc:
        error = exc
        raise
    finally:
        if token is not None: _ACTIVE.reset(token)
        failures = []
        try: pool.close()
        except BaseException as exc: failures.append(exc)
        if not failures:
            try:
                proof.verify(); _config(str(config)); os.rmdir(config)
            except BaseException as exc: failures.append(exc)
        if failures:
            if error is not None: raise BaseExceptionGroup('metadata scope and cleanup failed',[error,*failures]) from None
            if len(failures) == 1: raise failures[0]
            raise BaseExceptionGroup('metadata scope cleanup failed',failures)
