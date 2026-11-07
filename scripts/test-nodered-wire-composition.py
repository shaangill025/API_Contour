#!/usr/bin/env python3
"""Qualify seven synthetic inactive Node modes; no production authority is created."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
IMAGE = 'docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963'
LABEL = 'org.apicontour.node-component-run'
MODES = {
    'exporter': ['mTLS accepted receipt','duplicate receipt','explicit retry preserves batch','events during flight survive','close prevents late acknowledgement','wrong-name certificate trusted control','wrong CA rejects before HTTP','wrong hostname rejects before HTTP'],
    'wire-positive': ['synthetic pinned Node-RED mTLS causal wire fixture'],
    'wire-hook': ['synthetic pinned Node-RED live hook invalidation; forwarding unmarked'],
    'wire-cache': ['synthetic pinned Node-RED live cache invalidation; forwarding unmarked'],
    'wire-composition': ['synthetic factory handoff fenced exporter mTLS composition'],
    'wire-composition-hook': ['synthetic composition hook held ACK invalidation; forwarding unmarked'],
    'wire-composition-cache': ['synthetic composition cache held ACK invalidation; forwarding unmarked'],
}


def command(args, timeout=30, limit=1_048_576, cwd=ROOT):
    """Bound combined output and kill the owned process group on failure to finish."""
    p = subprocess.Popen(args, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, start_new_session=True)
    data = bytearray(); sel = selectors.DefaultSelector(); sel.register(p.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    complete = False
    try:
        while sel.get_map():
            left = deadline - time.monotonic()
            if left <= 0: raise TimeoutError('command deadline')
            for key, _ in sel.select(left):
                chunk = os.read(key.fd, min(65536, limit + 1 - len(data)))
                if not chunk: sel.unregister(key.fileobj)
                else:
                    data.extend(chunk)
                    if len(data) > limit: raise RuntimeError('command output bound')
        code = p.wait(timeout=max(0.01, deadline-time.monotonic()))
        complete = True
        return code, bytes(data)
    finally:
        sel.close()
        signal_error = None
        if not complete:
            try: os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            except OSError as error: signal_error = error
        wait_error = None
        try:
            if p.poll() is None: p.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            wait_error = error
        finally:
            p.stdout.close()
        if signal_error is not None:
            raise RuntimeError('process group signal denied') from signal_error
        if wait_error is not None:
            raise RuntimeError('process cleanup timeout') from wait_error


def checked(args, timeout=30, limit=1_048_576):
    code, data = command(args, timeout, limit)
    if code != 0: raise RuntimeError('command failed')
    return data


def head_and_clean():
    head = checked(['git','rev-parse','HEAD'], 15, 256).strip().decode('ascii')
    if not re.fullmatch(r'[0-9a-f]{40}',head): raise RuntimeError('source head invalid')
    if checked(['git','status','--porcelain','--untracked-files=all'], 15, 65536): raise RuntimeError('source not clean')
    return head


def snapshot():
    result = {}
    for base in (ROOT/'collectors/nodered', ROOT/'tests/fixtures/nodered-causal'):
        for part in (base,*base.parents):
            if part.is_symlink(): raise RuntimeError('source symlink')
        if not base.is_dir(): raise RuntimeError('source missing')
        def onerror(error): raise error
        for directory, dirs, files in os.walk(base, followlinks=False, onerror=onerror):
            for name in dirs + files:
                path = Path(directory)/name
                if path.is_symlink(): raise RuntimeError('source symlink')
                if path.is_file(): result[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
                elif not path.is_dir(): raise RuntimeError('source type')
    # These files define the harness and must also stay unchanged.
    for path in (Path(__file__), ROOT/'tests/fixtures/nodered-wire-composition/test_driver.py'):
        if path.is_symlink() or not path.is_file(): raise RuntimeError('source missing')
        result[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def verify_profile(snapshot_values):
    fixed = {
        'collectors/nodered/error-integration/wire-v2-profile.js': 'dea4caff5cde9f25151d967f130623d27ceceb218e29e88865cd4b794ac23653',
        'collectors/nodered/error-integration/wire-v2-image-manifest.json': '63560c3dbe43d22c9391d0ac2e46dbad1d428f5b8ea8418b2a9038322da2ad0b',
        'tests/fixtures/nodered-causal/image-private-causal-exporter.js': '1d8da5afc5dac8586e4bc668f71c4be430355a30a0da7805a18013bac74511c8',
    }
    if any(snapshot_values.get(path) != digest for path,digest in fixed.items()): raise RuntimeError('fixed source mismatch')
    profile = ROOT/'collectors/nodered/error-integration/wire-v2-profile.js'
    text = profile.read_text()
    entries = re.findall(r"'(/(?:adapter|fixture)/[^']+)':'([0-9a-f]{64})'",text)
    if len(entries) != 15 or len(dict(entries)) != 15 or IMAGE not in text: raise RuntimeError('profile mismatch')
    for path, digest in entries:
        rel = ('collectors/nodered/'+path[len('/adapter/'):] if path.startswith('/adapter/')
               else 'tests/fixtures/nodered-causal/'+path[len('/fixture/'):])
        if snapshot_values.get(rel) != digest: raise RuntimeError('profile source mismatch')


WIRE_WARNING = (b'(node:1) ExperimentalWarning: vm.USE_MAIN_CONTEXT_DEFAULT_LOADER is an experimental feature and might change at any time\n'
                b'(Use `node --trace-warnings ...` to show where the warning was created)\n')

def validate_mode(mode, output, status):
    if mode not in MODES or status != '0': raise RuntimeError('qualification failed')
    expected = (b'' if mode == 'exporter' else WIRE_WARNING)
    expected += b''.join(b'PASS: '+stage.encode()+b'\n' for stage in MODES[mode])
    if output != expected: raise RuntimeError('qualification output mismatch')


def validate_owned(obj, name, token, cid, image_id):
    if not re.fullmatch(r'[0-9a-f]{64}',cid) or obj.get('Id') != cid or obj.get('Name') != '/'+name: raise RuntimeError('container identity mismatch')
    config=obj.get('Config') or {}; labels=config.get('Labels') or {}
    if (config.get('Image') != IMAGE or obj.get('Image') != image_id or labels.get(LABEL) != token
            or any(k.startswith('com.docker.compose.') for k in labels) or (obj.get('HostConfig') or {}).get('NetworkMode') != 'none'):
        raise RuntimeError('container ownership mismatch')


def inspect(ref):
    code, data = command(['docker','inspect',ref],10,262144)
    if code: return None
    objects=json.loads(data)
    if not isinstance(objects,list) or len(objects)!=1: raise RuntimeError('container inspection invalid')
    return objects[0]


def owned(cid,name,token,image_id):
    obj=inspect(cid)
    if obj is None: raise RuntimeError('container unavailable')
    validate_owned(obj,name,token,cid,image_id)


def sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def durable_intent(folder, value):
    path=folder/'owner-intent.json'
    with path.open('x') as f:
        os.fchmod(f.fileno(),0o600); json.dump(value,f,sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
    sync_directory(folder)


def make_certificates(certs):
    for ca in ('ca','untrusted-ca'):
        checked(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=APIContour inert '+ca,'-keyout',str(certs/(ca+'-key')),'-out',str(certs/ca),'-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'])
    for serial,kind,san,purpose in ((1,'server','IP:127.0.0.1,DNS:pilot-destination','serverAuth'),(2,'wrong-name-server','DNS:wrong.example','serverAuth'),(3,'client',None,'clientAuth'),(4,'export-client',None,'clientAuth')):
        extension=certs/(kind+'.extensions')
        extension.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+purpose+'\n'+('subjectAltName='+san+'\n' if san else ''))
        checked(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=APIContour inert '+kind,'-keyout',str(certs/(kind+'-key')),'-out',str(certs/(kind+'.csr'))])
        checked(['openssl','x509','-req','-in',str(certs/(kind+'.csr')),'-CA',str(certs/'ca'),'-CAkey',str(certs/'ca-key'),'-set_serial',str(serial),'-days','1','-extfile',str(extension),'-out',str(certs/kind)])
        checked(['openssl','verify','-purpose','sslserver' if purpose=='serverAuth' else 'sslclient','-CAfile',str(certs/'ca'),str(certs/kind)])
    checked(['openssl','verify','-verify_hostname','wrong.example','-CAfile',str(certs/'ca'),str(certs/'wrong-name-server')])
    for kind in ('client','export-client'):
        der=checked(['openssl','x509','-in',str(certs/kind),'-outform','DER'])
        public=checked(['openssl','pkey','-in',str(certs/(kind+'-key')),'-pubout','-outform','DER'])
        if kind=='client': product=(hashlib.sha256(der).digest(),hashlib.sha256(public).digest())
        elif hashlib.sha256(der).digest()==product[0] or hashlib.sha256(public).digest()==product[1]:
            raise RuntimeError('fixture identities identical')


def run_mode(mode, folder, certs, image_id):
    if mode not in MODES: raise ValueError('unsupported mode')
    token=uuid.uuid4().hex; name='contour-node-component-'+token
    view=ROOT/'tests/fixtures/nodered-causal'
    entry=['/fixture/image-private-causal-exporter.js'] if mode=='exporter' else ['--require','/adapter/error-integration/wire-v2-bootstrap.js','/fixture/image-wire-v2-fixture.js']
    if mode not in ('exporter','wire-positive'):
        view=folder/'fixture-view'; shutil.copytree(ROOT/'tests/fixtures/nodered-causal',view,symlinks=False)
        original=ROOT/'tests/fixtures/nodered-causal'
        for path in original.rglob('*'):
            if path.is_symlink(): raise RuntimeError('source symlink')
            if path.is_file() and (view/path.relative_to(original)).read_bytes()!=path.read_bytes(): raise RuntimeError('fixture copy mismatch')
        (view/'qualification-mode.json').write_text(json.dumps({'mode':mode.removeprefix('wire-')}))
    mounts=['-v',str(ROOT/'collectors/nodered')+':/adapter:ro','-v',str(view)+':/fixture:ro','-v',str(certs)+':/fixture-tls:ro']
    durable_intent(folder,{'name':name,'label':LABEL,'token':token,'image':IMAGE,'image_id':image_id,'mode':mode})
    args=['docker','create','--name',name,'--hostname','causal-wire-v2','--label',LABEL+'='+token,
          '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
          '--memory','256m','--cpus','1','--pids-limit','128','--user',str(os.getuid())+':'+str(os.getgid()),
          '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777','--tmpfs','/data:rw,nosuid,nodev,noexec,size=16m,mode=1777',
          '-e','HOME=/data','-e','LANG=C.UTF-8','-e','TZ=UTC','-e','NODE_OPTIONS=','-e','NODE_PATH=/usr/src/node-red/node_modules',
          *mounts,'--entrypoint','node',IMAGE,*entry]
    cid=None; ambiguous=True; failure=None
    try:
        raw=checked(args,30,1024).strip().decode('ascii')
        if not re.fullmatch(r'[0-9a-f]{64}',raw): raise RuntimeError('container id invalid')
        cid=raw; owned(cid,name,token,image_id); ambiguous=False
        checked(['docker','start',cid],30,1024)
        status=checked(['docker','wait',cid],60,1024).strip().decode('ascii')
        output=checked(['docker','logs',cid],10,1_048_576)
        validate_mode(mode,output,status)
    except BaseException as exc:
        failure=exc
    finally:
        try:
            if ambiguous and cid is None:
                # Name reconciliation can permit cleanup, never acceptance.
                for _ in range(3):
                    obj=inspect(name)
                    if obj is not None:
                        candidate=obj.get('Id',''); validate_owned(obj,name,token,candidate,image_id); cid=candidate; break
                    time.sleep(.2)
            if cid is not None:
                owned(cid,name,token,image_id)
                checked(['docker','rm','-f','-v',cid],30,1024)
                if checked(['docker','ps','-aq','--no-trunc','--filter','id='+cid],10,1024).strip(): raise RuntimeError('container still present')
                if checked(['docker','ps','-aq','--no-trunc','--filter','name=^/'+name+'$'],10,1024).strip(): raise RuntimeError('container name still present')
            if ambiguous: raise RuntimeError('ambiguous container creation')
        except BaseException as exc:
            if failure is not None: raise RuntimeError('qualification and cleanup failed') from exc
            raise
    if failure is not None: raise failure


def main():
    if len(sys.argv)!=1: raise ValueError('no arguments accepted')
    if os.getuid()==0: raise RuntimeError('nonroot required')
    os.umask(0o077)
    head=head_and_clean(); before=snapshot(); verify_profile(before)
    image=json.loads(checked(['docker','image','inspect',IMAGE],20,262144))
    if not isinstance(image,list) or len(image)!=1: raise RuntimeError('image inspection invalid')
    image_id=image[0].get('Id','')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',image_id): raise RuntimeError('image identity invalid')
    # Resolve platform temp aliases (e.g. /var -> /private/var) before mounting.
    parent=Path(os.path.realpath(tempfile.gettempdir()))
    folder=Path(tempfile.mkdtemp(prefix='contour-node-qualification-',dir=parent)).resolve(strict=True)
    os.chmod(folder,0o700); sync_directory(parent)
    print('Private qualification directory: '+str(folder),flush=True)
    certs=folder/'tls'; certs.mkdir(mode=0o700)
    passed=[]; failure=None
    try:
        make_certificates(certs)
        for index,mode in enumerate(MODES):
            if head_and_clean()!=head or snapshot()!=before: raise RuntimeError('source changed')
            mode_dir=folder/('%02d-%s'%(index,mode)); mode_dir.mkdir(mode=0o700)
            sync_directory(folder)
            run_mode(mode,mode_dir,certs,image_id)
            passed.append(mode); print('PASS: '+mode,flush=True)
    except BaseException as exc: failure=exc
    finally:
        try:
            shutil.rmtree(certs)
            if certs.exists(): raise RuntimeError('certificate cleanup failed')
            if head_and_clean()!=head or snapshot()!=before: raise RuntimeError('source changed')
        except BaseException as exc:
            if failure is not None: raise RuntimeError('qualification and cleanup failed') from exc
            raise
    if failure is not None: raise failure
    if passed != list(MODES): raise RuntimeError('qualification incomplete')
    print('PASS: seven synthetic inactive Node modes; no production authority',flush=True)


if __name__=='__main__':
    try: main()
    except BaseException as exc:
        print('FAIL: '+type(exc).__name__,file=sys.stderr)
        raise SystemExit(1) from None
