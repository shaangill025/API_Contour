#!/usr/bin/env python3
"""Owned Node-RED receiver seam runner; no production/profile authority."""
import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
SOCKET = 'unix:///Users/shaanjotgill/.docker/run/docker.sock'
DOCKER_PATH = '/Users/shaanjotgill/Library/Caches/APIContour/tools/docker-29.8.2-31ae2d64/docker'
DOCKER_HASH = '31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f'
OWNER = 'org.apicontour.fixture-owner'
DATA_TMPFS = 'rw,noexec,nosuid,size=16m,uid=%d,gid=%d,mode=0700' % (os.getuid(),os.getgid())
TMP_TMPFS = 'rw,noexec,nosuid,size=16m'
PARENT_COMMAND = 'exec 3<&0 0<&-; exec /usr/local/bin/node /work/tests/fixtures/receiver504-actual/parent.js'
SCRIPTS = {'component': ('/work/tests/fixtures/receiver504-actual/parent.js', b'PASS phase=receiver504_component checks=1,1,1\n')}
HEX = re.compile(r'^[0-9a-f]{64}$')
SHA = re.compile(r'^sha256:[0-9a-f]{64}$')


def fail(message): raise ValueError(message)


def shared_module():
    spec = importlib.util.spec_from_file_location('owned_runner', ROOT / 'scripts/qualify-origin21-onboarding.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def safe_file(path, limit):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts: fail('file path')
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit or before.st_size < 1: fail('file type')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        held = os.fstat(fd)
        fields = ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
        if any(getattr(before,k) != getattr(held,k) for k in fields): fail('file identity')
        h = hashlib.sha256(); chunks = []; remain = held.st_size
        while remain:
            chunk = os.read(fd, min(remain, 1048576))
            if not chunk: fail('file truncated')
            h.update(chunk); chunks.append(chunk); remain -= len(chunk)
        after = os.fstat(fd); current = os.lstat(path)
        if any(getattr(before,k) != getattr(after,k) or getattr(before,k) != getattr(current,k) for k in fields): fail('file changed')
        return b''.join(chunks), h.hexdigest()
    finally: os.close(fd)


def receipt_parent(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or not path.name: fail('receipt path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    chain = []
    try:
        parts = path.parts[1:-1]
        for index in range(len(parts) + 1):
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0,os.geteuid()) or st.st_mode & 0o022:
                fail('receipt ancestor')
            if index == len(parts) and (st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700):
                fail('receipt parent')
            chain.append((st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid))
            if index < len(parts):
                child = os.open(parts[index],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd); fd = child
        return fd, tuple(chain)
    except BaseException:
        os.close(fd)
        raise


def receipt_file(path):
    path = Path(path); parent, chain = receipt_parent(path); fd = None
    try:
        fd = os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        before = os.fstat(fd)
        def valid(st):
            return (stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
                    stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1 and 0 < st.st_size <= 1048576)
        if not valid(before): fail('receipt file')
        parts = []; remaining = before.st_size
        while remaining:
            chunk = os.read(fd,min(remaining,65536))
            if not chunk: fail('receipt truncated')
            parts.append(chunk); remaining -= len(chunk)
        again, final_chain = receipt_parent(path)
        try:
            current = os.stat(path.name,dir_fd=again,follow_symlinks=False)
            after = os.fstat(fd)
            fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
            if final_chain != chain or not valid(current) or not valid(after) or any(
                    getattr(before,k) != getattr(current,k) or getattr(before,k) != getattr(after,k) for k in fields):
                fail('receipt changed')
        finally: os.close(again)
        raw = b''.join(parts)
        return raw, hashlib.sha256(raw).hexdigest()
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


def tool_snapshot(path, hash_content=False):
    """Observe the private executable and protected parent chain without following links."""
    path = Path(path); parent, chain = receipt_parent(path); fd = None
    try:
        fd = os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        before = os.fstat(fd)
        def valid(st):
            return (stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
                    stat.S_IMODE(st.st_mode) == 0o500 and st.st_nlink == 1 and
                    0 < st.st_size <= 256 * 1024 * 1024)
        if not valid(before): fail('docker file')
        h = hashlib.sha256() if hash_content else None
        if h is not None:
            remaining = before.st_size
            while remaining:
                chunk = os.read(fd,min(remaining,1048576))
                if not chunk: fail('docker truncated')
                h.update(chunk); remaining -= len(chunk)
        again, final_chain = receipt_parent(path)
        try:
            current = os.stat(path.name,dir_fd=again,follow_symlinks=False); after = os.fstat(fd)
            fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
            if final_chain != chain or not valid(current) or not valid(after) or any(
                    getattr(before,k) != getattr(current,k) or getattr(before,k) != getattr(after,k) for k in fields):
                fail('docker changed')
        finally: os.close(again)
        return (chain, tuple(getattr(before,k) for k in fields)), h.hexdigest() if h else None
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


def pairs(items):
    result = {}
    for k,v in items:
        if k in result: fail('duplicate JSON key')
        result[k] = v
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: fail('JSON number'))


def receipt(raw):
    data = parse(raw)
    if not isinstance(data,dict) or not HEX.fullmatch(data.get('token','')): fail('receipt token')
    if data.get('scope') != 'version-native-bcrypt-config-and-layer-prefix': fail('receipt scope')
    images = data.get('images')
    if not isinstance(images,dict) or set(images) != {'arm64','amd64'}: fail('receipt images')
    for arch in images:
        row = images[arch]
        if not isinstance(row,dict) or not isinstance(row.get('image'),str) or not SHA.fullmatch(row['image']): fail('receipt image')
        probe = row.get('probe')
        if not isinstance(probe,dict) or not isinstance(probe.get('sha256'),str) or not HEX.fullmatch(probe['sha256']): fail('receipt probe')
        if any(type(probe.get(k)) is not int or probe[k] < 0 for k in ('size','mode','uid','gid','user')) or probe['size'] == 0 or probe['user'] != 1000: fail('receipt probe attributes')
    return data


def one(raw):
    value = parse(raw)
    if not isinstance(value,list) or len(value) != 1 or not isinstance(value[0],dict): fail('inspect')
    return value[0]


def check_image(value, image_id, arch, owner):
    if value.get('Id') != image_id or value.get('Os') != 'linux' or value.get('Architecture') != arch: fail('image identity')
    config = value.get('Config')
    if not isinstance(config,dict): fail('image config')
    env = config.get('Env'); labels = config.get('Labels')
    if not isinstance(env,list) or any(not isinstance(x,str) for x in env) or [x for x in env if x.startswith('NODE_VERSION=')] != ['NODE_VERSION=24.22.3']: fail('image version')
    if not isinstance(labels,dict) or labels.get(OWNER) != owner: fail('image owner')


MATERIAL_NAMES = ('ca.pem','product.pem','product.key','export.pem','export.key','server.pem','server.key','evidence.pem','evidence.key')

def material_snapshot(material):
    material=Path(material)
    if not material.is_absolute() or '..' in material.parts or ',' in str(material) or ':' in str(material): fail('material path')
    fd,chain=receipt_parent(material/'ca.pem')
    try:
        if sorted(os.listdir(fd))!=sorted(MATERIAL_NAMES): fail('material inventory')
    finally: os.close(fd)
    return chain,tuple((name,receipt_file(material/name)[1]) for name in MATERIAL_NAMES)

def mount_map(source,material):
    source=Path(source);material=Path(material)
    result={'/work/tests/fixtures/receiver504-actual/parent.js':str(source/'tests/fixtures/receiver504-actual/parent.js'),
            '/work/tests/fixtures/receiver504-bootstrap/vector.json':str(source/'tests/fixtures/receiver504-bootstrap/vector.json'),
            '/work/docs/specification/fixtures/causal-evidence-v1.json':str(source/'docs/specification/fixtures/causal-evidence-v1.json'),
            '/adapter':str(source/'collectors/nodered'),
            '/data/flows.json':str(source/'collectors/nodered/live-integration/flows.json'),
            '/adapter/live-integration/tree-arm64.json':str(source/'collectors/nodered/error-integration/wire-v2-image-manifest.json'),
            '/adapter/live-integration/tree-x64.json':str(source/'collectors/nodered/error-integration/wire-v2-image-manifest-x64.json')}
    for name in MATERIAL_NAMES:result['/run/apicontour/live/'+name]=str(material/name)
    return result

def validate(c, cid, token, image, script, source, material):
    cfg = c['Config']; host = c['HostConfig']; mounts = c['Mounts']
    if c['Id'] != cid or c['Image'] != image or cfg['Labels'].get(OWNER) != token: fail('container identity')
    if cfg['User'] != str(os.getuid())+':'+str(os.getgid()) or cfg['Hostname'] != 'causal-live' or cfg.get('OpenStdin') is not True or cfg.get('Tty') is not False or cfg.get('StdinOnce') is not True or cfg['Entrypoint'] != ['/bin/sh'] or cfg['Cmd'] != ['-c',PARENT_COMMAND] or script != SCRIPTS['component'][0]: fail('command')
    if (host['NetworkMode'] != 'none' or host['ReadonlyRootfs'] is not True or host['CapDrop'] != ['ALL']
        or host['SecurityOpt'] not in (['no-new-privileges'], ['no-new-privileges:true'])
        or host['Memory'] != 536870912 or host['PidsLimit'] != 32 or host['Privileged'] is not False
        or host['CapAdd'] not in (None,[]) or host['Devices'] not in (None,[])
        or host['PidMode'] not in ('','private') or host['IpcMode'] not in ('','private')
        or host['UTSMode'] not in ('','private') or host['UsernsMode'] not in ('','private')
        or host['PortBindings'] not in (None,{}) or host['PublishAllPorts'] is not False
        or host['AutoRemove'] is not False or host['RestartPolicy']['Name'] != 'no'): fail('container isolation')
    if host.get('OomKillDisable', 'missing') is not None and host.get('OomKillDisable', 'missing') is not False: fail('oom')
    if host['Tmpfs'] != {'/data':DATA_TMPFS,'/tmp':TMP_TMPFS}: fail('tmpfs')
    if not isinstance(mounts,list): fail('mount count')
    expected=mount_map(source,material)
    binds=[m for m in mounts if m.get('Type')=='bind']
    if len(binds)!=len(expected) or any(m.get('RW') is not False or expected.get(m.get('Destination'))!=m.get('Source') for m in binds) or {m.get('Destination') for m in binds}!=set(expected): fail('bind mounts')
    tmp=[m for m in mounts if m.get('Type')=='tmpfs']
    if len(mounts) not in (len(expected),len(expected)+2) or (tmp and (len(tmp)!=2 or {m.get('Destination') for m in tmp}!={'/data','/tmp'})): fail('mount count')
    if sorted(host.get('ExtraHosts') or [])!=sorted(['causal-receiver:127.0.0.1','causal-ingress:127.0.0.1','pilot-gateway:127.0.0.1']): fail('host aliases')
    if type(c['RestartCount']) is not int or c['RestartCount'] != 0: fail('restart')


def signature(c):
    result = copy.deepcopy({k:c[k] for k in ('Id','Image','Config','HostConfig','Mounts','Created')})
    if result['HostConfig']['OomKillDisable'] not in (None,False): fail('oom')
    result['HostConfig']['OomKillDisable'] = None
    return result


def created(c, cid, token, image, script, source, material):
    validate(c,cid,token,image,script,source,material)
    if c['State']['Status'] != 'created' or c['State']['Running'] is not False: fail('creation state')
    return signature(c)


def generation(c, cid, token, image, script, source, material, frozen):
    validate(c,cid,token,image,script,source,material)
    if signature(c) != frozen: fail('configuration drift')
    state = c['State']; started = state['StartedAt']
    if state['Status'] != 'exited' or state['Running'] is not False or type(state['ExitCode']) is not int or state['ExitCode'] != 0 or not isinstance(started,str): fail('exit state')
    match = re.fullmatch(r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z',started)
    if not match: fail('generation timestamp')
    try:
        parts = [int(x) for x in match.groups()[:6]]
        if parts[0] < 1970: fail('generation timestamp')
        datetime.datetime(*parts,tzinfo=datetime.timezone.utc)
    except ValueError: fail('generation timestamp')
    return started


def record(owner, name, value):
    if not re.fullmatch(r'(intent|cid|created|generation)-(arm64|amd64)-(component)\.json|source-before\.json|receipt\.json',name): fail('record name')
    owner.verify()
    fd = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=owner.fd)
    with os.fdopen(fd,'wb') as out:
        out.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')); out.flush(); os.fsync(out.fileno())
    os.fsync(owner.fd); owner.verify()


def run_case(docker, owner, arch, case, image, token, root, material, payload, payload_hash):
    script, expected = SCRIPTS[case]
    record(owner,'intent-'+arch+'-'+case+'.json',{'image':image,'owner':token,'architecture':arch,'script':script})
    cid = docker('create','--interactive','--platform','linux/'+arch,'--label',OWNER+'='+token,'--network','none',
        '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges', '--memory','512m', '--pids-limit','32',
        '--hostname','causal-live','--user',str(os.getuid())+':'+str(os.getgid()),
        '--add-host','causal-receiver:127.0.0.1','--add-host','causal-ingress:127.0.0.1','--add-host','pilot-gateway:127.0.0.1',
        '--tmpfs','/data:'+DATA_TMPFS,'--tmpfs','/tmp:'+TMP_TMPFS,
        *sum((['--mount','type=bind,src='+src+',dst='+dst+',readonly'] for dst,src in mount_map(root,material).items()),[]),
        '--entrypoint','/bin/sh',image,'-c',PARENT_COMMAND).decode('ascii').strip()
    if not HEX.fullmatch(cid): fail('created id')
    record(owner,'cid-'+arch+'-'+case+'.json',{'cid':cid,'image':image,'owner':token})
    frozen = created(one(docker('inspect',cid)),cid,token,image,script,root,material)
    record(owner,'created-'+arch+'-'+case+'.json',{'cid':cid,'signature':frozen})
    docker('start-private',cid,timeout=75,expect=expected,private_input=(payload,payload_hash))
    observed = generation(one(docker('inspect',cid)),cid,token,image,script,root,material,frozen)
    record(owner,'generation-'+arch+'-'+case+'.json',{'cid':cid,'started_at':observed})
    if generation(one(docker('inspect',cid)),cid,token,image,script,root,material,frozen) != observed: fail('generation changed')
    docker('rm',cid)
    if docker('ps','-a','--no-trunc','--filter','id='+cid,'--format','{{.ID}}').strip(): fail('container remains')
    return {'image':image,'generation':observed}


def socket_snapshot():
    path=Path(SOCKET.removeprefix('unix://'));fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);chain=[]
    try:
        for part in path.parent.parts[1:]:
            info=os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,os.getuid()) or info.st_mode&0o022:raise ValueError('socket ancestor')
            chain.append((info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid))
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
        info=os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,os.getuid()) or info.st_mode&0o022:raise ValueError('socket ancestor')
        chain.append((info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid))
        sock=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
        if not stat.S_ISSOCK(sock.st_mode) or sock.st_uid not in (0,os.getuid()):raise ValueError('socket')
        data={'ancestors':chain,'socket':(sock.st_dev,sock.st_ino,sock.st_mode,sock.st_uid,sock.st_gid)}
        return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest()
    finally:os.close(fd)

def endpoint_call(expected,observe,call):
    if observe()!=expected: fail('docker endpoint changed')
    try:return call()
    finally:
        if observe()!=expected: fail('docker endpoint changed')

PHASES=frozenset(('setup','tool','receipt','source','material','payload','endpoint','image','container','final','receipt-write'))

def failure_locations(error,depth=0):
    """Return only closed local source locations; never expose exception contents."""
    if depth>3:return []
    if isinstance(error,BaseExceptionGroup):
        return [x for item in error.exceptions[:8] for x in failure_locations(item,depth+1)][:8]
    result=[];tb=error.__traceback__
    while tb is not None:
        allowed={__file__:'qualify-receiver504.py',str(ROOT/'scripts/qualify-origin21-onboarding.py'):'qualify-origin21-onboarding.py'}
        name=allowed.get(tb.tb_frame.f_code.co_filename)
        if name is not None and 1<=tb.tb_lineno<=1000000:
            value=name+':'+str(tb.tb_lineno)
            if value not in result:result.append(value)
        tb=tb.tb_next
    return result[-8:]

def qualify(args, shared, run, owner, progress=None):
    def phase(value):
        if value not in PHASES:raise ValueError('phase')
        if progress is not None:progress['phase']=value
    phase('tool')
    if args.docker_sha256 != DOCKER_HASH: fail('unqualified docker hash')
    root = shared.checked_path(ROOT)
    if ',' in str(root) or ':' in str(root): fail('source mount path')
    cli = shared.checked_path(args.docker)
    if str(cli)!=DOCKER_PATH: fail('unqualified docker path')
    cli_identity, cli_hash = tool_snapshot(cli, True)
    if cli_hash != args.docker_sha256: fail('docker hash')
    phase('receipt')
    raw, receipt_hash = receipt_file(args.receipt)
    source_receipt = receipt(raw)
    phase('source')
    head, sources = shared.snapshot(run,root)
    fixtures = ('tests/fixtures/receiver504-actual/parent.js','tests/fixtures/receiver504-actual/exec_input.py')
    if any(name not in sources or not HEX.fullmatch(sources[name]) for name in fixtures): fail('fixture source missing')
    snapshot_hash = hashlib.sha256(json.dumps(sources,sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest()
    record(owner,'source-before.json',{'head':head,'source_sha256':snapshot_hash,'files':sources})
    phase('material')
    material=Path(args.material); material_before=material_snapshot(material)
    phase('payload')
    payload=Path(args.payload); private_bytes,payload_hash=receipt_file(payload)
    if len(private_bytes)>65536: fail('private input size')
    del private_bytes
    config = owner.path / 'docker-config'; config.mkdir(mode=0o700)
    token = uuid.uuid4().hex + uuid.uuid4().hex
    phase('endpoint')
    endpoint=socket_snapshot()
    stage_number = 0
    def docker(*parts,timeout=30,expect=None,private_input=None):
        nonlocal stage_number
        owner.verify()
        if tool_snapshot(cli)[0] != cli_identity: fail('docker identity')
        stage_number += 1
        path = owner.path / ('stage-%03d' % stage_number); path.mkdir(mode=0o700)
        stage = shared.OwnedDirectory(path); previous = run.owner
        try:
            run.owner = stage
            if private_input is not None:
                if len(parts)!=2 or parts[0]!='start-private' or not HEX.fullmatch(parts[1]): fail('private start')
                payload_path,payload_digest=private_input
                cmd=[sys.executable,str(root/'tests/fixtures/receiver504-actual/exec_input.py'),'--payload',str(payload_path),'--sha256',payload_digest,'--config',str(config),'--cid',parts[1],'--socket-sha256',endpoint]
            else:
                cmd = ['/usr/bin/env','-i','PATH=/usr/bin:/bin','DOCKER_CONFIG='+str(config)]
                if 'HOME' in os.environ: cmd.append('HOME='+os.environ['HOME'])
                cmd.extend([str(cli),'--host',SOCKET,*parts])
            output = endpoint_call(endpoint,socket_snapshot,lambda:run(cmd,cwd=root,timeout=timeout,log=path/'build.log'))
            if expect is not None:
                logged, _ = safe_file(path/'build.log', 65536)
                if output != expect or logged != expect+b'\n': fail('fixture output')
            return output
        finally:
            run.owner = previous; stage.close()
            if tool_snapshot(cli)[0] != cli_identity: fail('docker identity')
    results = {}
    for arch in ('arm64','amd64'):
        image = source_receipt['images'][arch]['image']
        phase('image')
        check_image(one(docker('image','inspect',image)),image,arch,source_receipt['token'])
        for case in SCRIPTS:
            phase('container')
            results[arch+'-'+case] = run_case(docker,owner,arch,case,image,token,root,material,payload,payload_hash)
    phase('final')
    if shared.snapshot(run,root) != (head,sources) or material_snapshot(material)!=material_before or receipt_file(payload)[1]!=payload_hash: fail('source or input changed')
    if receipt_file(args.receipt)[1] != receipt_hash or tool_snapshot(cli,True) != (cli_identity,cli_hash): fail('input changed')
    phase('receipt-write')
    record(owner,'receipt.json',{'head':head,'source_receipt_sha256':receipt_hash,'docker_sha256':cli_hash,'source_sha256':snapshot_hash,
        'fixture_sha256':{name:sources[name] for name in fixtures},
        'results':results,'scope':'receiver504-synthetic-local-component',
        'remaining_unverified':['receipt_and_image_association','publisher_provenance','profile504','loader','enrollment','deployment','sql','edge']})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--material',required=True); parser.add_argument('--payload',required=True); parser.add_argument('--receipt',required=True); parser.add_argument('--docker',required=True); parser.add_argument('--docker-sha256',required=True)
    args = parser.parse_args()
    if args.docker_sha256 != DOCKER_HASH: parser.error('unqualified docker sha256')
    os.umask(0o077); owner = None; progress={'phase':'setup'}
    try:
        shared = shared_module(); path = Path(tempfile.mkdtemp(prefix='contour-receiver-nodered-')).resolve(); path.chmod(0o700)
        owner = shared.OwnedDirectory(path)
        qualify(args,shared,shared.Runner(time.monotonic()+900,owner),owner,progress)
        print(json.dumps({'pass':True,'phase':'receiver504_synthetic_local_component','evidence_dir':str(path)}))
        return 0
    except BaseException as error:
        kind = type(error).__name__ if type(error).__name__ in ('ValueError','RuntimeError','TimeoutError','OSError','KeyError','TypeError','ExceptionGroup','BaseExceptionGroup') else 'Other'
        print(json.dumps({'pass':False,'phase':'receiver504_synthetic_local_component','error':kind,'stage':progress['phase'] if progress['phase'] in PHASES else 'setup','location':failure_locations(error),'evidence_dir':str(owner.path) if owner else None}))
        return 1
    finally:
        if owner is not None: owner.close()


if __name__ == '__main__': sys.exit(main())
