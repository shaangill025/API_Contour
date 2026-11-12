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
DOCKER_HASH = '31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f'
OWNER = 'org.apicontour.fixture-owner'
SCRIPTS = {
    'identity': ('/work/tests/fixtures/causal-receiver-nodered/actual.js', b'PASS phase=identity counts=3,3,3\n'),
    'mtls': ('/work/tests/fixtures/causal-receiver-incoming/host-mtls.js', b'receiver incoming host mTLS: passed\n'),
}
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
        if any(type(probe.get(k)) is not int or probe[k] < 0 for k in ('size','mode','uid','gid','user')) or probe['size'] == 0 or probe['user'] == 0: fail('receipt probe attributes')
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


def validate(c, cid, token, image, script, source):
    cfg = c['Config']; host = c['HostConfig']; mounts = c['Mounts']
    if c['Id'] != cid or c['Image'] != image or cfg['Labels'].get(OWNER) != token: fail('container identity')
    if cfg['User'] != 'node-red' or cfg['Entrypoint'] != ['/usr/local/bin/node'] or cfg['Cmd'] != [script]: fail('command')
    if (host['NetworkMode'] != 'none' or host['ReadonlyRootfs'] is not True or host['CapDrop'] != ['ALL']
        or host['SecurityOpt'] not in (['no-new-privileges'], ['no-new-privileges:true'])
        or host['Memory'] != 536870912 or host['PidsLimit'] != 32 or host['Privileged'] is not False
        or host['CapAdd'] not in (None,[]) or host['Devices'] not in (None,[])
        or host['PidMode'] not in ('','private') or host['IpcMode'] not in ('','private')
        or host['UTSMode'] not in ('','private') or host['UsernsMode'] not in ('','private')
        or host['PortBindings'] not in (None,{}) or host['PublishAllPorts'] is not False
        or host['AutoRemove'] is not False or host['RestartPolicy']['Name'] != 'no'): fail('container isolation')
    if host.get('OomKillDisable', 'missing') is not None and host.get('OomKillDisable', 'missing') is not False: fail('oom')
    if host['Tmpfs'] != {'/data':'rw,noexec,nosuid,size=16m','/tmp':'rw,noexec,nosuid,size=16m'}: fail('tmpfs')
    if not isinstance(mounts,list) or len(mounts) not in (1,3): fail('mount count')
    bind = [m for m in mounts if m.get('Destination') == '/work']
    if len(bind) != 1 or bind[0].get('Type') != 'bind' or bind[0].get('Source') != str(source) or bind[0].get('RW') is not False: fail('source mount')
    tmp = [m for m in mounts if m.get('Type') == 'tmpfs']
    if len(mounts) == 1:
        if tmp: fail('tmpfs mounts')
    elif len(tmp) != 2 or {m.get('Destination') for m in tmp} != {'/data','/tmp'}: fail('tmpfs mounts')
    if type(c['RestartCount']) is not int or c['RestartCount'] != 0: fail('restart')


def signature(c):
    result = copy.deepcopy({k:c[k] for k in ('Id','Image','Config','HostConfig','Mounts','Created')})
    if result['HostConfig']['OomKillDisable'] not in (None,False): fail('oom')
    result['HostConfig']['OomKillDisable'] = None
    return result


def created(c, cid, token, image, script, source):
    validate(c,cid,token,image,script,source)
    if c['State']['Status'] != 'created' or c['State']['Running'] is not False: fail('creation state')
    return signature(c)


def generation(c, cid, token, image, script, source, frozen):
    validate(c,cid,token,image,script,source)
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
    if not re.fullmatch(r'(intent|cid|created|generation)-(arm64|amd64)-(identity|mtls)\.json|source-before\.json|receipt\.json',name): fail('record name')
    owner.verify()
    fd = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=owner.fd)
    with os.fdopen(fd,'wb') as out:
        out.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')); out.flush(); os.fsync(out.fileno())
    os.fsync(owner.fd); owner.verify()


def run_case(docker, owner, arch, case, image, token, root):
    script, expected = SCRIPTS[case]
    record(owner,'intent-'+arch+'-'+case+'.json',{'image':image,'owner':token,'architecture':arch,'script':script})
    cid = docker('create','--platform','linux/'+arch,'--label',OWNER+'='+token,'--network','none',
        '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges', '--memory','512m', '--pids-limit','32',
        '--tmpfs','/data:rw,noexec,nosuid,size=16m','--tmpfs','/tmp:rw,noexec,nosuid,size=16m',
        '--mount','type=bind,src='+str(root)+',dst=/work,readonly', '--entrypoint','/usr/local/bin/node',image,script).decode('ascii').strip()
    if not HEX.fullmatch(cid): fail('created id')
    record(owner,'cid-'+arch+'-'+case+'.json',{'cid':cid,'image':image,'owner':token})
    frozen = created(one(docker('inspect',cid)),cid,token,image,script,root)
    record(owner,'created-'+arch+'-'+case+'.json',{'cid':cid,'signature':frozen})
    docker('start','--attach',cid,timeout=60,expect=expected)
    observed = generation(one(docker('inspect',cid)),cid,token,image,script,root,frozen)
    record(owner,'generation-'+arch+'-'+case+'.json',{'cid':cid,'started_at':observed})
    if generation(one(docker('inspect',cid)),cid,token,image,script,root,frozen) != observed: fail('generation changed')
    docker('rm',cid)
    if docker('ps','-a','--no-trunc','--filter','id='+cid,'--format','{{.ID}}').strip(): fail('container remains')
    return {'image':image,'generation':observed}


def qualify(args, shared, run, owner):
    if args.docker_sha256 != DOCKER_HASH: fail('unqualified docker hash')
    root = shared.checked_path(ROOT)
    if ',' in str(root) or ':' in str(root): fail('source mount path')
    cli = shared.checked_path(args.docker)
    cli_identity, cli_hash = tool_snapshot(cli, True)
    if cli_hash != args.docker_sha256: fail('docker hash')
    raw, receipt_hash = receipt_file(args.receipt)
    source_receipt = receipt(raw)
    head, sources = shared.snapshot(run,root)
    fixtures = ('tests/fixtures/causal-receiver-nodered/actual.js', 'tests/fixtures/causal-receiver-incoming/host-mtls.js')
    if any(name not in sources or not HEX.fullmatch(sources[name]) for name in fixtures): fail('fixture source missing')
    snapshot_hash = hashlib.sha256(json.dumps(sources,sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest()
    record(owner,'source-before.json',{'head':head,'source_sha256':snapshot_hash,'files':sources})
    config = owner.path / 'docker-config'; config.mkdir(mode=0o700)
    token = uuid.uuid4().hex + uuid.uuid4().hex
    stage_number = 0
    def docker(*parts,timeout=30,expect=None):
        nonlocal stage_number
        owner.verify()
        if tool_snapshot(cli)[0] != cli_identity: fail('docker identity')
        stage_number += 1
        path = owner.path / ('stage-%03d' % stage_number); path.mkdir(mode=0o700)
        stage = shared.OwnedDirectory(path); previous = run.owner
        try:
            run.owner = stage
            cmd = ['/usr/bin/env','-i','PATH=/usr/bin:/bin','DOCKER_CONFIG='+str(config)]
            if 'HOME' in os.environ: cmd.append('HOME='+os.environ['HOME'])
            cmd.extend([str(cli),'--host',SOCKET,*parts])
            output = run(cmd,cwd=root,timeout=timeout,log=path/'build.log')
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
        check_image(one(docker('image','inspect',image)),image,arch,source_receipt['token'])
        for case in SCRIPTS:
            results[arch+'-'+case] = run_case(docker,owner,arch,case,image,token,root)
    if shared.snapshot(run,root) != (head,sources): fail('source changed')
    if receipt_file(args.receipt)[1] != receipt_hash or tool_snapshot(cli,True) != (cli_identity,cli_hash): fail('input changed')
    record(owner,'receipt.json',{'head':head,'source_receipt_sha256':receipt_hash,'docker_sha256':cli_hash,'source_sha256':snapshot_hash,
        'fixture_sha256':{name:sources[name] for name in fixtures},
        'results':results,'scope':'receiver-nodered-local-mtls-seam',
        'remaining_unverified':['receipt_and_image_association','publisher_provenance','profile504','loader','enrollment','deployment','sql','edge']})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--receipt',required=True); parser.add_argument('--docker',required=True); parser.add_argument('--docker-sha256',required=True)
    args = parser.parse_args()
    if args.docker_sha256 != DOCKER_HASH: parser.error('unqualified docker sha256')
    os.umask(0o077); owner = None
    try:
        shared = shared_module(); path = Path(tempfile.mkdtemp(prefix='contour-receiver-nodered-')).resolve(); path.chmod(0o700)
        owner = shared.OwnedDirectory(path)
        qualify(args,shared,shared.Runner(time.monotonic()+900,owner),owner)
        print(json.dumps({'pass':True,'phase':'receiver_nodered_local_mtls_seam','evidence_dir':str(path)}))
        return 0
    except BaseException as error:
        kind = type(error).__name__ if type(error).__name__ in ('ValueError','RuntimeError','TimeoutError','OSError','KeyError','TypeError','ExceptionGroup','BaseExceptionGroup') else 'Other'
        print(json.dumps({'pass':False,'phase':'receiver_nodered_local_mtls_seam','error':kind,'evidence_dir':str(owner.path) if owner else None}))
        return 1
    finally:
        if owner is not None: owner.close()


if __name__ == '__main__': sys.exit(main())
