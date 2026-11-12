#!/usr/bin/env python3
"""Bounded owned runtime and image-comparison qualification for Node 24.22.3.

This does not establish publisher provenance, TLS behavior, or release approval.
"""
import copy
import json
import sys
import os
import re
import hashlib
import importlib.util
import tempfile
import time
import uuid
import stat
import datetime
from pathlib import Path

OWNER = 'org.apicontour.fixture-owner'


def compare_images(base, candidate, owner):
    """Compare Docker image-inspect records, rejecting all unexplained drift."""
    if not isinstance(owner, str) or len(owner) != 64 or any(c not in '0123456789abcdef' for c in owner):
        raise ValueError('invalid owner')
    if not isinstance(base, dict) or not isinstance(candidate, dict):
        raise ValueError('invalid image metadata')
    if base.get('Os') != 'linux' or candidate.get('Os') != 'linux' or base.get('Architecture') != candidate.get('Architecture') or base.get('Architecture') not in ('amd64', 'arm64'):
        raise ValueError('platform mismatch')
    original = copy.deepcopy(base['Config'])
    updated = copy.deepcopy(candidate['Config'])
    labels = updated.get('Labels')
    if not isinstance(labels, dict) or labels.get(OWNER) != owner:
        raise ValueError('owner mismatch')
    del labels[OWNER]
    if not labels and original.get('Labels') is None:
        updated['Labels'] = None
    source_env, target_env = original.get('Env'), updated.get('Env')
    if not isinstance(source_env, list) or not isinstance(target_env, list):
        raise ValueError('environment invalid')
    if len([x for x in source_env if x.startswith('NODE_VERSION=')]) != 1:
        raise ValueError('base node version invalid')
    expected = ['NODE_VERSION=24.22.3' if x.startswith('NODE_VERSION=') else x for x in source_env]
    if target_env != expected:
        raise ValueError('environment drift')
    updated['Env'] = source_env
    if original != updated:
        raise ValueError('config drift')
    left, right = base['RootFS']['Layers'], candidate['RootFS']['Layers']
    if not isinstance(left, list) or not isinstance(right, list) or len(right) != len(left) + 1 or right[:-1] != left:
        raise ValueError('layer drift')
    if any(not isinstance(x, str) or len(x) != 71 or not x.startswith('sha256:') or any(c not in '0123456789abcdef' for c in x[7:]) for x in right):
        raise ValueError('invalid layer hash')
    return True



ROOT = Path(__file__).resolve().parents[1]
DOCKER = '/Users/shaanjotgill/Library/Caches/APIContour/tools/docker-29.8.2-31ae2d64/docker'
DOCKER_HASH = '31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f'
SOCKET = 'unix:///Users/shaanjotgill/.docker/run/docker.sock'
NODE = 'docker.io/library/node:24.22.3-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5'
BASE = 'docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963'
EXPECTED = {
    'arm64': ('sha256:9ca3f7b76099c042f1e655ca8936e0a1ccda68b3c74a8a36375428ef76476d4e', 'sha256:a2130198be80a76bc657795801e4e4c880f4f6aa2bd7d964766d4b953445248a'),
    'amd64': ('sha256:b791832e17c3a8a5897bdb5087381ffbc07b77bc634d204bf603b5f63c1ffe57', 'sha256:1c532f9dd00d6f77750bb2a9fedcdbb3f178ca6e539cbefb66084494d9e568d6'),
}
PROBE = r"""const fs=require('fs'),crypto=require('crypto');
if(process.version!=='v24.22.3') throw Error('version');
if(require('/usr/src/node-red/node_modules/node-red/package.json').version!=='5.0.9') throw Error('red');
const b=require('/usr/src/node-red/node_modules/@node-rs/bcrypt');
const s='synthetic-node243-probe', h=b.hashSync(s,4);
if(!b.verifySync(s,h) || b.verifySync(s+'x',h)) throw Error('bcrypt');
const p='/usr/local/bin/node', st=fs.statSync(p);
console.log(JSON.stringify({sha256:crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex'),mode:st.mode&4095,uid:st.uid,gid:st.gid,user:process.getuid()}));"""


def load_runner():
    spec = importlib.util.spec_from_file_location('owned_runner', ROOT/'scripts/qualify-origin21-onboarding.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def record(owner, name, value):
    if not re.fullmatch(r'(intent|cid|created|generation|result)-(arm64|amd64)\.json|receipt\.json|restore\.json', name):
        raise ValueError('invalid record')
    owner.verify()
    fd = os.open(name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=owner.fd)
    with os.fdopen(fd, 'wb') as f:
        f.write(json.dumps(value, sort_keys=True).encode('ascii')); f.flush(); os.fsync(f.fileno())
    os.fsync(owner.fd); owner.verify()


def one(data):
    value = json.loads(data)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict): raise ValueError('inspect invalid')
    return value[0]


def image_id_file(path):
    before = os.lstat(path)
    def valid(st):
        return (stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
                and st.st_uid == os.geteuid() and st.st_nlink == 1 and st.st_size <= 80)
    if not valid(before): raise ValueError('iid unsafe')
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW)
    try:
        held = os.fstat(fd)
        if not valid(held) or (before.st_dev, before.st_ino) != (held.st_dev, held.st_ino): raise ValueError('iid identity')
        data = os.read(fd, 81)
        after = os.fstat(fd); current = os.lstat(path)
        if not valid(after) or not valid(current) or before != after or before != current: raise ValueError('iid changed')
    finally:
        os.close(fd)
    image = data.decode('ascii').strip()
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image): raise ValueError('iid invalid')
    return image


def signature(c):
    return copy.deepcopy({key:c[key] for key in ('Id','Image','Config','HostConfig','Mounts','Created')})


def validate_container(c, cid, token, image):
    cfg, host = c['Config'], c['HostConfig']
    if c['Id'] != cid or c['Image'] != image or cfg['Labels'].get(OWNER) != token: raise ValueError('identity')
    if cfg['User'] != 'node-red' or cfg['Entrypoint'] != ['/usr/local/bin/node'] or cfg['Cmd'] != ['-e', PROBE]: raise ValueError('command')
    if (host['NetworkMode'] != 'none' or host['ReadonlyRootfs'] is not True or host['CapDrop'] != ['ALL']
        or host['SecurityOpt'] not in (['no-new-privileges'], ['no-new-privileges:true'])
        or host['Memory'] != 536870912 or host['PidsLimit'] != 32 or host['Privileged'] is not False
        or host['CapAdd'] not in (None, []) or host['Devices'] not in (None, [])
        or host['PidMode'] not in ('', 'private') or host['IpcMode'] not in ('', 'private')
        or host['UTSMode'] not in ('', 'private') or host['UsernsMode'] not in ('', 'private')
        or host['PortBindings'] not in (None, {}) or host['PublishAllPorts'] is not False): raise ValueError('isolation')
    if host['Tmpfs'] != {'/data':'rw,noexec,nosuid,size=16m', '/tmp':'rw,noexec,nosuid,size=16m'} or any(x.get('Type') != 'tmpfs' or x.get('Destination') not in ('/data','/tmp') for x in c['Mounts']): raise ValueError('mounts')
    if c['RestartCount'] != 0: raise ValueError('restart')


def created_signature(c, cid, token, image):
    validate_container(c, cid, token, image)
    if c['State']['Status'] != 'created' or c['State']['Running']: raise ValueError('creation state')
    return signature(c)


def generation(c, cid, token, image, frozen):
    validate_container(c, cid, token, image)
    if signature(c) != frozen: raise ValueError('configuration changed')
    state = c['State']; started = state['StartedAt']
    if state['Status'] != 'exited' or state['Running'] or state['ExitCode'] != 0 or not isinstance(started,str): raise ValueError('generation')
    match = re.fullmatch(r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z', started)
    if match is None: raise ValueError('generation timestamp')
    parts = [int(x) for x in match.groups()[:6]]
    if parts[0] < 1970: raise ValueError('generation timestamp')
    try: datetime.datetime(*parts, tzinfo=datetime.timezone.utc)
    except ValueError: raise ValueError('generation timestamp') from None
    return started


def run_probe(docker, owner, arch, cid, token, image, frozen):
    result = None; observed_generation = None
    try:
        output = docker('start','--attach',cid,timeout=30)
        stopped = one(docker('inspect',cid))
        observed = generation(stopped,cid,token,image,frozen)
        record(owner,'generation-'+arch+'.json',{'cid':cid,'started_at':observed})
        observed_generation = observed
        result = json.loads(output)
        if set(result) != {'sha256','mode','uid','gid','user'} or not re.fullmatch(r'[0-9a-f]{64}',result['sha256']) or not all(type(result[k]) is int for k in ('mode','uid','gid','user')) or result['user'] == 0: raise ValueError('probe result')
    finally:
        # If execution identity was not observed, retain the object for review.
        if observed_generation is not None:
            current = one(docker('inspect',cid))
            if generation(current,cid,token,image,frozen) != observed_generation: raise ValueError('generation changed')
            docker('rm',cid)
            if docker('ps','-a','--no-trunc','--filter','id='+cid,'--format','{{.ID}}').strip(): raise ValueError('container remains')
    return result


class CacheRestoreFailure(RuntimeError):
    pass


def qualify(run, owner, shared):
    if hashlib.sha256(Path(DOCKER).read_bytes()).hexdigest() != DOCKER_HASH: raise ValueError('docker hash')
    head, source = shared.snapshot(run, ROOT)
    recipe = ROOT/'deploy/pilot/node-red-node243.Dockerfile'
    recipe_hash = hashlib.sha256(recipe.read_bytes()).hexdigest()
    config = owner.path/'docker-config'; config.mkdir(mode=0o700)
    token = uuid.uuid4().hex + uuid.uuid4().hex
    stage_number = 0
    def docker(*args, timeout=30):
        nonlocal stage_number
        owner.verify(); stage_number += 1
        stage_path = owner.path/('stage-%03d' % stage_number); stage_path.mkdir(mode=0o700)
        stage = shared.OwnedDirectory(stage_path); previous_owner = run.owner
        try:
            run.owner = stage
            env = ['/usr/bin/env','-i','PATH=/usr/bin:/bin','DOCKER_CONFIG='+str(config)]
            if 'HOME' in os.environ: env.append('HOME='+os.environ['HOME'])
            return run([*env,DOCKER,'--host',SOCKET,*args],cwd=ROOT,timeout=timeout,log=stage.path/'build.log')
        finally:
            run.owner = previous_owner; stage.close()

    results = {}
    primary = None; restore_failure = None; x64_started = False
    try:
        for arch in ('arm64', 'amd64'):
            if arch == 'amd64': x64_started = True
            platform = 'linux/'+arch
            for ref in (NODE, BASE): docker('pull','--platform',platform,ref,timeout=120)
            node = one(docker('image','inspect',NODE)); base = one(docker('image','inspect',BASE))
            if (node['Id'],base['Id']) != EXPECTED[arch] or node['Architecture'] != arch or base['Architecture'] != arch: raise ValueError('input identity')
            iid = owner.path/('iid-'+arch)
            docker('build','--platform',platform,'--pull=false','--label',OWNER+'='+token,'--iidfile',str(iid),'-f',str(recipe),str(ROOT),timeout=330)
            image = image_id_file(iid)
            candidate = one(docker('image','inspect',image))
            if candidate['Id'] != image: raise ValueError('image identity')
            compare_images(base,candidate,token)
            record(owner,'intent-'+arch+'.json',{'image':image,'token':token,'architecture':arch})
            cid = docker('create','--platform',platform,'--label',OWNER+'='+token,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','512m','--pids-limit','32','--tmpfs','/data:rw,noexec,nosuid,size=16m','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','--entrypoint','/usr/local/bin/node',image,'-e',PROBE).decode('ascii').strip()
            if not re.fullmatch(r'[0-9a-f]{64}',cid): raise ValueError('cid invalid')
            record(owner,'cid-'+arch+'.json',{'cid':cid,'token':token,'image':image})
            created = one(docker('inspect',cid))
            frozen = created_signature(created,cid,token,image)
            record(owner,'created-'+arch+'.json',{'cid':cid,'signature':frozen})
            result = run_probe(docker,owner,arch,cid,token,image,frozen)
            record(owner,'result-'+arch+'.json',result)
            results[arch] = {'image':image,'probe':result}
    except BaseException as error:
        primary = error
    finally:
        if x64_started:
            failures = []
            for ref in (NODE, BASE):
                try: docker('pull','--platform','linux/arm64',ref,timeout=120)
                except BaseException as error: failures.append(error)
            if failures: restore_failure = BaseExceptionGroup('cache restoration failures', failures)
    if restore_failure is not None:
        record(owner,'restore.json',{'failed':True,'primary_failed':primary is not None})
        if primary is not None: raise BaseExceptionGroup('qualification and cache restoration failures', [primary, restore_failure])
        raise CacheRestoreFailure('cache restoration failed') from restore_failure
    if primary is not None: raise primary
    if shared.snapshot(run, ROOT) != (head, source) or hashlib.sha256(recipe.read_bytes()).hexdigest() != recipe_hash: raise ValueError('source changed')
    record(owner,'receipt.json',{'head':head,'recipe_sha256':recipe_hash,'images':results,'token':token,'scope':'version-native-bcrypt-config-and-layer-prefix', 'remaining_unverified':['donor_binary_hash_match','added_layer_contents','publisher_provenance','actual_TLS','profile504']})


def main():
    if sys.argv[1:] != ['--run-owned']: return 1
    os.umask(0o077); shared = load_runner(); owner = None
    try:
        folder = Path(tempfile.mkdtemp(prefix='contour-node243-')).resolve(); folder.chmod(0o700)
        owner = shared.OwnedDirectory(folder)
        qualify(shared.Runner(time.monotonic()+900, owner), owner, shared)
        print(json.dumps({'pass':True,'phase':'version_native_bcrypt_config_layer_prefix'}))
        return 0
    except BaseException as error:
        kind = type(error).__name__ if type(error).__name__ in ('ValueError','RuntimeError','TimeoutError','OSError','KeyError','TypeError','ExceptionGroup','BaseExceptionGroup') else 'Other'
        restore_failed = isinstance(error, CacheRestoreFailure) or (isinstance(error, BaseExceptionGroup) and str(error).startswith('qualification and cache restoration failures'))
        print(json.dumps({'pass':False,'phase':'qualification','error':kind,'cache_restore_failed':restore_failed}))
        return 1
    finally:
        if owner is not None: owner.close()


if __name__ == '__main__':
    sys.exit(main())
