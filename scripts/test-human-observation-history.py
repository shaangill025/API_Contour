"""Owned fixture assertions for the real in-process Business handler.

Called by an owned PG/capture qualification. This module neither creates a DB
nor makes an HTTP/session claim; callers supply the existing fixture's exact
reader config, verified token files and stored capture operation.
"""
import json
import hashlib
import runpy
from pathlib import Path
import re
from urllib.parse import urlencode

ROOT=Path(__file__).resolve().parents[1]
HELPER=ROOT/'scripts/test-postgres-causal-bridge.py'


def _runner():
    if any(p.is_symlink() for p in (HELPER,*HELPER.parents)) or not HELPER.is_file(): raise ValueError('fixture runner unavailable')
    before=hashlib.sha256(HELPER.read_bytes()).digest()
    module=runpy.run_path(str(HELPER))
    if hashlib.sha256(HELPER.read_bytes()).digest()!=before: raise ValueError('fixture runner changed')
    return module['run_process']


UUID=re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


def _get(probe,config,token,uri,environment):
    if not uri.startswith('/v1/observations') or len(uri)>512: raise ValueError('invalid fixture request')
    result=_runner()([str(probe),str(config),uri],env=dict(environment,CONTOUR_FIXTURE_ID_TOKEN=str(token)),cwd=ROOT,timeout=35,limit=1_100_000)
    if result.returncode or result.stderr: raise RuntimeError('observation probe output invalid')
    value=json.loads(result.stdout)
    if type(value) is not dict or set(value)!={'status','body'} or type(value['status']) is not int or type(value['body']) is not dict: raise ValueError('observation probe result invalid')
    return value


def run_cases(execute,config,other_scope_config,other_environment_config,normal_token,unknown_token,scope,operation,target_dir,environment):
    """Check only real immutable observation rows already written by capture."""
    if not callable(execute) or type(scope) not in (tuple,list) or len(scope)!=4 or any(type(x) is not str or UUID.fullmatch(x) is None for x in [*scope,operation]): raise ValueError('invalid fixture scope')
    probe=Path(target_dir)/'debug/examples/human_origin_business_probe'
    tenant,project,service,environment_id=scope
    sql=("SELECT observation_id::text FROM contour.observation_windows WHERE tenant_id='%s' AND project_id='%s' AND service_id='%s' AND environment_id='%s' AND operation_id='%s' ORDER BY observation_id LIMIT 51;" % (tenant,project,service,environment_id,operation))
    ids=execute(sql).splitlines()
    if not ids or len(ids)>50 or any(UUID.fullmatch(x) is None for x in ids) or ids!=sorted(set(ids)): raise RuntimeError('real observation fixture unavailable or exceeds bound')
    def get(uri,token=normal_token): return _get(probe,config,token,uri,environment)
    cursor=None; seen=[]
    while True:
        query={'operation_id':operation,'limit':'1'}
        if cursor is not None: query['cursor']=cursor
        page=get('/v1/observations?'+urlencode(query))
        if page['status']!=200 or set(page['body'])!={'items','next_cursor'}: raise AssertionError('observation page failed')
        items=page['body']['items']; cursor=page['body']['next_cursor']
        if type(items) is not list or len(items)!=1: raise AssertionError('observation page shape invalid')
        item=items[0]; ident=item.get('id') if type(item) is dict else None
        if ident not in ids or item.get('operation_id')!=operation or item.get('origin_evidence')!='unavailable' or 'structure' not in item or 'completeness' not in item or 'sample_numerator' not in item or 'sample_denominator' not in item or 'status_code' not in item or type(item.get('structure_fingerprint')) is not str: raise AssertionError('observation projection invalid')
        if item.get('direction')=='request' and item['status_code'] is not None: raise AssertionError('request status invalid')
        detail=get('/v1/observations/'+ident+'?'+urlencode({'operation_id':operation}))
        if detail['status']!=200 or detail['body']!=item: raise AssertionError('observation detail changed')
        seen.append(ident)
        if cursor is None: break
        if cursor!=ident or len(seen)>len(ids): raise AssertionError('observation cursor invalid')
    if seen!=ids: raise AssertionError('observation coverage mismatch')
    uri='/v1/observations?'+urlencode({'operation_id':operation})
    if get(uri,unknown_token)['status']!=403: raise AssertionError('unknown identity accepted')
    if _get(probe,other_scope_config,normal_token,uri,environment)['status']!=403: raise AssertionError('foreign scope accepted')
    if _get(probe,other_environment_config,normal_token,uri,environment)['status']!=404: raise AssertionError('foreign environment accepted')
    if get('/v1/observations?'+urlencode({'operation_id':operation,'cursor':'00000000-0000-0000-0000-000000000000'}))['status']!=400: raise AssertionError('unscoped cursor accepted')
    if get('/v1/observations?'+urlencode({'operation_id':operation,'limit':'51'}))['status']!=400: raise AssertionError('invalid limit accepted')
    if get('/v1/observations?'+urlencode({'operation_id':operation,'cursor':'invalid'}))['status']!=400: raise AssertionError('invalid cursor accepted')
    return {'stored_observations':len(seen),'handler_authorization':True,'historical_origin':'unavailable'}


def source_snapshot():
    """Hash the complete clean tracked source before and after qualification."""
    runner=_runner()
    def git(*args):
        result=runner(['git',*args],cwd=ROOT,timeout=15,limit=16_777_216)
        if result.returncode or result.stderr: raise RuntimeError('fixture source check failed')
        return result.stdout
    if git('status','--porcelain','--untracked-files=all'): raise ValueError('fixture source not clean')
    head=git('rev-parse','HEAD').decode('ascii').strip()
    if not re.fullmatch('[0-9a-f]{40}',head): raise ValueError('fixture source head invalid')
    files={}
    for raw in git('ls-files','-z').split(b'\0'):
        if not raw: continue
        name=raw.decode('utf-8'); relative=Path(name); path=ROOT/relative
        if relative.is_absolute() or '..' in relative.parts or name in files or any(p.is_symlink() for p in (path,*path.parents)) or not path.is_file(): raise ValueError('fixture source path invalid')
        digest=hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda:stream.read(1_048_576),b''): digest.update(chunk)
        files[name]=digest.hexdigest()
    if not files: raise ValueError('fixture source empty')
    return head,files


class OwnedFixtureDirectory:
    """Retain unknown/failed fixtures; remove only the original private tree.

    If setup fails after construction but before context entry, its directory
    descriptor remains open until this one-shot fixture process exits.
    """
    def __init__(self):
        import os,tempfile,stat
        self.path=Path(tempfile.mkdtemp(prefix='contour-observation-history-')).resolve(); self.path.chmod(0o700)
        self.fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); info=os.fstat(self.fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError('fixture owner invalid')
        self.identity=(info.st_dev,info.st_ino);self.complete=False
    def verify(self):
        import os,stat
        current=os.lstat(self.path); held=os.fstat(self.fd)
        if not stat.S_ISDIR(current.st_mode) or current.st_uid!=os.getuid() or stat.S_IMODE(current.st_mode)!=0o700 or (current.st_dev,current.st_ino)!=self.identity or (held.st_dev,held.st_ino)!=self.identity: raise ValueError('fixture owner changed')
    def intent(self,name,value):
        import os
        if name not in ('network','volume','container','generation','target'): raise ValueError('invalid fixture intent')
        self.verify(); data=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        fd=os.open(name+'.intent',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
        with os.fdopen(fd,'wb') as out: out.write(data);out.flush();os.fsync(out.fileno())
        os.fsync(self.fd);self.verify()
    def __enter__(self): self.verify();return str(self.path)
    def __exit__(self,kind,error,tb):
        import os,shutil,stat
        failures=[]
        try:
            if kind is None and self.complete:
                self.verify()
                if not shutil.rmtree.avoids_symlink_attacks: raise RuntimeError('safe fixture cleanup unavailable')
                for parent,dirs,files in os.walk(self.path,followlinks=False):
                    for name in dirs+files:
                        entry=os.lstat(Path(parent)/name)
                        if entry.st_uid!=os.getuid() or entry.st_dev!=self.identity[0] or stat.S_ISLNK(entry.st_mode) or not (stat.S_ISDIR(entry.st_mode) or stat.S_ISREG(entry.st_mode)): raise ValueError('fixture content changed')
                self.verify();shutil.rmtree(self.path)
        except BaseException as cleanup: failures.append(cleanup)
        try: os.close(self.fd)
        except BaseException as cleanup: failures.append(cleanup)
        if failures:
            if error is not None: failures.insert(0,error)
            if len(failures)==1: raise failures[0]
            raise BaseExceptionGroup('fixture and cleanup failures',failures) from None


def cleanup_resources(run, container, volume, network, owner, image_id, network_name, image, started):
    """Remove only resources whose original recorded identities still match."""
    def inspect(kind, identity):
        values=json.loads(run(['docker',*([kind] if kind else []),'inspect',identity]))
        if type(values) is not list or len(values)!=1 or type(values[0]) is not dict: raise ValueError('fixture inspection invalid')
        return values[0]
    def check_container():
        obj=inspect('',container); config=obj.get('Config') or {}; host=obj.get('HostConfig') or {}
        mounts=[m for m in obj.get('Mounts',[]) if m.get('Destination')=='/var/lib/postgresql/data']
        state=obj.get('State') or {}; attached=(obj.get('NetworkSettings') or {}).get('Networks') or {}
        if started is None or state.get('StartedAt')!=started or len(attached)!=1 or next(iter(attached.values())).get('NetworkID')!=network: raise ValueError('fixture container generation changed')
        if obj.get('Id')!=container or obj.get('Image')!=image_id or config.get('Image')!=image or (config.get('Labels') or {}).get('org.apicontour.fixture-owner')!=owner or host.get('Init') is not True or len(mounts)!=1 or mounts[0].get('Name')!=volume: raise ValueError('fixture container ownership changed')
    def check_volume():
        obj=inspect('volume',volume); labels=obj.get('Labels') or {}
        if obj.get('Name')!=volume or labels.get('contour.fixture')!=volume or labels.get('org.apicontour.observation-owner')!=owner: raise ValueError('fixture volume ownership changed')
    def check_network(allowed):
        obj=inspect('network',network); members=set((obj.get('Containers') or {}).keys())
        if obj.get('Id')!=network or obj.get('Name')!=network_name or (obj.get('Labels') or {}).get('org.apicontour.observation-owner')!=owner or not members.issubset(allowed): raise ValueError('fixture network ownership changed')
    if container: check_container()
    if volume: check_volume()
    if network: check_network({container} if container else set())
    if container:
        check_container(); run(['docker','rm','-f',container])
        if run(['docker','ps','-aq','--no-trunc','--filter','id='+container]): raise ValueError('fixture container remains')
    if volume:
        check_volume(); run(['docker','volume','rm',volume])
        if run(['docker','volume','ls','-q','--filter','name=^'+volume+'$']): raise ValueError('fixture volume remains')
    if network:
        check_network(set()); run(['docker','network','rm',network])
        if run(['docker','network','ls','-q','--no-trunc','--filter','id='+network]): raise ValueError('fixture network remains')


def require_receipt(directory):
    import os,stat
    path=Path(directory)/'human-observation-history.done'
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid() or info.st_size!=len(b'history-fixture-complete\n') or os.read(fd,64)!=b'history-fixture-complete\n': raise ValueError('history fixture receipt invalid')
    finally: os.close(fd)


def artifact_identity(path, target):
    import os,stat
    path=Path(path); target=Path(target)
    if path.parent!=target/'debug'/'examples' or any(p.is_symlink() for p in (path,*path.parents)): raise ValueError('artifact path invalid')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not info.st_mode&0o100 or info.st_size>1_000_000_000: raise ValueError('artifact invalid')
        digest=hashlib.sha256(); total=0
        while True:
            block=os.read(fd,1_048_576)
            if not block: break
            total+=len(block)
            if total>1_000_000_000: raise ValueError('artifact exceeds hash limit')
            digest.update(block)
        after=os.fstat(fd)
        if (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns): raise ValueError('artifact changed')
        return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,digest.digest())
    finally: os.close(fd)


def artifact_guard(target, artifacts):
    """Bind every in-process inherited subprocess launch under the private target."""
    import os
    target=Path(target)
    def guard(event,args):
        if event!='subprocess.Popen': return
        executable=args[0]
        if not isinstance(executable,(str,bytes,os.PathLike)): return
        executable=os.fsdecode(executable)
        if executable.startswith(str(target)+'/'):
            path=Path(executable); name=path.name
            if name not in artifacts or path!=target/'debug'/'examples'/name or artifact_identity(path,target)!=artifacts[name]: raise ValueError('fixture executable changed')
    return guard


def select_artifacts(output, expected, package_id, target):
    selected={}
    for line in output.splitlines():
        event=json.loads(line)
        if event.get('reason')!='compiler-artifact' or (event.get('target') or {}).get('kind')!=['example']: continue
        name=event['target'].get('name')
        if name not in expected: continue
        wanted=Path(target)/'debug'/'examples'/name
        if event.get('package_id')!=package_id or event.get('executable')!=str(wanted) or name in selected: raise ValueError('fixture artifact identity invalid')
        selected[name]=artifact_identity(wanted,Path(target))
    if set(selected)!=set(expected): raise ValueError('fixture artifact missing')
    return selected
