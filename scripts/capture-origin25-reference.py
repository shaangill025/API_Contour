#!/usr/bin/env python3
"""Capture review-only metadata from a fresh owned PG16; never activate a profile."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
IMAGE='postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4'
MIGRATIONS={22:'0022_causal_generation',23:'0023_causal_marker_bindings',24:'0024_causal_live_profile',25:'0025_historical_origin'}
LEDGER_SQL='SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;'


def ledger(version):
    return '{'+','.join(map(str,range(1,version+1)))+'}'


def capture_forward(execute,source,write,fence,*,verify21,ledger_sql,inventory_sql):
    if execute(ledger_sql)!=ledger(21): raise ValueError('stage 21 ledger mismatch')
    verify21(execute)
    fence()
    for version in (22,23,24,25):
        execute(source(version).decode('utf-8'))
        if execute(ledger_sql)!=ledger(version): raise ValueError('forward ledger mismatch')
        value=json.loads(execute(inventory_sql))
        if (type(value) is not dict or set(value)!={'version','server_major','items'} or
            type(value['version']) is not int or value['version']!=1 or value['server_major']!=16 or
            type(value['items']) is not list or not value['items']): raise ValueError('invalid reference inventory')
        raw=(json.dumps({'stage':version,'phase':'enrolled','inventory':value},sort_keys=True,separators=(',',':'))+'\n').encode()
        fence(); write(version,raw); fence()


class PrivateOutput:
    """A new 0700 directory with exclusive, fsynced output records."""
    def __init__(self,path):
        path=Path(path)
        if not path.is_absolute() or '..' in path.parts or path==ROOT or ROOT in path.parents:
            raise ValueError('output must be outside checkout')
        if any(part.is_symlink() for part in (path,*path.parents)): raise ValueError('unsafe output path')
        parent=path.parent
        fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd)
            if info.st_uid!=os.geteuid() or info.st_mode & 0o022: raise ValueError('unsafe output parent')
            os.mkdir(path.name,0o700,dir_fd=fd);os.fsync(fd)
        finally: os.close(fd)
        self.path=path
        self.fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        info=os.fstat(self.fd);self.identity=(info.st_dev,info.st_ino)
        self.verify()
    def verify(self):
        if any(part.is_symlink() for part in (self.path,*self.path.parents)): raise ValueError('output path changed')
        current=os.lstat(self.path); held=os.fstat(self.fd)
        if (not stat.S_ISDIR(current.st_mode) or current.st_uid!=os.geteuid() or
            stat.S_IMODE(current.st_mode)!=0o700 or (current.st_dev,current.st_ino)!=self.identity or
            (held.st_dev,held.st_ino)!=self.identity): raise ValueError('output identity changed')
    def write(self,name,data):
        if name not in {'intent.json','generation.json','receipt.json','initial-secret',*(f'origin25_reference_{n}_enrolled.json' for n in (22,23,24,25))} or type(data) is not bytes:
            raise ValueError('invalid output record')
        self.verify();fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
        with os.fdopen(fd,'wb') as stream: stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.fsync(self.fd);self.verify()
    def close(self): os.close(self.fd)


def postgres_ready(process,cid):
    """Adapt the audited onboarding witness to contour_fixture without TLS."""
    sql="SELECT current_database()='contour_fixture' AND current_setting('listen_addresses')='*';"
    command=('test "$(cat /proc/1/comm)" = docker-init && p=$(head -n 1 /var/lib/postgresql/data/postmaster.pid) && '
             'case "$p" in *[!0-9]*|\'\') exit 1;; esac && test "$p" -gt 1 && test "$(cat /proc/$p/comm)" = postgres && '
             'pg_isready -U postgres -d contour_fixture >/dev/null && '
             'exec psql -XqAt -v ON_ERROR_STOP=1 -U postgres -d contour_fixture -c "'+sql+'"')
    try: result=process(['docker','exec',cid,'sh','-c',command],timeout=5)
    except (RuntimeError,TimeoutError): return False
    return result.returncode==0 and result.stdout==b't\n' and result.stderr==b''


def bootstrap_step(name,callback):
    if name not in ('create_database','logging_settings','version'): raise ValueError('invalid bootstrap step')
    try: return callback()
    except Exception as error:
        kind=type(error).__name__ if type(error) in (ValueError,RuntimeError,TimeoutError,OSError) else 'OtherError'
        print('reference-bootstrap step='+name+' type='+kind,file=sys.stderr,flush=True)
        raise


def record_generation(output,fixture,inspect,token,network_id,cid,image_id):
    item=inspect(['docker','inspect',cid]);candidate=(item.get('State') or {}).get('StartedAt')
    if (fixture['validate_postgres'](item,token,cid,image_id,network_id)!='running' or
        not isinstance(candidate,str) or
        re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',candidate) is None or
        candidate.startswith('0001-')): raise RuntimeError('generation unavailable')
    try: datetime.datetime.fromisoformat(candidate.replace('Z','+00:00'))
    except ValueError: raise RuntimeError('generation unavailable') from None
    fixture['validate_network'](inspect(['docker','network','inspect',network_id]),token,network_id,[cid])
    raw=(json.dumps({'version':1,'image_id':image_id,'network_id':network_id,'container_id':cid,'started_at':candidate},sort_keys=True,separators=(',',':'))+'\n').encode()
    output.write('generation.json',raw)
    return candidate


def cleanup_fixture(fixture,call,inspect,token,network_id,cid,image_id,network_attempted,container_attempted,start_attempted,started):
    if start_attempted and started is None: raise RuntimeError('start outcome unknown; resources retained')
    if started is not None:
        current=inspect(['docker','inspect',cid])
        if (current.get('State') or {}).get('StartedAt')!=started: raise RuntimeError('generation changed; resources retained')
    fixture['cleanup_owned'](call,inspect,token,network_id,cid,image_id,network_attempted,container_attempted)


def load_tracked(name):
    """Execute only exact, bounded committed helper bytes from this checkout."""
    path=ROOT/name
    if not path.is_file() or any(part.is_symlink() for part in (path,*path.parents)):
        raise ValueError('helper path unavailable')
    result=subprocess.run(['git','show','HEAD:'+name],cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=True)
    if result.stderr or len(result.stdout)>2_000_000: raise ValueError('helper source invalid')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size>2_000_000: raise ValueError('helper source invalid')
        with os.fdopen(fd,'rb',closefd=False) as stream: raw=stream.read(2_000_001)
        if raw!=result.stdout: raise ValueError('helper source changed')
        namespace={'__file__':str(path),'__name__':'origin25_capture_helper'}
        exec(compile(raw,str(path),'exec'),namespace)
        after=os.fstat(fd)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) or hashlib.sha256(path.read_bytes()).digest()!=hashlib.sha256(raw).digest():
            raise ValueError('helper source changed')
        return namespace
    finally: os.close(fd)


def main(argv):
    if len(argv)!=1: raise ValueError('expected a new private output directory')
    sys.dont_write_bytecode=True;os.umask(0o077)
    if not (ROOT/'.git').is_file() or (ROOT/'.git').is_symlink(): raise ValueError('isolated worktree required')
    if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
    # Reject dirty or untracked source before executing either local helper.
    status=subprocess.run(['git','status','--porcelain','--untracked-files=all'],cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=True)
    if status.stdout or status.stderr: raise ValueError('clean reviewed source required')
    for name in ('scripts/capture-origin25-reference.py','scripts/test-origin21-onboarding.py','scripts/test-postgres-causal-bridge.py','scripts/fixture_psql_transport.py'):
        checked=subprocess.run(['git','ls-files','--error-unmatch','--',name],cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,check=False)
        changed=subprocess.run(['git','diff','--quiet','HEAD','--',name],cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,check=False)
        if checked.returncode or changed.returncode: raise ValueError('capture source not tracked')
    # Both helpers are tracked project code; they are never loaded from captures.
    fixture=load_tracked('scripts/test-origin21-onboarding.py')
    process=load_tracked('scripts/test-postgres-causal-bridge.py')['run_process']
    def call(args,data=None,timeout=30):
        result=process(args,data=data,cwd=ROOT,timeout=timeout,limit=8*1024*1024)
        if result.returncode or result.stderr: raise RuntimeError('fixture command failed')
        return result.stdout.strip()
    def inspect(args):
        value=json.loads(call(args))
        if type(value) is not list or len(value)!=1 or type(value[0]) is not dict: raise RuntimeError('fixture inspection failed')
        return value[0]
    head=fixture['clean_head'](call); sources=fixture['tracked_snapshot'](call)
    if fixture['clean_head'](call)!=head or fixture['tracked_snapshot'](call)!=sources: raise RuntimeError('source changed')
    required=['scripts/capture-origin25-reference.py','scripts/test-origin21-onboarding.py','scripts/test-postgres-causal-bridge.py','scripts/fixture_psql_transport.py']+['db/opt-in-migrations/'+name+'.sql' for name in MIGRATIONS.values()]
    if any(name not in sources for name in required): raise ValueError('capture source not tracked')
    from deploy.local import origin21_logins,origin21_profile,origin21_schema,origin21_setup,origin21_transport,provision
    fresh=load_tracked('scripts/fixture_psql_transport.py')['FreshPsqlTransport']
    source_bytes={version:(ROOT/'db/opt-in-migrations'/(name+'.sql')).read_bytes() for version,name in MIGRATIONS.items()}
    def source(version): return source_bytes[version]
    output=PrivateOutput(argv[0]);token=secrets.token_hex(16);name='contour-origin21-qual-'+token
    record=lambda value:(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    image_id=network_id=cid=started=None
    network_attempted=container_attempted=start_attempted=False
    runner=None; primary=None; cleanup=[]; artifacts={}; secret_identity=None; receipt=None; phase='intent'
    try:
        output.write('intent.json',record({'version':1,'owner':token,'image':IMAGE,'source_head':head,'kind':'origin25-metadata'}))
        phase='image'
        image=inspect(['docker','image','inspect',IMAGE]);image_id=image.get('Id','')
        if not isinstance(image_id,str) or not re.fullmatch('sha256:[0-9a-f]{64}',image_id): raise ValueError('fixture image identity')
        digest=IMAGE.split('@',1)[1]
        if not any(ref in ('postgres@'+digest,'docker.io/library/postgres@'+digest) for ref in image.get('RepoDigests',[])): raise ValueError('fixture image digest')
        phase='network';network_attempted=True
        network_id=call(['docker','network','create','--internal','--label',fixture['LABEL']+'='+token,name]).decode('ascii')
        if not re.fullmatch('[0-9a-f]{64}',network_id): network_id=None;raise RuntimeError('network outcome unknown')
        fixture['durable_id'](output.path,'network',network_id)
        fixture['validate_network'](inspect(['docker','network','inspect',network_id]),token,network_id,[])
        # Synthetic bootstrap secret is copied into the private container.
        output.write('initial-secret',secrets.token_hex(32).encode())
        secret=os.stat('initial-secret',dir_fd=output.fd,follow_symlinks=False)
        secret_identity=(secret.st_dev,secret.st_ino)
        phase='container';container_attempted=True
        cid=call(['docker','create','--init','--pull=never','--name',name+'-postgres','--label',fixture['LABEL']+'='+token,
                  '--network',network_id,'--network-alias','postgres','--memory','512m','--cpus','1','--pids-limit','128',
                  '--tmpfs','/var/lib/postgresql/data:rw,nosuid,noexec,size=256m','-e','POSTGRES_DB=contour_fixture',
                  '-e','POSTGRES_PASSWORD_FILE=/tmp/initial-secret',IMAGE,'postgres','-c','listen_addresses=*']).decode('ascii')
        if not re.fullmatch('[0-9a-f]{64}',cid): cid=None;raise RuntimeError('container outcome unknown')
        fixture['durable_id'](output.path,'postgres',cid)
        if fixture['validate_postgres'](inspect(['docker','inspect',cid]),token,cid,image_id,network_id)!='created': raise RuntimeError('container started early')
        fixture['validate_network'](inspect(['docker','network','inspect',network_id]),token,network_id,[])
        call(['docker','cp',str(output.path/'initial-secret'),cid+':/tmp/initial-secret'])
        start_attempted=True
        if call(['docker','start',cid]).decode('ascii')!=cid: raise RuntimeError('start outcome unknown')
        until=time.monotonic()+60
        while True:
            if postgres_ready(process,cid): break
            if time.monotonic()>=until: raise TimeoutError('fixture readiness')
            time.sleep(.2)
        started=record_generation(output,fixture,inspect,token,network_id,cid,image_id)
        phase='bootstrap';sql=['docker','exec','-i',cid,'psql','-XAtq','-v','ON_ERROR_STOP=1','-U','postgres','-d','contour_fixture']
        runner=fresh(sql,os.environ.copy(),token)
        def raw_execute(text): return runner.execute(text,timeout=120)
        bootstrap_step('create_database',lambda:raw_execute('CREATE DATABASE contour_local;'))
        # Establish safe logging at connection startup before synthetic verifier
        # SQL is parsed. These role settings belong only to this disposable PG.
        settings=('log_statement=none','log_min_duration_statement=-1','log_min_duration_sample=-1',
                  'log_min_error_statement=panic','log_min_messages=panic','log_duration=off',
                  'log_statement_sample_rate=0','log_transaction_sample_rate=0')
        bootstrap_step('logging_settings',lambda:raw_execute(''.join('ALTER ROLE postgres SET '+item+';' for item in settings)))
        def execute(text):
            fence()
            result=raw_execute('\\connect contour_local\n'+origin21_transport.GUARD+text)
            fence()
            return result
        def fence():
            output.verify()
            if fixture['clean_head'](call)!=head or fixture['tracked_snapshot'](call)!=sources: raise RuntimeError('source changed')
            current=inspect(['docker','inspect',cid])
            if fixture['validate_postgres'](current,token,cid,image_id,network_id)!='running' or (current.get('State') or {}).get('StartedAt')!=started: raise RuntimeError('postgres generation changed')
            fixture['validate_network'](inspect(['docker','network','inspect',network_id]),token,network_id,[cid])
        fence()
        def check_version():
            value=execute('SHOW server_version_num;')
            if not re.fullmatch('[0-9]{6}',value) or not 160000<=int(value)<170000: raise ValueError('PostgreSQL 16 required')
            return value
        version_text=bootstrap_step('version',check_version)
        execute((ROOT/'db/bootstrap.sql').read_text())
        for kind in provision.PROVISION: execute((ROOT/('db/provision_'+kind+'.sql')).read_text())
        migrations=sorted((ROOT/'db/migrations').glob('*.sql'))
        if [int(path.name[:4]) for path in migrations]!=list(range(1,15)): raise ValueError('baseline migration drift')
        for path in migrations: execute(path.read_text())
        def login(role,groups):
            password=secrets.token_hex(32)
            return 'CREATE ROLE '+role+" LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD '"+password+"'; GRANT "+','.join(groups)+' TO '+role+'; GRANT CONNECT ON DATABASE contour_local TO '+role+'; '
        execute('BEGIN; '+login('contour_app',provision.GROUPS)+login('contour_local_ingress',['contour_ingestion'])+login('contour_local_worker',['contour_catalog_worker'])+'COMMIT;')
        phase='baseline14'
        origin21_schema.require_ready(list(range(1,15)),execute,stage=14,phase='pre')
        phase='schema21';context={'login':False};origin21_setup.Groups(execute,context).apply()
        for version in range(15,22):
            path=ROOT/origin21_setup.MIGRATIONS[version]
            origin21_setup.Migration(execute,version,path.read_bytes(),context).apply()
        class SyntheticLogins(origin21_logins.Logins):
            def _password(self,name):
                if name not in ('ingress','worker'): raise ValueError('invalid synthetic role')
                return self._synthetic[name]
        def sensitive(text): return execute(text)
        logins=SyntheticLogins(origin21_profile.PROFILE,execute,sensitive,lambda *_:False)
        logins._synthetic={'ingress':secrets.token_hex(32),'worker':secrets.token_hex(32)}
        logins.apply()
        def write(version,raw):
            name='origin25_reference_'+str(version)+'_enrolled.json';output.write(name,raw)
            artifacts[name]=hashlib.sha256(raw).hexdigest()
        phase='capture22_25'
        capture_forward(execute,source,write,fence,
            verify21=lambda cb:origin21_schema.require_ready(list(range(1,22)),cb,stage=21,phase='enrolled'),
            ledger_sql=LEDGER_SQL,inventory_sql=origin21_schema.inventory_sql())
        fence()
        receipt=record({'version':1,'kind':'unreviewed-metadata-capture','source_head':head,
            'source_snapshot_sha256':hashlib.sha256(json.dumps(sources,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'image_ref':IMAGE,'image_id':image_id,'postgres_version_num':int(version_text),'inventories':artifacts})
    except BaseException as error:
        primary=error
        kind=type(error).__name__ if type(error) in (ValueError,RuntimeError,TimeoutError,OSError) else 'OtherError'
        print('reference-capture phase='+phase+' type='+kind,file=sys.stderr,flush=True)
    finally:
        if runner is not None:
            try: runner.close()
            except BaseException as error: cleanup.append(error)
        try:
            if cleanup: raise RuntimeError('transport cleanup unproved; resources retained')
            cleanup_fixture(fixture,call,inspect,token,network_id,cid,image_id,network_attempted,container_attempted,start_attempted,started)
            if secret_identity is not None:
                output.verify();info=os.stat('initial-secret',dir_fd=output.fd,follow_symlinks=False)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or
                    info.st_nlink!=1 or (info.st_dev,info.st_ino)!=secret_identity): raise ValueError('secret identity changed')
                os.unlink('initial-secret',dir_fd=output.fd);os.fsync(output.fd)
            if primary is None:
                if fixture['clean_head'](call)!=head or fixture['tracked_snapshot'](call)!=sources: raise RuntimeError('source changed during cleanup')
                if receipt is None: raise RuntimeError('capture receipt missing')
                output.write('receipt.json',receipt)
        except BaseException as error: cleanup.append(error)
        output.close()
    if cleanup: raise BaseExceptionGroup('capture and cleanup failures',([primary] if primary else [])+cleanup)
    if primary is not None: raise primary
    print('Review-only metadata captured in private directory.',flush=True)


if __name__=='__main__':
    try: main(sys.argv[1:])
    except Exception:
        print('Reference capture failed; private state retained.',file=sys.stderr,flush=True)
        raise SystemExit(1) from None
