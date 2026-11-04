"""Cross-tenant product/export leaf concurrency probe for migration18.

Root-owned disposable PG harness calls run_cases(container_id, execute) after
pre-fixture, migration18 and post-fixture. No container is created here. This is
registry evidence only; no certificate authentication or runtime is exercised.
"""
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time
import uuid


ROOT=Path(__file__).resolve().parents[1]
MANIFEST_SHA256='b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510'


def verify_qualified_profile():
    """Require the exact public manifest and the qualified source it names."""
    path=ROOT/'collectors/nodered/qualified-runtime-profile.json'
    raw=checked_file(path)
    data=json.loads(raw)
    canonical=json.dumps(data,sort_keys=True,separators=(',',':')).encode()
    if raw!=canonical+b'\n' or hashlib.sha256(canonical).hexdigest()!=MANIFEST_SHA256:
        raise ValueError('qualified profile manifest mismatch')
    if data.get('profile_id')!='00000000-0000-4000-8000-000000000501' or data.get('profile_source')!='collectors/nodered/error-integration/profile.js':
        raise ValueError('qualified profile scope mismatch')
    source=ROOT/data['profile_source']
    if hashlib.sha256(checked_file(source)).hexdigest()!=data.get('profile_source_sha256'):
        raise ValueError('qualified profile source missing or changed')


def run_cases(container, execute):
    verify_qualified_profile()
    args=['docker','exec','-i',container,'psql','-X','-qAt','-v','ON_ERROR_STOP=1',
          '-v','VERBOSITY=verbose','-h','/var/run/postgresql','-U','postgres','-d','contour_local']
    t1='f0000000-0000-4000-8000-000000000001'; t2='f0000000-0000-4000-8000-000000000002'
    def product(leaf,cred):
        return ("SELECT set_config('apicontour.tenant_id','"+t2+"',true); SET LOCAL ROLE contour_admin; "
                "SELECT contour.enroll_origin_credential('"+t2+"','"+cred+"','f9000000-0000-4000-8000-000000000002',decode(repeat('"+leaf+"',32),'hex')); ")
    def export(leaf,runtime):
        return ("SELECT set_config('apicontour.tenant_id','"+t1+"',true); SET LOCAL ROLE contour_causal_provisioner; "
                "SELECT contour.enroll_causal_runtime('"+t1+"','"+runtime+"','f6000000-0000-4000-8000-000000000003','f7000000-0000-4000-8000-000000000003',"
                "'f1000000-0000-4000-8000-000000000001','f2000000-0000-4000-8000-000000000001','f3000000-0000-4000-8000-000000000001',"
                "'f4000000-0000-4000-8000-000000000001','f5000000-0000-4000-8000-000000000003','f9000000-0000-4000-8000-000000000003',"
                "'00000000-0000-4000-8000-000000000501',decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex'),decode(repeat('"+leaf+"',32),'hex')); ")
    def race(first,second,leaf,expected_class,duplicate_subject=None):
        marker='causal_registry_held_'+uuid.uuid4().hex
        process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        selector=selectors.DefaultSelector()
        try:
            selector.register(process.stdout,selectors.EVENT_READ)
            process.stdin.write(('BEGIN; '+first+'\n\\echo '+marker+'\n').encode());process.stdin.flush()
            deadline=time.monotonic()+15; buffered=b''; ready=False
            while time.monotonic()<deadline:
                if not selector.select(max(0,deadline-time.monotonic())): break
                chunk=os.read(process.stdout.fileno(),65536)
                if not chunk: break
                buffered+=chunk
                if len(buffered)>65536: raise RuntimeError('registry barrier output limit')
                if marker.encode() in buffered.splitlines(): ready=True; break
            if not ready: raise RuntimeError('registry barrier unavailable')
            conflict=subprocess.run(args,input='BEGIN; '+second+' COMMIT;',text=True,capture_output=True,timeout=10)
            if conflict.returncode==0 or 'credential gate busy' not in conflict.stderr:
                raise AssertionError('cross-tenant leaf lock did not serialize')
            if duplicate_subject is not None:
                duplicate=subprocess.run(args,input='BEGIN; '+duplicate_subject+' COMMIT;',text=True,capture_output=True,timeout=10)
                if duplicate.returncode==0 or 'origin gate busy' not in duplicate.stderr:
                    raise AssertionError('duplicate lifecycle did not serialize')
            process.communicate(b'COMMIT;\n',timeout=10)
            if process.returncode: raise RuntimeError('registry winning transaction failed')
            retry=subprocess.run(args,input='BEGIN; '+second+' COMMIT;',text=True,capture_output=True,timeout=10)
            if retry.returncode==0 or '23505' not in retry.stderr:
                raise AssertionError('committed leaf reservation was not enforced')
            if duplicate_subject is not None:
                duplicate=subprocess.run(args,input='BEGIN; '+duplicate_subject+' COMMIT;',text=True,capture_output=True,timeout=10)
                if duplicate.returncode==0 or '23505' not in duplicate.stderr:
                    raise AssertionError('duplicate lifecycle accepted')
                if execute("SELECT count(*) FROM contour.causal_leaf_reservations WHERE leaf_sha256=decode(repeat('99',32),'hex');")!='0':
                    raise AssertionError('duplicate lifecycle retained a leaf claim')
            actual=execute("SELECT leaf_class FROM contour.causal_leaf_reservations WHERE leaf_sha256=decode(repeat('"+leaf+"',32),'hex');")
            if actual!=expected_class: raise AssertionError('winner reservation changed')
        finally:
            selector.close()
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill();process.wait(timeout=5)
            for stream in (process.stdin,process.stdout,process.stderr):
                if stream is not None: stream.close()
    race(product('44','fa000000-0000-4000-8000-000000000044'),export('44','fc000000-0000-4000-8000-000000000002'),'44','product')
    race(export('55','fc000000-0000-4000-8000-000000000002'),product('55','fa000000-0000-4000-8000-000000000055'),'55','export',export('99','fc000000-0000-4000-8000-000000000099'))
    # Hold the collector gate while disabling the current head. Enrollment must
    # first fail closed on C contention, then re-read the disabled state after
    # the competing transaction commits; it must not rely on a stale snapshot.
    marker='causal_authority_held_'+uuid.uuid4().hex
    process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    selector=selectors.DefaultSelector(); committed=False
    authority=("SELECT set_config('apicontour.tenant_id','"+t1+"',true); SET LOCAL ROLE contour_admin; "
        "SELECT contour.lock_collector('"+t1+"','f6000000-0000-4000-8000-000000000003'); "
        "UPDATE contour.collector_authorization SET enabled=false WHERE tenant_id='"+t1+"' AND collector_id='f6000000-0000-4000-8000-000000000003'; ")
    try:
        selector.register(process.stdout,selectors.EVENT_READ)
        process.stdin.write(('BEGIN; '+authority+'\n\\echo '+marker+'\n').encode());process.stdin.flush()
        deadline=time.monotonic()+15; buffered=b''; ready=False
        while time.monotonic()<deadline:
            if not selector.select(max(0,deadline-time.monotonic())): break
            chunk=os.read(process.stdout.fileno(),65536)
            if not chunk: break
            buffered+=chunk
            if len(buffered)>65536: raise RuntimeError('authority barrier output limit')
            if marker.encode() in buffered.splitlines(): ready=True; break
        if not ready: raise RuntimeError('authority barrier unavailable')
        attempt=export('66','fc000000-0000-4000-8000-000000000006')
        blocked=subprocess.run(args,input='BEGIN; '+attempt+' COMMIT;',text=True,capture_output=True,timeout=10)
        if blocked.returncode==0 or 'collector gate busy' not in blocked.stderr: raise AssertionError('collector gate did not serialize')
        process.communicate(b'COMMIT;\n',timeout=10)
        if process.returncode: raise RuntimeError('authority transaction failed')
        committed=True
        denied=subprocess.run(args,input='BEGIN; '+attempt+' COMMIT;',text=True,capture_output=True,timeout=10)
        if denied.returncode==0 or '23514' not in denied.stderr: raise AssertionError('disabled collector was accepted')
        if execute("SELECT count(*) FROM contour.causal_leaf_reservations WHERE leaf_sha256=decode(repeat('66',32),'hex');")!='0':
            raise AssertionError('denied enrollment retained a leaf claim')
    finally:
        selector.close()
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill();process.wait(timeout=5)
        for stream in (process.stdin,process.stdout,process.stderr):
            if stream is not None: stream.close()
        if committed:
            execute("BEGIN; SELECT set_config('apicontour.tenant_id','"+t1+"',true); SET LOCAL ROLE contour_admin; SELECT contour.lock_collector('"+t1+"','f6000000-0000-4000-8000-000000000003'); UPDATE contour.collector_authorization SET enabled=true WHERE tenant_id='"+t1+"' AND collector_id='f6000000-0000-4000-8000-000000000003'; COMMIT;")
    # Revocation also leaves the lifecycle permanently bound, so a fresh
    # runtime ID and leaf cannot act as an implicit credential rotation.
    execute("SELECT set_config('apicontour.tenant_id','"+t1+"',false); SET ROLE contour_causal_provisioner; SELECT contour.end_causal_runtime('"+t1+"','fc000000-0000-4000-8000-000000000002','export_revoked');")
    retry=subprocess.run(args,input='BEGIN; '+export('99','fc000000-0000-4000-8000-000000000099')+' COMMIT;',text=True,capture_output=True,timeout=10)
    if retry.returncode==0 or '23505' not in retry.stderr: raise AssertionError('revoked lifecycle reused')
    if execute("SELECT count(*) FROM contour.causal_leaf_reservations WHERE leaf_sha256=decode(repeat('99',32),'hex');")!='0':
        raise AssertionError('revoked replacement retained a leaf claim')
    return 'cross-tenant leaf, lifecycle and current-authority races passed'


class PostgresDiagnosticError(RuntimeError):
    """Executor-supplied PostgreSQL diagnostic; do not include SQL or secrets."""

    def __init__(self, sqlstate, message):
        super().__init__("PostgreSQL fixture operation failed")
        self.sqlstate = sqlstate
        self.message = message


def verify_migration_failures(execute, migration_sql):
    """Run before migration18 in the caller-owned disposable PostgreSQL cluster.

    The executor must open a new psql session per call with ON_ERROR_STOP, so a
    failed transaction disconnects and rolls back. On SQL errors it must raise
    PostgresDiagnosticError with the parsed SQLSTATE and primary message.
    The caller must subsequently
    run the unmodified migration successfully; these expected failures alone do
    not establish that the migration is otherwise valid.
    """
    verify_qualified_profile()
    def unchanged():
        actual=execute("""SELECT (to_regclass('contour.causal_leaf_reservations') IS NULL
          AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='contour_causal_provisioner')
          AND (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)=ARRAY(SELECT generate_series(1,17))
          AND (SELECT count(*) FROM contour.origin_credentials)=3)::text;""")
        if actual!='true': raise AssertionError('failed migration left partial state')
    unchanged()
    try: execute('SET ROLE contour_admin; '+migration_sql)
    except PostgresDiagnosticError as error:
        if (error.sqlstate, error.message) != ('42501', 'trusted runtime registry migration required'):
            raise AssertionError('unexpected unprivileged migration diagnostic') from error
    else: raise AssertionError('unprivileged migration accepted')
    unchanged()
    marker="INSERT INTO contour.causal_leaf_reservations SELECT leaf_sha256,'product' FROM contour.origin_credentials;"
    if migration_sql.count(marker)!=1: raise ValueError('unexpected backfill source')
    injected=migration_sql.replace(marker,marker+" DO $$ BEGIN RAISE EXCEPTION 'fixture backfill rollback'; END $$;",1)
    try: execute(injected)
    except PostgresDiagnosticError as error:
        if (error.sqlstate, error.message) != ('P0001', 'fixture backfill rollback'):
            raise AssertionError('unexpected backfill failure diagnostic') from error
    else: raise AssertionError('backfill failure was not observed')
    unchanged()
    return 'unprivileged and interrupted-backfill rollback checks passed'


IMAGE='postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4'


def checked_file(path):
    """Reject symlinks in each repository-relative component before reading."""
    relative=path.relative_to(ROOT)
    current=ROOT
    for part in relative.parts:
        current=current/part
        if current.is_symlink(): raise ValueError('symlink in qualification source')
    if not current.is_file(): raise ValueError('qualification source missing')
    return current.read_bytes()


def source_snapshot():
    paths=[ROOT/'db/bootstrap.sql', *sorted((ROOT/'db').glob('provision_*.sql')),
           *sorted((ROOT/'db/migrations').glob('*.sql')),
           *sorted((ROOT/'db/opt-in-migrations').glob('*.sql')),
           ROOT/'db/tests/causal_runtime_registry_pre.sql', ROOT/'db/tests/causal_runtime_registry_post.sql',
           ROOT/'scripts/test-postgres-causal-registry.py', ROOT/'tests/fixtures/causal-registry/test_registry_driver.py',
           ROOT/'collectors/nodered/qualified-runtime-profile.json', ROOT/'collectors/nodered/error-integration/profile.js']
    return {str(p.relative_to(ROOT)):hashlib.sha256(checked_file(p)).hexdigest() for p in paths}


def cleanup_owned(run, cid, name, run_id):
    import re
    if not re.fullmatch('[0-9a-f]{64}',cid): raise RuntimeError('invalid container identity')
    info=json.loads(run(['docker','inspect',cid]))[0]
    if (info['Id']!=cid or info['Name']!='/'+name or
            info['Config']['Labels'].get('org.apicontour.registry-run')!=run_id):
        raise RuntimeError('container ownership mismatch')
    run(['docker','rm','-f',cid])
    if run(['docker','ps','-aq','--no-trunc','--filter','id='+cid]) or run(['docker','ps','-aq','--filter','name=^/'+name+'$']):
        raise RuntimeError('container cleanup incomplete')


def recover_owned_container(inspect, name, run_id):
    """Find a container after an ambiguous create; only explicit absence is benign."""
    import re
    info=inspect(name)
    if info is None: return None
    if not isinstance(info,list) or len(info)!=1: raise RuntimeError('ambiguous container inspection')
    item=info[0]; cid=item.get('Id','')
    if (not re.fullmatch('[0-9a-f]{64}',cid) or item.get('Name')!='/'+name or
            (item.get('Config',{}).get('Labels') or {}).get('org.apicontour.registry-run')!=run_id):
        raise RuntimeError('container ownership mismatch')
    return cid


def main():
    import re
    import sys
    if len(sys.argv)!=1: raise ValueError('this qualification takes no arguments')
    os.umask(0o077)
    before=source_snapshot()
    verify_qualified_profile()
    run_id=uuid.uuid4().hex; name='contour-causal-registry-'+run_id; cid=None; create_attempted=False
    def run(args, *, input=None, timeout=30):
        result=subprocess.run(args,input=input,text=True,capture_output=True,timeout=timeout)
        if result.returncode:
            diagnostic=re.search(r'^ERROR:\s+([0-9A-Z]{5}): (.*)$',result.stderr,re.M)
            if diagnostic: raise PostgresDiagnosticError(diagnostic.group(1),diagnostic.group(2))
            raise RuntimeError('owned fixture command failed')
        return result.stdout.strip()
    def execute(sql):
        return run(['docker','exec','-i',cid,'psql','-XqAt','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-h','/var/run/postgresql','-U','postgres','-d','contour_local'],input=sql)
    def inspect_name(container_name):
        result=subprocess.run(['docker','inspect',container_name],text=True,capture_output=True,timeout=30)
        if result.returncode:
            if re.fullmatch(r'Error: No such object: '+re.escape(container_name)+r'\s*',result.stderr): return None
            raise RuntimeError('container inspection failed')
        try: return json.loads(result.stdout)
        except (ValueError, TypeError) as error: raise RuntimeError('invalid container inspection') from error
    try:
        run(['docker','image','inspect',IMAGE])
        create_attempted=True
        candidate=run(['docker','create','--name',name,'--label','org.apicontour.registry-run='+run_id,'--network','none','--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql/data:rw,nosuid,noexec,size=256m','-e','POSTGRES_DB=contour_local','-e','POSTGRES_PASSWORD=isolated-fixture-only','-e','POSTGRES_HOST_AUTH_METHOD=reject','-e','POSTGRES_INITDB_ARGS=--auth-local=trust --auth-host=reject',IMAGE,'-c','listen_addresses=','-c','unix_socket_directories=/var/run/postgresql'])
        if not re.fullmatch('[0-9a-f]{64}',candidate): raise RuntimeError('invalid container identity')
        cid=candidate
        run(['docker','start',cid]); deadline=time.monotonic()+60
        while True:
            result=subprocess.run(['docker','exec',cid,'sh','-c','test "$(cat /proc/1/comm)" = postgres && pg_isready -h /var/run/postgresql -U postgres -d contour_local'],capture_output=True,timeout=5)
            if result.returncode==0: break
            if time.monotonic()>=deadline: raise RuntimeError('owned PostgreSQL readiness deadline')
            time.sleep(.2)
        execute(checked_file(ROOT/'db/bootstrap.sql').decode())
        for path in sorted((ROOT/'db').glob('provision_*.sql')): execute(checked_file(path).decode())
        for path in sorted((ROOT/'db/migrations').glob('*.sql')): execute(checked_file(path).decode())
        if execute('SELECT max(version) FROM contour.schema_migrations;')!='14': raise RuntimeError('unexpected baseline')
        for path in sorted((ROOT/'db/opt-in-migrations').glob('*.sql')):
            if int(path.name.split('_')[0])<=17: execute(checked_file(path).decode())
        execute(checked_file(ROOT/'db/tests/causal_runtime_registry_pre.sql').decode())
        migration=checked_file(ROOT/'db/opt-in-migrations/0018_causal_runtime_registry.sql').decode()
        verify_migration_failures(execute,migration)
        execute(migration)
        execute(checked_file(ROOT/'db/tests/causal_runtime_registry_post.sql').decode())
        run_cases(cid,execute)
    finally:
        if create_attempted and not cid: cid=recover_owned_container(inspect_name,name,run_id)
        if cid: cleanup_owned(run,cid,name,run_id)
        if source_snapshot()!=before: raise RuntimeError('qualification source changed')
    print('PASS: isolated causal registry qualification; no runtime or TLS claims')


if __name__=='__main__':
    main()
