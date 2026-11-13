#!/usr/bin/env python3
"""Disposable SQL23 qualification. Synthetic SQL only; no TLS, signing or launch."""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).absolute().parent.parent
def load_generation(root):
    path=root/'scripts/test-postgres-causal-generation.py'
    for part in (path,*path.parents):
        if part.is_symlink(): raise ValueError('source symlink')
    if not path.is_file(): raise ValueError('source missing')
    return runpy.run_path(str(path))

GEN = load_generation(ROOT)
T, R, N = GEN['TENANT'], GEN['RUNTIME'], GEN['NONCE']
C = 'fa000000-0000-4000-8000-000000000001'
C2 = 'fa000000-0000-4000-8000-000000000011'
L = 'f9000000-0000-4000-8000-000000000001'
CASES = ('basic','wrong_identity','quota','rollback','race','export_revoked','credential_revoked','lifecycle_closed','selected_revoked_other_live','superseded','expired','product_leaf_lock','export_leaf_lock','disabled_duplicate','policy_drift_duplicate','delayed_insert')
EXTRAS = ('db/opt-in-migrations/0023_causal_marker_bindings.sql', 'db/tests/causal_marker_bindings.sql',
          'scripts/test-postgres-causal-marker-binding.py','tests/fixtures/causal-marker-binding/test_driver.py')
SOURCE_ONLY_MIGRATIONS = ('db/opt-in-migrations/0024_causal_live_profile.sql','db/opt-in-migrations/0025_historical_origin.sql','db/opt-in-migrations/0026_causal_evidence_enrollment.sql','db/opt-in-migrations/0027_causal_observer_inbox.sql','db/opt-in-migrations/0028_causal_receiver_enrollment.sql','db/opt-in-migrations/0029_causal_receiver_inbox.sql','db/opt-in-migrations/0030_causal_gateway_reader.sql')
SOURCES = GEN['SOURCES'] + EXTRAS + SOURCE_ONLY_MIGRATIONS


def checked_source(name):
    path=ROOT/name
    for part in (path,*path.parents):
        if part.is_symlink(): raise ValueError('source symlink')
    if not path.is_file(): raise ValueError('source missing')
    return path.read_bytes()


def snapshot():
    for pattern,expected in (('db/provision_*.sql',{'db/provision_'+x+'.sql' for x in GEN['PROVISIONS']}),
       ('db/migrations/*.sql',{'db/migrations/'+x+'.sql' for x in GEN['MIGRATIONS']}),
       ('db/opt-in-migrations/*.sql',{'db/opt-in-migrations/'+x+'.sql' for x in GEN['OPT_INS']}|{EXTRAS[0]}|set(SOURCE_ONLY_MIGRATIONS))):
        if {str(p.relative_to(ROOT)) for p in ROOT.glob(pattern)} != expected: raise ValueError('source list changed')
    return {p:hashlib.sha256(checked_source(p)).hexdigest() for p in SOURCES}


def bind(*,nonce=N,generation="decode(repeat('a1',32),'hex')",credential=C,leaf='11',marker='42',epoch=1):
    return (f"contour.bind_causal_marker_key('{T}','{R}',{epoch},'{nonce}',{generation},"
            f"'{credential}',decode(repeat('{leaf}',32),'hex'),decode(repeat('{marker}',32),'hex'))")


def txn(helper,sql,role='contour_causal_provisioner'):
    return 'BEGIN; '+helper['_setup'](role)+sql+' COMMIT;'


def state(execute,rows,used):
    actual=execute(f"SELECT (SELECT count(*) FROM contour.causal_marker_bindings WHERE tenant_id='{T}')||'|'||coalesce((SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='{T}'),0);")
    if actual!=f'{rows}|{used}': raise AssertionError('marker rows or quota mismatch')


def run_case(argv,execute,case,h):
    if case not in CASES: raise ValueError('unknown case')
    issue=h['_issue']; expect=GEN['_expect']; claim=GEN['_call']()
    if case in ('expired','delayed_insert'):
        ttl='5000000' if case=='expired' else '4000000'
        short=h['_claim'](N).replace('900000000,10,1024,1024,60)', ttl+',10,1024,1024,60)')
        execute(txn(h,'SELECT * FROM contour.issue_causal_session('+short+');','contour_causal_issuer'))
    else: execute('BEGIN; '+issue(N)+' COMMIT;')
    execute(txn(h,'SELECT '+claim+';','contour_causal_issuer'))
    if case=='basic':
        values={'tenant':T,'runtime':R,'epoch':'1','nonce':N}
        prefix=''.join(f"SELECT set_config('test.generation_{k}','{v}',false);" for k,v in values.items())
        execute(prefix+f"SELECT set_config('test.marker_credential','{C}',false);"+checked_source(EXTRAS[1]).decode()); return
    if case=='wrong_identity':
        for value in (bind(nonce=GEN['NEXT']),bind(generation=GEN['OTHER']),bind(epoch=2),bind(credential=C2),bind(leaf='22'),bind(credential='fa000000-0000-4000-8000-000000000003',leaf='03'),bind(credential='fa000000-0000-4000-8000-000000000002',leaf='22')):
            execute(txn(h,expect(value,'check_violation')))
        state(execute,0,92); return
    if case=='delayed_insert':
        execute("CREATE SEQUENCE contour.fixture_marker_delayed; GRANT USAGE,SELECT ON SEQUENCE contour.fixture_marker_delayed TO contour_owner; CREATE FUNCTION contour.fixture_marker_delayed_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('contour.fixture_marker_delayed'); PERFORM pg_sleep(5); RETURN NEW; END $$; CREATE TRIGGER fixture_marker_delayed_insert BEFORE INSERT ON contour.causal_marker_bindings FOR EACH ROW EXECUTE FUNCTION contour.fixture_marker_delayed_insert();")
        execute(txn(h,f"DO $$ BEGIN IF NOT contour.check_causal_session('{T}','{R}',1) THEN RAISE EXCEPTION 'short session already expired'; END IF; END $$;",'contour_causal_issuer'))
        execute(txn(h,expect(bind(),'check_violation')))
        if execute("SELECT is_called::text||'|'||last_value::text FROM contour.fixture_marker_delayed;")!='true|1': raise AssertionError('delayed insert not entered')
        state(execute,0,92); return
    if case=='quota':
        GEN['_usage'](execute,1073741824); execute(txn(h,expect(bind(),'program_limit_exceeded'))); state(execute,0,1073741824)
        GEN['_usage'](execute,1073741552); execute(txn(h,'SELECT '+bind()+';')); state(execute,1,1073741824)
        execute(txn(h,'SELECT '+bind()+';')); state(execute,1,1073741824); return
    if case=='rollback':
        execute('BEGIN; '+h['_setup']('contour_causal_provisioner')+'SELECT '+bind()+'; ROLLBACK;'); state(execute,0,92)
        execute(txn(h,'SELECT '+bind(marker='43')+';')); state(execute,1,364); return
    if case=='race':
        a=h['_setup']('contour_causal_provisioner')+'SELECT '+bind()+';'
        b=h['_setup']('contour_causal_provisioner')+'SELECT '+bind(marker='43')+';'
        h['race'](argv,a,b,b,retry_sqlstate='23505'); state(execute,1,364); return
    if case in ('product_leaf_lock','export_leaf_lock'):
        lock_leaf='11' if case=='product_leaf_lock' else '33'
        winner=h['_setup']('contour_owner')+f"SELECT contour.lock_origin_credential(decode(repeat('{lock_leaf}',32),'hex'));"
        candidate=h['_setup']('contour_causal_provisioner')+'SELECT '+bind()+';'
        h['race'](argv,winner,candidate,candidate); state(execute,1,364); return
    if case=='selected_revoked_other_live':
        execute(txn(h,f"SELECT contour.enroll_origin_credential('{T}','{C2}','{L}',decode(repeat('44',32),'hex'));",'contour_admin'))
    execute(txn(h,'SELECT '+bind()+';')); state(execute,1,364)
    if case in ('disabled_duplicate','policy_drift_duplicate'):
        kind='disable' if case=='disabled_duplicate' else 'cas'
        execute('BEGIN; '+h['_policy_change'](kind)+' COMMIT;')
    elif case in ('export_revoked','credential_revoked','lifecycle_closed'):
        execute('BEGIN; '+h['_terminal'](case)+' COMMIT;')
    elif case=='selected_revoked_other_live': execute('BEGIN; '+h['_terminal']('credential_revoked')+' COMMIT;')
    elif case=='superseded': execute('BEGIN; '+issue(GEN['NEXT'])+' COMMIT;')
    elif case=='expired': execute('SELECT pg_sleep(5.2);')
    if case=='selected_revoked_other_live':
        execute(txn(h,f"DO $$ BEGIN IF NOT contour.check_causal_session('{T}','{R}',1) THEN RAISE EXCEPTION 'other live credential not authoritative'; END IF; END $$;",'contour_causal_issuer'))
    execute(txn(h,expect(bind(),'check_violation'))); state(execute,1,364)


def assert_fresh(execute,db):
    value=execute(db,"SELECT current_database()||'|'||(SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations)||'|'||(SELECT count(*) FROM contour.causal_sessions)||'|'||(SELECT count(*) FROM contour.causal_generation_claims)||'|'||(SELECT count(*) FROM contour.causal_marker_bindings);")
    if value!=db+'|{'+','.join(map(str,range(1,24)))+'}|0|0|0': raise AssertionError('clone identity or ledger mismatch')


def qualify(cid,execute,helper):
    if len(CASES)!=16 or len(set(CASES))!=16: raise RuntimeError('invalid case list')
    for i,case in enumerate(CASES):
        db='marker_case_'+str(i); created=False
        try:
            execute('postgres','CREATE DATABASE '+db+' TEMPLATE contour_local;'); created=True
            assert_fresh(execute,db)
            run_case(GEN['psql_args'](cid,db),lambda sql:execute(db,sql),case,helper)
        finally:
            primary=sys.exc_info()[1]
            try:
                if created: execute('postgres','DROP DATABASE '+db+';')
            except BaseException as cleanup:
                if primary is not None: raise BaseExceptionGroup('case and cleanup',[primary,cleanup]) from None
                raise
        print('PASS:',case,flush=True)


def main():
    if len(sys.argv)!=1: raise ValueError('no arguments accepted')
    os.umask(0o077); before=snapshot(); registry,session=GEN['helpers'](); registry['verify_qualified_profile']()
    run_id=uuid.uuid4().hex; name='contour-causal-marker-'+run_id; cid=None; attempted=False
    def command(args,input=None,timeout=30): return session['_run'](args,input=input,timeout=timeout)
    def inspect_name(value):
        result=subprocess.run(['docker','inspect',value],text=True,capture_output=True,timeout=30)
        if result.returncode:
            if re.fullmatch(r'Error: No such object: '+re.escape(value)+r'\s*',result.stderr): return None
            raise RuntimeError('container inspection failed')
        return json.loads(result.stdout)
    def alarm(_sig,_frame): raise TimeoutError('marker qualification exceeded deadline')
    previous=signal.signal(signal.SIGALRM,alarm); signal.setitimer(signal.ITIMER_REAL,600)
    try:
        command(['docker','image','inspect',registry['IMAGE']]); attempted=True
        candidate=command(['docker','create','--pull=never','--name',name,'--label','org.apicontour.registry-run='+run_id,'--network','none','--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql/data:rw,nosuid,noexec,size=256m','-e','POSTGRES_DB=contour_local','-e','POSTGRES_PASSWORD=isolated-fixture-only','-e','POSTGRES_HOST_AUTH_METHOD=reject','-e','POSTGRES_INITDB_ARGS=--auth-local=trust --auth-host=reject',registry['IMAGE'],'-c','listen_addresses=','-c','unix_socket_directories=/var/run/postgresql'])
        if not re.fullmatch('[0-9a-f]{64}',candidate): raise RuntimeError('invalid container identity')
        cid=candidate
        command(['docker','start',cid]); deadline=time.monotonic()+60
        while True:
            result=subprocess.run(['docker','exec',cid,'sh','-c','test "$(cat /proc/1/comm)" = postgres && pg_isready -h /var/run/postgresql -U postgres -d contour_local'],capture_output=True,timeout=5)
            if result.returncode==0: break
            if time.monotonic()>=deadline: raise TimeoutError('PostgreSQL readiness deadline')
            time.sleep(.2)
        def execute(db,sql): return command(GEN['psql_args'](cid,db),input=sql,timeout=120)
        execute('contour_local',checked_source('db/bootstrap.sql').decode())
        for item in GEN['PROVISIONS']: execute('contour_local',checked_source('db/provision_'+item+'.sql').decode())
        for item in GEN['MIGRATIONS']: execute('contour_local',checked_source('db/migrations/'+item+'.sql').decode())
        for item in GEN['OPT_INS'][:3]: execute('contour_local',checked_source('db/opt-in-migrations/'+item+'.sql').decode())
        execute('contour_local',checked_source('db/tests/causal_runtime_registry_pre.sql').decode())
        execute('contour_local',checked_source('db/opt-in-migrations/'+GEN['OPT_INS'][3]+'.sql').decode())
        execute('contour_local',checked_source('db/tests/causal_session_setup.sql').decode())
        for item in GEN['OPT_INS'][4:]: execute('contour_local',checked_source('db/opt-in-migrations/'+item+'.sql').decode())
        execute('contour_local',checked_source(EXTRAS[0]).decode())
        assert_fresh(execute,'contour_local'); qualify(cid,execute,session)
    finally:
        primary=sys.exc_info()[1]; failures=[]
        def cleanup(action):
            try: action()
            except BaseException as error: failures.append(error)
        cleanup(lambda:signal.setitimer(signal.ITIMER_REAL,0))
        cleanup(lambda:signal.signal(signal.SIGALRM,previous))
        def owned_cleanup():
            owned=cid
            if attempted and not owned: owned=registry['recover_owned_container'](inspect_name,name,run_id)
            if owned: registry['cleanup_owned'](command,owned,name,run_id)
        cleanup(owned_cleanup)
        def source_check():
            if snapshot()!=before: raise RuntimeError('qualification source changed')
        cleanup(source_check)
        if failures:
            raise BaseExceptionGroup('qualification',([primary] if primary is not None else [])+failures) from None
    print('PASS: isolated SQL marker bindings; no signed issuer, bridge, Node, mTLS or launch')

if __name__=='__main__':
    try: main()
    except BaseException as error:
        print('FAIL:',type(error).__name__,file=sys.stderr)
        sys.exit(1)
