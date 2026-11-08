#!/usr/bin/env python3
"""Disposable SQL-only generation-claim qualification; no signed issuer or Node claim."""
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
PROVISIONS = ('approval','authority','catalog','comparison','declared','human','origin_ingress','review','v2_ingress')
MIGRATIONS = ('0001_identity','0002_policy','0003_ingestion','0004_catalog','0005_declared','0006_approval','0007_comparison','0008_review','0009_human','0010_public_contracts','0011_import_selectors','0012_public_comparisons','0013_instance_registry','0014_observation_evidence')
OPT_INS = ('0015_origin_lifecycle','0016_v2_unattributed','0017_origin_proofs','0018_causal_runtime_registry','0019_causal_sessions','0020_causal_inbox','0021_origin_admission','0022_causal_generation')
EXTRA_SOURCE_MIGRATIONS = ('0023_causal_marker_bindings','0024_causal_live_profile')
SOURCES = (('db/bootstrap.sql',) + tuple('db/provision_'+x+'.sql' for x in PROVISIONS)
    + tuple('db/migrations/'+x+'.sql' for x in MIGRATIONS)
    + tuple('db/opt-in-migrations/'+x+'.sql' for x in OPT_INS + EXTRA_SOURCE_MIGRATIONS)
    + ('db/tests/causal_runtime_registry_pre.sql','db/tests/causal_session_setup.sql',
       'db/tests/causal_generation_basic.sql','scripts/test-postgres-causal-registry.py',
       'scripts/test-postgres-causal-sessions.py','scripts/test-postgres-causal-generation.py',
       'tests/fixtures/causal-generation/test_driver.py',
       'collectors/nodered/qualified-runtime-profile.json','collectors/nodered/error-integration/profile.js'))
CASES = ('basic','roles','revoked','expired','superseded','quota','rollback','race','delayed_insert')
TENANT='f0000000-0000-4000-8000-000000000001'
RUNTIME='fc000000-0000-4000-8000-000000000001'
NONCE='fe000000-0000-4000-8000-000000000001'
NEXT='fe000000-0000-4000-8000-000000000002'
GEN="decode(repeat('a1',32),'hex')"
OTHER="decode(repeat('a2',32),'hex')"


def checked_source(relative):
    path=ROOT/relative
    for part in (path,*path.parents):
        if part.is_symlink(): raise ValueError('source symlink')
    if not path.is_file(): raise ValueError('source missing')
    return path.read_bytes()


def source_snapshot():
    for pattern, expected in (
        ('db/provision_*.sql', {'db/provision_'+x+'.sql' for x in PROVISIONS}),
        ('db/migrations/*.sql', {'db/migrations/'+x+'.sql' for x in MIGRATIONS}),
        ('db/opt-in-migrations/*.sql', {'db/opt-in-migrations/'+x+'.sql' for x in OPT_INS + EXTRA_SOURCE_MIGRATIONS})):
        if {str(p.relative_to(ROOT)) for p in ROOT.glob(pattern)} != expected:
            raise ValueError('source list changed')
    return {path:hashlib.sha256(checked_source(path)).hexdigest() for path in SOURCES}


def helpers():
    checked_source('scripts/test-postgres-causal-registry.py')
    checked_source('scripts/test-postgres-causal-sessions.py')
    return (runpy.run_path(str(ROOT/'scripts/test-postgres-causal-registry.py')),
            runpy.run_path(str(ROOT/'scripts/test-postgres-causal-sessions.py')))


def psql_args(cid,db):
    if not re.fullmatch('[0-9a-f]{64}',cid) or not re.fullmatch('[a-z][a-z0-9_]{0,40}',db): raise ValueError('invalid fixture identity')
    return ['docker','exec','-i',cid,'psql','-XqAt','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-h','/var/run/postgresql','-U','postgres','-d',db]


def assert_fresh(execute,db):
    actual=execute(db,"SELECT current_database()||'|'||(SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations)||'|'||(SELECT count(*) FROM contour.causal_sessions)||'|'||(SELECT count(*) FROM contour.causal_generation_claims);")
    if actual != db+'|{'+','.join(map(str,range(1,23)))+'}|0|0': raise AssertionError('clone identity or ledger mismatch')


def _call(generation=GEN,nonce=NONCE,tenant=TENANT,runtime=RUNTIME,epoch=1):
    return f"contour.claim_causal_generation('{tenant}','{runtime}',{epoch},'{nonce}',{generation})"


def _expect(call,condition):
    return f"DO $$ BEGIN BEGIN PERFORM {call}; RAISE EXCEPTION 'unexpected acceptance' USING ERRCODE='P0001'; EXCEPTION WHEN {condition} THEN NULL; END; END $$;"


def _txn(helper,statement,role='contour_causal_issuer'):
    return 'BEGIN; '+helper['_setup'](role)+statement+' COMMIT;'


def _usage(execute,value):
    execute('BEGIN; '+"SELECT set_config('apicontour.tenant_id','"+TENANT+"',true); SET LOCAL ROLE contour_owner; SELECT contour.begin_origin_operation('"+TENANT+"'); "
            +f"INSERT INTO contour.origin_logical_usage VALUES ('{TENANT}',{value}) ON CONFLICT(tenant_id) DO UPDATE SET used_bytes=excluded.used_bytes; COMMIT;")


def _state(execute,rows,used):
    result=execute(f"SELECT (SELECT count(*) FROM contour.causal_generation_claims WHERE tenant_id='{TENANT}')||'|'||coalesce((SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='{TENANT}'),0);")
    if result!=f'{rows}|{used}': raise AssertionError('generation state mismatch')


def run_case(argv,execute,case,helper):
    if case not in CASES: raise ValueError('unknown generation case')
    setup=helper['_setup']; issue=helper['_issue']; claim=_call()
    if case=='delayed_insert':
        # Sequence advancement survives the rejected transaction; this proves
        # the INSERT trigger actually began while the short session was live.
        execute("CREATE SEQUENCE contour.fixture_generation_entered; GRANT USAGE,SELECT ON SEQUENCE contour.fixture_generation_entered TO contour_owner; CREATE FUNCTION contour.fixture_generation_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('contour.fixture_generation_entered'); PERFORM pg_sleep(3); RETURN NEW; END $$; CREATE TRIGGER fixture_generation_delay BEFORE INSERT ON contour.causal_generation_claims FOR EACH ROW EXECUTE FUNCTION contour.fixture_generation_delay();")
        short=helper['_claim'](NONCE).replace('900000000,10,1024,1024,60)', '2000000,10,1024,1024,60)')
        execute(_txn(helper,'SELECT * FROM contour.issue_causal_session('+short+');'))
        execute(_txn(helper,f"DO $$ BEGIN IF NOT contour.check_causal_session('{TENANT}','{RUNTIME}',1) THEN RAISE EXCEPTION 'short session expired before test'; END IF; END $$;"))
        execute(_txn(helper,_expect(claim,'check_violation')))
        entry=execute("SELECT is_called::text||'|'||last_value::text FROM contour.fixture_generation_entered;")
        if entry != 'true|1': raise AssertionError('delayed insert trigger not entered exactly once')
        _state(execute,0,0); return
    execute('BEGIN; '+issue(NONCE)+' COMMIT;')
    if case=='basic':
        prefix=''.join("SELECT set_config('test.generation_"+name+"','"+value+"',false);" for name,value in [('tenant',TENANT),('runtime',RUNTIME),('epoch','1'),('nonce',NONCE)])
        execute(prefix+checked_source('db/tests/causal_generation_basic.sql').decode()); return
    if case=='roles':
        execute(_txn(helper,_expect(claim,'insufficient_privilege'),'contour_runtime'))
        execute(_txn(helper,_expect(_call(nonce=NEXT),'check_violation')))
        execute(_txn(helper,_expect(_call(runtime='fc000000-0000-4000-8000-000000000099'),'check_violation')))
        wrong=_call(tenant='f0000000-0000-4000-8000-000000000002')
        execute(_txn(helper,_expect(wrong,'insufficient_privilege')))
        _state(execute,0,0); return
    if case=='quota':
        _usage(execute,1073741824); execute(_txn(helper,_expect(claim,'program_limit_exceeded'))); _state(execute,0,1073741824)
        _usage(execute,1073741732); execute(_txn(helper,'SELECT '+claim+';')); _state(execute,1,1073741824)
        execute(_txn(helper,'SELECT '+claim+';')); _state(execute,1,1073741824); return
    if case=='rollback':
        execute('BEGIN; '+setup('contour_causal_issuer')+'SELECT '+claim+'; ROLLBACK;'); _state(execute,0,0)
        execute(_txn(helper,'SELECT '+_call(OTHER)+';')); _state(execute,1,92); return
    if case=='race':
        a=setup('contour_causal_issuer')+'SELECT '+claim+';'
        b=setup('contour_causal_issuer')+'SELECT '+_call(OTHER)+';'
        helper['race'](argv,a,b,b,retry_sqlstate='23505'); _state(execute,1,92); return
    execute(_txn(helper,'SELECT '+claim+';')); _state(execute,1,92)
    if case=='revoked': execute('BEGIN; '+helper['_terminal']('export_revoked')+' COMMIT;')
    elif case=='superseded': execute('BEGIN; '+issue(NEXT)+' COMMIT;')
    elif case=='expired':
        # A separately issued short session is required; old one is superseded.
        short=helper['_claim'](NEXT).replace('900000000,10,1024,1024,60)', '1000000,10,1024,1024,60)')
        execute(_txn(helper,'SELECT * FROM contour.issue_causal_session('+short+');'))
        execute(_txn(helper,'SELECT '+_call(nonce=NEXT,epoch=2)+';'))
        execute('SELECT pg_sleep(1.2);')
        claim=_call(nonce=NEXT,epoch=2)
    execute(_txn(helper,_expect(claim,'check_violation')))
    _state(execute,2 if case=='expired' else 1,184 if case=='expired' else 92)


def qualify_cases(cid,execute,run_case_fn,helper):
    if len(CASES)!=len(set(CASES)) or len(CASES)!=9: raise RuntimeError('invalid case list')
    for index,case in enumerate(CASES):
        db='generation_case_'+str(index); created=False
        try:
            execute('postgres','CREATE DATABASE '+db+' TEMPLATE contour_local;'); created=True
            assert_fresh(execute,db)
            run_case_fn(psql_args(cid,db),lambda sql, db=db:execute(db,sql),case,helper)
        finally:
            if created: execute('postgres','DROP DATABASE '+db+';')
        print('PASS:',case,flush=True)


def main():
    if len(sys.argv)!=1: raise ValueError('no arguments accepted')
    os.umask(0o077); before=source_snapshot(); registry,session=helpers(); registry['verify_qualified_profile']()
    run_id=uuid.uuid4().hex; name='contour-causal-generation-'+run_id; cid=None; attempted=False
    def command(args,input=None,timeout=30): return session['_run'](args,input=input,timeout=timeout)
    def inspect_name(value):
        result=subprocess.run(['docker','inspect',value],text=True,capture_output=True,timeout=30)
        if result.returncode:
            if re.fullmatch(r'Error: No such object: '+re.escape(value)+r'\s*',result.stderr): return None
            raise RuntimeError('container inspection failed')
        return json.loads(result.stdout)
    def alarm(_sig,_frame): raise TimeoutError('generation qualification exceeded deadline')
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
        def execute(db,sql): return command(psql_args(cid,db),input=sql,timeout=120)
        execute('contour_local',checked_source('db/bootstrap.sql').decode())
        for name_part in PROVISIONS: execute('contour_local',checked_source('db/provision_'+name_part+'.sql').decode())
        for name_part in MIGRATIONS: execute('contour_local',checked_source('db/migrations/'+name_part+'.sql').decode())
        for name_part in OPT_INS[:3]: execute('contour_local',checked_source('db/opt-in-migrations/'+name_part+'.sql').decode())
        execute('contour_local',checked_source('db/tests/causal_runtime_registry_pre.sql').decode())
        execute('contour_local',checked_source('db/opt-in-migrations/'+OPT_INS[3]+'.sql').decode())
        execute('contour_local',checked_source('db/tests/causal_session_setup.sql').decode())
        for name_part in OPT_INS[4:]: execute('contour_local',checked_source('db/opt-in-migrations/'+name_part+'.sql').decode())
        assert_fresh(execute,'contour_local'); qualify_cases(cid,execute,run_case,session)
    finally:
        signal.setitimer(signal.ITIMER_REAL,0); signal.signal(signal.SIGALRM,previous)
        try:
            if attempted and not cid: cid=registry['recover_owned_container'](inspect_name,name,run_id)
            if cid: registry['cleanup_owned'](command,cid,name,run_id)
        finally:
            if source_snapshot()!=before: raise RuntimeError('qualification source changed')
    print('PASS: isolated SQL generation claims; no signed issuer, Node, mTLS or journal integration')

if __name__=='__main__': main()
