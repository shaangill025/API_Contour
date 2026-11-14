"""Qualify internal causal sessions in one disposable isolated PostgreSQL.

The default command runs SQL fixtures and deterministic races in fresh cloned
databases. Helper callers can supply their own disposable database and psql
argv. All claims are synthetic; no signature, TLS or runtime is exercised.
"""
import os
import re
import selectors
import subprocess
import time
import uuid


def race(psql_argv, winner_sql, contender_sql, retry_sql, *, rollback=False,
         retry_sqlstate=None, timeout=15):
    """Hold winner's locks, require contender 40001, then check the retry.

    Supply winner/contender in both orders to exercise issue/issue, issue/CAS,
    issue/revoke and issue/terminal. A rollback winner tests absence of leaked
    epoch, nonce and highwater through a caller-supplied positive retry/assertion.
    Every SQL statement should raise on a failed positive assertion. The caller
    must additionally check committed rows and expected terminal state.
    """
    marker = 'session_barrier_' + uuid.uuid4().hex
    process = subprocess.Popen(psql_argv, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               bufsize=0)
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        process.stdin.write(('BEGIN;\n' + winner_sql + '\n\\echo ' + marker + '\n').encode())
        process.stdin.flush()
        deadline = time.monotonic() + timeout
        output = b''
        while marker.encode() not in output.splitlines():
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise TimeoutError('session lock barrier not reached')
            part = os.read(process.stdout.fileno(), 65536)
            if not part:
                raise RuntimeError('session winner exited before barrier')
            output += part
            if len(output) > 65536:
                raise RuntimeError('session barrier output limit')
        rival = subprocess.run(psql_argv, input='BEGIN;\n' + contender_sql + '\nCOMMIT;\n',
                               text=True, capture_output=True, timeout=timeout)
        if rival.returncode == 0 or not re.search(r'ERROR:\s+40001:', rival.stderr):
            raise AssertionError('contender did not fail with serialization_failure')
        _, errors = process.communicate(('ROLLBACK;\n' if rollback else 'COMMIT;\n').encode(), timeout=timeout)
        if process.returncode:
            raise RuntimeError('winner transaction failed: ' + errors.decode(errors='replace'))
        retry = subprocess.run(psql_argv, input='BEGIN;\n' + retry_sql + '\nCOMMIT;\n',
                               text=True, capture_output=True, timeout=timeout)
        if retry_sqlstate is None:
            if retry.returncode:
                raise AssertionError('positive retry failed: ' + retry.stderr)
        elif retry.returncode == 0 or not re.search(r'ERROR:\s+' + re.escape(retry_sqlstate) + r':', retry.stderr):
            raise AssertionError('retry did not produce expected SQLSTATE')
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)

# Each scenario requires a freshly provisioned disposable database after
# causal_session_setup.sql and migration 19 (without causal_session_basic.sql).
# psql_argv must use ON_ERROR_STOP=1 and VERBOSITY=verbose. execute(sql) uses
# the same database and raises on SQL failure. All identities and bytes below
# are synthetic; they are not signed claims or transport authentication.
TENANT = 'f0000000-0000-4000-8000-000000000001'
RUNTIME = 'fc000000-0000-4000-8000-000000000001'
COLLECTOR = 'f6000000-0000-4000-8000-000000000001'


def _claim(nonce, revision=1, digest='ab'):
    return ("ROW('" + TENANT + "'::uuid,'" + RUNTIME + "'::uuid,'" + COLLECTOR + "'::uuid,"
            "'f7000000-0000-4000-8000-000000000001'::uuid,"
            "'f1000000-0000-4000-8000-000000000001'::uuid,"
            "'f2000000-0000-4000-8000-000000000001'::uuid,"
            "'f3000000-0000-4000-8000-000000000001'::uuid,"
            "'f4000000-0000-4000-8000-000000000001'::uuid,"
            "'f5000000-0000-4000-8000-000000000001'::uuid,"
            "'f9000000-0000-4000-8000-000000000001'::uuid,decode(repeat('33',32),'hex'),"
            "'nodered_5_0_9_v1',decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex'),'"
            + nonce + "'::uuid," + str(revision) + ",decode(repeat('" + digest + "',32),'hex'),"
            "clock_timestamp()-interval '1 minute',clock_timestamp()+interval '10 minutes',"
            "1,decode('01','hex'),clock_timestamp()-interval '1 minute',clock_timestamp()+interval '10 minutes',"
            "900000000,10,1024,1024,60)::contour.causal_session_claim")


def _setup(role):
    return "SELECT set_config('apicontour.tenant_id','" + TENANT + "',true); SET LOCAL ROLE " + role + "; "


def _issue(nonce, revision=1, digest='ab'):
    return _setup('contour_causal_issuer') + 'SELECT * FROM contour.issue_causal_session(' + _claim(nonce, revision, digest) + ');'


def _terminal(kind):
    if kind in ('runtime_closed', 'export_revoked'):
        return (_setup('contour_causal_provisioner') + "SELECT contour.end_causal_runtime('" + TENANT + "','" + RUNTIME + "','" + kind + "');")
    target = ('fa000000-0000-4000-8000-000000000001' if kind == 'credential_revoked'
              else 'f9000000-0000-4000-8000-000000000001')
    return _setup('contour_admin') + "SELECT contour.end_origin('" + TENANT + "','" + kind + "','" + target + "');"



def _policy_change(kind):
    prefix = _setup('contour_admin') + "SELECT contour.lock_collector('" + TENANT + "','" + COLLECTOR + "'); "
    where = " WHERE tenant_id='" + TENANT + "' AND collector_id='" + COLLECTOR + "'"
    if kind == 'cas':
        return (prefix + "INSERT INTO contour.policy_revisions VALUES ('" + TENANT + "','" + COLLECTOR + "',2,decode('02','hex')); "
                "UPDATE contour.collector_authorization SET active_revision=2" + where + " AND active_revision=1;")
    if kind == 'disable':
        return prefix + 'UPDATE contour.collector_authorization SET enabled=false' + where + ';'
    if kind == 'revoke':
        return prefix + 'UPDATE contour.collector_authorization SET enabled=false,revoked_at=clock_timestamp()' + where + ';'
    raise ValueError('unknown policy change')


def _assert_rows(execute, count, highest):
    execute("DO $$ BEGIN IF (SELECT count(*) FROM contour.causal_sessions)<>" + str(count)
            + " OR coalesce((SELECT max(epoch) FROM contour.causal_sessions),0)<>" + str(highest)
            + " THEN RAISE EXCEPTION 'concurrency rows mismatch'; END IF; END $$;")


def run_scenario(psql_argv, execute, scenario):
    """Run one named concrete race against a newly initialized disposable DB.

    Caller repeats setup for each scenario. SQL role and signed claim inputs are
    synthetic. The race verifies serialization and post-commit state; it does
    not verify mTLS, signatures, or application integration.
    """
    one = 'fe000000-0000-4000-8000-000000000011'
    two = 'fe000000-0000-4000-8000-000000000012'
    if scenario == 'issue_issue':
        race(psql_argv, _issue(one), _issue(two), _issue(two))
        _assert_rows(execute, 2, 2)
        check = (_setup('contour_causal_issuer') + "DO $$ BEGIN IF contour.check_causal_session('" + TENANT + "','" + RUNTIME + "',1) THEN RAISE EXCEPTION 'superseded accepted'; END IF; END $$;")
        execute('BEGIN; ' + check + ' COMMIT;')
        check = (_setup('contour_causal_issuer') + "DO $$ BEGIN IF NOT contour.check_causal_session('" + TENANT + "','" + RUNTIME + "',2) THEN RAISE EXCEPTION 'latest session denied'; END IF; END $$;")
        execute('BEGIN; ' + check + ' COMMIT;')
    elif scenario == 'rollback':
        # Rolled-back revision 2 and nonce must not block the lower revision or
        # same nonce on retry, and no epoch may be consumed.
        race(psql_argv, _issue(one, 2), _issue(two), _issue(one, 1), rollback=True)
        _assert_rows(execute, 1, 1)
    elif scenario in ('runtime_closed', 'export_revoked', 'credential_revoked', 'lifecycle_closed'):
        # Test terminal winner: a concurrent issuance gets 40001; after commit
        # the same issuance must fail for current terminal authorization.
        race(psql_argv, _terminal(scenario), _issue(one), _issue(one), retry_sqlstate='23514')
        _assert_rows(execute, 0, 0)
    elif scenario.startswith('issue_then_') and scenario[11:] in ('runtime_closed', 'export_revoked', 'credential_revoked', 'lifecycle_closed'):
        kind = scenario[11:]
        race(psql_argv, _issue(one), _terminal(kind), _terminal(kind))
        _assert_rows(execute, 1, 1)
        check = (_setup('contour_causal_issuer') + "DO $$ BEGIN IF contour.check_causal_session('" + TENANT + "','" + RUNTIME + "',1) THEN RAISE EXCEPTION 'terminal session accepted'; END IF; END $$;")
        execute('BEGIN; ' + check + ' COMMIT;')
    elif scenario in ('issue_cas', 'issue_disable', 'issue_revoke'):
        # Legacy CAS blocks on C rather than returning 40001. Observe the actual
        # PostgreSQL lock wait before releasing the issue transaction.
        marker = 'session_issue_' + uuid.uuid4().hex
        app = 'session_cas_' + uuid.uuid4().hex
        winner = subprocess.Popen(psql_argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        rival = None
        selector = selectors.DefaultSelector()
        try:
            selector.register(winner.stdout, selectors.EVENT_READ)
            winner.stdin.write(('BEGIN; ' + _issue(one) + '\n\\echo ' + marker + '\n').encode())
            winner.stdin.flush()
            deadline = time.monotonic() + 15
            output = b''
            while marker.encode() not in output.splitlines():
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError('issue barrier not reached')
                part = os.read(winner.stdout.fileno(), 65536)
                if not part:
                    raise RuntimeError('issue winner exited before barrier')
                output += part
                if len(output) > 65536:
                    raise RuntimeError('issue barrier output limit')
            cas = _policy_change(scenario.removeprefix('issue_'))
            rival = subprocess.Popen(psql_argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            rival.stdin.write(("SET application_name='" + app + "'; BEGIN; " + cas + " COMMIT;\n").encode())
            rival.stdin.close()
            rival.stdin = None
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                waiting = execute("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name='" + app + "' AND wait_event_type='Lock';")
                if waiting.strip() == '1':
                    break
                if rival.poll() is not None:
                    raise AssertionError('CAS exited without waiting for C')
                time.sleep(0.05)
            else:
                raise TimeoutError('CAS lock wait not observed')
            _, errors = winner.communicate(b'COMMIT;\n', timeout=15)
            if winner.returncode:
                raise RuntimeError('issue commit failed: ' + errors.decode(errors='replace'))
            _, errors = rival.communicate(timeout=15)
            if rival.returncode:
                raise RuntimeError('CAS after issue failed: ' + errors.decode(errors='replace'))
            check = (_setup('contour_causal_issuer') + "DO $$ BEGIN IF contour.check_causal_session('" + TENANT + "','" + RUNTIME + "',1) THEN RAISE EXCEPTION 'superseded policy accepted'; END IF; END $$;")
            execute('BEGIN; ' + check + ' COMMIT;')
            _assert_rows(execute, 1, 1)
        finally:
            selector.close()
            for process in (winner, rival):
                if process is not None and process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
    elif scenario in ('cas_issue', 'disable_issue', 'revoke_issue'):
        # Legacy administrative CAS owns C without Q. An issuer can take Q and
        # leaf but must fail immediately on C; after CAS it cannot use old head.
        cas = _policy_change(scenario.removesuffix('_issue'))
        race(psql_argv, cas, _issue(one), _issue(one), retry_sqlstate='23514')
        _assert_rows(execute, 0, 0)
    else:
        raise ValueError('unknown scenario: ' + scenario)

# Self-contained disposable qualification. The registry helper supplies the
# pinned image, checked reads, typed diagnostics and ownership-safe cleanup.
import hashlib
import json
from pathlib import Path
import runpy
import signal
import sys

ROOT = Path(__file__).absolute().parent.parent
PROVISIONS = ('approval','authority','catalog','comparison','declared','human','origin_ingress','review','v2_ingress')
MIGRATIONS = ('0001_identity','0002_policy','0003_ingestion','0004_catalog','0005_declared',
              '0006_approval','0007_comparison','0008_review','0009_human','0010_public_contracts',
              '0011_import_selectors','0012_public_comparisons','0013_instance_registry','0014_observation_evidence')
OPT_INS = ('0015_origin_lifecycle','0016_v2_unattributed','0017_origin_proofs',
           '0018_causal_runtime_registry','0019_causal_sessions')
# Reviewed sources that this 1..19 session qualification hashes, but never applies.
EXTRA_SOURCE_MIGRATIONS = ('0020_causal_inbox','0021_origin_admission','0022_causal_generation','0023_causal_marker_bindings','0024_causal_live_profile','0025_historical_origin','0026_causal_evidence_enrollment','0027_causal_observer_inbox','0028_causal_receiver_enrollment','0029_causal_receiver_inbox','0030_causal_gateway_reader','0031_causal_edge_reconciliation','0032_human_causal_reader')
TERMINALS = ('runtime_closed','export_revoked','credential_revoked','lifecycle_closed')
SCENARIOS = (('issue_issue','rollback') + TERMINALS + tuple('issue_then_'+x for x in TERMINALS)
             + ('issue_cas','issue_disable','issue_revoke','cas_issue','disable_issue','revoke_issue'))
SOURCE_PATHS = (('db/bootstrap.sql',) + tuple('db/provision_'+x+'.sql' for x in PROVISIONS)
                + tuple('db/migrations/'+x+'.sql' for x in MIGRATIONS)
                + tuple('db/opt-in-migrations/'+x+'.sql' for x in OPT_INS + EXTRA_SOURCE_MIGRATIONS)
                + ('db/tests/causal_runtime_registry_pre.sql','db/tests/causal_runtime_registry_post.sql',
                   'db/tests/causal_session_setup.sql','db/tests/causal_session_basic.sql',
                   'db/tests/causal_session_clock.sql','scripts/test-postgres-causal-registry.py',
                   'scripts/test-postgres-causal-sessions.py',
                   'tests/fixtures/causal-registry/test_registry_driver.py',
                   'tests/fixtures/causal-sessions/test_session_driver.py',
                   'collectors/nodered/qualified-runtime-profile.json',
                   'collectors/nodered/error-integration/profile.js','.github/workflows/native.yml'))


def checked_source(relative):
    """Fail closed on missing files and symlinks in all absolute ancestors."""
    path = ROOT / relative
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError('symlink in qualification source: ' + relative)
    if not path.is_file():
        raise ValueError('qualification source missing: ' + relative)
    return path.read_bytes()


def source_snapshot():
    # Fixed lists ensure missing required files fail; reject additional migration
    # or provisioning SQL instead of silently omitting it from the snapshot.
    for pattern, expected in (
        ('db/provision_*.sql', {'db/provision_'+x+'.sql' for x in PROVISIONS}),
        ('db/migrations/*.sql', {'db/migrations/'+x+'.sql' for x in MIGRATIONS}),
        ('db/opt-in-migrations/*.sql', {'db/opt-in-migrations/'+x+'.sql' for x in OPT_INS + EXTRA_SOURCE_MIGRATIONS}),
    ):
        actual={str(p.relative_to(ROOT)) for p in ROOT.glob(pattern)}
        if actual != expected:
            raise ValueError('qualification source list changed: '+pattern)
    return {name: hashlib.sha256(checked_source(name)).hexdigest() for name in SOURCE_PATHS}


def registry_helpers():
    # Check the helper before executing its module; its own routines are reused
    # without modifying the older driver.
    checked_source('scripts/test-postgres-causal-registry.py')
    return runpy.run_path(str(ROOT/'scripts/test-postgres-causal-registry.py'))



class FixtureCommandError(RuntimeError):
    """Bounded, sanitized diagnostic; never retain SQL, paths or server text."""
    def __init__(self, category, sqlstate=None):
        self.category = category
        self.sqlstate = sqlstate
        detail = category + ('; SQLSTATE '+sqlstate if sqlstate else '')
        super().__init__('owned fixture command failed ('+detail+')')


def connection_diagnostic(stderr):
    """Classify only known PostgreSQL connection failures; never return raw text."""
    text = stderr[:8192]
    match = re.search(r'FATAL:\s*(?:([0-9A-Z]{5}):\s*)?([^\r\n]*)',text)
    detail = match.group(2).lower() if match else text.lower()
    sqlstate = match.group(1) if match else None
    if match and 'database ' in detail and ' does not exist' in detail:
        category='database unavailable'
    elif match and 'role ' in detail and ' does not exist' in detail:
        category='role unavailable'
    elif match and 'starting up' in detail:
        category='server starting'
    elif match and 'shutting down' in detail:
        category='server stopping'
    elif match and 'authentication failed' in detail:
        category='authentication failed'
    elif match:
        category='postgres fatal'
    elif 'connection refused' in detail:
        category='connection refused'
    elif 'no such file or directory' in detail and 'connection' in detail:
        category='connection socket unavailable'
    elif 'server closed the connection' in detail:
        category='connection closed'
    elif 'connection' in detail and ('timed out' in detail or 'timeout' in detail):
        category='connection timeout'
    else:
        category='command failure'
    return FixtureCommandError(category,sqlstate)


def _run(args, *, input=None, timeout=30):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        match = re.search(r'^ERROR:\s+([0-9A-Z]{5}): (.*)$',result.stderr,re.M)
        if match:
            raise registry_helpers()['PostgresDiagnosticError'](match.group(1),match.group(2))
        raise connection_diagnostic(result.stderr)
    return result.stdout.strip()


def psql_args(container, database):
    if not re.fullmatch(r'[0-9a-f]{64}',container) or not re.fullmatch(r'[a-z][a-z0-9_]{0,40}',database):
        raise ValueError('invalid fixture identity')
    return ['docker','exec','-i',container,'psql','-XqAt','-v','ON_ERROR_STOP=1',
            '-v','VERBOSITY=verbose','-h','/var/run/postgresql','-U','postgres','-d',database]



def assert_fresh(execute, database):
    probe=execute(database,"SELECT current_database() || '|' || (SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations) || '|' || (SELECT count(*) FROM contour.causal_sessions);")
    expected=database+'|{'+','.join(str(x) for x in range(1,20))+'}|0'
    if probe != expected:
        raise AssertionError('clone identity, ledger or initial sessions mismatch')


def qualify_cases(container, execute, run_case):
    """Create an isolated template clone for each required, explicitly named case.

    execute(database, sql) starts a new psql; run_case gets an argv and callback
    bound to exactly the same clone. It may never connect to the template.
    """
    cases = ('basic','clock') + SCENARIOS
    if len(cases)!=18 or len(set(cases))!=18:
        raise RuntimeError('invalid qualification case list')
    for index, case in enumerate(cases):
        database='session_case_'+str(index)
        execute('postgres','CREATE DATABASE '+database+' TEMPLATE contour_local;')
        assert_fresh(execute,database)
        callback=lambda sql, db=database: execute(db,sql)
        if case in ('basic','clock'):
            callback(checked_source('db/tests/causal_session_'+case+'.sql').decode())
        else:
            run_case(psql_args(container,database),callback,case)
        execute('postgres','DROP DATABASE '+database+';')
        print('PASS:',case,flush=True)
    return cases


def main():
    if len(sys.argv)!=1:
        raise ValueError('this qualification takes no arguments')
    os.umask(0o077)
    before=source_snapshot()
    registry=registry_helpers()
    registry['verify_qualified_profile']()
    run_id=uuid.uuid4().hex
    name='contour-causal-sessions-'+run_id
    cid=None
    create_attempted=False
    def inspect_name(container_name):
        result=subprocess.run(['docker','inspect',container_name],text=True,capture_output=True,timeout=30)
        if result.returncode:
            if re.fullmatch(r'Error: No such object: '+re.escape(container_name)+r'\s*',result.stderr):
                return None
            raise RuntimeError('container inspection failed')
        try:
            return json.loads(result.stdout)
        except (ValueError,TypeError) as error:
            raise RuntimeError('invalid container inspection') from error
    def deadline_handler(_signum,_frame):
        raise TimeoutError('session qualification exceeded overall deadline')
    previous=signal.signal(signal.SIGALRM,deadline_handler)
    signal.setitimer(signal.ITIMER_REAL,600)
    try:
        _run(['docker','image','inspect',registry['IMAGE']])
        create_attempted=True
        candidate=_run(['docker','create','--pull=never','--name',name,'--label','org.apicontour.registry-run='+run_id,
                        '--network','none','--memory','512m','--cpus','1','--pids-limit','128',
                        '--tmpfs','/var/lib/postgresql/data:rw,nosuid,noexec,size=256m',
                        '-e','POSTGRES_DB=contour_local','-e','POSTGRES_PASSWORD=isolated-fixture-only',
                        '-e','POSTGRES_HOST_AUTH_METHOD=reject','-e','POSTGRES_INITDB_ARGS=--auth-local=trust --auth-host=reject',
                        registry['IMAGE'],'-c','listen_addresses=','-c','unix_socket_directories=/var/run/postgresql'])
        if not re.fullmatch(r'[0-9a-f]{64}',candidate):
            raise RuntimeError('invalid container identity')
        cid=candidate
        _run(['docker','start',cid])
        deadline=time.monotonic()+60
        while True:
            result=subprocess.run(['docker','exec',cid,'sh','-c','test "$(cat /proc/1/comm)" = postgres && pg_isready -h /var/run/postgresql -U postgres -d contour_local'],capture_output=True,timeout=5)
            if result.returncode==0: break
            if time.monotonic()>=deadline: raise TimeoutError('PostgreSQL readiness deadline')
            time.sleep(.2)
        def execute(database,sql):
            return _run(psql_args(cid,database),input=sql,timeout=120)
        execute('contour_local',checked_source('db/bootstrap.sql').decode())
        for name_part in PROVISIONS:
            execute('contour_local',checked_source('db/provision_'+name_part+'.sql').decode())
        for name_part in MIGRATIONS:
            execute('contour_local',checked_source('db/migrations/'+name_part+'.sql').decode())
        for name_part in OPT_INS[:3]:
            execute('contour_local',checked_source('db/opt-in-migrations/'+name_part+'.sql').decode())
        execute('contour_local',checked_source('db/tests/causal_runtime_registry_pre.sql').decode())
        execute('contour_local',checked_source('db/opt-in-migrations/'+OPT_INS[3]+'.sql').decode())
        execute('contour_local',checked_source('db/tests/causal_session_setup.sql').decode())
        execute('contour_local',checked_source('db/opt-in-migrations/'+OPT_INS[4]+'.sql').decode())
        assert_fresh(execute,'contour_local')
        qualify_cases(cid,execute,run_scenario)
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        signal.signal(signal.SIGALRM,previous)
        try:
            if create_attempted and not cid:
                cid=registry['recover_owned_container'](inspect_name,name,run_id)
            if cid:
                registry['cleanup_owned'](_run,cid,name,run_id)
        finally:
            if source_snapshot()!=before:
                raise RuntimeError('qualification source changed')
    print('PASS: isolated causal session qualification; no runtime or TLS claims')


if __name__ == '__main__':
    main()
