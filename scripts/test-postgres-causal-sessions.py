"""Barrier-based SQL race helpers for an owner-supplied disposable PostgreSQL.

No database is started here. The caller supplies a psql argv and complete fixed
synthetic SQL statements. Statements must include tenant/role setup; they must
not contain real signed material. Each contender runs in a fresh transaction.
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
            process.communicate()

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
                    process.communicate()
    elif scenario in ('cas_issue', 'disable_issue', 'revoke_issue'):
        # Legacy administrative CAS owns C without Q. An issuer can take Q and
        # leaf but must fail immediately on C; after CAS it cannot use old head.
        cas = _policy_change(scenario.removesuffix('_issue'))
        race(psql_argv, cas, _issue(one), _issue(one), retry_sqlstate='23514')
        _assert_rows(execute, 0, 0)
    else:
        raise ValueError('unknown scenario: ' + scenario)
