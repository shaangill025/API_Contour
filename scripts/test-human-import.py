"""Current human authorization inside restricted PostgreSQL TLS import transactions."""
import base64
import concurrent.futures
import contextlib
import json
from pathlib import Path
import queue
import runpy
import socket
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
ITEM = '00000000-0000-0000-0000-000000000001'
OTHER = '00000000-0000-0000-0000-000000000002'
ISSUER = 'https://idp.example.test/realms/demo'


def run_cases(container, sql, port, directory, environment):
    def execute(text):
        result = subprocess.run(sql, input=text, text=True, capture_output=True,
                                timeout=10, env=environment)
        assert result.returncode == 0, 'human fixture SQL failed'
        return result.stdout.strip()

    execute((ROOT / 'db/bootstrap.sql').read_text())
    for name in ['authority', 'catalog', 'declared', 'approval', 'comparison', 'review', 'human']:
        execute((ROOT / ('db/provision_' + name + '.sql')).read_text())
    for path in sorted((ROOT / 'db/migrations').glob('*.sql')):
        execute(path.read_text())
    for role in ['reader', 'writer']:
        execute("CREATE ROLE contour_human_%s_tls LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%s'; GRANT contour_declared_%s,contour_human_lookup TO contour_human_%s_tls;" %
                (role, environment['CONTOUR_FIXTURE_PASSWORD'], role, role))
    execute("INSERT INTO contour.tenants VALUES ('%s'); INSERT INTO contour.projects VALUES ('%s','%s'); INSERT INTO contour.services VALUES ('%s','%s','%s'); INSERT INTO contour.environments VALUES ('%s','%s','%s'); INSERT INTO contour.service_import_defaults VALUES ('%s','%s','%s','%s');" % ((ITEM,) * 13))
    execute("SET ROLE contour_human_provisioner; INSERT INTO contour.human_actors VALUES ('%s',true); INSERT INTO contour.human_identities VALUES ('%s','synthetic-user','%s',true); INSERT INTO contour.human_tenant_memberships VALUES ('%s','%s',true); INSERT INTO contour.human_project_memberships VALUES ('%s','%s','%s',true); INSERT INTO contour.human_service_roles VALUES ('%s','%s','%s','%s','service_owner',true);" %
            (ITEM, ISSUER, ITEM, ITEM, ITEM, ITEM, ITEM, ITEM, ITEM, ITEM, ITEM, ITEM))
    assert execute("SELECT has_table_privilege('contour_human_reader_tls','contour.public_declared_contracts','INSERT'),has_table_privilege('contour_human_reader_tls','contour.public_declared_members','INSERT'),pg_has_role('contour_human_writer_tls','contour_human_provisioner','MEMBER')") == 'f|f|f'
    target = json.loads(subprocess.check_output(['cargo', 'metadata', '--format-version', '1', '--no-deps', '--offline'], text=True, timeout=15))['target_directory']
    probe = Path(target) / 'debug/examples/service_import_probe'
    source = directory / 'human-import.json'
    source.write_text(json.dumps({'openapi': '3.0.3', 'paths': {'/source': {'post': {'responses': {'200': {'content': {'application/json': {'schema': {'type': 'string'}}}}}}}}}))

    def token(subject='synthetic-user', lifetime=300):
        now = int(time.time())
        claims = {'iss': ISSUER, 'sub': subject, 'aud': 'apicontour', 'iat': now,
                  'exp': now + lifetime, 'nonce': 'server-generated-one-use-nonce',
                  'roles': ['service_owner'], 'actor_id': OTHER, 'email': 'synthetic-user'}
        enc = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b'=')
        data = enc({'alg': 'RS256', 'kid': 'synthetic-rsa'}) + b'.' + enc(claims)
        signature = subprocess.run(['openssl', 'dgst', '-sha256', '-keyform', 'DER', '-sign',
                                    str(ROOT / 'crates/contour-auth/tests/fixtures/synthetic-rsa.der')],
                                   input=data, capture_output=True, timeout=5, check=True).stdout
        # Case-only subjects must not alias on a case-insensitive host filesystem.
        path = directory / ('token-' + str(time.time_ns()))
        path.write_bytes(data + b'.' + base64.urlsafe_b64encode(signature).rstrip(b'='))
        return path, claims['exp']

    normal, _ = token()
    EofRelay = runpy.run_path(str(ROOT / 'scripts/test-declared-store.py'))['EofRelay']

    def check(wanted, mode='store', number=500, scope=None, credential=normal, via=None, cancel=None):
        env = dict(environment, CONTOUR_FIXTURE_ID_TOKEN=str(credential))
        relay = control = None
        if cancel:
            relay = EofRelay(port)
            via = relay.port
            control = socket.socket()
            control.bind(('127.0.0.1', 0)); control.listen(1); control.settimeout(3)
        process = subprocess.Popen([str(probe), str(via or port), str(directory / 'ca.crt'), str(source),
                                    *(scope or [ITEM] * 4), '00000000-0000-0000-0000-%012x' % number,
                                    mode, '10000', wanted, str(control.getsockname()[1] if control else 0)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env=env)
        output = queue.Queue()
        reader = threading.Thread(target=lambda: output.put(process.stdout.readline()), daemon=True)
        reader.start()
        try:
            if control:
                peer, _ = control.accept()
                with peer:
                    wait_for("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_human_writer_tls' AND wait_event_type='Lock'", '1')
                    assert not relay.eof.is_set(), 'connection closed before cancellation'
                    peer.sendall(b'C')
            line = output.get(timeout=15)
            assert line.startswith('{'), 'human import unexpected outcome: ' + line.strip()
            value = json.loads(line)
            if relay:
                relay.finish()
                cancel()
            assert process.poll() is None, 'probe exited before acknowledgement'
            out, err = process.communicate('\n', timeout=3)
            assert process.returncode == 0 and not out and not err, 'human import probe failed'
            return value
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=3)
            reader.join(2)
            for pipe in [process.stdin, process.stdout, process.stderr]: pipe.close()
            if relay: relay.close()
            if control: control.close()

    def wait_for(query, expected, failure='expected PostgreSQL lock state was not reached'):
        until = time.monotonic() + 3
        while execute(query) != expected:
            assert time.monotonic() < until, failure
            time.sleep(.01)

    @contextlib.contextmanager
    def holder(statement):
        process = subprocess.Popen(sql, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env=environment)
        marker = queue.Queue()
        listener = threading.Thread(target=lambda: marker.put(process.stdout.readline().strip()), daemon=True)
        listener.start()
        try:
            process.stdin.write('BEGIN; ' + statement + ';\n\\echo HELD\n'); process.stdin.flush()
            assert marker.get(timeout=3) == 'HELD', 'fixture lock acquisition failed'
            def release():
                process.stdin.write('COMMIT;\n'); process.stdin.flush()
            yield release
        finally:
            try: process.communicate('ROLLBACK;\n', timeout=3)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=3)
            listener.join(2)
            for pipe in [process.stdin, process.stdout, process.stderr]: pipe.close()

    assert check('Resolved', mode='resolve')['value'] == [ITEM] * 4
    first = check('Stored')['value']
    assert check('Read', mode='read')['value'] == first
    assert check('Duplicate')['value'] == first
    before = execute('SELECT count(*) FROM contour.public_declared_contracts')
    tables = ['human_identities', 'human_actors', 'human_tenant_memberships', 'human_project_memberships', 'human_service_roles']
    for table in tables:
        execute('SET ROLE contour_human_provisioner; UPDATE contour.' + table + ' SET enabled=false')
        for mode in ['resolve', 'read', 'store']:
            check('Forbidden', mode=mode)  # Includes historical retry.
        check('Forbidden', number=501)
        execute('SET ROLE contour_human_provisioner; UPDATE contour.' + table + ' SET enabled=true')
    for subject in ['Synthetic-user', 'unmapped']:
        credential, _ = token(subject)
        check('Forbidden', credential=credential)
    # Same subject under a different (operator-provisioned) issuer never matches.
    execute("SET ROLE contour_human_provisioner; UPDATE contour.human_identities SET enabled=false; INSERT INTO contour.human_identities VALUES ('https://other.example.test','synthetic-user','%s',true)" % ITEM)
    check('Forbidden')
    execute("SET ROLE contour_human_provisioner; UPDATE contour.human_identities SET enabled=true WHERE issuer='%s'" % ISSUER)
    for index in range(3):
        scope = [ITEM] * 4; scope[index] = OTHER
        for mode in ['read', 'store', 'resolve']: check('Forbidden', mode=mode, scope=scope)
    execute("SET ROLE contour_human_provisioner; UPDATE contour.human_service_roles SET enabled=false; INSERT INTO contour.human_service_roles VALUES ('%s','%s','%s','%s','viewer',true)" % ((ITEM,) * 4))
    assert check('Read', mode='read')['value'] == first
    check('Forbidden'); check('Forbidden', mode='resolve')
    # Unrelated roles never imply contract mutation permission.
    for role in ['operator', 'policy_administrator', 'security_reviewer']:
        execute("SET ROLE contour_human_provisioner; INSERT INTO contour.human_service_roles VALUES ('%s','%s','%s','%s','%s',true)" % (ITEM, ITEM, ITEM, ITEM, role))
    check('Forbidden', number=501)
    assert execute('SELECT count(*) FROM contour.public_declared_contracts') == before
    execute("SET ROLE contour_human_provisioner; UPDATE contour.human_service_roles SET enabled=true WHERE role='service_owner'")
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        # Observe two readers past authorization simultaneously (SHARE is compatible).
        with holder('LOCK TABLE contour.public_declared_contracts IN ACCESS EXCLUSIVE MODE') as release:
            readers = [pool.submit(check, 'Read', 'read') for _ in range(2)]
            wait_for("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_human_reader_tls' AND wait_event_type='Lock' AND query LIKE '%public_declared_contracts%'", '2')
            release()
            assert all(f.result()['value'] == first for f in readers)
        # Every metadata lock must survive until the actual business commit.
        for index, table in enumerate(tables):
            with holder('LOCK TABLE contour.public_declared_contracts IN ACCESS EXCLUSIVE MODE') as release:
                write = pool.submit(check, 'Stored', number=510 + index)
                wait_for("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_human_writer_tls' AND wait_event_type='Lock' AND query LIKE '%public_declared_contracts%'", '1')
                disable = pool.submit(execute, 'SET ROLE contour_human_provisioner; UPDATE contour.' + table + ' SET enabled=false')
                wait_for("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE contour.human_% SET enabled=false%'", '1', 'revocation did not wait on ' + table)
                assert not disable.done(), 'revocation bypassed active authorization lock'
                release()
                write.result(); disable.result()
            check('Forbidden', number=510 + index)
            execute('SET ROLE contour_human_provisioner; UPDATE contour.' + table + ' SET enabled=true')
        # A committed disable that wins the lock is seen after the waiting read wakes.
        with holder('SET LOCAL ROLE contour_human_provisioner; UPDATE contour.human_actors SET enabled=false') as release:
            denied = pool.submit(check, 'Forbidden', 'read')
            wait_for("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_human_reader_tls' AND wait_event_type='Lock'", '1')
            release(); denied.result()
        execute('SET ROLE contour_human_provisioner; UPDATE contour.human_actors SET enabled=true')
        short, expiry = token(lifetime=3)
        with holder('DO $$ BEGIN PERFORM 1 FROM contour.human_actors FOR UPDATE; END $$') as release:
            expired = pool.submit(check, 'Forbidden', credential=short, number=520)
            wait_for("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_human_writer_tls' AND wait_event_type='Lock'", '1')
            while time.time() < expiry + .05: time.sleep(.02)
            release(); expired.result()
        # Expiry after authorization must roll back the business writes too.
        counts = 'SELECT (SELECT count(*) FROM contour.public_declared_contracts),(SELECT count(*) FROM contour.public_declared_members),(SELECT count(*) FROM contour.declared_versions),(SELECT count(*) FROM contour.operations)'
        before_expiry = execute(counts)
        short, expiry = token(lifetime=3)
        with holder('LOCK TABLE contour.public_declared_contracts IN ACCESS EXCLUSIVE MODE') as release:
            expired = pool.submit(check, 'Forbidden', credential=short, number=522)
            wait_for("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_human_writer_tls' AND wait_event_type='Lock' AND query LIKE '%public_declared_contracts%'", '1')
            while time.time() < expiry + .05: time.sleep(.02)
            release(); expired.result()
        assert execute(counts) == before_expiry, 'expired operation retained business writes'
    with holder('DO $$ BEGIN PERFORM 1 FROM contour.human_service_roles FOR UPDATE; END $$') as release:
        assert not check('Invalidated', mode='cancel-store', number=521, cancel=release)['reusable']
    # Cancellation must have released the earlier actor/membership locks too.
    execute("SET lock_timeout='500ms'; SET ROLE contour_human_provisioner; UPDATE contour.human_actors SET enabled=false; UPDATE contour.human_actors SET enabled=true")
    CommitProxy = runpy.run_path(str(ROOT / 'scripts/test-postgres-recovery.py'))['CommitProxy']
    for number, fault, wanted in [(530, 'drop', 'OutcomeUnknown'), (531, 'cleanup', 'Stored')]:
        proxy = CommitProxy(port, directory, fault)
        try:
            result = check(wanted, number=number, via=proxy.port)
            proxy.finish(); assert not result['reusable']
        finally: proxy.close()
        retry = check('Duplicate', number=number)['value']
        assert check('Read', mode='read', number=number)['value'] == retry
        if fault == 'cleanup': assert result['value'] == retry
    wait_for("SELECT count(*) FROM pg_stat_activity WHERE usename IN ('contour_human_reader_tls','contour_human_writer_tls')", '0')
    runpy.run_path(str(ROOT / 'scripts/test-human-review.py'))['run_cases'](execute, port, directory, environment, normal, token, holder, wait_for)
    # Public comparisons preserve whole-import identity even for equal graphs.
    for role in ['reader', 'writer']:
        execute('GRANT contour_review_reader TO contour_comparison_' + role + '_tls')
    operation = execute("SELECT operation_id FROM contour.public_declared_members WHERE contract_id='%s'" % ('00000000-0000-0000-0000-%012x' % 500))
    comparison_probe = Path(target) / 'debug/examples/comparison_store_probe'
    def public_compare(wanted, left=500, right=510, number=700, mode='public'):
        ident = lambda n: '00000000-0000-0000-0000-%012x' % n
        result = subprocess.run([str(comparison_probe), str(port), str(directory / 'ca.crt'), *([ITEM] * 4),
                                 operation, ident(number), 'declared', ident(left), 'declared', ident(right),
                                 mode, wanted, '10000', '0'], input='\n', text=True, capture_output=True,
                                timeout=15, env=dict(environment, CONTOUR_FIXTURE_ID_TOKEN=str(normal)))
        assert result.returncode == 0 and result.stdout.startswith('{') and not result.stderr, 'public comparison: ' + result.stdout.strip()
        return json.loads(result.stdout)['value']
    public = public_compare('Stored')
    assert public['public_inputs'] == [['declared', '00000000-0000-0000-0000-%012x' % 500], ['declared', '00000000-0000-0000-0000-%012x' % 510]]
    assert public_compare('Duplicate') == public
    assert public_compare('Read', mode='public-read') == public
    public_compare('Conflict', right=511)
    public_compare('NotFound', number=600, mode='public-read')
    execute('SET ROLE contour_human_provisioner; UPDATE contour.human_actors SET enabled=false')
    public_compare('Forbidden'); public_compare('Forbidden', mode='public-read')
    execute('SET ROLE contour_human_provisioner; UPDATE contour.human_actors SET enabled=true')
    runpy.run_path(str(ROOT / 'scripts/test-public-comparison.py'))['run_cases'](execute, port, directory, environment, normal, token, holder, wait_for, check, source, target, operation)
    runpy.run_path(str(ROOT / 'scripts/test-public-review.py'))['run_cases'](execute, port, directory, environment, normal, operation)
    unknown, _ = token(subject='unmapped-catalog')
    runpy.run_path(str(ROOT / 'scripts/test-human-catalog.py'))['run_cases'](execute, port, directory, environment, normal, unknown, token, holder, wait_for, check, source, operation)
    print('Human exact identity/scope, all enabled flags, owner/viewer permissions, restricted readers, historical retry denial, concurrent reads, all revocation locks, reverse revocation, expiry after wait, cancellation EOF and COMMIT faults passed')
