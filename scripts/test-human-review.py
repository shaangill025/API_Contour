"""Human comparison and review authorization on real checked import graphs."""
import concurrent.futures
import json
from pathlib import Path
import subprocess
import runpy
import queue
import socket
import threading
import time

ITEM = '00000000-0000-0000-0000-000000000001'
OTHER = '00000000-0000-0000-0000-000000000002'
def identity(number): return '00000000-0000-0000-0000-%012x' % number


def run_cases(execute, port, directory, environment, normal, token, holder, wait_for):
    for role, groups in [('writer', 'contour_review_writer,contour_approval_writer,contour_human_lookup'),
                         ('reader', 'contour_review_reader,contour_human_lookup')]:
        execute("CREATE ROLE contour_review_%s_tls LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%s'; GRANT %s TO contour_review_%s_tls" % (role, environment['CONTOUR_FIXTURE_PASSWORD'], groups, role))
    assert execute("SELECT has_table_privilege('contour_review_reader_tls','contour.review_requests','INSERT'),pg_has_role('contour_review_writer_tls','contour_human_provisioner','MEMBER')") == 'f|f'
    operation, version = execute("SELECT operation_id,version_id FROM contour.public_declared_members WHERE contract_id='%s'" % identity(500)).split('|')
    comparison = identity(600)

    target = json.loads(subprocess.check_output(['cargo', 'metadata', '--format-version', '1', '--no-deps', '--offline'], text=True, timeout=15))['target_directory']
    probe = Path(target) / 'debug/examples/review_store_probe'
    for role in ['writer','reader']:
        execute("CREATE ROLE contour_comparison_%s_tls LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%s'; GRANT contour_comparison_%s,contour_declared_reader,contour_human_lookup TO contour_comparison_%s_tls" % (role,environment['CONTOUR_FIXTURE_PASSWORD'],role,role))
    def compare(wanted='Stored', number=600, mode='store', credential=normal, scope=None):
        result = subprocess.run([str(probe.parent / 'comparison_store_probe'),str(port),str(directory / 'ca.crt'),*(scope or [ITEM]*4),operation,identity(number),'declared',version,'declared',version,mode,wanted,'10000','0'],input='\n',text=True,capture_output=True,timeout=15,env=dict(environment,CONTOUR_FIXTURE_ID_TOKEN=str(credential)))
        closed = result.stdout.strip()
        assert result.stdout.startswith('{'), 'human comparison expected ' + wanted + ' got ' + (closed if closed in ['Stored','Read','Duplicate','Forbidden','Conflict','NotFound','Database'] else 'no closed result')
        assert result.returncode == 0 and not result.stderr
        return json.loads(result.stdout)['value']
    compared = compare()
    assert compare('Read', mode='read') == compared
    assert compare('Duplicate') == compared
    def check(wanted='Stored', number=610, mode='store', credential=normal, scope=None, actor=OTHER, via=None):
        result = subprocess.run([str(probe), str(via or port), str(directory / 'ca.crt'), *(scope or [ITEM] * 4),
                                 operation, identity(number), identity(number + 1000) if mode == 'approve' else comparison,
                                 version, '-', actor, '1', mode, wanted, '10000', '0'],
                                input='\n', text=True, capture_output=True, timeout=15,
                                env=dict(environment, CONTOUR_FIXTURE_ID_TOKEN=str(credential)))
        if not result.stdout.startswith('{'):
            closed = result.stdout.strip()
            assert False, 'human review expected ' + wanted + ' got ' + (closed if closed in ['Stored','Read','Duplicate','Decided','Forbidden','Conflict','NotFound','Database'] else 'no closed result')
        assert result.returncode == 0 and not result.stderr, 'human review probe failed'
        receipt = json.loads(result.stdout)
        if via is not None: assert not receipt['reusable'], 'faulted review connection reused'
        return receipt['value']
    first = check()
    assert first['creator'] == ITEM, 'caller actor affected review attribution'
    assert check('Duplicate', actor=identity(999)) == first
    assert check('Read', mode='read') == first
    tables = ['human_identities', 'human_actors', 'human_tenant_memberships', 'human_project_memberships', 'human_service_roles']
    counts = 'SELECT (SELECT count(*) FROM contour.review_requests),(SELECT count(*) FROM contour.review_decisions),(SELECT count(*) FROM contour.approval_events)'
    before = execute(counts)
    assert execute('SELECT count(*) FROM contour.comparisons') == '1'
    for table in tables:
        execute('SET ROLE contour_human_provisioner; UPDATE contour.' + table + ' SET enabled=false')
        for mode in ['store', 'read', 'approve', 'reject']: check('Forbidden', mode=mode)
        compare('Forbidden'); compare('Forbidden', mode='read'); compare('Forbidden', number=601)
        check('Forbidden', number=611)
        execute('SET ROLE contour_human_provisioner; UPDATE contour.' + table + ' SET enabled=true')
    execute("SET ROLE contour_human_provisioner; UPDATE contour.human_service_roles SET enabled=false WHERE role='service_owner'")
    assert check('Read', mode='read') == first
    assert compare('Read', mode='read') == compared
    compare('Forbidden', number=601)
    for mode in ['store', 'approve', 'reject']: check('Forbidden', mode=mode)
    execute("SET ROLE contour_human_provisioner; UPDATE contour.human_service_roles SET enabled=true WHERE role='service_owner'")
    for index in range(3):
        scope = [ITEM] * 4; scope[index] = OTHER
        for mode in ['store', 'read', 'approve']: check('Forbidden', mode=mode, scope=scope)
        compare('Forbidden', scope=scope); compare('Forbidden', mode='read', scope=scope)
    assert execute(counts) == before, 'denied review retained writes'
    assert execute('SELECT count(*) FROM contour.comparisons') == '1', 'denied comparison retained writes'
    second, _ = token(subject='second-user')
    execute("SET ROLE contour_human_provisioner; INSERT INTO contour.human_actors VALUES ('%s',true); INSERT INTO contour.human_identities VALUES ('https://idp.example.test/realms/demo','second-user','%s',true); INSERT INTO contour.human_tenant_memberships VALUES ('%s','%s',true); INSERT INTO contour.human_project_memberships VALUES ('%s','%s','%s',true); INSERT INTO contour.human_service_roles VALUES ('%s','%s','%s','%s','service_owner',true)" % (OTHER, OTHER, ITEM, OTHER, ITEM, ITEM, OTHER, ITEM, ITEM, ITEM, OTHER))
    approved = check('Decided', mode='approve', credential=second, actor=ITEM)
    assert approved['creator'] == ITEM and approved['actor'] == OTHER, 'distinct decider attribution lost'
    assert execute("SELECT actor_id FROM contour.approval_events WHERE event_id='%s'" % identity(1610)) == OTHER
    assert check('Duplicate', mode='approve', credential=second, actor=identity(999)) == approved
    check('Conflict', mode='approve')
    execute('SET ROLE contour_human_provisioner; UPDATE contour.human_tenant_memberships SET enabled=false')
    check('Forbidden', mode='approve', credential=second)  # Terminal retry must check current access.
    execute('SET ROLE contour_human_provisioner; UPDATE contour.human_tenant_memberships SET enabled=true')
    execute("UPDATE contour.approval_heads SET current_event_id=NULL WHERE operation_id='%s'" % operation)
    check(number=611)
    rejected = check('Decided', number=611, mode='reject')
    assert rejected['actor'] == ITEM and rejected['event'] is None
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        short, expiry = token(lifetime=3)
        with holder('LOCK TABLE contour.declared_versions IN ACCESS EXCLUSIVE MODE') as release:
            expired_comparison = pool.submit(compare, 'Forbidden', 601, 'store', short)
            wait_for("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_comparison_writer_tls' AND wait_event_type='Lock' AND query LIKE '%FROM contour.declared_versions%'", '1')
            while time.time() < expiry + .05: time.sleep(.02)
            release(); expired_comparison.result()
        assert execute('SELECT count(*) FROM contour.comparisons') == '1', 'expired comparison retained writes'

        # Authorization stays held until a pending decision commits.
        check(number=612)
        with holder('LOCK TABLE contour.review_requests IN ACCESS EXCLUSIVE MODE') as release:
            decision = pool.submit(check, 'Decided', 612, 'reject')
            wait_for("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_review_writer_tls' AND wait_event_type='Lock' AND query LIKE '%FROM contour.review_requests%'", '1')
            disable = pool.submit(execute, 'SET ROLE contour_human_provisioner; UPDATE contour.human_actors SET enabled=false')
            wait_for("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE contour.human_actors SET enabled=false%'", '1', 'review revocation did not wait on actor')
            release(); decision.result(); disable.result()
        check('Forbidden', number=612, mode='reject')
        execute('SET ROLE contour_human_provisioner; UPDATE contour.human_actors SET enabled=true')
        # Both review creation and approval must roll back if expiry wins before commit.
        check(number=614)
        for number, mode, table, query in [(613, 'store', 'comparisons', '%FROM contour.comparisons%'),
                                            (614, 'approve', 'review_requests', '%FROM contour.review_requests%')]:
            before_expiry = execute(counts)
            short, expiry = token(lifetime=3)
            with holder('LOCK TABLE contour.' + table + ' IN ACCESS EXCLUSIVE MODE') as release:
                expired = pool.submit(check, 'Forbidden', number, mode, short)
                wait_for("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_review_writer_tls' AND wait_event_type='Lock' AND query LIKE '%s'" % query, '1')
                while time.time() < expiry + .05: time.sleep(.02)
                release(); expired.result()
            assert execute(counts) == before_expiry, 'expired review retained writes'
    assert check('Read', number=614, mode='read')['status'] == 'Pending'
    assert execute("SELECT current_event_id IS NULL FROM contour.approval_heads WHERE operation_id='%s'" % operation) == 't'
    CommitProxy = runpy.run_path(str(Path(__file__).resolve().parent / 'test-postgres-recovery.py'))['CommitProxy']
    for number, fault, wanted in [(620, 'drop', 'OutcomeUnknown'), (621, 'cleanup', 'Decided')]:
        check(number=number)
        proxy = CommitProxy(port, directory, fault)
        try:
            result = check(wanted, number=number, mode='reject', via=proxy.port)
            proxy.finish()
        finally: proxy.close()
        retry = check('Duplicate', number=number, mode='reject')
        assert check('Read', number=number, mode='read') == retry
        if fault == 'cleanup': assert result == retry
    check(number=622)
    EofRelay = runpy.run_path(str(Path(__file__).resolve().parent / 'test-declared-store.py'))['EofRelay']
    with holder('DO $$ BEGIN PERFORM 1 FROM contour.human_service_roles FOR UPDATE; END $$') as release:
        relay = EofRelay(port)
        control = socket.socket(); control.bind(('127.0.0.1', 0)); control.listen(1); control.settimeout(3)
        process = None
        try:
            process = subprocess.Popen([str(probe), str(relay.port), str(directory / 'ca.crt'), *([ITEM] * 4),
                                        operation, identity(622), comparison, version, '-', OTHER, '1',
                                        'cancel-reject', 'Invalidated', '10000', str(control.getsockname()[1])],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, env=dict(environment, CONTOUR_FIXTURE_ID_TOKEN=str(normal)))
            output = queue.Queue()
            reader = threading.Thread(target=lambda: output.put(process.stdout.readline()), daemon=True)
            reader.start()
            peer, _ = control.accept()
            with peer:
                wait_for("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_review_writer_tls' AND wait_event_type='Lock' AND query LIKE '%human_service_roles%'", '1')
                assert not relay.eof.is_set(), 'human review closed before cancellation'
                peer.sendall(b'C')
            line = output.get(timeout=15)
            assert line.startswith('{'), 'human review cancellation produced no closed result'
            result = json.loads(line)
            assert result['outcome'] == 'Invalidated' and not result['reusable']
            assert process.poll() is None, 'human review runtime exited before EOF proof'
            relay.finish(); release()
            out, err = process.communicate('\n', timeout=3)
            assert process.returncode == 0 and not out and not err
            reader.join(2)
        finally:
            if process:
                if process.poll() is None:
                    process.kill(); process.wait(timeout=3)
                for pipe in [process.stdin, process.stdout, process.stderr]: pipe.close()
            control.close(); relay.close()
    execute("SET lock_timeout='500ms'; SET ROLE contour_human_provisioner; UPDATE contour.human_actors SET enabled=false; UPDATE contour.human_actors SET enabled=true")
    assert check('Read', number=622, mode='read')['status'] == 'Pending'
    print('Human review distinct creator/decider attribution, owner/viewer and scope denial, current-access retries, revocation serialization, expired create/approval rollback, COMMIT faults and cancellation EOF passed.')
