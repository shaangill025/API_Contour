"""Owned isolated PostgreSQL concurrency tests; run only by test-postgres.sh."""
import queue
import subprocess
import sys
import threading
import time

CONTAINER = sys.argv[1]
A = 'aaaaaaaa-0000-0000-0000-000000000000'
B = 'bbbbbbbb-0000-0000-0000-000000000000'
C = '00000000-0000-0000-0000-000000000001'
LIFE_A = '00000000-0000-0000-0000-000000000501'
LIFE_B = '00000000-0000-0000-0000-000000000502'
STALE_LIFE = '00000000-0000-0000-0000-000000000503'


def argv(user):
    return ['docker','exec','-i',CONTAINER,'psql','-X','-Atq','-v','ON_ERROR_STOP=1',
            '-h','/var/run/postgresql','-U',user,'-d','contour_fixture']


def observer(sql):
    return subprocess.run(argv('postgres'), input=sql, text=True, capture_output=True,
                          check=True, timeout=5).stdout.strip()


class Session:
    def __init__(self, name):
        self.name=name; self.lines=queue.Queue(); self.serial=0
        self.process=subprocess.Popen(argv('contour_admin_test'),stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
        threading.Thread(target=self._read,daemon=True).start()
        self.run("SET application_name='%s'; SET statement_timeout='15s';" % name)

    def _read(self):
        for line in self.process.stdout: self.lines.put(line.rstrip('\n'))
        self.lines.put(None)

    def send(self, sql):
        self.serial+=1; marker='done_%s_%d' % (self.name,self.serial)
        self.process.stdin.write(sql+'\n\\echo '+marker+'\n'); self.process.stdin.flush()
        return marker

    def finish(self, marker):
        deadline=time.monotonic()+18; output=[]
        while True:
            line=self.lines.get(timeout=max(.01,deadline-time.monotonic()))
            if line is None: raise AssertionError('fixture session ended before marker')
            if line==marker: return output
            output.append(line)
            if time.monotonic()>=deadline: raise TimeoutError('fixture session deadline')

    def run(self, sql): return self.finish(self.send(sql))

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.write('ROLLBACK;\n\\q\n'); self.process.stdin.flush()
                self.process.stdin.close(); self.process.wait(timeout=3)
            except (BrokenPipeError,subprocess.TimeoutExpired):
                observer("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='%s'" % self.name)
                self.process.wait(timeout=3)


def begin(tenant):
    return "BEGIN; SELECT set_config('apicontour.tenant_id','%s',true);" % tenant


def expect(command, state):
    return "SELECT fixture.expect_state($fixture$%s$fixture$,'%s');" % (command,state)


def credential(tenant, credential_id, lifecycle, leaf):
    return "SELECT contour.enroll_origin_credential('%s','%s','%s',decode(repeat('%s',32),'hex'))" % (tenant,credential_id,lifecycle,leaf)


def grant(tenant, grant_id, lifecycle):
    return "SELECT contour.grant_origin_observer('%s','%s','%s','%s','%s','%s','%s','%s','%s')" % (tenant,grant_id,lifecycle,C,C,C,C,C,C)


def uid(number):
    return '00000000-0000-0000-0000-%012d' % number


def close(lifecycle):
    return "SELECT contour.end_origin('%s','lifecycle_closed','%s')" % (A,lifecycle)


def revoke(grant_id):
    return "SELECT contour.end_origin('%s','grant_revoked','%s')" % (A,grant_id)


def assert_prompt(session, command, state):
    started=time.monotonic()
    session.run(expect(command,state))
    if time.monotonic()-started>=3: raise AssertionError('contending origin operation waited')


def case_lifecycle(session, lifecycle_number, instance_number):
    instance=uid(instance_number); lifecycle=uid(lifecycle_number)
    session.run(begin(A)+"INSERT INTO contour.workload_instances VALUES ('%s','%s','%s','%s','%s','%s'); COMMIT;" % (A,C,C,C,C,instance))
    session.run(begin(A)+"SELECT contour.enroll_origin('%s','%s','%s','%s','%s','%s','%s','trusted_platform_v1',decode(repeat('88',32),'hex')); COMMIT;" % (A,lifecycle,C,C,C,C,instance))
    return lifecycle


def wait_sleep(name):
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        if observer("SELECT count(*) FROM pg_stat_activity WHERE application_name='%s' AND wait_event='PgSleep'" % name)=='1': return
        time.sleep(.05)
    raise AssertionError('stale-snapshot participant did not reach barrier')


def assert_sleeping(name):
    if observer("SELECT count(*) FROM pg_stat_activity WHERE application_name='%s' AND wait_event='PgSleep'" % name)!='1':
        raise AssertionError('stale-snapshot barrier ended before concurrent commit')


sessions=[]
try:
    first=Session('origin_fixture_first'); sessions.append(first)
    second=Session('origin_fixture_second'); sessions.append(second)

    # Legacy C-first plus origin-first contention must abort promptly, never wait.
    first.run(begin(A)+"SELECT contour.lock_collector('%s','%s');" % (A,C))
    second.run(begin(A))
    started=time.monotonic()
    second.run(expect(grant(A,'00000000-0000-0000-0000-000000000531',LIFE_A),'40001'))
    if time.monotonic()-started>=3: raise AssertionError('origin operation waited for collector')
    second.run("SELECT pg_advisory_xact_lock(1330792270,hashtext('%s'));" % A)
    started=time.monotonic()
    first.run(expect(credential(A,'00000000-0000-0000-0000-000000000532',LIFE_A,'33'),'40001'))
    if time.monotonic()-started>=3: raise AssertionError('C-first operation did not abort promptly')
    second.run('ROLLBACK;'); first.run('ROLLBACK;')

    # A session-level preheld lock and repeatable-read cannot fake the protocol.
    first.run("SELECT pg_advisory_lock(123456);"+begin(A))
    first.run(expect(credential(A,'00000000-0000-0000-0000-000000000533',LIFE_A,'33'),'40001'))
    first.run('ROLLBACK; SELECT pg_advisory_unlock(123456);')
    first.run("BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT set_config('apicontour.tenant_id','%s',true);" % A)
    first.run(expect(credential(A,'00000000-0000-0000-0000-000000000533',LIFE_A,'33'),'25001'))
    first.run('ROLLBACK;')

    # Same leaf across tenants: the fingerprint gate must fail promptly while the
    # first transaction is pending; after commit the global unique key rejects it.
    first.run(begin(A)+credential(A,'00000000-0000-0000-0000-000000000534',LIFE_A,'66')+';')
    second.run(begin(B))
    started=time.monotonic()
    second.run(expect(credential(B,'00000000-0000-0000-0000-000000000535',LIFE_B,'66'),'40001'))
    if time.monotonic()-started>=3: raise AssertionError('credential contention waited')
    first.run('COMMIT;')
    second.run(expect(credential(B,'00000000-0000-0000-0000-000000000535',LIFE_B,'66'),'23505'))
    second.run('ROLLBACK;')

    # The outer SELECT's snapshot is established before the close commits. A
    # VOLATILE entrypoint must use a fresh inner snapshot after acquiring its gate.
    second.run(begin(A))
    stale=credential(A,'00000000-0000-0000-0000-000000000536',STALE_LIFE,'77')+' FROM (SELECT pg_sleep(8)) barrier'
    marker=second.send(expect(stale,'23514'))
    wait_sleep(second.name)
    first.run(begin(A)+"SELECT contour.end_origin('%s','lifecycle_closed','%s'); COMMIT;" % (A,STALE_LIFE))
    assert_sleeping(second.name)
    second.finish(marker)
    second.run("SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.origin_credentials WHERE credential_id='00000000-0000-0000-0000-000000000536'),'fresh inner snapshot'); ROLLBACK;")

    # Each pair retains a winning gate until the loser is observed to abort.
    # Retries use a fresh READ COMMITTED statement after the winner commits.
    close_first=case_lifecycle(first,506,113)
    enroll_first=case_lifecycle(first,507,114)
    grant_close_first=case_lifecycle(first,508,115)
    grant_first=case_lifecycle(first,509,116)
    revoke_first=case_lifecycle(first,510,117)
    regrant_first=case_lifecycle(first,511,118)

    first.run(begin(A)+close(close_first)+';')
    second.run(begin(A)); assert_prompt(second,credential(A,uid(541),close_first,'81'),'40001')
    first.run('COMMIT;')
    second.run(expect(credential(A,uid(541),close_first,'81'),'23514')); second.run('ROLLBACK;')
    first.run(begin(A)+"SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.origin_credentials WHERE credential_id='%s'),'close-first has no credential'); ROLLBACK;" % uid(541))

    first.run(begin(A)+credential(A,uid(542),enroll_first,'82')+';')
    second.run(begin(A)); assert_prompt(second,close(enroll_first),'40001')
    first.run('COMMIT;'); second.run(close(enroll_first)+'; COMMIT;')
    first.run(begin(A)+"SELECT fixture.assert(EXISTS(SELECT 1 FROM contour.origin_credentials c JOIN contour.origin_terminal_events e ON e.tenant_id=c.tenant_id AND e.lifecycle_id=c.lifecycle_id WHERE c.credential_id='%s' AND e.event_kind='lifecycle_closed' AND e.event_at>=c.enrolled_at),'enroll-first retained then closed'); ROLLBACK;" % uid(542))

    first.run(begin(A)+close(grant_close_first)+';')
    second.run(begin(A)); assert_prompt(second,grant(A,uid(551),grant_close_first),'40001')
    first.run('COMMIT;'); second.run(expect(grant(A,uid(551),grant_close_first),'23514')); second.run('ROLLBACK;')
    first.run(begin(A)+"SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.origin_observer_grants WHERE grant_id='%s'),'close-first has no grant'); ROLLBACK;" % uid(551))

    first.run(begin(A)+grant(A,uid(552),grant_first)+';')
    second.run(begin(A)); assert_prompt(second,close(grant_first),'40001')
    first.run('COMMIT;'); second.run(close(grant_first)+'; COMMIT;')
    first.run(begin(A)+"SELECT fixture.assert(EXISTS(SELECT 1 FROM contour.origin_observer_grants g JOIN contour.origin_terminal_events e ON e.tenant_id=g.tenant_id AND e.lifecycle_id=g.lifecycle_id WHERE g.grant_id='%s' AND e.event_kind='lifecycle_closed' AND e.event_at>=g.granted_at),'grant-first retained then closed'); ROLLBACK;" % uid(552))

    first.run(begin(A)+grant(A,uid(560),revoke_first)+'; COMMIT;')
    first.run(begin(A)+revoke(uid(560))+';')
    second.run(begin(A)); assert_prompt(second,grant(A,uid(561),revoke_first),'40001')
    first.run('COMMIT;'); second.run(grant(A,uid(561),revoke_first)+'; COMMIT;')
    first.run(begin(A)+"SELECT fixture.assert((SELECT count(*)=2 FROM contour.origin_observer_grants WHERE lifecycle_id='%s') AND (SELECT count(*)=1 FROM contour.origin_observer_grants g WHERE g.lifecycle_id='%s' AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events e WHERE e.tenant_id=g.tenant_id AND e.grant_id=g.grant_id AND e.event_kind='grant_revoked')),'revoke-first keeps history and one active grant'); ROLLBACK;" % (revoke_first,revoke_first))

    first.run(begin(A)+grant(A,uid(562),regrant_first)+'; COMMIT;')
    first.run(begin(A)+revoke(uid(562))+'; COMMIT;')
    first.run(begin(A)+grant(A,uid(563),regrant_first)+';')
    second.run(begin(A)); assert_prompt(second,revoke(uid(563)),'40001')
    first.run('COMMIT;'); second.run(revoke(uid(563))+'; COMMIT;')
    first.run(begin(A)+"SELECT fixture.assert((SELECT count(*)=2 FROM contour.origin_observer_grants WHERE lifecycle_id='%s') AND (SELECT count(*)=0 FROM contour.origin_observer_grants g WHERE g.lifecycle_id='%s' AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events e WHERE e.tenant_id=g.tenant_id AND e.grant_id=g.grant_id AND e.event_kind='grant_revoked')),'regrant-first retains both revoked grants'); ROLLBACK;" % (regrant_first,regrant_first))
    print('PostgreSQL origin lifecycle concurrency assertions passed')
finally:
    for session in reversed(sessions): session.close()
