"""Real isolated PostgreSQL sessions; standard library only, Python 3.9+."""
import queue
import subprocess
import sys
import threading
import time

CONTAINER = sys.argv[1]
TENANT = "aaaaaaaa-0000-0000-0000-000000000000"
COLLECTOR = "00000000-0000-0000-0000-000000000001"
LOCK = "SELECT contour.lock_collector('%s','%s');" % (TENANT, COLLECTOR)
BEGIN = "BEGIN; SELECT set_config('apicontour.tenant_id','%s',true);" % TENANT


def argv(user):
    return ["docker", "exec", "-i", CONTAINER, "psql", "-X", "-Atq",
            "-v", "ON_ERROR_STOP=1", "-h", "/var/run/postgresql", "-U", user,
            "-d", "contour_fixture"]


def observer(sql):
    return subprocess.run(argv("postgres"), input=sql, text=True,
                          capture_output=True, check=True, timeout=5).stdout.strip()


class Session:
    def __init__(self, user, name):
        self.name = name
        self.process = subprocess.Popen(argv(user), stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, bufsize=1)
        self.lines = queue.Queue()
        self.serial = 0
        threading.Thread(target=self.read, daemon=True).start()
        self.run("SET application_name='%s'; SET statement_timeout='10s';" % name)

    def read(self):
        for line in self.process.stdout:
            self.lines.put(line.rstrip("\n"))
        self.lines.put(None)

    def send(self, sql):
        self.serial += 1
        marker = "done_%s_%d" % (self.name, self.serial)
        self.process.stdin.write(sql + "\n\\echo " + marker + "\n")
        self.process.stdin.flush()
        return marker

    def finish(self, marker):
        deadline = time.monotonic() + 12
        output = []
        while True:
            line = self.lines.get(timeout=max(0.01, deadline - time.monotonic()))
            if line is None:
                raise AssertionError("session exited: " + "\n".join(output))
            if line == marker:
                return output
            output.append(line)
            if time.monotonic() >= deadline:
                raise TimeoutError("session output timeout")

    def run(self, sql):
        return self.finish(self.send(sql))

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.write("ROLLBACK;\n\\q\n")
                self.process.stdin.flush()
                self.process.stdin.close()
                self.process.wait(timeout=3)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                # Terminate only this fixture's named session; never other clients.
                observer("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                         "WHERE application_name='%s';" % self.name)
                self.process.wait(timeout=3)


def wait_blocked(name):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if observer("SELECT count(*) FROM pg_stat_activity WHERE application_name='%s' "
                    "AND wait_event_type='Lock' AND wait_event='advisory';" % name) == "1":
            return
        time.sleep(0.05)
    raise AssertionError("session did not block on advisory lock")


sessions = []
try:
    ingress = Session("contour_ingest_test", "policy_fixture_ingress")
    sessions.append(ingress)
    admin = Session("contour_admin_test", "policy_fixture_admin")
    sessions.append(admin)

    ingress.run(BEGIN + LOCK)
    admin.run(BEGIN)
    pending = admin.send(LOCK)
    wait_blocked(admin.name)
    ingress.run("ROLLBACK;")
    admin.finish(pending)
    admin.run("UPDATE contour.source_authorization SET parser_profiles=ARRAY['http_json_v1']; COMMIT;")

    admin.run(BEGIN + LOCK)
    admin.run("UPDATE contour.collector_authorization SET enabled=false WHERE collector_id='%s';" % COLLECTOR)
    ingress.run(BEGIN)
    pending = ingress.send(LOCK)
    wait_blocked(ingress.name)
    admin.run("COMMIT;")
    ingress.finish(pending)
    # Deliberately a separate statement after the blocking lock's snapshot.
    if ingress.run("SELECT enabled FROM contour.collector_authorization WHERE collector_id='%s';" % COLLECTOR) != ["f"]:
        raise AssertionError("post-wait next statement missed committed authorization")
    ingress.run("ROLLBACK;")

    ingress.run(BEGIN + LOCK)
    admin.run(BEGIN)
    for command in [
        "UPDATE contour.collector_authorization SET enabled=true WHERE collector_id='%s'" % COLLECTOR,
        "UPDATE contour.source_authorization SET parser_profiles=ARRAY['other'] WHERE collector_id='%s'" % COLLECTOR,
        "INSERT INTO contour.policy_revisions VALUES ('%s','%s',3,'inert')" % (TENANT, COLLECTOR),
        "INSERT INTO contour.workload_assignments VALUES ('%s','%s',"
        "'00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002',"
        "'00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002')" % (TENANT, COLLECTOR),
        "INSERT INTO contour.sources VALUES ('%s','00000000-0000-0000-0000-000000000003','%s',"
        "'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',"
        "'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',"
        "'00000000-0000-0000-0000-000000000098')" % (TENANT, COLLECTOR),
    ]:
        started = time.monotonic()
        admin.run("SELECT fixture.expect_state($q$%s$q$,'40001');" % command)
        if time.monotonic() - started >= 3:
            raise AssertionError("trigger blocked instead of failing promptly")
    admin.run("ROLLBACK;")
    ingress.run("ROLLBACK;")
    admin.run(BEGIN + LOCK + "UPDATE contour.collector_authorization SET enabled=true WHERE collector_id='%s'; COMMIT;" % COLLECTOR)

    for session in [ingress, admin]:
        session.run("BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT set_config('apicontour.tenant_id','%s',true);" % TENANT)
        session.run("SELECT fixture.expect_state($q$%s$q$,'25001');" % LOCK.rstrip(";"))
        if session is admin:
            session.run("SELECT fixture.expect_state($q$UPDATE contour.collector_authorization SET enabled=enabled WHERE collector_id='%s'$q$,'25001');" % COLLECTOR)
        session.run("ROLLBACK;")
    print("PostgreSQL two-session policy assertions passed")
finally:
    for session in reversed(sessions):
        session.close()
