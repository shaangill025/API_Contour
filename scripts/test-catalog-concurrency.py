"""Actual concurrent restricted logins: claim commit and rollback/retry."""
import queue
import subprocess
import sys
import threading
import time

CONTAINER = sys.argv[1]
TENANT = "aaaaaaaa-0000-0000-0000-000000000000"
BEGIN = "BEGIN; SELECT set_config('apicontour.tenant_id','%s',true);" % TENANT
CLAIM = """INSERT INTO contour.catalog_processed_batches VALUES
    ('%s','00000000-0000-0000-0000-000000000002',
     '00000000-0000-0000-0000-000000000001',1,DEFAULT)
    ON CONFLICT DO NOTHING RETURNING processor_version;""" % TENANT

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
                    "AND wait_event_type='Lock' AND wait_event='transactionid';" % name) == "1":
            return
        time.sleep(0.05)
    raise AssertionError("duplicate claim did not block on the original transaction")


sessions = []
try:
    first = Session("contour_catalog_worker_test", "catalog_claim_first")
    sessions.append(first)
    second = Session("contour_catalog_worker_test", "catalog_claim_second")
    sessions.append(second)
    first.run(BEGIN)
    assert first.run(CLAIM) == ["1"]
    second.run(BEGIN)
    pending = second.send(CLAIM)
    wait_blocked(second.name)
    first.run("ROLLBACK;")
    assert second.finish(pending) == ["1"], "rollback must release claim for retry"
    first.run(BEGIN)
    pending = first.send(CLAIM)
    wait_blocked(first.name)
    second.run("COMMIT;")
    assert first.finish(pending) == [], "committed duplicate must not claim twice"
    assert first.run("SELECT count(*) FROM contour.catalog_processed_batches WHERE collector_id="
                     "'00000000-0000-0000-0000-000000000002';") == ["1"]
    first.run("COMMIT;")
    print("PostgreSQL catalog concurrent claim rollback/retry and duplicate passed")
finally:
    for session in reversed(sessions):
        session.close()
