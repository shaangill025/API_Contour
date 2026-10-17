"""Actual selected import -> restricted declared writer -> fresh checked reader."""
import concurrent.futures
import copy
import json
from pathlib import Path
import queue
import runpy
import select
import socket
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
ITEM = '00000000-0000-0000-0000-000000000001'
OTHER = '00000000-0000-0000-0000-000000ffffff'


class EofRelay:
    """Owned ciphertext forwarder: observe client EOF without terminating TLS."""
    def __init__(self, port):
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0)); self.listener.listen(1)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.eof = threading.Event(); self.stop = threading.Event()
        self.error = None; self.streams = []
        def serve():
            try:
                until = time.monotonic()+3
                while not self.stop.is_set():
                    try:
                        front, _ = self.listener.accept()
                        break
                    except socket.timeout:
                        assert time.monotonic()<until, 'EOF relay accept deadline'
                else:
                    return
                self.streams.append(front)
                back = socket.create_connection(('127.0.0.1', port), timeout=3)
                self.streams.append(back)
                for stream in self.streams: stream.settimeout(3)
                until = time.monotonic()+30
                while not self.stop.is_set() and time.monotonic()<until:
                    ready, _, _ = select.select([front, back], [], [], 0.1)
                    for stream in ready:
                        data = stream.recv(65536)
                        if not data:
                            assert stream is front, 'backend closed before client EOF'
                            self.eof.set(); return
                        (back if stream is front else front).sendall(data)
                assert self.stop.is_set(), 'EOF relay deadline'
            except Exception as error:
                if not self.stop.is_set(): self.error = error
            finally:
                for stream in self.streams: stream.close()
                self.listener.close()
        self.thread = threading.Thread(target=serve, daemon=True); self.thread.start()

    def finish(self):
        assert self.eof.wait(3), 'cancelled transport did not reach client EOF'
        self.thread.join(3)
        assert not self.thread.is_alive() and self.error is None, 'EOF relay failed'

    def close(self):
        self.stop.set(); self.listener.close()
        for stream in self.streams:
            try: stream.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            stream.close()
        self.thread.join(3)
        assert not self.thread.is_alive(), 'EOF relay survived cleanup'


def run_cases(container, sql, port, directory, environment):
    def execute(text):
        result = subprocess.run(sql, input=text, text=True, capture_output=True, timeout=10, env=environment)
        assert result.returncode == 0, 'declared fixture SQL failed'
        return result.stdout.strip()

    for path in ['provision_declared.sql', 'migrations/0005_declared.sql']:
        execute((ROOT/'db'/path).read_text())
    for role in ['writer', 'reader']:
        execute("CREATE ROLE contour_declared_%s_tls LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%s'; GRANT contour_declared_%s TO contour_declared_%s_tls; ALTER ROLE contour_declared_%s_tls SET log_statement='all';" % (role, environment['CONTOUR_FIXTURE_PASSWORD'], role, role, role))
    execute("INSERT INTO contour.tenants VALUES ('%s'); INSERT INTO contour.projects VALUES ('%s','%s'); INSERT INTO contour.services VALUES ('%s','%s','%s'); INSERT INTO contour.environments VALUES ('%s','%s','%s');" % ((ITEM,)*9))
    target = json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps','--offline'], text=True, timeout=15))['target_directory']
    examples = Path(target)/'debug/examples'
    document = {'openapi':'3.0.3','paths':{'/source':{'post':{'requestBody':{'content':{'application/json':{'schema':{'type':'object','properties':{'é':{'type':'string','example':'SECRET-MUST-NOT-PERSIST'}},'required':['é']}}}}}}}}
    imported = subprocess.run([str(examples/'import_probe'),'openapi_json','request','POST','/source','application/json','-','é'], input=json.dumps(document).encode(), capture_output=True, timeout=5)
    assert imported.returncode == 0 and not imported.stderr
    assert b'SECRET-MUST-NOT-PERSIST' not in imported.stdout
    graph = json.loads(imported.stdout)
    path = directory/'declared-wire.json'
    path.write_bytes(imported.stdout)
    scope = [ITEM]*4
    version = '00000000-0000-0000-0000-000000000081'

    def check(wanted='Stored', mode='store', selected=None, identity=version, wire=path, budget=10000, via=port, unblock=None):
        control = socket.socket() if mode.startswith('cancel') else None
        relay = EofRelay(via) if control else None
        if control:
            control.bind(('127.0.0.1',0)); control.listen(1); control.settimeout(3)
            via = relay.port
        process = subprocess.Popen([str(examples/'declared_store_probe'), str(via), str(directory/'ca.crt'), str(wire), *(selected or scope), identity, mode, wanted, str(budget), str(control.getsockname()[1] if control else 0)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
        output = queue.Queue()
        thread = threading.Thread(target=lambda: output.put(process.stdout.readline()), daemon=True)
        thread.start()
        try:
            if control:
                peer, _ = control.accept()
                with peer:
                    # Regression: first observation comes after the former 600ms
                    # automatic cancellation. The operation must still be pending.
                    time.sleep(0.8)
                    until = time.monotonic()+3
                    while execute("SELECT count(*) FROM pg_stat_activity WHERE usename IN ('contour_declared_writer_tls','contour_declared_reader_tls') AND wait_event_type='Lock';") != '1':
                        assert time.monotonic()<until, 'declared future did not reach real lock wait'
                        time.sleep(0.01)
                    assert not relay.eof.is_set(), 'transport closed before cancellation signal'
                    peer.sendall(b'C')
            line = output.get(timeout=25)
            assert line.startswith('{'), 'declared probe expected '+wanted+'; got '+(line.strip() if line.strip() in ['Scope','NotFound','Conflict','Corrupt','Database','Deadline','Invalidated','OutcomeUnknown','Stored','Duplicate','Read'] else 'no closed result')
            result = json.loads(line)
            if relay:
                assert not result['reusable'] and process.poll() is None
                relay.finish()
                # PostgreSQL may remain lock-blocked after client EOF. Release
                # only after independent local transport closure, then prove
                # backend cleanup within the existing five-second bound.
                assert unblock is not None
                unblock()
            until = time.monotonic()+5
            while execute("SELECT count(*) FROM pg_stat_activity WHERE usename IN ('contour_declared_writer_tls','contour_declared_reader_tls');") != '0':
                if time.monotonic()>until:
                    raise AssertionError('declared backend survived while runtime alive')
                time.sleep(0.02)
            assert process.poll() is None, 'runtime exited before backend cleanup proof'
            out, errors = process.communicate(input='\n', timeout=3)
            assert process.returncode == 0 and not out and not errors, 'declared probe failed'
            return result
        finally:
            try:
                if control:
                    control.close()
                if relay:
                    relay.close()
            finally:
                if process.poll() is None:
                    process.kill(); process.wait(timeout=3)
                thread.join(2)
                for pipe in [process.stdin, process.stdout, process.stderr]:
                    pipe.close()

    first = check()
    assert first['value']['graph'] == graph and first['value']['id'] == version and first['reusable']
    assert execute("SELECT encode(declared_wire,'hex') FROM contour.declared_versions WHERE tenant_id='%s';" % ITEM) == imported.stdout.hex(), 'persisted bytes differ from sanitized import'
    assert execute("SELECT count(*) FROM contour.observation_windows WHERE tenant_id='%s';" % ITEM) == '0', 'declared fixture unexpectedly depends on traffic'
    assert check('Duplicate')['value'] == first['value'], 'exact retry changed original timestamp/bytes'
    assert check('Read','read')['value'] == first['value'], 'fresh reader changed checked graph'
    for index in range(4):
        wrong = scope.copy(); wrong[index] = OTHER
        check('Scope', selected=wrong)
        check('NotFound','read',selected=wrong)
    check('NotFound','read',identity=OTHER)
    changed = copy.deepcopy(graph)
    changed['operation'][-1] = '/different'
    alternate = directory/'declared-changed.json'
    alternate.write_text(json.dumps(changed))
    check('Conflict',wire=alternate)
    same_operation = copy.deepcopy(graph)
    # Toggle requiredness without changing any operation component.
    object_node = next(node for node in same_operation['nodes'] if node['kind'] == 'object')
    object_node['properties'][0]['required'] = False
    content_path = directory/'declared-content-changed.json'
    content_path.write_text(json.dumps(same_operation))
    check('Conflict',wire=content_path)
    assert execute("SELECT count(*) FROM contour.operations WHERE tenant_id='%s';" % ITEM) == '1', 'conflicting version left orphan operation'
    assert execute("SELECT count(*) FROM contour.declared_versions WHERE tenant_id='%s';" % ITEM) == '1'
    assert check('Read','read')['value'] == first['value']
    # Each concurrent caller waits for all peer connections to close before ack;
    # the probe closes its connection before emitting its result, so no deadlock.
    concurrent_id = '00000000-0000-0000-0000-000000000082'
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: check('Either',identity=concurrent_id), range(2)))
    assert sorted(row['outcome'] for row in results) == ['Duplicate','Stored'], 'concurrent first writers did not serialize'
    assert results[0]['value'] == results[1]['value'], 'concurrent retries changed original receipt'
    assert execute("SELECT count(*) FROM contour.declared_versions WHERE version_id='%s';" % concurrent_id) == '1'

    where = "tenant_id='%s' AND version_id='%s'" % (ITEM,version)
    def damage(expression, preflight=False):
        original = execute("SELECT encode(declared_wire,'hex') FROM contour.declared_versions WHERE "+where)
        execute("BEGIN; ALTER TABLE contour.declared_versions DISABLE TRIGGER immutable_declared; UPDATE contour.declared_versions SET declared_wire=%s WHERE %s; ALTER TABLE contour.declared_versions ENABLE TRIGGER immutable_declared; COMMIT;" % (expression,where))
        try:
            before = subprocess.run(['docker','logs',container], capture_output=True, text=True, check=True, timeout=5) if preflight else None
            check('Corrupt','read')
            check('Corrupt')
            if preflight:
                after = subprocess.run(['docker','logs',container], capture_output=True, text=True, check=True, timeout=5)
                assert 'SELECT d.declared_wire,o.canonical_key' not in (after.stdout+after.stderr)[len(before.stdout+before.stderr):], 'oversize bytes fetched before preflight rejection'
        finally:
            execute("BEGIN; ALTER TABLE contour.declared_versions DISABLE TRIGGER immutable_declared; UPDATE contour.declared_versions SET declared_wire=decode('%s','hex') WHERE %s; ALTER TABLE contour.declared_versions ENABLE TRIGGER immutable_declared; COMMIT;" % (original,where))
    damage("decode('7b','hex')")  # malformed graph
    damage("decode('%s','hex')" % alternate.read_bytes().hex())  # mismatched embedded operation
    damage("decode('%s','hex')" % (b' '+imported.stdout).hex())  # valid but noncanonical
    execute('ALTER TABLE contour.declared_versions DROP CONSTRAINT declared_versions_declared_wire_check;')
    try:
        damage("decode(repeat('00',1048577),'hex')", preflight=True)
    finally:
        execute('ALTER TABLE contour.declared_versions ADD CHECK (octet_length(declared_wire) BETWEEN 1 AND 1048576);')
    execute('ALTER TABLE contour.declared_versions DROP CONSTRAINT declared_versions_codec_version_check;')
    try:
        execute("BEGIN; ALTER TABLE contour.declared_versions DISABLE TRIGGER immutable_declared; UPDATE contour.declared_versions SET codec_version=2 WHERE %s; ALTER TABLE contour.declared_versions ENABLE TRIGGER immutable_declared; COMMIT;" % where)
        check('Corrupt','read'); check('Corrupt')
    finally:
        execute("BEGIN; ALTER TABLE contour.declared_versions DISABLE TRIGGER immutable_declared; UPDATE contour.declared_versions SET codec_version=1 WHERE %s; ALTER TABLE contour.declared_versions ENABLE TRIGGER immutable_declared; ALTER TABLE contour.declared_versions ADD CHECK (codec_version=1); COMMIT;" % where)
    assert check('Read','read')['value'] == first['value']

    # A real table lock holds the future pending. Dropping it must close its backend
    # while the probe runtime remains alive, and release all transaction ownership.
    for mode, wanted, budget in [('cancel-store','Invalidated',10000),('cancel-read','Invalidated',10000),('read','Deadline',150),('read','Deadline',20000)]:
        holder = subprocess.Popen(sql, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
        marker = queue.Queue()
        listener = threading.Thread(target=lambda: marker.put(holder.stdout.readline().strip()), daemon=True)
        listener.start()
        released = False
        def unblock():
            nonlocal released
            holder.stdin.write('ROLLBACK;\n'); holder.stdin.flush(); released = True
        try:
            holder.stdin.write('BEGIN; LOCK TABLE contour.declared_versions IN ACCESS EXCLUSIVE MODE;\n\\echo HELD\n');holder.stdin.flush()
            assert marker.get(timeout=3) == 'HELD'
            started = time.monotonic()
            assert not check(wanted,mode,budget=budget,unblock=unblock)['reusable']
            if budget == 20000:
                assert time.monotonic()-started < 15, 'caller extended configured 10s deadline'
        finally:
            try:
                holder.communicate('' if released else 'ROLLBACK;\n',timeout=3)
            except subprocess.TimeoutExpired:
                holder.kill(); holder.wait(timeout=3)
            listener.join(2)
            for pipe in [holder.stdin, holder.stdout, holder.stderr]:
                pipe.close()
        assert check('Read','read')['value'] == first['value']

    CommitProxy = runpy.run_path(str(ROOT/'scripts/test-postgres-recovery.py'))['CommitProxy']
    for offset, mode, wanted in [(83,'drop','OutcomeUnknown'),(84,'cleanup','Stored')]:
        identity = '00000000-0000-0000-0000-%012x' % offset
        proxy = CommitProxy(port,directory,mode)
        try:
            faulted = check(wanted,identity=identity,via=proxy.port)
            proxy.finish()
            assert not faulted['reusable']
        finally:
            proxy.close()
        retry = check('Duplicate',identity=identity)
        assert check('Read','read',identity=identity)['value'] == retry['value']
        if mode == 'cleanup':
            assert faulted['value'] == retry['value'], 'known commit receipt lost on cleanup failure'
        assert execute("SELECT count(*) FROM contour.declared_versions WHERE version_id='%s';" % identity) == '1'
    print('Declared import, restricted persistence/reload, scope, retries, corruption bounds, live cancellation and actual COMMIT faults passed', flush=True)
