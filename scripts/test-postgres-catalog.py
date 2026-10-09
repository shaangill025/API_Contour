"""Restricted worker TLS consumer; real committed inbox and atomic catalog evidence."""
import copy
import json
from pathlib import Path
import queue
import runpy
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def run_cases(container, execute, setup, submit, port, directory, environment):
    execute((ROOT / 'db/provision_catalog.sql').read_text())
    execute((ROOT / 'db/migrations/0004_catalog.sql').read_text())
    execute("CREATE ROLE contour_catalog_tls LOGIN PASSWORD '%s'; GRANT contour_catalog_worker TO contour_catalog_tls; ALTER ROLE contour_catalog_tls SET log_statement='all';" % environment['CONTOUR_FIXTURE_PASSWORD'])
    target = json.loads(subprocess.check_output(['cargo', 'metadata', '--format-version', '1', '--no-deps', '--offline'], text=True, timeout=15))['target_directory']
    probe = str(Path(target) / 'debug/examples/catalog_probe')
    CommitProxy = runpy.run_path(str(ROOT / 'scripts/test-postgres-recovery.py'))['CommitProxy']

    def scope(body):
        return "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (body['tenant_id'], body['collector_id'], body['batch_id'])

    def counts(body, ledger, observations):
        actual = execute("SELECT (SELECT count(*) FROM contour.catalog_processed_batches WHERE %s),(SELECT count(*) FROM contour.observation_windows WHERE %s);" % (scope(body), scope(body)))
        if actual != '%d|%d' % (ledger, observations):
            raise AssertionError('catalog atomic row counts differ: ' + actual)

    def check(body, wanted='Processed', port_override=None, deadline=5000):
        process = subprocess.Popen([probe, str(port_override or port), str(directory / 'ca.crt'), body['batch_id'], wanted, body['tenant_id'], body['collector_id'], str(deadline)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
        markers = queue.Queue()
        reader = threading.Thread(target=lambda: markers.put(process.stdout.readline()), daemon=True)
        reader.start()
        try:
            actual = markers.get(timeout=15).strip()
            expected = 'Invalidated' if wanted == 'Cancel' else 'Processed' if wanted == 'ProcessedInvalidated' else wanted
            if actual != expected and not (wanted == 'Either' and actual in ['Processed', 'AlreadyProcessed']):
                raise AssertionError('catalog marker mismatch: expected ' + expected + ', got ' + actual)
            until = time.monotonic() + 5
            while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_catalog_tls';") != '0':
                if time.monotonic() > until:
                    raise AssertionError('catalog backend survived while runtime alive')
                time.sleep(0.02)
            if process.poll() is not None:
                raise AssertionError('catalog runtime exited before cleanup proof')
            out, errors = process.communicate(input='\n', timeout=3)
            if process.returncode or out or errors:
                raise AssertionError('catalog probe failed')
            return actual
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            reader.join(2)
            for pipe in [process.stdin, process.stdout, process.stderr]:
                pipe.close()

    def parallel(body, wanted='Either', deadline=5000):
        results = queue.Queue()
        def run():
            try:
                results.put(check(body, wanted, deadline=deadline))
            except Exception as error:
                results.put(error)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread, results

    def finish(job):
        thread, results = job
        try:
            result = results.get(timeout=20)
            if isinstance(result, Exception):
                raise result
            return result
        finally:
            thread.join(20)
            if thread.is_alive():
                raise AssertionError('catalog worker thread leaked')

    def accepted(name, records=1, names=()):
        body, _, _ = setup('catalog_' + name, lambda policy: policy.update(approved_names=policy['approved_names'] + list(names)), current=1)
        original = body['records'][0]
        body['records'] = [dict(original, record_id='00000000-0000-4000-8000-%012x' % (index + 1), count=index + 7, sample_numerator=1, sample_denominator=97, reasons=['sampled'], request_header_names=list(names)) for index in range(records)]
        submit(body, status='accepted')
        return body

    names = ['nul\x00name', 'control\nname', '雪']
    body = accepted('fields', 2, names)
    check(body)
    counts(body, 1, 2)
    rows = json.loads(execute("SELECT json_agg(row_to_json(w) ORDER BY record_id) FROM contour.observation_windows w WHERE %s;" % scope(body)))
    for stored, record in zip(rows, body['records']):
        for field in ['record_id', 'source_id', 'project_id', 'service_id', 'environment_id', 'deployment_id', 'sample_numerator', 'sample_denominator', 'visibility', 'completeness', 'reasons', 'route_uncertain', 'status_code', 'first_seen', 'last_seen', 'queued_at', 'expires_at']:
            if stored[field] != record[field]:
                raise AssertionError('catalog evidence changed: ' + field)
        if stored['observation_count'] != record['count']:
            raise AssertionError('catalog count changed')
        for field in ['request_header_names', 'response_header_names', 'query_parameter_names']:
            if json.loads(bytes.fromhex(stored[field][2:])) != record[field]:
                raise AssertionError('catalog name bytes changed')
    if len({row['operation_id'] for row in rows}) != 1 or len({row['variant_id'] for row in rows}) != 1:
        raise AssertionError('equal operation/structure did not share identities')
    check(body, 'AlreadyProcessed')
    counts(body, 1, 2)
    # Independently accepted same key/shape, different collector: same operation,
    # separate collector-scoped policy variant and separate source observations.
    second = accepted('second_collector')
    check(second)
    relation = execute("SELECT operation_id::text,variant_id::text FROM contour.observation_windows WHERE %s;" % scope(second)).split('|')
    if relation[0] != rows[0]['operation_id'] or relation[1] == rows[0]['variant_id']:
        raise AssertionError('collector-scoped policy variant identity changed')

    candidate = accepted('parallel', 2)
    # Hold the first worker after its unique claim but before any observation can
    # finish. The second worker must wait on that transaction's claim, not arrive
    # after it has already committed.
    execute("CREATE FUNCTION contour.catalog_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(724013,1); RETURN NEW; END $$; CREATE TRIGGER catalog_barrier BEFORE INSERT ON contour.observation_windows FOR EACH ROW EXECUTE FUNCTION contour.catalog_barrier();")
    holder = subprocess.Popen(['docker', 'exec', '-i', container, 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'contour_fixture'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    markers = queue.Queue()
    reader = threading.Thread(target=lambda: [markers.put(line.strip()) for line in holder.stdout], daemon=True)
    jobs = []
    try:
        reader.start()
        holder.stdin.write("BEGIN; SELECT pg_advisory_xact_lock(724013,1);\n\\echo HELD\n")
        holder.stdin.flush()
        until = time.monotonic() + 3
        while markers.get(timeout=max(0.01, until - time.monotonic())) != 'HELD':
            pass
        jobs.append(parallel(candidate, deadline=10000))
        until = time.monotonic() + 3
        while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_catalog_tls' AND wait_event='advisory' AND query LIKE 'INSERT INTO contour.observation_windows%';") != '1':
            if time.monotonic() > until:
                raise AssertionError('first catalog worker did not reach controlled barrier')
            time.sleep(0.01)
        jobs.append(parallel(candidate, deadline=10000))
        until = time.monotonic() + 3
        while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_catalog_tls' AND wait_event='transactionid' AND query LIKE 'INSERT INTO contour.catalog_processed_batches%';") != '1':
            if time.monotonic() > until:
                raise AssertionError('second catalog claim did not wait on first transaction')
            time.sleep(0.01)
        counts(candidate, 0, 0)
        holder.stdin.write('ROLLBACK;\n\\q\n')
        holder.stdin.flush()
        holder.wait(timeout=3)
        if holder.returncode:
            raise AssertionError('catalog barrier owner failed')
        if {finish(job) for job in jobs} != {'Processed', 'AlreadyProcessed'}:
            raise AssertionError('concurrent catalog claims did not serialize')
        counts(candidate, 1, 2)
    finally:
        if holder.poll() is None:
            holder.stdin.write('ROLLBACK;\n\\q\n')
            holder.stdin.flush()
            try:
                holder.wait(timeout=3)
            except subprocess.TimeoutExpired:
                holder.kill()
                holder.wait(timeout=3)
        reader.join(2)
        for pipe in [holder.stdin, holder.stdout, holder.stderr]:
            pipe.close()
        for thread, _ in jobs:
            thread.join(20)
            if thread.is_alive():
                raise AssertionError('catalog barrier worker thread leaked')
        execute('DROP TRIGGER catalog_barrier ON contour.observation_windows; DROP FUNCTION contour.catalog_barrier();')

    candidate = accepted('historical')
    execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); UPDATE contour.collector_authorization SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id='%s' AND collector_id='%s'; COMMIT;" % (candidate['tenant_id'], candidate['tenant_id'], candidate['collector_id'], candidate['tenant_id'], candidate['collector_id']))
    check(candidate)
    counts(candidate, 1, 1)
    missing = dict(candidate, batch_id='00000000-0000-4000-8000-000000ffffff')
    check(missing, 'NotFound')
    check(dict(candidate, tenant_id='bbbbbbbb-0000-0000-0000-000000000000'), 'NotFound')
    check(dict(candidate, collector_id='00000000-0000-0000-0000-000000000001'), 'NotFound')

    # A later record failure must undo the earlier observation, variant, and claim.
    candidate = accepted('rollback', 2)
    before = execute('SELECT count(*) FROM contour.variants;')
    execute("CREATE FUNCTION contour.catalog_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.record_id='00000000-0000-4000-8000-000000000002' THEN RAISE EXCEPTION 'synthetic later record'; END IF; RETURN NEW; END $$; CREATE TRIGGER catalog_fail BEFORE INSERT ON contour.observation_windows FOR EACH ROW EXECUTE FUNCTION contour.catalog_fail();")
    try:
        check(candidate, 'Database')
        counts(candidate, 0, 0)
        if execute('SELECT count(*) FROM contour.variants;') != before:
            raise AssertionError('failed catalog transaction retained variant')
    finally:
        execute('DROP TRIGGER catalog_fail ON contour.observation_windows; DROP FUNCTION contour.catalog_fail();')
    check(candidate)
    counts(candidate, 1, 2)

    # Simulate privileged storage damage only; application roles cannot mutate inbox.
    for kind in ['malformed', 'digest', 'scope', 'missing']:
        candidate = accepted(kind)
        altered = copy.deepcopy(candidate)
        altered['collector_id'] = '00000000-0000-0000-0000-000000000001'
        raw = b'{}' if kind == 'malformed' else json.dumps(altered).encode()
        if kind == 'missing':
            mutation = 'DELETE FROM contour.ingestion_payloads WHERE %s;' % scope(candidate)
        elif kind == 'digest':
            mutation = "UPDATE contour.ingestion_batches SET request_digest=decode(repeat('00',32),'hex') WHERE %s;" % scope(candidate)
        else:
            mutation = "UPDATE contour.ingestion_payloads SET checked_batch=decode('%s','hex') WHERE %s;" % (raw.hex(), scope(candidate))
        execute('BEGIN; ALTER TABLE contour.ingestion_payloads DISABLE TRIGGER immutable_inbox; ALTER TABLE contour.ingestion_batches DISABLE TRIGGER immutable_inbox; ' + mutation + ' ALTER TABLE contour.ingestion_payloads ENABLE TRIGGER immutable_inbox; ALTER TABLE contour.ingestion_batches ENABLE TRIGGER immutable_inbox; COMMIT;')
        check(candidate, 'Corrupt')
        counts(candidate, 0, 0)

    # Damaged bytea lengths must be rejected from metadata, before either body
    # field is selected. Restore constraints and original bytes after each case.
    for table, column, constraint, length in [
        ('ingestion_batches', 'request_digest', 'ingestion_batches_request_digest_check', 33),
        ('ingestion_payloads', 'checked_batch', 'ingestion_payloads_checked_batch_check', 1048577),
    ]:
        candidate = accepted('preflight_' + column)
        original = execute("SELECT encode(%s,'hex') FROM contour.%s WHERE %s;" % (column, table, scope(candidate)))
        check_sql = 'octet_length(request_digest)=32' if column == 'request_digest' else 'octet_length(checked_batch) BETWEEN 1 AND 1048576'
        execute("BEGIN; ALTER TABLE contour.%s DISABLE TRIGGER immutable_inbox; ALTER TABLE contour.%s DROP CONSTRAINT %s; UPDATE contour.%s SET %s=decode(repeat('00',%d),'hex') WHERE %s; ALTER TABLE contour.%s ENABLE TRIGGER immutable_inbox; COMMIT;" % (table, table, constraint, table, column, length, scope(candidate), table))
        try:
            before = subprocess.run(['docker', 'logs', container], capture_output=True, text=True, check=True, timeout=5)
            check(candidate, 'Corrupt')
            after = subprocess.run(['docker', 'logs', container], capture_output=True, text=True, check=True, timeout=5)
            emitted = (after.stdout + after.stderr)[len(before.stdout + before.stderr):]
            if 'SELECT b.digest_version,octet_length(b.request_digest)' not in emitted or 'SELECT b.request_digest,p.checked_batch' in emitted:
                raise AssertionError('catalog metadata preflight fetched damaged bytea')
            counts(candidate, 0, 0)
        finally:
            execute("BEGIN; ALTER TABLE contour.%s DISABLE TRIGGER immutable_inbox; UPDATE contour.%s SET %s=decode('%s','hex') WHERE %s; ALTER TABLE contour.%s ADD CONSTRAINT %s CHECK (%s); ALTER TABLE contour.%s ENABLE TRIGGER immutable_inbox; COMMIT;" % (table, table, column, original, scope(candidate), table, constraint, check_sql, table))

    # Existing hashes are not trusted in place of exact canonical bytes.
    candidate = accepted('collision')
    operation = rows[0]['operation_id']
    original = execute("SELECT encode(canonical_key,'hex') FROM contour.operations WHERE operation_id='%s';" % operation)
    execute("BEGIN; ALTER TABLE contour.operations DISABLE TRIGGER immutable_catalog; UPDATE contour.operations SET canonical_key=decode('5b5d','hex') WHERE operation_id='%s'; ALTER TABLE contour.operations ENABLE TRIGGER immutable_catalog; COMMIT;" % operation)
    try:
        check(candidate, 'Collision')
        counts(candidate, 0, 0)
    finally:
        execute("BEGIN; ALTER TABLE contour.operations DISABLE TRIGGER immutable_catalog; UPDATE contour.operations SET canonical_key=decode('%s','hex') WHERE operation_id='%s'; ALTER TABLE contour.operations ENABLE TRIGGER immutable_catalog; COMMIT;" % (original, operation))
    check(candidate)

    variant = execute("SELECT variant_id::text FROM contour.observation_windows WHERE %s;" % scope(candidate))
    original = execute("SELECT encode(canonical_structure,'hex') FROM contour.variants WHERE variant_id='%s';" % variant)
    candidate = dict(candidate, batch_id='00000000-0000-4000-8000-000000eeeeee')
    submit(candidate, status='accepted')
    execute("BEGIN; ALTER TABLE contour.variants DISABLE TRIGGER immutable_catalog; UPDATE contour.variants SET canonical_structure=decode('5b5d','hex') WHERE variant_id='%s'; ALTER TABLE contour.variants ENABLE TRIGGER immutable_catalog; COMMIT;" % variant)
    try:
        check(candidate, 'Collision')
        counts(candidate, 0, 0)
    finally:
        execute("BEGIN; ALTER TABLE contour.variants DISABLE TRIGGER immutable_catalog; UPDATE contour.variants SET canonical_structure=decode('%s','hex') WHERE variant_id='%s'; ALTER TABLE contour.variants ENABLE TRIGGER immutable_catalog; COMMIT;" % (original, variant))
    check(candidate)

    # Changing only stored wire bytes must not let a new batch reuse a damaged
    # variant whose canonical bytes and structural hash still match.
    original = execute("SELECT encode(structure_wire,'hex') FROM contour.variants WHERE variant_id='%s';" % variant)
    candidate = dict(candidate, batch_id='00000000-0000-4000-8000-000000dddddd')
    submit(candidate, status='accepted')
    execute("BEGIN; ALTER TABLE contour.variants DISABLE TRIGGER immutable_catalog; UPDATE contour.variants SET structure_wire=decode('7b7d','hex') WHERE variant_id='%s'; ALTER TABLE contour.variants ENABLE TRIGGER immutable_catalog; COMMIT;" % variant)
    try:
        check(candidate, 'Collision')
        counts(candidate, 0, 0)
    finally:
        execute("BEGIN; ALTER TABLE contour.variants DISABLE TRIGGER immutable_catalog; UPDATE contour.variants SET structure_wire=decode('%s','hex') WHERE variant_id='%s'; ALTER TABLE contour.variants ENABLE TRIGGER immutable_catalog; COMMIT;" % (original, variant))
    check(candidate)
    counts(candidate, 1, 1)

    # Block inside the worker transaction, cancel while its async runtime remains alive.
    candidate = accepted('cancel')
    execute("CREATE FUNCTION contour.catalog_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(3); RETURN NEW; END $$; CREATE TRIGGER catalog_delay BEFORE INSERT ON contour.observation_windows FOR EACH ROW EXECUTE FUNCTION contour.catalog_delay();")
    try:
        job = parallel(candidate, 'Cancel')
        until = time.monotonic() + 3
        while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_catalog_tls' AND wait_event='PgSleep';") != '1':
            if time.monotonic() > until:
                raise AssertionError('catalog cancellation did not reach row insertion')
            time.sleep(0.01)
        finish(job)
        counts(candidate, 0, 0)
    finally:
        execute('DROP TRIGGER catalog_delay ON contour.observation_windows; DROP FUNCTION contour.catalog_delay();')
    check(candidate)

    for mode, wanted in [('drop', 'OutcomeUnknown'), ('cleanup', 'ProcessedInvalidated')]:
        candidate = accepted(mode, 2)
        proxy = CommitProxy(port, directory, mode)
        try:
            check(candidate, wanted, port_override=proxy.port)
            proxy.finish()
        finally:
            proxy.close()
        counts(candidate, 1, 2)
        check(candidate, 'AlreadyProcessed')
        counts(candidate, 1, 2)

    privileges = execute("SELECT has_table_privilege('contour_catalog_tls','contour.ingestion_batches','INSERT'),has_table_privilege('contour_catalog_tls','contour.ingestion_payloads','INSERT'),has_table_privilege('contour_catalog_tls','contour.collector_authorization','SELECT'),has_function_privilege('contour_catalog_tls','contour.lock_collector(uuid,uuid)','EXECUTE');")
    if privileges != 'f|f|f|f':
        raise AssertionError('worker acquired capture or inbox-write privilege')
    print('Restricted worker TLS catalog projection, concurrent claims, historical scope, integrity, collision, later-record rollback, live cancellation and COMMIT faults passed')

    # Reuse the one owned restart. A separate restricted worker is held inside
    # real deferred COMMIT while the existing ingestion crash case is also held.
    class Recovery:
        process = None
        reader = None

        def snapshot(self):
            return execute("SELECT coalesce(json_agg(row_to_json(t) ORDER BY tenant_id,operation_id)::text,'[]') FROM contour.operations t; SELECT coalesce(json_agg(row_to_json(t) ORDER BY tenant_id,variant_id)::text,'[]') FROM contour.variants t; SELECT coalesce(json_agg(row_to_json(t) ORDER BY tenant_id,collector_id,batch_id,record_id)::text,'[]') FROM contour.observation_windows t; SELECT coalesce(json_agg(row_to_json(t) ORDER BY tenant_id,collector_id,batch_id)::text,'[]') FROM contour.catalog_processed_batches t;")

        def prepare(self):
            self.body = accepted('crash', 2)
            execute("CREATE FUNCTION contour.catalog_crash_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(30); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER catalog_crash_delay AFTER INSERT ON contour.catalog_processed_batches DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION contour.catalog_crash_delay();")

        def start(self):
            body = self.body
            self.process = subprocess.Popen([probe, str(port), str(directory / 'ca.crt'), body['batch_id'], 'OutcomeUnknown', body['tenant_id'], body['collector_id'], '10000'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
            self.markers = queue.Queue()
            self.reader = threading.Thread(target=lambda: self.markers.put(self.process.stdout.readline()), daemon=True)
            self.reader.start()
            until = time.monotonic() + 4
            while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_catalog_tls' AND query='COMMIT' AND wait_event='PgSleep';") != '1':
                if time.monotonic() > until:
                    raise AssertionError('catalog crash did not reach deferred COMMIT')
                time.sleep(0.02)

        def restore(self, restarted_port):
            if self.markers.get(timeout=15).strip() != 'OutcomeUnknown' or self.process.poll() is not None:
                raise AssertionError('crashed catalog commit was acknowledged or runtime exited')
            if execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_catalog_tls';") != '0':
                raise AssertionError('crashed catalog backend survived')
            out, errors = self.process.communicate(input='\n', timeout=3)
            if self.process.returncode or out or errors:
                raise AssertionError('crashed catalog probe failed')
            counts(self.body, 0, 0)
            execute('DROP TRIGGER catalog_crash_delay ON contour.catalog_processed_batches; DROP FUNCTION contour.catalog_crash_delay();')
            check(self.body, port_override=restarted_port)
            counts(self.body, 1, 2)
            check(self.body, 'AlreadyProcessed', port_override=restarted_port)
            print('Owned PostgreSQL crash preserves committed catalog bytes and rolls back interrupted catalog COMMIT; exact replay passed')

        def close(self):
            if self.process is not None:
                if self.process.poll() is None:
                    self.process.kill()
                    self.process.wait(timeout=3)
                if self.reader is not None:
                    self.reader.join(2)
                for pipe in [self.process.stdin, self.process.stdout, self.process.stderr]:
                    pipe.close()
    return Recovery()
