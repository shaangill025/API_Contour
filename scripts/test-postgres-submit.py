"""Real restricted TLS inbox assertions; setup is owned by the authority fixture."""
import copy
import datetime
import itertools
import json
from pathlib import Path
import queue
import runpy
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
OTHER = 'bbbbbbbb-0000-0000-0000-000000000000'


def run_cases(container, execute, setup, probe, port, directory, environment):
    execute((ROOT / 'db/migrations/0003_ingestion.sql').read_text())
    sequence = itertools.count()

    def scope(body):
        return "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (body['tenant_id'], body['collector_id'], body['batch_id'])

    def pairs(body, wanted):
        counts = execute("SELECT (SELECT count(*) FROM contour.ingestion_batches WHERE %s),(SELECT count(*) FROM contour.ingestion_payloads WHERE %s);" % (scope(body), scope(body)))
        if counts != '%d|%d' % (wanted, wanted):
            raise AssertionError('inbox atomic pair count mismatch')

    def check(body, wanted='Accepted', deadline=5000, discard=False, port_override=None, status=None, include_status=False):
        path = directory / ('submit-%d.json' % next(sequence))
        path.write_text(json.dumps(body))
        process = subprocess.Popen([probe, str(port_override or port), str(directory / 'ca.crt'), str(directory / 'signer.raw'), str(path), wanted, body['tenant_id'], body['collector_id'], str(deadline)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
        output = queue.Queue()
        reader = threading.Thread(target=lambda: output.put(process.stdout.readline()), daemon=True)
        reader.start()
        try:
            actual = output.get(timeout=15).strip()
            observed_status = None
            if actual.startswith('Accepted '):
                parts = actual.split()
                if len(parts) != 4 or parts[3] not in ['accepted', 'duplicate']:
                    raise AssertionError('invalid receipt outcome marker')
                observed_status = parts[3]
                if status is not None and observed_status != status:
                    raise AssertionError('receipt status mismatch: expected ' + status + ', got ' + observed_status)
                actual = ' '.join(parts[:3])
            expected = 'Invalidated' if wanted == 'Cancel' else 'Accepted' if wanted == 'AcceptedInvalidated' else wanted
            if not (actual == expected or expected == 'Accepted' and actual.startswith('Accepted ')):
                raise AssertionError('submission marker mismatch')
            until = time.monotonic() + 5
            while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls';") != '0':
                if time.monotonic() > until:
                    raise AssertionError('submission backend leaked while runtime alive')
                time.sleep(0.02)
            if process.poll() is not None:
                raise AssertionError('submission runtime exited before cleanup proof')
            if discard:
                # Discard the application result, not the PostgreSQL COMMIT response.
                process.kill()
                process.wait(timeout=3)
            else:
                out, errors = process.communicate(input='\n', timeout=3)
                if process.returncode or out or errors:
                    raise AssertionError('submission probe failed')
            return actual + ' ' + observed_status if include_status and observed_status else actual
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            reader.join(2)
            for pipe in [process.stdin, process.stdout, process.stderr]:
                pipe.close()

    def parallel(body, wanted='Accepted', deadline=5000, include_status=False):
        outcomes = queue.Queue()

        def submit():
            try:
                outcomes.put(check(body, wanted, deadline, include_status=include_status))
            except Exception as error:
                outcomes.put(error)
        thread = threading.Thread(target=submit, daemon=True)
        thread.start()
        return thread, outcomes

    def finish(thread, outcomes):
        try:
            result = outcomes.get(timeout=20)
            if isinstance(result, Exception):
                raise result
            return result
        finally:
            thread.join(20)
            if thread.is_alive():
                raise AssertionError('submission fixture thread leaked')

    def change_authority(body, update):
        execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); UPDATE contour.collector_authorization SET %s WHERE tenant_id='%s' AND collector_id='%s'; COMMIT;" % (body['tenant_id'], body['tenant_id'], body['collector_id'], update, body['tenant_id'], body['collector_id']))

    body, _, _ = setup('submit_valid')
    receipt = check(body, status='accepted')
    pairs(body, 1)
    stored = execute("SELECT receipt_id::text,floor(extract(epoch FROM accepted_at)*1000000000)::bigint FROM contour.ingestion_batches WHERE %s;" % scope(body))
    if receipt != 'Accepted ' + stored.replace('|', ' '):
        raise AssertionError('receipt did not match PostgreSQL generated values')
    if check(body, status='duplicate') != receipt:
        raise AssertionError('retry changed original receipt')
    equivalent = dict(reversed(list(body.items())))
    if check(equivalent, status='duplicate') != receipt:
        raise AssertionError('canonical equivalence conflicted')
    conflict = copy.deepcopy(body)
    conflict['records'][0]['count'] += 1
    check(conflict, 'Conflict')
    pairs(body, 1)
    if check(body, status='duplicate') != receipt:
        raise AssertionError('conflict mutated committed content or receipt')
    candidate, _, _ = setup('submit_concurrent')
    first, one = parallel(candidate, include_status=True)
    second, two = parallel(candidate, include_status=True)
    results = [finish(first, one).rsplit(' ', 1), finish(second, two).rsplit(' ', 1)]
    if results[0][0] != results[1][0] or {result[1] for result in results} != {'accepted', 'duplicate'}:
        raise AssertionError('concurrent duplicate receipts differ')
    pairs(candidate, 1)
    for tenant in [body['tenant_id'], OTHER]:
        candidate, _, _ = setup('submit_isolated', tenant=tenant, collector_id=body['collector_id'] if tenant == OTHER else None)
        if check(candidate) == receipt:
            raise AssertionError('collector or tenant receipt scope leaked')
        pairs(candidate, 1)

    for corruption in ['orphan', 'malformed', 'different_checked']:
        candidate, _, _ = setup('submit_' + corruption)
        check(candidate)
        if corruption == 'orphan':
            mutation = "DELETE FROM contour.ingestion_payloads WHERE %s;" % scope(candidate)
        else:
            altered = copy.deepcopy(candidate)
            altered['records'][0]['count'] += 1
            raw = b'{}' if corruption == 'malformed' else json.dumps(altered).encode()
            mutation = "UPDATE contour.ingestion_payloads SET checked_batch=decode('%s','hex') WHERE %s;" % (raw.hex(), scope(candidate))
        execute('BEGIN; ALTER TABLE contour.ingestion_payloads DISABLE TRIGGER immutable_inbox; ' + mutation + ' ALTER TABLE contour.ingestion_payloads ENABLE TRIGGER immutable_inbox; COMMIT;')
        check(candidate, 'Corrupt')

    candidate, _, _ = setup('submit_expired_retry')
    now = datetime.datetime.fromisoformat(candidate['created_at'].replace('Z', '+00:00'))
    candidate['records'][0]['expires_at'] = (now + datetime.timedelta(seconds=2)).isoformat().replace('+00:00', 'Z')
    receipt = check(candidate)
    time.sleep(2.1)
    if check(candidate, status='duplicate') != receipt:
        raise AssertionError('committed retry re-admitted expired record')
    for update, wanted in [('enabled=false', 'Disabled'), ('enabled=false,revoked_at=clock_timestamp()', 'Revoked')]:
        candidate, _, _ = setup('submit_' + wanted)
        check(candidate)
        change_authority(candidate, update)
        check(candidate, wanted)
        pairs(candidate, 1)
    candidate, _, _ = setup('submit_lease_retry', lambda value: value.update(expires_at=(datetime.datetime.fromisoformat(value['issued_at'].replace('Z', '+00:00')) + datetime.timedelta(seconds=33)).isoformat().replace('+00:00', 'Z')))
    check(candidate)
    time.sleep(3.1)
    check(candidate, 'Policy')
    pairs(candidate, 1)

    candidate, _, _ = setup('submit_last_record')
    last = copy.deepcopy(candidate['records'][0])
    last.update(record_id='00000000-0000-0000-0000-000000999999', operation='SYNTHETIC_SECRET')
    candidate['records'].append(last)
    check(candidate, 'Admission')
    pairs(candidate, 0)
    candidate, _, _ = setup('submit_payload_fail')
    execute("CREATE FUNCTION contour.submit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='synthetic payload failure'; END $$; CREATE TRIGGER synthetic_payload_failure BEFORE INSERT ON contour.ingestion_payloads FOR EACH ROW EXECUTE FUNCTION contour.submit_failure();")
    try:
        check(candidate, 'Database')
        pairs(candidate, 0)
    finally:
        execute('DROP TRIGGER synthetic_payload_failure ON contour.ingestion_payloads; DROP FUNCTION contour.submit_failure();')

    names = ['nul\x00name', 'control\nname', '雪']
    candidate, _, _ = setup('submit_names', lambda value: value.update(approved_names=value['approved_names'] + names), current=1)
    candidate['records'][0]['structure']['fields'].update({name: {'kind': 'string'} for name in names})
    receipt = check(candidate)
    raw = bytes.fromhex(execute("SELECT encode(checked_batch,'hex') FROM contour.ingestion_payloads WHERE %s;" % scope(candidate)))
    decoded = json.loads(raw)
    if not all(name in decoded['records'][0]['structure']['fields'] for name in names) or check(candidate, status='duplicate') != receipt:
        raise AssertionError('bytea names or digest roundtrip failed')

    candidate, _, _ = setup('submit_aggregate', current=116, history=tuple(range(100, 117)), padded=True)
    original = candidate['records'][0]
    candidate['records'] = []
    for revision in range(100, 117):
        record = dict(original, record_id='00000000-0000-0000-0000-%012x' % revision, policy_revision=revision)
        candidate['records'].append(record)
    before = subprocess.run(['docker', 'logs', container], capture_output=True, text=True, check=True, timeout=5)
    check(candidate, 'AuthorityTooLarge')
    after = subprocess.run(['docker', 'logs', container], capture_output=True, text=True, check=True, timeout=5)
    emitted = (after.stdout + after.stderr)[len(before.stdout + before.stderr):]
    if 'octet_length(signed_envelope)' not in emitted or ',signed_envelope FROM' in emitted:
        raise AssertionError('submission staged-current budget did not gate remaining envelope fetch')
    pairs(candidate, 0)

    candidate, _, _ = setup('submit_cancel')
    # An owned backend holds the same collector lock until cancelled submission is proved gone.
    holder = subprocess.Popen(['docker', 'exec', '-i', container, 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'contour_fixture', '-At'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    markers = queue.Queue()
    reader = threading.Thread(target=lambda: [markers.put(line.strip()) for line in holder.stdout], daemon=True)
    try:
        holder.stdin.write("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s');\n\\echo HELD\n" % (candidate['tenant_id'], candidate['tenant_id'], candidate['collector_id']))
        holder.stdin.flush()
        # Read all output through a queue, rather than relying on the first SQL row.
        reader.start()
        until = time.monotonic() + 5
        while markers.get(timeout=max(0.01, until - time.monotonic())) != 'HELD':
            pass
        thread, outcomes = parallel(candidate, 'Cancel')
        until = time.monotonic() + 3
        while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls' AND wait_event='advisory';") != '1':
            if time.monotonic() > until or not outcomes.empty():
                raise AssertionError('submission cancellation did not reach held lock')
            time.sleep(0.01)
        finish(thread, outcomes)
        pairs(candidate, 0)
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

    candidate, _, _ = setup('submit_commit_timeout')
    execute("CREATE FUNCTION contour.submit_commit_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(3); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER synthetic_commit_delay AFTER INSERT ON contour.ingestion_batches DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION contour.submit_commit_delay();")
    try:
        thread, outcomes = parallel(candidate, 'OutcomeUnknown', deadline=1200)
        until = time.monotonic() + 3
        while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls' AND query='COMMIT' AND wait_event='PgSleep';") != '1':
            if time.monotonic() > until or not outcomes.empty():
                raise AssertionError('timeout was not observed during real COMMIT')
            time.sleep(0.02)
        finish(thread, outcomes)
    finally:
        execute('DROP TRIGGER synthetic_commit_delay ON contour.ingestion_batches; DROP FUNCTION contour.submit_commit_delay();')
    existing = execute("SELECT count(*) FROM contour.ingestion_batches WHERE %s;" % scope(candidate))
    if existing not in ['0', '1']:
        raise AssertionError('uncertain COMMIT header count invalid')
    receipt = check(candidate, status='duplicate' if existing == '1' else 'accepted')
    pairs(candidate, 1)
    if check(candidate, status='duplicate') != receipt:
        raise AssertionError('uncertain COMMIT exact retry changed receipt')
    candidate, _, _ = setup('submit_lost_app_ack')
    discarded = check(candidate, discard=True, status='accepted')
    if check(candidate, status='duplicate') != discarded:
        raise AssertionError('discarded application result retry changed receipt')
    pairs(candidate, 1)
    print('Restricted TLS atomic inbox accepted/duplicate statuses, concurrent/retry identity, integrity/scope/expiry and bytea assertions passed')
    print('Runtime-held precommit cancellation, observed real COMMIT uncertainty and discarded application acknowledgement replay passed')
    runpy.run_path(str(ROOT / 'scripts/test-postgres-recovery.py'))['run_cases'](container, execute, setup, check, probe, port, directory, environment)
