"""Restricted-login TLS authority fixture, reusing the owned TLS setup."""
import base64
import copy
import datetime
import json
from pathlib import Path
import queue
import runpy
import subprocess
import threading
import time
ROOT = Path(__file__).resolve().parents[1]
TENANT = 'aaaaaaaa-0000-0000-0000-000000000000'
OTHER = 'bbbbbbbb-0000-0000-0000-000000000000'
ITEM = '00000000-0000-0000-0000-000000000001'

def run_cases(container, sql, probe, port, directory, environment):

    def command(argv, input=None, timeout=30):
        result = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout, env=environment)
        if result.returncode:
            if argv[0] == probe:
                raise AssertionError('authority probe failed: ' + result.stderr.strip())
            raise RuntimeError('authority fixture command failed')
        return result.stdout.strip()

    def execute(text):
        return command(sql, text)
    for path in ['bootstrap.sql', 'provision_authority.sql', 'migrations/0001_identity.sql', 'migrations/0002_policy.sql']:
        execute((ROOT / 'db' / path).read_text())
    execute("GRANT contour_ingestion TO contour_tls; ALTER ROLE contour_tls SET log_statement='all';")
    for tenant in [TENANT, OTHER]:
        execute("INSERT INTO contour.tenants VALUES ('%s');" % tenant + "INSERT INTO contour.projects VALUES ('%s','%s');" % (tenant, ITEM) + "INSERT INTO contour.services VALUES ('%s','%s','%s');" % (tenant, ITEM, ITEM) + "INSERT INTO contour.environments VALUES ('%s','%s','%s');" % (tenant, ITEM, ITEM) + "INSERT INTO contour.deployments VALUES ('%s','%s','%s','%s','%s');" % (tenant, ITEM, ITEM, ITEM, ITEM))
    for name in ['signer', 'wrong']:
        command(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(directory / (name + '.key'))])
    public = subprocess.run(['openssl', 'pkey', '-in', str(directory / 'signer.key'), '-pubout', '-outform', 'DER'], capture_output=True, check=True, timeout=5).stdout[-32:]
    (directory / 'signer.raw').write_bytes(public)
    counter = 10
    fixtures = json.loads((ROOT / 'docs/specification/fixtures/batches.json').read_text())
    baseline = next((row['body'] for row in fixtures if row['id'] == 'valid_structure'))

    def iso(instant):
        return instant.isoformat(timespec='microseconds').replace('+00:00', 'Z')

    def envelope(policy, wrong=False):
        payload = json.dumps(policy, separators=(',', ':')).encode()
        (directory / 'message').write_bytes(b'apicontour/policy/1\n' + payload)
        command(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(directory / ('wrong.key' if wrong else 'signer.key')), '-in', str(directory / 'message'), '-out', str(directory / 'signature')])
        encode = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b'=').decode()
        return json.dumps(dict(key_id='fixture', signature_profile='ed25519-v1', payload_base64url=encode(payload), signature_base64url=encode((directory / 'signature').read_bytes())), separators=(',', ':')).encode()

    def setup(name, change=None, current=2, history=(1,), tenant=TENANT, padded=False, collector_id=None):
        nonlocal counter
        counter += 1
        collector = collector_id or '00000000-0000-0000-0000-%012x' % counter
        source = collector
        micros = int(execute('SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint;'))
        now = datetime.datetime.fromtimestamp(micros // 1000000, datetime.timezone.utc) + datetime.timedelta(microseconds=micros % 1000000)
        body = copy.deepcopy(baseline)
        body.update(tenant_id=tenant, collector_id=collector, created_at=iso(now))
        record = body['records'][0]
        record.update(source_id=source, project_id=ITEM, service_id=ITEM, environment_id=ITEM, deployment_id=ITEM, queued_at=iso(now), first_seen=iso(now), last_seen=iso(now), expires_at=iso(now + datetime.timedelta(hours=1)), policy_revision=history[0])
        policy = dict(tenant_id=tenant, collector_id=collector, revision=1, issued_at=iso(now - datetime.timedelta(seconds=30)), expires_at=iso(now + datetime.timedelta(minutes=10)), enabled=True, service_ids=[ITEM], techniques=['runtime'], approved_names=['GET', 'id', 'quantity'], denied_templates=[], inspection_bytes=65536, depth_limit=32, queue_bytes=268435456, queue_ttl_seconds=86400, durable_queue_enabled=False, approved_route_segments=['orders'], parser_profiles=['http_json_v1'])
        text = "BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s');" % (tenant, tenant, collector)
        text += "INSERT INTO contour.collectors VALUES ('%s','%s');" % (tenant, collector)
        text += "INSERT INTO contour.workload_assignments VALUES ('%s','%s','%s','%s','%s','%s');" % (tenant, collector, ITEM, ITEM, ITEM, ITEM)
        text += "INSERT INTO contour.sources VALUES ('%s','%s','%s','%s','%s','%s','%s','%s');" % (tenant, source, collector, ITEM, ITEM, ITEM, ITEM, source)
        text += "INSERT INTO contour.source_authorization VALUES ('%s','%s','%s','runtime',ARRAY['http_json_v1']);" % (tenant, source, collector)
        for revision in sorted(set(history + (current,))):
            if name == 'missing_history' and revision == 1:
                continue
            value = dict(policy, revision=revision)
            if name == 'historical_expired' and revision == 1:
                value.update(issued_at=iso(now - datetime.timedelta(seconds=700)), expires_at=iso(now - datetime.timedelta(seconds=100)))
                record.update(queued_at=iso(now - datetime.timedelta(seconds=110)), first_seen=iso(now - datetime.timedelta(seconds=110)), last_seen=iso(now - datetime.timedelta(seconds=110)))
            if revision == current and change:
                change(value)
            raw = envelope(value, wrong=name == 'wrong_signer' and revision == current)
            padding = " || decode(repeat('20',%d),'hex')" % (1048576 - len(raw)) if padded else ''
            numeric = '1.000' if revision == 1 else str(revision)
            text += "INSERT INTO contour.policy_revisions VALUES ('%s','%s',%s,decode('%s','hex')%s);" % (tenant, collector, numeric, raw.hex(), padding)
        text += "UPDATE contour.collector_authorization SET active_revision=%d,enabled=true WHERE tenant_id='%s' AND collector_id='%s'; COMMIT;" % (current, tenant, collector)
        execute(text)
        return (body, collector, source)

    def logs():
        result = subprocess.run(['docker', 'logs', container], capture_output=True, text=True, check=True, timeout=5)
        return result.stdout + result.stderr

    def check(body, wanted='Ok', expected=None, deadline=5000):
        (directory / 'batch.json').write_text(json.dumps(body))
        identity = expected or (body['tenant_id'], body['collector_id'])
        process = subprocess.Popen([probe, port, str(directory / 'ca.crt'), str(directory / 'signer.raw'), str(directory / 'batch.json'), wanted, *identity, str(deadline)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
        output = queue.Queue()
        reader = threading.Thread(target=lambda : output.put(process.stdout.readline()), daemon=True)
        reader.start()
        try:
            if output.get(timeout=15).strip() != ('Invalidated' if wanted == 'Cancel' else wanted):
                raise AssertionError('authority outcome mismatch')
            until = time.monotonic() + 5
            while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls';") != '0':
                if time.monotonic() > until:
                    raise AssertionError('authority backend leaked while runtime alive')
                time.sleep(0.05)
            if process.poll() is not None:
                raise AssertionError('probe runtime exited before cleanup proof')
            (out, errors) = process.communicate(input='\n', timeout=3)
            if process.returncode or out or errors:
                raise AssertionError('unsafe probe exit')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            reader.join(2)
            for pipe in [process.stdin, process.stdout, process.stderr]:
                pipe.close()
    (body, collector, source) = setup('valid')
    check(body)
    missing = copy.deepcopy(body)
    missing['collector_id'] = '00000000-0000-0000-0000-000000999999'
    check(missing, 'Missing')
    started = time.monotonic()
    try:
        check(body, 'HarnessMismatch')
    except AssertionError:
        pass
    else:
        raise AssertionError('unexpected marker was accepted')
    if time.monotonic() - started > 5:
        raise AssertionError('unexpected marker failure was not bounded')
    check(body, 'Identity', expected=(OTHER, collector))
    (candidate, _, _) = setup('missing_history')
    check(candidate, 'Missing')
    (candidate, _, _) = setup('historical_expired')
    check(candidate)
    invalid = copy.deepcopy(candidate)
    invalid['records'][0]['queued_at'] = invalid['created_at']
    check(invalid, 'Policy')
    for (name, change, wanted) in [('wrong_identity', lambda value: value.update(tenant_id=OTHER), 'Policy'), ('wrong_revision', lambda value: value.update(revision=3), 'Policy'), ('wrong_signer', None, 'Policy'), ('narrowed_names', lambda value: value.update(approved_names=['GET', 'id']), 'Admission'), ('narrowed_profiles', lambda value: value.update(parser_profiles=['other']), 'Admission'), ('expired', lambda value: value.update(expires_at=iso(datetime.datetime.fromisoformat(value['issued_at'].replace('Z', '+00:00')) + datetime.timedelta(seconds=29))), 'Policy')]:
        (candidate, _, _) = setup(name, change)
        check(candidate, wanted)
    (candidate, _, _) = setup('tenant_b', tenant=OTHER)
    check(candidate)
    other_body = candidate
    for (update, wanted) in [('enabled=false', 'Disabled'), ('enabled=false,revoked_at=clock_timestamp()', 'Revoked')]:
        (candidate, collector, _) = setup(wanted)
        execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); UPDATE contour.collector_authorization SET %s WHERE tenant_id='%s' AND collector_id='%s'; COMMIT;" % (TENANT, TENANT, collector, update, TENANT, collector))
        check(candidate, wanted)
    (candidate, _, _) = setup('unknown_source')
    candidate['records'][0]['source_id'] = ITEM
    check(candidate, 'Source')
    (candidate, _, _) = setup('foreign_source')
    candidate['records'][0]['source_id'] = source
    check(candidate, 'Source')
    (candidate, _, _) = setup('all_records')
    second = copy.deepcopy(candidate['records'][0])
    second.update(record_id='00000000-0000-0000-0000-000000000002', operation='SYNTHETIC_SECRET')
    candidate['records'].append(second)
    check(candidate, 'Admission')
    (candidate, _, _) = setup('max_revision', current=18446744073709551615, history=(18446744073709551615,))
    check(candidate)
    (candidate, collector, _) = setup('profiles128')
    execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); UPDATE contour.source_authorization SET parser_profiles=ARRAY['http_json_v1'] || ARRAY(SELECT 'p'||n FROM generate_series(1,127)n) WHERE tenant_id='%s' AND collector_id='%s'; COMMIT;" % (TENANT, TENANT, collector, TENANT, collector))
    check(candidate)

    def blocked(candidate, wanted, update='', table=False, delay=0, deadline=5000):
        collector = candidate['collector_id']
        holder = subprocess.Popen(sql, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        markers = queue.Queue()

        def read_holder():
            for line in holder.stdout:
                markers.put(line.strip())
        reader = threading.Thread(target=read_holder, daemon=True)
        reader.start()
        outcome = queue.Queue()
        worker = None
        try:
            lock = 'LOCK TABLE contour.policy_revisions IN ACCESS EXCLUSIVE MODE;' if table else "SELECT contour.lock_collector('%s','%s');" % (TENANT, collector)
            holder.stdin.write("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); %s %s\n\\echo HELD\n" % (TENANT, lock, update))
            holder.stdin.flush()
            until = time.monotonic() + 5
            while markers.get(timeout=max(0.01, until - time.monotonic())) != 'HELD':
                pass

            def run_check():
                try:
                    check(candidate, wanted, deadline=deadline)
                    outcome.put(None)
                except Exception as error:
                    outcome.put(error)
            worker = threading.Thread(target=run_check, daemon=True)
            worker.start()
            until = time.monotonic() + 3
            wait = 'relation' if table else 'advisory'
            while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_tls' AND wait_event_type='Lock' AND wait_event='%s';" % wait) != '1':
                if time.monotonic() > until or not outcome.empty():
                    raise AssertionError('authority did not reach expected lock wait')
                time.sleep(0.02)
            if update or table:
                time.sleep(delay)
                holder.stdin.write('COMMIT;\n\\echo RELEASED\n')
                holder.stdin.flush()
                while markers.get(timeout=5) != 'RELEASED':
                    pass
            result = outcome.get(timeout=20)
            if result:
                raise result
        finally:
            if holder.poll() is None:
                holder.stdin.write('ROLLBACK;\n\\q\n')
                holder.stdin.flush()
                holder.stdin.close()
                try:
                    holder.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    holder.kill()
                    holder.wait(timeout=3)
            reader.join(2)
            if worker:
                worker.join(20)
            for pipe in [holder.stdout, holder.stderr]:
                pipe.close()
    for wanted in ['Deadline', 'Cancel', 'Disabled']:
        (candidate, collector, _) = setup('locked_' + wanted)
        update = "UPDATE contour.collector_authorization SET enabled=false WHERE tenant_id='%s' AND collector_id='%s';" % (TENANT, collector) if wanted == 'Disabled' else ''
        blocked(candidate, wanted, update, deadline=1500 if wanted == 'Deadline' else 5000)
    (candidate, collector, _) = setup('expires_during_load', lambda value: value.update(expires_at=iso(datetime.datetime.fromisoformat(value['issued_at'].replace('Z', '+00:00')) + datetime.timedelta(seconds=33))))
    blocked(candidate, 'Admission', table=True, delay=3.2, deadline=8000)
    (candidate, _, _) = setup('record_expires_during_load')
    candidate['records'][0]['expires_at'] = iso(datetime.datetime.fromisoformat(candidate['created_at'].replace('Z', '+00:00')) + datetime.timedelta(seconds=3))
    blocked(candidate, 'Admission', table=True, delay=3.2, deadline=8000)
    (candidate, _, _) = setup('aggregate', current=116, history=tuple(range(100, 117)), padded=True)
    records = []
    for revision in range(100, 117):
        record = copy.deepcopy(candidate['records'][0])
        record.update(record_id='00000000-0000-0000-0000-%012x' % revision, policy_revision=revision)
        records.append(record)
    candidate['records'] = records
    before = logs()
    check(candidate, 'AuthorityTooLarge')
    emitted = logs()[len(before):]
    if 'octet_length(signed_envelope)' not in emitted or ',signed_envelope FROM' in emitted:
        raise AssertionError('aggregate rejection did not precede envelope fetch')
    for (number, subset) in enumerate([records[:15], records[15:]]):
        split = copy.deepcopy(candidate)
        split['records'] = subset
        split['batch_id'] = '00000000-0000-0000-0000-%012x' % (500 + number)
        check(split)
    print('Restricted TLS authority scope/signature/revision/source/all-record/16MiB gate and split assertions passed')
    print('Authority lock-wait timeout/cancel invalidation, live-runtime cleanup, fresh disable and expiry refresh passed')
    submit_probe = str(Path(probe).with_name('submit_probe'))
    runpy.run_path(str(ROOT / 'scripts/test-postgres-submit.py'))['run_cases'](container, execute, setup, submit_probe, port, directory, environment)
if __name__ == '__main__':
    subprocess.run(['python3', str(ROOT / 'scripts/test-postgres-tls.py'), '--authority'], check=True)
