"""Restricted TLS V2 atomic submission cases within the authority lane."""
import copy
import datetime
from pathlib import Path
import runpy
import time

ROOT = Path(__file__).resolve().parents[1]


def run_cases(container, execute, setup, check, port, directory, environment):
    prerequisite = execute("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='contour_v2_ingress') AND EXISTS (SELECT 1 FROM contour.schema_migrations WHERE version=16) AND to_regclass('contour.ingestion_v2_metadata') IS NOT NULL;")
    if prerequisite != 't':
        raise AssertionError('V2 catalog role and schema 16 must be installed before submission cases')
    execute("CREATE ROLE contour_v2_ingress_test LOGIN PASSWORD '%s'; GRANT contour_v2_ingress TO contour_v2_ingress_test;" % environment['CONTOUR_FIXTURE_PASSWORD'])
    CommitProxy = runpy.run_path(str(ROOT / 'scripts/test-postgres-recovery.py'))['CommitProxy']

    def v2(body):
        result = copy.deepcopy(body)
        result['wire_version'] = 2
        result['records'] = [dict(record=record, origin_witness={'kind': 'unattributed'}) for record in result['records']]
        return result

    def submit(body, wanted='Accepted', **kwargs):
        return check(body, wanted, v2=True, **kwargs)

    def scope(body):
        return "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (body['tenant_id'], body['collector_id'], body['batch_id'])

    def counts(body, wanted):
        where = scope(body)
        actual = execute("SELECT (SELECT count(*) FROM contour.ingestion_batches WHERE %s),(SELECT count(*) FROM contour.ingestion_payloads WHERE %s),(SELECT count(*) FROM contour.ingestion_v2_metadata WHERE %s);" % (where, where, where))
        if actual != wanted:
            raise AssertionError('V2 atomic counts: expected ' + wanted + ', got ' + actual)

    def update_authority(body, update):
        execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); UPDATE contour.collector_authorization SET %s WHERE tenant_id='%s' AND collector_id='%s'; COMMIT;" % (body['tenant_id'], body['tenant_id'], body['collector_id'], update, body['tenant_id'], body['collector_id']))

    def now_plus(seconds):
        micros = int(execute('SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint;'))
        instant = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=micros, seconds=seconds)
        return instant.isoformat(timespec='microseconds').replace('+00:00', 'Z')

    def wait_expired(value):
        deadline = time.monotonic() + 20
        while execute("SELECT clock_timestamp() >= '%s'::timestamptz;" % value) != 't':
            if time.monotonic() > deadline:
                raise AssertionError('policy expiry wait timed out')
            time.sleep(0.1)

    raw, _, _ = setup('v2_submit_valid')
    body = v2(raw)
    receipt = submit(body, status='accepted')
    counts(body, '1|1|1')
    row = execute("SELECT b.receipt_id::text,floor(extract(epoch FROM b.accepted_at)*1000000000)::bigint,m.record_id::text,m.source_id::text,m.project_id::text,m.service_id::text,m.environment_id::text,m.deployment_id::text,m.policy_revision::text,m.parser_profile,m.attribution_class,(m.request_digest=b.request_digest AND m.accepted_at=b.accepted_at AND m.digest_version=b.digest_version) FROM contour.ingestion_batches b JOIN contour.ingestion_v2_metadata m USING(tenant_id,collector_id,batch_id) WHERE b." + scope(body).replace(' AND ', ' AND b.'))
    record = body['records'][0]['record']
    expected = [record[k] for k in ['record_id', 'source_id', 'project_id', 'service_id', 'environment_id', 'deployment_id']] + [str(record['policy_revision']), record['parser_profile'], 'unattributed', 't']
    fields = row.split('|')
    if receipt != 'Accepted ' + ' '.join(fields[:2]) or fields[2:] != expected:
        raise AssertionError('database receipt or complete V2 metadata mismatch')
    if submit(body, status='duplicate') != receipt:
        raise AssertionError('duplicate changed receipt')
    changed = copy.deepcopy(body)
    changed['records'][0]['record']['count'] += 1
    submit(changed, 'Conflict')
    counts(body, '1|1|1')

    legacy, _, _ = setup('v2_cross_version')
    check(legacy, status='accepted')
    submit(v2(legacy), 'Conflict')
    counts(legacy, '1|1|0')

    for kind in ['fingerprint', 'mixed']:
        raw, _, _ = setup('v2_' + kind)
        candidate = v2(raw)
        if kind == 'mixed':
            second = copy.deepcopy(candidate['records'][0])
            second['record']['record_id'] = '00000000-0000-0000-0000-000000999991'
            candidate['records'].append(second)
        candidate['records'][-1]['origin_witness'] = {'kind': 'downstream_mtls_leaf_sha256_v1', 'leaf_sha256': 'ab' * 32}
        submit(candidate, 'Batch')
        counts(candidate, '0|0|0')

    for corruption in ['missing', 'extra', 'changed']:
        raw, _, _ = setup('v2_corrupt_' + corruption)
        candidate = v2(raw)
        submit(candidate, status='accepted')
        where = scope(candidate)
        if corruption == 'missing':
            mutation = 'DELETE FROM contour.ingestion_v2_metadata WHERE ' + where
        elif corruption == 'changed':
            mutation = "UPDATE contour.ingestion_v2_metadata SET parser_profile='different' WHERE " + where
        else:
            mutation = "INSERT INTO contour.ingestion_v2_metadata SELECT tenant_id,collector_id,batch_id,'00000000-0000-0000-0000-000000999992',digest_version,request_digest,accepted_at,source_id,project_id,service_id,environment_id,deployment_id,policy_revision,parser_profile,attribution_class FROM contour.ingestion_v2_metadata WHERE " + where
        execute('BEGIN; ALTER TABLE contour.ingestion_v2_metadata DISABLE TRIGGER immutable_v2_metadata; ' + mutation + '; ALTER TABLE contour.ingestion_v2_metadata ENABLE TRIGGER immutable_v2_metadata; COMMIT;')
        submit(candidate, 'Corrupt')

    for update, wanted in [('enabled=false', 'Disabled'), ('enabled=false,revoked_at=clock_timestamp()', 'Revoked')]:
        raw, _, _ = setup('v2_retry_' + wanted)
        candidate = v2(raw)
        submit(candidate)
        update_authority(candidate, update)
        submit(candidate, wanted)
        counts(candidate, '1|1|1')
    expiry = []
    def short_policy(policy):
        expiry.append(now_plus(5))
        policy['expires_at'] = expiry[0]
    raw, _, _ = setup('v2_retry_expiry', short_policy)
    candidate = v2(raw)
    submit(candidate)
    wait_expired(expiry[0])
    submit(candidate, 'Policy')
    counts(candidate, '1|1|1')

    raw, _, _ = setup('v2_last_invalid')
    candidate = v2(raw)
    last = copy.deepcopy(candidate['records'][0])
    last['record'].update(record_id='00000000-0000-0000-0000-000000999993', operation='SYNTHETIC_SECRET')
    candidate['records'].append(last)
    submit(candidate, 'Admission')
    counts(candidate, '0|0|0')
    raw, _, _ = setup('v2_metadata_rollback')
    candidate = v2(raw)
    last = copy.deepcopy(candidate['records'][0])
    last['record']['record_id'] = '00000000-0000-0000-0000-000000999994'
    candidate['records'].append(last)
    execute("CREATE FUNCTION contour.v2_fixture_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.record_id='00000000-0000-0000-0000-000000999994' THEN RAISE EXCEPTION USING ERRCODE='23514'; END IF; RETURN NEW; END $$; CREATE TRIGGER v2_fixture_failure BEFORE INSERT ON contour.ingestion_v2_metadata FOR EACH ROW EXECUTE FUNCTION contour.v2_fixture_failure();")
    try:
        submit(candidate, 'Database')
        counts(candidate, '0|0|0')
    finally:
        execute('DROP TRIGGER v2_fixture_failure ON contour.ingestion_v2_metadata; DROP FUNCTION contour.v2_fixture_failure();')

    raw, _, _ = setup('v2_generic_role')
    submit(v2(raw), 'RoleDenied')
    counts(raw, '0|0|0')

    execute("ALTER ROLE contour_v2_ingress_test SET apicontour.tenant_id='aaaaaaaa-0000-0000-0000-000000000000';")
    try:
        raw, _, _ = setup('v2_contaminated')
        submit(v2(raw), 'Contaminated')
    finally:
        execute('ALTER ROLE contour_v2_ingress_test RESET apicontour.tenant_id;')

    for mode, wanted in [('drop', 'OutcomeUnknown'), ('cleanup', 'AcceptedInvalidated')]:
        raw, _, _ = setup('v2_commit_' + mode)
        candidate = v2(raw)
        proxy = CommitProxy(port, directory, mode)
        try:
            result = submit(candidate, wanted, port_override=proxy.port, status='accepted' if mode == 'cleanup' else None)
            proxy.finish()
        finally:
            proxy.close()
        counts(candidate, '1|1|1')
        receipt = submit(candidate, status='duplicate')
        persisted = execute("SELECT receipt_id::text,floor(extract(epoch FROM accepted_at)*1000000000)::bigint FROM contour.ingestion_batches WHERE " + scope(candidate))
        if receipt != 'Accepted ' + persisted.replace('|', ' '):
            raise AssertionError('COMMIT retry did not return stored receipt')
        if mode == 'cleanup' and result != receipt:
            raise AssertionError('known COMMIT receipt lost during cleanup')
    print('Restricted TLS V2 session, metadata, retry, rejection, rollback and COMMIT fault assertions passed')

    runpy.run_path(str(ROOT / 'scripts/test-postgres-origin-submit.py'))['run_cases'](container, execute, setup, check, port, directory, environment)
    runpy.run_path(str(ROOT / 'scripts/test-postgres-origin-https.py'))['run_cases'](execute, setup, port, directory, environment, environment['CONTOUR_ORIGIN_HTTPS_PROBE'])
    if environment.get('CONTOUR_ORIGIN_SENSOR_IMAGE'):
        runpy.run_path(str(ROOT / 'scripts/test-postgres-origin-sensor.py'))['run_cases'](container, execute, setup, directory, environment)
