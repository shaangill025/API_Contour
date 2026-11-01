"""Opt-in restricted TLS origin facade fixture. Requires migrated schema 17."""
import copy
import datetime
import json
import runpy
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
ITEM = '00000000-0000-0000-0000-000000000001'


def run_cases(container, execute, setup, check, port, directory, environment):
    ledger = execute("SELECT string_agg(version::text,',' ORDER BY version) FROM contour.schema_migrations;")
    if ledger != '1,2,3,4,16':
        raise AssertionError('unexpected origin fixture input ledger: ' + ledger)
    if execute("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='contour_origin_ingress');") != 'f':
        raise AssertionError('origin role already exists')
    def basic_body(name):
        raw, _, _ = setup(name)
        body = copy.deepcopy(raw)
        body['wire_version'] = 2
        body['records'] = [dict(record=record, origin_witness={'kind': 'unattributed'}) for record in raw['records']]
        receipt = check(body, status='accepted', v2=True)
        return body, receipt

    before_17, before_receipt = basic_body('catalog_basic_before_17')
    v1_before_17, _, _ = setup('catalog_v1_before_17')
    check(v1_before_17, status='accepted')
    # Isolated component fixture only: this sparse order is not a deployment
    # sequence. Production applies 1..14, then 15, 16, and 17.
    for migration in ['db/migrations/0013_instance_registry.sql', 'db/migrations/0014_observation_evidence.sql', 'db/opt-in-migrations/0015_origin_lifecycle.sql', 'db/provision_origin_ingress.sql', 'db/opt-in-migrations/0017_origin_proofs.sql']:
        execute((ROOT / migration).read_text())
    if execute("SELECT string_agg(version::text,',' ORDER BY version) FROM contour.schema_migrations;") != '1,2,3,4,13,14,15,16,17' or execute("SELECT to_regprocedure('contour.verify_origin_batch_proofs(uuid,uuid,uuid,bytea)') IS NOT NULL;") != 't':
        raise AssertionError('origin fixture migration failed')
    after_17, after_receipt = basic_body('catalog_basic_after_17')
    execute("CREATE ROLE contour_origin_ingress_test LOGIN PASSWORD '%s'; GRANT contour_origin_ingress TO contour_origin_ingress_test;" % environment['CONTOUR_FIXTURE_PASSWORD'])
    probe = Path(environment['CONTOUR_ORIGIN_PROBE'])
    if not probe.is_file():
        raise AssertionError('origin fixture probe missing')
    serial = 0

    def submit(body, wanted='Accepted', status=None, override=None):
        nonlocal serial
        serial += 1
        path = directory / ('origin-submit-%d.json' % serial)
        path.write_text(json.dumps(body))
        process = subprocess.Popen([str(probe), str(override or port), str(directory/'ca.crt'), str(directory/'signer.raw'), str(path), wanted, body['tenant_id'], body['collector_id'], '5000'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
        try:
            # The probe exits only after this acknowledgement and after connection cleanup.
            out, err = process.communicate(input='\n', timeout=15)
            if process.returncode or err:
                raise AssertionError('origin probe failed: ' + err)
            fields = out.strip().split()
            prefix = 'Accepted' if wanted == 'AcceptedInvalidated' else wanted
            if not fields or fields[0] != prefix or (status and (len(fields) != 4 or fields[3] != status)):
                raise AssertionError('unexpected origin outcome: ' + out.strip())
            return ' '.join(fields[:3])
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)

    def scoped(candidate):
        return "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (candidate['tenant_id'],candidate['collector_id'],candidate['batch_id'])
    def retained(candidate):
        where = scoped(candidate)
        return execute("SELECT b.receipt_id::text,floor(extract(epoch FROM b.accepted_at)*1000000)::bigint,b.record_count,encode(b.request_digest,'hex'),encode(sha256(p.checked_batch),'hex'),p.origin_writer_provenance,(SELECT count(*) FROM contour.ingestion_v2_metadata WHERE %s),(SELECT count(*) FROM contour.origin_proofs WHERE %s),(SELECT count(*) FROM contour.origin_batch_proof_completion WHERE %s),(SELECT count(*) FROM contour.catalog_origin_projection WHERE %s),COALESCE((SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=b.tenant_id),0) FROM contour.ingestion_batches b JOIN contour.ingestion_payloads p USING(tenant_id,collector_id,batch_id) WHERE b.%s;" % (where,where,where,where,where.replace(' AND ',' AND b.')))

    def quota(candidate):
        return execute("SELECT COALESCE((SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='%s'),0);" % candidate['tenant_id'])
    def provenance(candidate):
        return execute("SELECT origin_writer_provenance FROM contour.ingestion_payloads WHERE " + scoped(candidate))

    # Table-level INSERT was narrowed to the original five columns. Ordinary
    # callers cannot submit the marker; even a privileged fixture caller cannot
    # forge it because the owner trigger overwrites both supplied values.
    for role in ('contour_ingestion','contour_v2_ingress','contour_origin_ingress'):
        if execute("SELECT has_column_privilege('%s','contour.ingestion_payloads','origin_writer_provenance','INSERT');" % role) != 'f':
            raise AssertionError('writer can supply provenance column')
    for selected_origin in (False,True):
        source = before_17; where_source = scoped(source)
        new_batch = '00000000-0000-4000-8000-00000000ff1%d' % int(selected_origin)
        gate = "SELECT contour.begin_origin_ingress('%s','%s');" % (source['tenant_id'],source['collector_id']) if selected_origin else "SELECT contour.lock_collector('%s','%s');" % (source['tenant_id'],source['collector_id'])
        # Inverse supplied value is deliberately ignored by the trigger.
        sql = "BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); %s INSERT INTO contour.ingestion_batches (tenant_id,collector_id,batch_id,request_digest,digest_version,record_count) SELECT tenant_id,collector_id,'%s',request_digest,digest_version,record_count FROM contour.ingestion_batches WHERE %s; INSERT INTO contour.ingestion_payloads (tenant_id,collector_id,batch_id,payload_format,checked_batch,origin_writer_provenance) SELECT tenant_id,collector_id,'%s',payload_format,checked_batch,%s FROM contour.ingestion_payloads WHERE %s; SELECT origin_writer_provenance FROM contour.ingestion_payloads WHERE tenant_id='%s' AND collector_id='%s' AND batch_id='%s'; ROLLBACK;" % (source['tenant_id'],gate,new_batch,where_source,new_batch,'false' if selected_origin else 'true',where_source,source['tenant_id'],source['collector_id'],new_batch)
        if execute(sql).splitlines()[-1] != ('t' if selected_origin else 'f'):
            raise AssertionError('provenance trigger trusted the caller supplied value')

    # Explicit spoof attempts are rejected before a restricted Basic writer can
    # use the marker column (the origin role is tested in origin_proofs.sql).
    execute("""BEGIN; SET LOCAL ROLE contour_v2_ingress_test;
      DO $$ DECLARE rejected boolean:=false; BEGIN
        BEGIN INSERT INTO contour.ingestion_payloads (tenant_id,collector_id,batch_id,payload_format,checked_batch,origin_writer_provenance)
          VALUES ('%s','%s','00000000-0000-4000-8000-00000000ff20',2,decode('7b7d','hex'),true);
        EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'Basic writer supplied provenance'; END IF;
      END $$; ROLLBACK;""" % (before_17['tenant_id'],before_17['collector_id']))

    # Both batches came from Basic ingress. Their immutable ordinary wire bytes
    # intentionally differ from the origin canonical serialization.
    execute("""DO $$ DECLARE rejected boolean:=false; BEGIN
      BEGIN UPDATE contour.ingestion_payloads SET origin_writer_provenance=NOT origin_writer_provenance WHERE %s;
      EXCEPTION WHEN check_violation THEN rejected:=true; END;
      IF NOT rejected THEN RAISE EXCEPTION 'payload provenance is mutable'; END IF;
    END $$;""" % scoped(before_17))

    for candidate, original_receipt in [(before_17,before_receipt),(after_17,after_receipt)]:
        before = retained(candidate)
        if provenance(candidate) != 'f':
            raise AssertionError('Basic payload was not marked Basic')
        stored = execute("SELECT encode(checked_batch,'hex') FROM contour.ingestion_payloads WHERE " + scoped(candidate))
        canonical = json.dumps(candidate,sort_keys=True,separators=(',', ':'),ensure_ascii=False).encode().hex()
        if stored == canonical:
            raise AssertionError('Basic wire unexpectedly canonical; retry reproducer invalid')
        if submit(candidate,status='duplicate') != original_receipt:
            raise AssertionError('Basic to origin duplicate changed original receipt')
        changed = copy.deepcopy(candidate); changed['records'][0]['record']['count'] += 1
        submit(changed,'Conflict')
        if retained(candidate) != before:
            raise AssertionError('Basic to origin retries changed receipt, storage, metadata, or quota')

    # Reverse interoperability: an unattributed origin admission can be retried
    # by Basic ingress with the same receipt and no added proof charge.
    raw_reverse, _, _ = setup('origin_unattributed_to_basic')
    reverse = copy.deepcopy(raw_reverse); reverse['wire_version'] = 2
    reverse['records'] = [dict(record=r,origin_witness={'kind':'unattributed'}) for r in raw_reverse['records']]
    before_quota = quota(reverse)
    original_receipt = submit(reverse,status='accepted'); before = retained(reverse)
    if provenance(reverse) != 't':
        raise AssertionError('Origin payload provenance missing')
    if quota(reverse) != before_quota:
        raise AssertionError('unattributed origin admission charged proof quota')
    if check(reverse,status='duplicate',v2=True) != original_receipt:
        raise AssertionError('origin to Basic duplicate changed original receipt')
    changed = copy.deepcopy(reverse); changed['records'][0]['record']['count'] += 1
    check(changed,'Conflict',v2=True)
    if retained(reverse) != before:
        raise AssertionError('origin to Basic retry changed retained history or quota')

    # Re-encoding preserves the V2 semantic digest but violates the immutable
    # canonical bytes required of Origin-created payloads, even with no witness.
    original_wire = execute("SELECT encode(checked_batch,'hex') FROM contour.ingestion_payloads WHERE " + scoped(reverse))
    rewritten_wire = json.dumps(reverse,indent=2,ensure_ascii=False).encode().hex()
    if rewritten_wire == original_wire:
        raise AssertionError('canonical corruption reproducer did not alter bytes')
    execute("BEGIN; SET LOCAL session_replication_role=replica; UPDATE contour.ingestion_payloads SET checked_batch=decode('%s','hex') WHERE %s; COMMIT;" % (rewritten_wire,scoped(reverse)))
    try:
        submit(reverse,'Corrupt')
    finally:
        execute("BEGIN; SET LOCAL session_replication_role=replica; UPDATE contour.ingestion_payloads SET checked_batch=decode('%s','hex') WHERE %s; COMMIT;" % (original_wire,scoped(reverse)))
    if retained(reverse) != before or submit(reverse,status='duplicate') != original_receipt:
        raise AssertionError('restored canonical origin retry changed retained receipt')
    runpy.run_path(str(ROOT / 'scripts/test-postgres-v2-catalog.py'))['run_origin_zero_canonical_cases'](execute, reverse, port, directory, environment)

    # Rechecking an old Basic batch still requires current collector authority.
    raw_revoked, _, _ = setup('basic_origin_retry_revoked')
    revoked = copy.deepcopy(raw_revoked); revoked['wire_version'] = 2
    revoked['records'] = [dict(record=r,origin_witness={'kind':'unattributed'}) for r in raw_revoked['records']]
    check(revoked,status='accepted',v2=True); submit(revoked,status='duplicate')
    before = retained(revoked)
    execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); UPDATE contour.collector_authorization SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id='%s' AND collector_id='%s'; COMMIT;" % (revoked['tenant_id'],revoked['tenant_id'],revoked['collector_id'],revoked['tenant_id'],revoked['collector_id']))
    submit(revoked,'Revoked')
    if retained(revoked) != before:
        raise AssertionError('revoked retry changed retained history or quota')

    raw, collector, source = setup('origin_facade')
    tenant = raw['tenant_id']
    instance_ids = ['00000000-0000-0000-0000-00000000a101', '00000000-0000-0000-0000-00000000a102']
    lifecycle_ids = ['00000000-0000-0000-0000-00000000a201', '00000000-0000-0000-0000-00000000a202']
    credentials = ['00000000-0000-0000-0000-00000000a301', '00000000-0000-0000-0000-00000000a302']
    grants = ['00000000-0000-0000-0000-00000000a401', '00000000-0000-0000-0000-00000000a402']
    fingerprints = ['11'*32, '22'*32]
    origin_scopes = [["00000000-0000-0000-0000-%012x" % (0xb000 + i * 16 + j) for j in range(4)] for i in range(2)]
    for instance, lifecycle, credential, grant, fingerprint, origin in zip(instance_ids, lifecycle_ids, credentials, grants, fingerprints, origin_scopes):
        project, service, environment_id, deployment = origin
        execute("SELECT set_config('apicontour.tenant_id','%s',false); INSERT INTO contour.projects VALUES ('%s','%s'); INSERT INTO contour.services VALUES ('%s','%s','%s'); INSERT INTO contour.environments VALUES ('%s','%s','%s'); INSERT INTO contour.deployments VALUES ('%s','%s','%s','%s','%s'); INSERT INTO contour.workload_instances VALUES ('%s','%s','%s','%s','%s','%s');" % (tenant, tenant, project, tenant, service, project, tenant, environment_id, project, tenant, deployment, project, service, environment_id, tenant, project, service, environment_id, deployment, instance))
        execute("SELECT set_config('apicontour.tenant_id','%s',false); SELECT contour.enroll_origin('%s','%s','%s','%s','%s','%s','%s','trusted_platform_v1',decode(repeat('aa',32),'hex'));" % (tenant, tenant, lifecycle, project, service, environment_id, deployment, instance))
        execute("SELECT set_config('apicontour.tenant_id','%s',false); SELECT contour.enroll_origin_credential('%s','%s','%s',decode('%s','hex'));" % (tenant, tenant, credential, lifecycle, fingerprint))
        execute("SELECT set_config('apicontour.tenant_id','%s',false); SELECT contour.grant_origin_observer('%s','%s','%s','%s','%s','%s','%s','%s','%s');" % (tenant, tenant, grant, lifecycle, collector, source, ITEM, ITEM, ITEM, ITEM))
    body = copy.deepcopy(raw)
    body['wire_version'] = 2
    template = body['records'][0]
    body['records'] = []
    for i in range(3):
        record = copy.deepcopy(template)
        record['record_id'] = '00000000-0000-0000-0000-%012x' % (0xa501+i)
        if environment.get('CONTOUR_HUMAN_ORIGIN_FIXTURE') == '1' and i < 2:
            queued = datetime.datetime.fromisoformat(record['queued_at'].replace('Z','+00:00'))
            seen = queued - datetime.timedelta(seconds=2-i)
            record['first_seen'] = record['last_seen'] = seen.isoformat(timespec='microseconds').replace('+00:00','Z')
            if i == 1:
                record['visibility'] = 'operation'; record['completeness'] = 'partial'
                record['structure'] = {'kind':'unknown','reason':'unsupported'}; record['reasons'] = ['unsupported']
        witness = {'kind': 'unattributed'} if i == 2 else {'kind': 'downstream_mtls_leaf_sha256_v1', 'leaf_sha256': fingerprints[i]}
        body['records'].append({'record': record, 'origin_witness': witness})
    where = "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (tenant, collector, body['batch_id'])
    receipt = submit(body, status='accepted')
    if provenance(body) != 't':
        raise AssertionError('fingerprint origin payload provenance missing')
    runpy.run_path(str(ROOT / 'scripts/test-postgres-v2-catalog.py'))['run_basic_compat_cases'](execute, [before_17, after_17], body, port, directory, environment)
    runpy.run_path(str(ROOT / 'scripts/test-postgres-v2-catalog.py'))['run_v1_origin_absence_cases'](execute, v1_before_17, body, port, directory, environment)
    if execute("SELECT string_agg(attribution_class,',' ORDER BY record_id) FROM contour.ingestion_v2_metadata WHERE " + where) != 'verified_origin_v1,verified_origin_v1,unattributed':
        raise AssertionError('origin metadata classes differ')
    stored = execute("SELECT encode(checked_batch,'hex') FROM contour.ingestion_payloads WHERE " + where)
    canonical = json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode().hex()
    if stored != canonical:
        raise AssertionError('stored origin bytes are not canonical')
    # Basic ingress must reject unsupported stored fingerprint evidence before
    # reporting the proposed unattributed payload's digest conflict.
    basic_candidate = copy.deepcopy(body)
    for record in basic_candidate['records']:
        record['origin_witness'] = {'kind': 'unattributed'}
    check(basic_candidate, 'Corrupt', v2=True)
    usage = execute("SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='%s'" % tenant)
    execute("SELECT set_config('apicontour.tenant_id','%s',false); SELECT contour.end_origin('%s','lifecycle_closed','%s');" % (tenant, tenant, lifecycle_ids[0]))
    if submit(body, status='duplicate') != receipt or provenance(body) != 't' or execute("SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='%s'" % tenant) != usage:
        raise AssertionError('closed-origin retry changed receipt or quota')
    expected_origins = [dict(zip(('origin_project_id', 'origin_service_id', 'origin_environment_id', 'origin_deployment_id', 'instance_id'), origin + [instance])) for origin, instance in zip(origin_scopes, instance_ids)]
    if environment.get('CONTOUR_HUMAN_ORIGIN_FIXTURE') == '1':
        execute("CREATE ROLE contour_catalog_reader_tls LOGIN PASSWORD '%s'; GRANT contour_catalog_reader TO contour_catalog_reader_tls;" % environment['CONTOUR_FIXTURE_PASSWORD'])
        runpy.run_path(str(ROOT / 'scripts/test-human-origin.py'))['run_smoke'](execute, body)
    runpy.run_path(str(ROOT / 'scripts/test-postgres-v2-catalog.py'))['run_origin_cases'](execute, body, port, directory, environment, expected_origins)
    if environment.get('CONTOUR_HUMAN_ORIGIN_FIXTURE') == '1':
        runpy.run_path(str(ROOT / 'scripts/test-human-origin.py'))['run_cases'](execute, submit, body, expected_origins, port, directory, environment)

    # Deliberate owner-only corruption demonstrates the absence verifier fails
    # closed on each retained history component, even before digest conflicts.
    candidate = before_17; target_scope = scoped(candidate)
    original_record = candidate['records'][0]['record']['record_id']
    changed = copy.deepcopy(candidate); changed['records'][0]['record']['count'] += 1
    for table in ('origin_proofs','origin_batch_proof_completion','catalog_origin_projection'):
        before = retained(candidate)
        overrides = "jsonb_build_object('collector_id','%s','batch_id','%s'" % (candidate['collector_id'],candidate['batch_id'])
        if table in ('origin_proofs','catalog_origin_projection'):
            overrides += ",'record_id','%s'" % original_record
        if table == 'origin_proofs':
            overrides += ",'proof_id','00000000-0000-4000-8000-00000000ff01'"
        overrides += ')'
        statement = "INSERT INTO contour.%s SELECT (jsonb_populate_record(NULL::contour.%s,to_jsonb(p) || %s)).* FROM contour.%s p WHERE p.%s LIMIT 1 RETURNING 1;" % (table,table,overrides,table,where.replace(' AND ',' AND p.'))
        try:
            if execute('BEGIN; SET LOCAL session_replication_role=replica; ' + statement + ' COMMIT;') != '1':
                raise AssertionError('absence-corruption fixture did not insert exactly one row')
            submit(candidate,'Corrupt')
            submit(changed,'Corrupt')
        finally:
            execute('BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM contour.' + table + ' WHERE ' + target_scope + '; COMMIT;')
        if retained(candidate) != before:
            raise AssertionError('absence-corruption fixture changed retained Basic batch')
    changed = copy.deepcopy(body)
    changed['records'][0]['record']['count'] += 1
    submit(changed, 'Conflict')
    # Remove a single immutable proof under fixture-owner maintenance; retry must never repair it.
    execute("BEGIN; ALTER TABLE contour.origin_proofs DISABLE TRIGGER origin_proof_immutable; DELETE FROM contour.origin_proofs WHERE %s AND record_id='%s'; ALTER TABLE contour.origin_proofs ENABLE TRIGGER origin_proof_immutable; COMMIT;" % (where, body['records'][0]['record']['record_id']))
    submit(body, 'Corrupt')
    if execute('SELECT count(*) FROM contour.origin_proofs WHERE ' + where) != '1':
        raise AssertionError('retry repaired missing proof')
    execute("BEGIN; ALTER TABLE contour.origin_proofs DISABLE TRIGGER origin_proof_immutable; DELETE FROM contour.origin_proofs WHERE %s; ALTER TABLE contour.origin_proofs ENABLE TRIGGER origin_proof_immutable; COMMIT;" % where)
    submit(body, 'Corrupt')
    execute("BEGIN; ALTER TABLE contour.origin_batch_proof_completion DISABLE TRIGGER origin_batch_completion_immutable; DELETE FROM contour.origin_batch_proof_completion WHERE %s; ALTER TABLE contour.origin_batch_proof_completion ENABLE TRIGGER origin_batch_completion_immutable; COMMIT;" % where)
    submit(body, 'Corrupt')
    if execute('SELECT count(*) FROM contour.origin_proofs WHERE ' + where) != '0':
        raise AssertionError('retry reconstructed missing proof set')
    def fresh_candidate(n):
        candidate = copy.deepcopy(body)
        candidate['batch_id'] = '00000000-0000-0000-0000-%012x' % (0xa600+n)
        candidate['records'] = [copy.deepcopy(body['records'][1])]
        candidate['records'][0]['record']['record_id'] = '00000000-0000-0000-0000-%012x' % (0xa700+n)
        return candidate

    for n, mutation in enumerate(['proof', 'metadata', 'marker'], 1):
        candidate = fresh_candidate(n)
        submit(candidate, status='accepted')
        scoped = "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (tenant, collector, candidate['batch_id'])
        if mutation == 'proof':
            execute("BEGIN; ALTER TABLE contour.origin_proofs DISABLE TRIGGER origin_proof_immutable; UPDATE contour.origin_proofs SET canonical_proof=canonical_proof || decode('00','hex') WHERE %s; ALTER TABLE contour.origin_proofs ENABLE TRIGGER origin_proof_immutable; COMMIT;" % scoped)
            submit(candidate, 'Corrupt')
        elif mutation == 'metadata':
            execute("BEGIN; ALTER TABLE contour.ingestion_v2_metadata DISABLE TRIGGER immutable_v2_metadata; UPDATE contour.ingestion_v2_metadata SET parser_profile='different' WHERE %s; ALTER TABLE contour.ingestion_v2_metadata ENABLE TRIGGER immutable_v2_metadata; COMMIT;" % scoped)
            submit(candidate, 'Corrupt')
        else:
            execute("BEGIN; ALTER TABLE contour.origin_batch_proof_completion DISABLE TRIGGER origin_batch_completion_immutable; DELETE FROM contour.origin_batch_proof_completion WHERE %s; ALTER TABLE contour.origin_batch_proof_completion ENABLE TRIGGER origin_batch_completion_immutable; COMMIT;" % scoped)
            submit(candidate, 'Corrupt')

    extra = fresh_candidate(8)
    extra['records'].append(copy.deepcopy(body['records'][2]))
    extra['records'][1]['record']['record_id'] = '00000000-0000-0000-0000-00000000a788'
    submit(extra, status='accepted')
    extra_where = "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (tenant, collector, extra['batch_id'])
    execute("BEGIN; SET LOCAL session_replication_role=replica; INSERT INTO contour.origin_proofs SELECT (jsonb_populate_record(NULL::contour.origin_proofs,to_jsonb(p) || jsonb_build_object('proof_id','00000000-0000-0000-0000-00000000a889','record_id','00000000-0000-0000-0000-00000000a788'))).* FROM contour.origin_proofs p WHERE %s; COMMIT;" % extra_where)
    submit(extra, 'Corrupt')

    # Synthetic counter seed tests real cap arithmetic without allocating 1 GiB.
    quota = fresh_candidate(10)
    quota_where = "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (tenant, collector, quota['batch_id'])
    original_usage = int(execute("SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='%s'" % tenant))
    execute("UPDATE contour.origin_logical_usage SET used_bytes=1073741824 WHERE tenant_id='%s';" % tenant)
    try:
        submit(quota, 'LogicalQuota')
        counts = execute("SELECT (SELECT count(*) FROM contour.ingestion_batches WHERE %s),(SELECT count(*) FROM contour.ingestion_payloads WHERE %s),(SELECT count(*) FROM contour.ingestion_v2_metadata WHERE %s),(SELECT count(*) FROM contour.origin_proofs WHERE %s),(SELECT count(*) FROM contour.origin_batch_proof_completion WHERE %s),(SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='%s');" % (quota_where, quota_where, quota_where, quota_where, quota_where, tenant))
        if counts != '0|0|0|0|0|1073741824':
            raise AssertionError('quota rejection did not roll back atomically: ' + counts)
    finally:
        execute("UPDATE contour.origin_logical_usage SET used_bytes=%d WHERE tenant_id='%s';" % (original_usage, tenant))

    # Exercise the private begin as the actual restricted session with Q, C,
    # and a session advisory lock already held. Every case must fail closed.
    collector_key = int(execute("SELECT contour.collector_lock_key('%s','%s');" % (tenant, collector)))
    for preheld in ["SELECT pg_advisory_xact_lock(1330792270,hashtext('%s'));" % tenant,
                    "SELECT pg_advisory_xact_lock(%d);" % collector_key,
                    "SELECT pg_advisory_lock(123,456);"]:
        execute("SET SESSION AUTHORIZATION contour_origin_ingress_test; BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); %s DO $$ BEGIN BEGIN PERFORM contour.begin_origin_ingress('%s','%s'); RAISE EXCEPTION 'preheld lock accepted'; EXCEPTION WHEN serialization_failure THEN NULL; END; END $$; ROLLBACK; RESET SESSION AUTHORIZATION;" % (tenant, preheld, tenant, collector))

    candidate = fresh_candidate(9)
    late = copy.deepcopy(candidate['records'][0])
    late['record']['record_id'] = '00000000-0000-0000-0000-00000000a799'
    candidate['records'].append(late)
    execute("CREATE FUNCTION contour.origin_fixture_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.record_id='00000000-0000-0000-0000-00000000a799' THEN RAISE EXCEPTION USING ERRCODE='23514'; END IF; RETURN NEW; END $$; CREATE TRIGGER origin_fixture_failure BEFORE INSERT ON contour.ingestion_v2_metadata FOR EACH ROW EXECUTE FUNCTION contour.origin_fixture_failure();")
    try:
        submit(candidate, 'Database')
        scoped = "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (tenant, collector, candidate['batch_id'])
        if execute('SELECT count(*) FROM contour.ingestion_batches WHERE ' + scoped) != '0':
            raise AssertionError('late metadata failure retained batch')
    finally:
        execute('DROP TRIGGER origin_fixture_failure ON contour.ingestion_v2_metadata; DROP FUNCTION contour.origin_fixture_failure();')

    submit(body, 'RoleDenied')
    execute("GRANT contour_origin_ingress TO contour_v2_ingress_test;")
    try:
        check(body, 'CrossRole', v2=True)
    finally:
        execute("REVOKE contour_origin_ingress FROM contour_v2_ingress_test;")
    execute("GRANT contour_v2_ingress TO contour_origin_ingress_test;")
    try:
        submit(body, 'CrossRole')
    finally:
        execute("REVOKE contour_v2_ingress FROM contour_origin_ingress_test;")
    execute("ALTER ROLE contour_origin_ingress_test SET apicontour.tenant_id='bbbbbbbb-0000-0000-0000-000000000000';")
    try:
        submit(body, 'Contaminated')
    finally:
        execute("ALTER ROLE contour_origin_ingress_test RESET apicontour.tenant_id;")

    expiry = []
    def short_policy(policy):
        micros = int(execute('SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint;'))
        expiry.append(datetime.datetime.fromtimestamp(micros / 1000000, datetime.timezone.utc) + datetime.timedelta(seconds=5))
        policy['expires_at'] = expiry[-1].isoformat(timespec='microseconds').replace('+00:00', 'Z')
    expired, _, _ = setup('origin_expiry', short_policy)
    expired['wire_version'] = 2
    expired['records'] = [dict(record=record, origin_witness={'kind':'unattributed'}) for record in expired['records']]
    submit(expired, status='accepted')
    until = time.monotonic() + 20
    while execute("SELECT clock_timestamp() >= '%s'::timestamptz;" % expiry[0].isoformat()) != 't':
        if time.monotonic() >= until:
            raise AssertionError('origin policy expiry timed out')
        time.sleep(0.1)
    submit(expired, 'Policy')

    basic_expiry = []
    def short_basic_policy(policy):
        micros = int(execute('SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint;'))
        basic_expiry.append(datetime.datetime.fromtimestamp(micros / 1000000, datetime.timezone.utc) + datetime.timedelta(seconds=5))
        policy['expires_at'] = basic_expiry[-1].isoformat(timespec='microseconds').replace('+00:00', 'Z')
    basic_expired, _, _ = setup('basic_origin_retry_expiry', short_basic_policy)
    basic_expired['wire_version'] = 2
    basic_expired['records'] = [dict(record=record, origin_witness={'kind':'unattributed'}) for record in basic_expired['records']]
    check(basic_expired, status='accepted', v2=True)
    submit(basic_expired, status='duplicate')
    before_expiry = retained(basic_expired)
    until = time.monotonic() + 20
    while execute("SELECT clock_timestamp() >= '%s'::timestamptz;" % basic_expiry[0].isoformat()) != 't':
        if time.monotonic() >= until:
            raise AssertionError('Basic to origin policy expiry timed out')
        time.sleep(0.1)
    submit(basic_expired, 'Policy')
    if retained(basic_expired) != before_expiry:
        raise AssertionError('expired retry changed retained history or quota')

    # No current origin liveness is needed on exact retry, but collector authority
    # remains mandatory. Check revocation even after retained proof corruption.
    execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); UPDATE contour.collector_authorization SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id='%s' AND collector_id='%s'; COMMIT;" % (tenant, tenant, collector, tenant, collector))
    submit(body, 'Revoked')

    CommitProxy = runpy.run_path(str(ROOT/'scripts/test-postgres-recovery.py'))['CommitProxy']
    for mode, wanted in [('drop', 'OutcomeUnknown'), ('cleanup', 'AcceptedInvalidated')]:
        fresh, _, _ = setup('origin_commit_' + mode)
        fresh['wire_version'] = 2
        fresh['records'] = [dict(record=record, origin_witness={'kind': 'unattributed'}) for record in fresh['records']]
        proxy = CommitProxy(port, directory, mode)
        try:
            known = submit(fresh, wanted, override=proxy.port)
            proxy.finish()
        finally:
            proxy.close()
        retried = submit(fresh, status='duplicate')
        if mode == 'cleanup' and known != retried:
            raise AssertionError('known origin COMMIT receipt was lost')
    print('Restricted origin TLS mixed proof, canonical bytes, closed retry, role and COMMIT fault assertions passed')
