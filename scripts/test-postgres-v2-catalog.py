"""Opt-in synthetic storage fixtures; run from the existing catalog TLS harness.

Call run_cases(execute, accepted, check, counts) after standard migrations 1 through 4 (or later). These
fixtures bypass ingress to exercise corruption detection, and prove no admission.
"""
import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_historical_cases(execute, body, rows):
    scope="tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (body['tenant_id'],body['collector_id'],body['batch_id'])
    # Migration 25 must already be installed by the exact-profile harness.
    # The two retained windows share an operation but have distinct origins.
    if rows[0]['operation_id'] != rows[1]['operation_id'] or rows[0]['instance_id'] == rows[1]['instance_id']:
        raise AssertionError('historical fixture requires two origins for one operation')
    for row in rows:
        args=(body['tenant_id'],row['project_id'],row['service_id'],row['environment_id'],row['operation_id'],row['observation_id'])
        quoted=','.join("'%s'" % value for value in args)
        execute("""BEGIN; SET LOCAL ROLE contour_catalog_reader_tls;
          SELECT set_config('apicontour.tenant_id','%s',true);
          CREATE TEMP TABLE origin_proofs (instance_id uuid);
          CREATE TEMP TABLE catalog_origin_projection (instance_id uuid);
          DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM contour.human_observation_origin(%s) o
            WHERE (o.origin_project_id,o.origin_service_id,o.origin_environment_id,o.origin_deployment_id,o.instance_id)
             =('%s','%s','%s','%s','%s') AND o.lifecycle_id IS NOT NULL AND o.credential_id IS NOT NULL AND o.grant_id IS NOT NULL)
            THEN RAISE EXCEPTION 'historical origin mismatch'; END IF; END $$; ROLLBACK;""" %
          (body['tenant_id'],quoted,row['origin_project_id'],row['origin_service_id'],row['origin_environment_id'],row['origin_deployment_id'],row['instance_id']))
    # Historical lookup must remain anchored to the older window even if the
    # derived current heads are absent; the transaction restores them.
    older=rows[0]
    old_args=(body['tenant_id'],older['project_id'],older['service_id'],older['environment_id'],older['operation_id'],older['observation_id'])
    old_quoted=','.join("'%s'" % value for value in old_args)
    execute("""BEGIN; SET LOCAL session_replication_role=replica;
      DELETE FROM contour.catalog_origin_heads WHERE tenant_id='%s' AND operation_id='%s';
      SET LOCAL ROLE contour_catalog_reader_tls; SELECT set_config('apicontour.tenant_id','%s',true);
      DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM contour.human_observation_origin(%s) o WHERE o.instance_id='%s')
        THEN RAISE EXCEPTION 'historical origin depended on head'; END IF; END $$; ROLLBACK;""" %
      (body['tenant_id'],older['operation_id'],body['tenant_id'],old_quoted,older['instance_id']))
    selected=rows[0]
    unattributed=body['records'][2]['record']['record_id']
    execute("""BEGIN; SET LOCAL ROLE contour_catalog_reader_tls;
      SELECT set_config('apicontour.tenant_id','%s',true);
      DO $$ DECLARE observation uuid; BEGIN
        SELECT w.observation_id INTO STRICT observation FROM contour.observation_windows w
          WHERE w.tenant_id='%s' AND w.collector_id='%s' AND w.batch_id='%s' AND w.record_id='%s';
        IF EXISTS (SELECT 1 FROM contour.human_observation_origin('%s','%s','%s','%s','%s',observation))
          THEN RAISE EXCEPTION 'unattributed origin disclosed'; END IF;
      END $$; ROLLBACK;""" % (body['tenant_id'],body['tenant_id'],body['collector_id'],body['batch_id'],unattributed,
        body['tenant_id'],selected['project_id'],selected['service_id'],selected['environment_id'],selected['operation_id']))
    args=(body['tenant_id'],selected['project_id'],selected['service_id'],selected['environment_id'],selected['operation_id'],selected['observation_id'])
    quoted=','.join("'%s'" % value for value in args)
    for table,assignment,record_id in (
        ('catalog_origin_projection',None,selected['record_id']),
        ('ingestion_v2_metadata',"attribution_class='unattributed'",selected['record_id']),
        ('ingestion_v2_metadata',"attribution_class='verified_origin_v1'",body['records'][2]['record']['record_id']),
        ('observation_windows',"visibility='connection'",selected['record_id'])):
        statement=("DELETE FROM contour.%s WHERE %s AND record_id='%s'" % (table,scope,record_id) if assignment is None else
                   "UPDATE contour.%s SET %s WHERE %s AND record_id='%s'" % (table,assignment,scope,record_id))
        execute("""BEGIN; SET LOCAL session_replication_role=replica; %s;
          SET LOCAL ROLE contour_catalog_reader_tls; SELECT set_config('apicontour.tenant_id','%s',true);
          DO $$ DECLARE rejected boolean:=false; BEGIN
            BEGIN PERFORM * FROM contour.human_observation_origin(%s);
            EXCEPTION WHEN check_violation THEN rejected:=true; END;
            IF NOT rejected THEN RAISE EXCEPTION 'corrupt historical evidence accepted'; END IF;
          END $$; ROLLBACK;""" % (statement,body['tenant_id'],quoted))
    # Retained V2 batch and completion cannot become legacy by removing payload
    # and all selected-record evidence. This corruption is rolled back.
    execute("""BEGIN; SET LOCAL session_replication_role=replica;
      DELETE FROM contour.catalog_origin_projection WHERE %s AND record_id='%s';
      DELETE FROM contour.origin_proofs WHERE %s AND record_id='%s';
      DELETE FROM contour.ingestion_v2_metadata WHERE %s AND record_id='%s';
      DELETE FROM contour.ingestion_payloads WHERE %s;
      SET LOCAL ROLE contour_catalog_reader_tls; SELECT set_config('apicontour.tenant_id','%s',true);
      DO $$ DECLARE rejected boolean:=false; BEGIN
        BEGIN PERFORM * FROM contour.human_observation_origin(%s);
        EXCEPTION WHEN check_violation THEN rejected:=true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'missing V2 payload downgraded'; END IF;
      END $$; ROLLBACK;""" % (scope,selected['record_id'],scope,selected['record_id'],scope,selected['record_id'],scope,body['tenant_id'],quoted))
    # A projection for the unattributed record is also inconsistent.
    execute("""BEGIN; SET LOCAL session_replication_role=replica;
      INSERT INTO contour.catalog_origin_projection
      SELECT tenant_id,collector_id,batch_id,'%s',proof_id,origin_project_id,origin_service_id,origin_environment_id,origin_deployment_id,instance_id
      FROM contour.catalog_origin_projection WHERE %s AND record_id='%s';
      SET LOCAL ROLE contour_catalog_reader_tls; SELECT set_config('apicontour.tenant_id','%s',true);
      DO $$ DECLARE rejected boolean:=false; BEGIN
        BEGIN PERFORM * FROM contour.human_observation_origin(%s);
        EXCEPTION WHEN check_violation THEN rejected:=true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'extra historical projection accepted'; END IF;
      END $$; ROLLBACK;""" % (body['records'][2]['record']['record_id'],scope,selected['record_id'],body['tenant_id'],quoted))


def run_cases(execute, accepted, check, counts):
    execute((ROOT / 'db/provision_v2_ingress.sql').read_text())
    execute((ROOT / 'db/opt-in-migrations/0016_v2_unattributed.sql').read_text())

    def where(body):
        return "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (
            body['tenant_id'], body['collector_id'], body['batch_id'])

    def seed(name, witness=None, wrong_scope=False):
        body = accepted('v2_' + name, 2)
        wire = copy.deepcopy(body)
        wire['wire_version'] = 2
        if wrong_scope:
            wire['tenant_id'] = 'bbbbbbbb-0000-0000-0000-000000000000'
        wire['records'] = [dict(record=r, origin_witness=witness or {'kind': 'unattributed'}) for r in body['records']]
        payload = json.dumps(wire, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        digest = hashlib.sha256(b'apicontour/batch/2\n' + payload).hexdigest()
        execute("BEGIN; SET LOCAL session_replication_role=replica; UPDATE contour.ingestion_batches SET digest_version=2,request_digest=decode('%s','hex') WHERE %s; UPDATE contour.ingestion_payloads SET payload_format=2,checked_batch=decode('%s','hex') WHERE %s; COMMIT;" % (digest, where(body), payload.hex(), where(body)))
        for record in body['records']:
            execute("INSERT INTO contour.ingestion_v2_metadata SELECT b.tenant_id,b.collector_id,b.batch_id,'%s',2,b.request_digest,b.accepted_at,'%s','%s','%s','%s','%s',%s,'%s','unattributed' FROM contour.ingestion_batches b WHERE %s;" % (record['record_id'], record['source_id'], record['project_id'], record['service_id'], record['environment_id'], record['deployment_id'], record['policy_revision'], record['parser_profile'], where(body)))
        return body

    valid = seed('valid')
    # Numeric scale is immaterial for an exact integer value.
    execute("BEGIN; SET LOCAL session_replication_role=replica; UPDATE contour.ingestion_v2_metadata SET policy_revision=policy_revision::numeric(22,3) WHERE %s; COMMIT;" % where(valid))
    if execute("SELECT count(*) FROM contour.ingestion_v2_metadata WHERE %s AND policy_revision::text LIKE '%%.000';" % where(valid)) != '2':
        raise AssertionError('scaled integer fixture was not stored')
    check(valid)
    counts(valid, 1, 2)
    check(valid, 'AlreadyProcessed')
    stored = json.loads(execute("SELECT json_agg(row_to_json(w) ORDER BY record_id) FROM contour.observation_windows w WHERE %s;" % where(valid)))
    for actual, record in zip(stored, valid['records']):
        for field in ('record_id', 'source_id', 'project_id', 'service_id', 'environment_id', 'deployment_id'):
            if actual[field] != record[field]:
                raise AssertionError('V2 projection binding differs: ' + field)

    mutations = {
        'missing': "DELETE FROM contour.ingestion_v2_metadata WHERE %s AND record_id=(SELECT min(record_id::text)::uuid FROM contour.ingestion_v2_metadata WHERE %s)",
        'extra': "INSERT INTO contour.ingestion_v2_metadata SELECT tenant_id,collector_id,batch_id,'00000000-0000-4000-8000-00000000ffff',digest_version,request_digest,accepted_at,source_id,project_id,service_id,environment_id,deployment_id,policy_revision,parser_profile,attribution_class FROM contour.ingestion_v2_metadata WHERE %s LIMIT 1",
        'source': "UPDATE contour.ingestion_v2_metadata SET source_id='00000000-0000-4000-8000-00000000ffff' WHERE %s",
        'destination': "UPDATE contour.ingestion_v2_metadata SET deployment_id='00000000-0000-4000-8000-00000000ffff' WHERE %s",
        'fractional_policy': "UPDATE contour.ingestion_v2_metadata SET policy_revision=policy_revision+0.5 WHERE %s",
        'oversized_profile': "UPDATE contour.ingestion_v2_metadata SET parser_profile=repeat('x',1000000) WHERE %s",
        'policy': "UPDATE contour.ingestion_v2_metadata SET policy_revision=policy_revision+1 WHERE %s",
        'profile': "UPDATE contour.ingestion_v2_metadata SET parser_profile='other' WHERE %s",
        'digest_binding': "UPDATE contour.ingestion_v2_metadata SET request_digest=decode(repeat('00',32),'hex') WHERE %s",
        'accepted_at': "UPDATE contour.ingestion_v2_metadata SET accepted_at=accepted_at+interval '1 second' WHERE %s",
        'digest': "UPDATE contour.ingestion_batches SET request_digest=decode(repeat('00',32),'hex') WHERE %s",
        'wire': "UPDATE contour.ingestion_payloads SET checked_batch=decode('7b7d','hex') WHERE %s",
        'version': "UPDATE contour.ingestion_payloads SET payload_format=1 WHERE %s",
        'count': "UPDATE contour.ingestion_batches SET record_count=1 WHERE %s",
    }
    for name, template in mutations.items():
        body = seed(name)
        condition = where(body)
        statement = template % ((condition, condition) if name == 'missing' else condition)
        # Deliberate privileged damage; no application role has these rights.
        if name == 'oversized_profile':
            execute('ALTER TABLE contour.ingestion_v2_metadata DROP CONSTRAINT ingestion_v2_metadata_parser_profile_check;')
        execute('BEGIN; SET LOCAL session_replication_role=replica; ' + statement + '; COMMIT;')
        check(body, 'Corrupt')
        counts(body, 0, 0)
        if name == 'oversized_profile':
            execute("BEGIN; SET LOCAL session_replication_role=replica; UPDATE contour.ingestion_v2_metadata SET parser_profile='restored' WHERE %s; ALTER TABLE contour.ingestion_v2_metadata ADD CONSTRAINT ingestion_v2_metadata_parser_profile_check CHECK (parser_profile COLLATE \"C\" ~ '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$'); COMMIT;" % where(body))
    fingerprint = seed('fingerprint', {'kind': 'downstream_mtls_leaf_sha256_v1', 'leaf_sha256': 'ab' * 32})
    check(fingerprint, 'Corrupt')
    counts(fingerprint, 0, 0)
    scope = seed('scope', wrong_scope=True)
    check(scope, 'Corrupt')
    counts(scope, 0, 0)


def run_origin_cases(execute, body, port, directory, environment, expected_origins):
    """Exercise committed proof history using the real restricted catalog login.

    Called after origin admission and lifecycle closure, before proof damage in
    the separate origin-ingress fixture. This function does not create proofs.
    """
    import subprocess

    target = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--format-version', '1', '--no-deps', '--offline'],
        text=True, timeout=15))['target_directory']
    probe = str(Path(target) / 'debug/examples/catalog_probe')
    scope = "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (
        body['tenant_id'], body['collector_id'], body['batch_id'])

    def check(wanted):
        process = subprocess.run([probe, str(port), str(directory / 'ca.crt'),
            body['batch_id'], wanted, body['tenant_id'], body['collector_id'], '5000'],
            input='\n', capture_output=True, text=True, env=environment, timeout=15)
        if process.returncode or process.stderr or process.stdout.strip() != wanted:
            raise AssertionError('restricted origin catalog result differs: ' + process.stdout + process.stderr)

    def counts(wanted):
        actual = execute("SELECT (SELECT count(*) FROM contour.catalog_processed_batches WHERE %s),(SELECT count(*) FROM contour.observation_windows WHERE %s),(SELECT count(*) FROM contour.catalog_origin_projection WHERE %s);" % (scope, scope, scope))
        if actual != wanted:
            raise AssertionError('origin catalog atomic counts differ: ' + actual)

    if execute("SELECT has_table_privilege('contour_catalog_tls','contour.origin_proofs','SELECT'),has_function_privilege('contour_catalog_tls','contour.catalog_origin_mapping(uuid,uuid,uuid,bytea)','EXECUTE');") != 'f|t':
        raise AssertionError('catalog proof privilege boundary differs')
    marker = execute("SELECT encode(proof_set_digest,'hex') FROM contour.origin_batch_proof_completion WHERE %s;" % scope)
    execute("BEGIN; ALTER TABLE contour.origin_batch_proof_completion DISABLE TRIGGER origin_batch_completion_immutable; UPDATE contour.origin_batch_proof_completion SET proof_set_digest=decode(repeat('00',32),'hex') WHERE %s; ALTER TABLE contour.origin_batch_proof_completion ENABLE TRIGGER origin_batch_completion_immutable; COMMIT;" % scope)
    check('Corrupt')
    counts('0|0|0')
    execute("BEGIN; ALTER TABLE contour.origin_batch_proof_completion DISABLE TRIGGER origin_batch_completion_immutable; UPDATE contour.origin_batch_proof_completion SET proof_set_digest=decode('%s','hex') WHERE %s; ALTER TABLE contour.origin_batch_proof_completion ENABLE TRIGGER origin_batch_completion_immutable; COMMIT;" % (marker, scope))
    execute("BEGIN; SET LOCAL session_replication_role=replica; UPDATE contour.ingestion_v2_metadata SET attribution_class='unattributed' WHERE %s AND attribution_class='verified_origin_v1'; COMMIT;" % scope)
    check('Corrupt')
    counts('0|0|0')
    execute("BEGIN; SET LOCAL session_replication_role=replica; UPDATE contour.ingestion_v2_metadata SET attribution_class='verified_origin_v1' WHERE %s AND record_id IN (SELECT record_id FROM contour.origin_proofs WHERE %s); COMMIT;" % (scope, scope))
    proof = execute("SELECT encode(canonical_proof,'hex') FROM contour.origin_proofs WHERE %s ORDER BY record_id LIMIT 1;" % scope)
    execute("BEGIN; ALTER TABLE contour.origin_proofs DISABLE TRIGGER origin_proof_immutable; UPDATE contour.origin_proofs SET canonical_proof=canonical_proof || decode('00','hex') WHERE %s AND record_id=(SELECT min(record_id::text)::uuid FROM contour.origin_proofs WHERE %s); ALTER TABLE contour.origin_proofs ENABLE TRIGGER origin_proof_immutable; COMMIT;" % (scope, scope))
    check('Corrupt')
    counts('0|0|0')
    execute("BEGIN; ALTER TABLE contour.origin_proofs DISABLE TRIGGER origin_proof_immutable; UPDATE contour.origin_proofs SET canonical_proof=decode('%s','hex') WHERE %s AND record_id=(SELECT min(record_id::text)::uuid FROM contour.origin_proofs WHERE %s); ALTER TABLE contour.origin_proofs ENABLE TRIGGER origin_proof_immutable; COMMIT;" % (proof, scope, scope))
    execute("CREATE FUNCTION contour.catalog_origin_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture projection failure'; END $$; CREATE TRIGGER catalog_origin_fixture_fail BEFORE INSERT ON contour.catalog_origin_projection FOR EACH ROW EXECUTE FUNCTION contour.catalog_origin_fixture_fail();")
    try:
        check('Database')
        counts('0|0|0')
    finally:
        execute('DROP TRIGGER catalog_origin_fixture_fail ON contour.catalog_origin_projection; DROP FUNCTION contour.catalog_origin_fixture_fail();')
    check('Processed')
    counts('1|3|2')
    # Execute the attempted writes as the actual restricted catalog login. A
    # missing privilege or a 23514/42501 verifier rejection is asserted in SQL.
    execute("""BEGIN; SET LOCAL ROLE contour_catalog_tls;
      SELECT set_config('apicontour.tenant_id','%(tenant)s',true);
      DO $$ DECLARE payload bytea; rejected boolean; BEGIN
        SELECT checked_batch INTO STRICT payload FROM contour.ingestion_payloads WHERE %(scope)s;
        rejected := false;
        BEGIN
          INSERT INTO contour.catalog_origin_projection
            SELECT tenant_id,collector_id,batch_id,record_id,
              '00000000-0000-0000-0000-00000000ffff'::uuid,
              project_id,service_id,environment_id,deployment_id,
              '00000000-0000-0000-0000-00000000ffff'::uuid
            FROM contour.observation_windows WHERE %(scope)s LIMIT 1;
        EXCEPTION WHEN insufficient_privilege THEN rejected := true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'forged direct projection accepted'; END IF;
        rejected := false;
        BEGIN
          PERFORM * FROM contour.catalog_origin_mapping('%(tenant)s','%(collector)s','%(batch)s',payload || decode('20','hex'));
        EXCEPTION WHEN check_violation THEN rejected := true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'forged payload accepted'; END IF;
        rejected := false;
        BEGIN
          PERFORM * FROM contour.catalog_origin_mapping('bbbbbbbb-0000-0000-0000-000000000000','%(collector)s','%(batch)s',payload);
        EXCEPTION WHEN insufficient_privilege THEN rejected := true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'forged tenant accepted'; END IF;
        rejected := false;
        BEGIN
          PERFORM contour.project_catalog_origins('%(tenant)s','%(collector)s','%(batch)s',
            convert_to(replace(convert_from(payload,'UTF8'),'%(record)s','00000000-0000-0000-0000-00000000ffff'),'UTF8'));
        EXCEPTION WHEN check_violation THEN rejected := true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'forged record accepted'; END IF;
      END $$; ROLLBACK;""" % dict(tenant=body['tenant_id'], collector=body['collector_id'],
                                 batch=body['batch_id'], record=body['records'][0]['record']['record_id'], scope=scope))
    execute("BEGIN; SET LOCAL ROLE contour_catalog_tls; SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true); DO $$ BEGIN IF EXISTS (SELECT 1 FROM contour.catalog_origin_projection WHERE %s) THEN RAISE EXCEPTION 'cross-tenant projection visible'; END IF; END $$; ROLLBACK;" % scope)
    rows = json.loads(execute("SELECT json_agg(row_to_json(x) ORDER BY record_id) FROM (SELECT p.record_id,p.proof_id,p.origin_project_id,p.origin_service_id,p.origin_environment_id,p.origin_deployment_id,p.instance_id,w.observation_id,w.operation_id,w.project_id,w.service_id,w.environment_id,w.deployment_id FROM contour.catalog_origin_projection p JOIN contour.observation_windows w USING(tenant_id,collector_id,batch_id,record_id) WHERE p.%s ORDER BY p.record_id) x;" % scope.replace(' AND ', ' AND p.')))
    target = body['records'][0]['record']
    for row, origin in zip(rows, expected_origins):
        for field, value in origin.items():
            if row[field] != value:
                raise AssertionError('origin projection mismatch: ' + field)
        for field in ('project_id', 'service_id', 'environment_id', 'deployment_id'):
            if row[field] != target[field]:
                raise AssertionError('API target projection mismatch: ' + field)
    if len(rows) != 2 or rows[0]['proof_id'] == rows[1]['proof_id']:
        raise AssertionError('expected two distinct proof identities')
    if environment.get('CONTOUR_HUMAN_ORIGIN_FIXTURE') == '1':
        # Exercise the human-reader helper on real historical projected proofs, with
        # the restricted reader role and full origin tuple. No private table grant.
        for row in rows:
            args = (body['tenant_id'], row['project_id'], row['service_id'], row['environment_id'], row['operation_id'],
                    row['origin_project_id'], row['origin_service_id'], row['origin_environment_id'], row['origin_deployment_id'], row['instance_id'])
            quoted = ','.join("'%s'" % value for value in args)
            candidate = ','.join("'%s'" % value for value in (*args[:4], *args[5:], None)).replace("'None'", 'NULL') + ',201'
            execute("""BEGIN; SET LOCAL ROLE contour_catalog_reader_tls;
              SELECT set_config('apicontour.tenant_id','%s',true);
              DO $$ BEGIN
               IF NOT EXISTS (SELECT 1 FROM contour.human_origin_candidates(%s) c WHERE c.operation_id='%s') THEN
                 RAISE EXCEPTION 'full origin candidate missing'; END IF;
               IF NOT EXISTS (SELECT 1 FROM contour.human_origin_operation(%s) o
                  WHERE (o.origin_project_id,o.origin_service_id,o.origin_environment_id,o.origin_deployment_id,o.instance_id)
                   =('%s','%s','%s','%s','%s') AND NOT o.truncated) THEN
                 RAISE EXCEPTION 'verified origin missing'; END IF;
              END $$; ROLLBACK;""" % (body['tenant_id'], candidate, row['operation_id'], quoted, *args[5:]))
            wrong = list(args); wrong[5] = '00000000-0000-0000-0000-00000000ffff'
            candidate_wrong = ','.join("'%s'" % value for value in (*wrong[:4], *wrong[5:], None)).replace("'None'", 'NULL') + ',201'
            execute("""BEGIN; SET LOCAL ROLE contour_catalog_reader_tls;
              SELECT set_config('apicontour.tenant_id','%s',true);
              DO $$ BEGIN IF EXISTS (SELECT 1 FROM contour.human_origin_candidates(%s)) THEN
               RAISE EXCEPTION 'partial or wrong origin matched'; END IF; END $$; ROLLBACK;""" % (body['tenant_id'], candidate_wrong))
        # One-sided projection corruption is detected before any verified row is returned.
        row = rows[0]
        args = (body['tenant_id'], row['project_id'], row['service_id'], row['environment_id'], row['operation_id'],
                row['origin_project_id'], row['origin_service_id'], row['origin_environment_id'], row['origin_deployment_id'], row['instance_id'])
        quoted = ','.join("'%s'" % value for value in args)
        execute("""BEGIN; SET LOCAL session_replication_role=replica;
          DELETE FROM contour.catalog_origin_projection WHERE %s AND record_id='%s';
          SET LOCAL ROLE contour_catalog_reader_tls; SELECT set_config('apicontour.tenant_id','%s',true);
          DO $$ DECLARE rejected boolean:=false; BEGIN
            BEGIN PERFORM * FROM contour.human_origin_operation(%s);
            EXCEPTION WHEN check_violation THEN rejected:=true; END;
            IF NOT rejected THEN RAISE EXCEPTION 'missing projection accepted'; END IF;
          END $$; ROLLBACK;""" % (scope, row['record_id'], body['tenant_id'], quoted))
        execute("""BEGIN; SET LOCAL session_replication_role=replica;
          DELETE FROM contour.observation_windows WHERE %s AND record_id='%s';
          SET LOCAL ROLE contour_catalog_reader_tls; SELECT set_config('apicontour.tenant_id','%s',true);
          DO $$ DECLARE rejected boolean:=false; BEGIN
            BEGIN PERFORM * FROM contour.human_origin_operation(%s);
            EXCEPTION WHEN check_violation THEN rejected:=true; END;
            IF NOT rejected THEN RAISE EXCEPTION 'missing selected window accepted'; END IF;
          END $$; ROLLBACK;""" % (scope, row['record_id'], body['tenant_id'], quoted))
        # Same-instant alternate timestamp text must fail, as must changed
        # visibility/completeness. These are checked against retained wire bytes.
        for assignment in ("last_seen=replace(last_seen,'Z','+00:00')", "visibility='connection'", "completeness='unavailable'"):
            execute("""BEGIN; SET LOCAL session_replication_role=replica;
              UPDATE contour.observation_windows SET %s WHERE %s AND record_id='%s';
              SET LOCAL ROLE contour_catalog_reader_tls; SELECT set_config('apicontour.tenant_id','%s',true);
              DO $$ DECLARE rejected boolean:=false; BEGIN
                BEGIN PERFORM * FROM contour.human_origin_operation(%s);
                EXCEPTION WHEN check_violation THEN rejected:=true; END;
                IF NOT rejected THEN RAISE EXCEPTION 'mismatched selected window accepted'; END IF;
              END $$; ROLLBACK;""" % (assignment, scope, row['record_id'], body['tenant_id'], quoted))
        # The whole batch is checked in both witness/class directions, including
        # an unattributed record unrelated to the selected verified head.
        for record_id, attribution in ((row['record_id'],'unattributed'), (body['records'][2]['record']['record_id'],'verified_origin_v1')):
            execute("""BEGIN; SET LOCAL session_replication_role=replica;
              UPDATE contour.ingestion_v2_metadata SET attribution_class='%s' WHERE %s AND record_id='%s';
              SET LOCAL ROLE contour_catalog_reader_tls; SELECT set_config('apicontour.tenant_id','%s',true);
              DO $$ DECLARE rejected boolean:=false; BEGIN
                BEGIN PERFORM * FROM contour.human_origin_operation(%s);
                EXCEPTION WHEN check_violation THEN rejected:=true; END;
                IF NOT rejected THEN RAISE EXCEPTION 'mismatched attribution accepted'; END IF;
              END $$; ROLLBACK;""" % (attribution, scope, record_id, body['tenant_id'], quoted))
        for damaged_table in ('origin_proofs', 'origin_batch_proof_completion'):
            execute("""BEGIN; SET LOCAL session_replication_role=replica;
              DELETE FROM contour.%s WHERE %s;
              SET LOCAL ROLE contour_catalog_reader_tls; SELECT set_config('apicontour.tenant_id','%s',true);
              DO $$ DECLARE rejected boolean:=false; BEGIN
                BEGIN PERFORM * FROM contour.human_origin_operation(%s);
                EXCEPTION WHEN check_violation THEN rejected:=true; END;
                IF NOT rejected THEN RAISE EXCEPTION 'missing proof history accepted'; END IF;
              END $$; ROLLBACK;""" % (damaged_table, scope, body['tenant_id'], quoted))
    check('AlreadyProcessed')
    execute("BEGIN; ALTER TABLE contour.catalog_origin_projection DISABLE TRIGGER catalog_origin_immutable; UPDATE contour.catalog_origin_projection SET instance_id='00000000-0000-0000-0000-00000000ffff' WHERE %s; ALTER TABLE contour.catalog_origin_projection ENABLE TRIGGER catalog_origin_immutable; COMMIT;" % scope)
    check('Corrupt')
    counts('1|3|2')
    # The fixture is subsequently used by ingress corruption checks, not catalog.
    # Restore the exact retained origin identities before continuing.
    for row in rows:
        execute("BEGIN; ALTER TABLE contour.catalog_origin_projection DISABLE TRIGGER catalog_origin_immutable; UPDATE contour.catalog_origin_projection SET instance_id='%s' WHERE %s AND record_id='%s'; ALTER TABLE contour.catalog_origin_projection ENABLE TRIGGER catalog_origin_immutable; COMMIT;" % (row['instance_id'], scope, row['record_id']))
    check('AlreadyProcessed')
    print('Restricted catalog origin projection, historical retry, corruption and rollback assertions passed', flush=True)


def run_basic_compat_cases(execute, bodies, origin_body, port, directory, environment):
    """Real Basic V2 admission before/after 17 retains ordinary wire encoding."""
    import subprocess

    target = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--format-version', '1', '--no-deps', '--offline'],
        text=True, timeout=15))['target_directory']
    probe = str(Path(target) / 'debug/examples/catalog_probe')

    def scope(body):
        return "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (
            body['tenant_id'], body['collector_id'], body['batch_id'])

    def check(body, wanted):
        process = subprocess.run([probe, str(port), str(directory / 'ca.crt'),
            body['batch_id'], wanted, body['tenant_id'], body['collector_id'], '5000'],
            input='\n', capture_output=True, text=True, env=environment, timeout=15)
        if process.returncode or process.stderr or process.stdout.strip() != wanted:
            raise AssertionError('basic V2 catalog result differs: ' + process.stdout + process.stderr)

    for body in bodies:
        where = scope(body)
        result = execute("BEGIN; SET LOCAL ROLE contour_catalog_tls; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.catalog_origin_requires_canonical('%s','%s','%s'); ROLLBACK;" % (body['tenant_id'],body['tenant_id'],body['collector_id'],body['batch_id']))
        if result.splitlines()[-1] != 'f':
            raise AssertionError('Basic wire provenance was not retained')
        row = execute("SELECT encode(p.checked_batch,'hex'),encode(b.request_digest,'hex') FROM contour.ingestion_payloads p JOIN contour.ingestion_batches b USING(tenant_id,collector_id,batch_id) WHERE p." + where.replace(' AND ', ' AND p.'))
        wire_hex, digest = row.split('|')
        wire = bytes.fromhex(wire_hex)
        canonical = json.dumps(json.loads(wire), sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        if wire == canonical or hashlib.sha256(b'apicontour/batch/2\n' + canonical).hexdigest() != digest:
            raise AssertionError('Basic V2 ordinary/canonical encoding fixture differs')
        if hashlib.sha256(b'apicontour/batch/2\n' + wire).hexdigest() == digest:
            raise AssertionError('ordinary wire unexpectedly has canonical digest')
        for table in ('origin_proofs', 'origin_batch_proof_completion'):
            # Preserve the source proof; manufacture only a damaged scoped key.
            execute("BEGIN; SET LOCAL session_replication_role=replica; INSERT INTO contour.%s SELECT (jsonb_populate_record(NULL::contour.%s,to_jsonb(x) || jsonb_build_object('tenant_id','%s','collector_id','%s','batch_id','%s','proof_id','00000000-0000-0000-0000-00000000ffff'))).* FROM contour.%s x WHERE %s LIMIT 1; COMMIT;" % (table, table, body['tenant_id'], body['collector_id'], body['batch_id'], table, scope(origin_body)))
            check(body, 'Corrupt')
            if execute("SELECT (SELECT count(*) FROM contour.catalog_processed_batches WHERE %s),(SELECT count(*) FROM contour.observation_windows WHERE %s);" % (where, where)) != '0|0':
                raise AssertionError('corrupt origin history claimed Basic V2 batch')
            execute('BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM contour.' + table + ' WHERE ' + where + '; COMMIT;')
        check(body, 'Processed')
        check(body, 'AlreadyProcessed')
        # A fabricated projection on an already processed unattributed record
        # must prevent the AlreadyProcessed success path.
        record = body['records'][0]['record']['record_id']
        values = (body['tenant_id'], body['collector_id'], body['batch_id'], record)
        execute("BEGIN; SET LOCAL session_replication_role=replica; INSERT INTO contour.catalog_origin_projection VALUES ('%s','%s','%s','%s','00000000-0000-0000-0000-00000000ffff','00000000-0000-0000-0000-00000000ffff','00000000-0000-0000-0000-00000000ffff','00000000-0000-0000-0000-00000000ffff','00000000-0000-0000-0000-00000000ffff','00000000-0000-0000-0000-00000000ffff'); COMMIT;" % values)
        check(body, 'Corrupt')
        execute('BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM contour.catalog_origin_projection WHERE ' + where + '; COMMIT;')
        check(body, 'AlreadyProcessed')
    print('Basic V2 ordinary-wire compatibility before and after schema 17 passed', flush=True)


def run_v1_origin_absence_cases(execute, body, origin_body, port, directory, environment):
    """V1 never acquires origin history, including before its first claim."""
    import subprocess

    target = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--format-version', '1', '--no-deps', '--offline'],
        text=True, timeout=15))['target_directory']
    probe = str(Path(target) / 'debug/examples/catalog_probe')

    def scope(item):
        return "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (
            item['tenant_id'], item['collector_id'], item['batch_id'])

    def check(wanted):
        process = subprocess.run([probe, str(port), str(directory / 'ca.crt'),
            body['batch_id'], wanted, body['tenant_id'], body['collector_id'], '5000'],
            input='\n', capture_output=True, text=True, env=environment, timeout=15)
        if process.returncode or process.stderr or process.stdout.strip() != wanted:
            raise AssertionError('V1 origin absence result differs: ' + process.stdout + process.stderr)

    where = scope(body)
    for table in ('origin_proofs', 'origin_batch_proof_completion', 'catalog_origin_projection'):
        if table == 'catalog_origin_projection':
            values = (body['tenant_id'], body['collector_id'], body['batch_id'], body['records'][0]['record_id'])
            statement = "INSERT INTO contour.catalog_origin_projection VALUES ('%s','%s','%s','%s','00000000-0000-0000-0000-00000000ffff','00000000-0000-0000-0000-00000000ffff','00000000-0000-0000-0000-00000000ffff','00000000-0000-0000-0000-00000000ffff','00000000-0000-0000-0000-00000000ffff','00000000-0000-0000-0000-00000000ffff')" % values
        else:
            statement = "INSERT INTO contour.%s SELECT (jsonb_populate_record(NULL::contour.%s,to_jsonb(x) || jsonb_build_object('tenant_id','%s','collector_id','%s','batch_id','%s','proof_id','00000000-0000-0000-0000-00000000ffff'))).* FROM contour.%s x WHERE %s LIMIT 1" % (table, table, body['tenant_id'], body['collector_id'], body['batch_id'], table, scope(origin_body))
        execute('BEGIN; SET LOCAL session_replication_role=replica; ' + statement + '; COMMIT;')
        check('Corrupt')
        if execute("SELECT (SELECT count(*) FROM contour.catalog_processed_batches WHERE %s),(SELECT count(*) FROM contour.observation_windows WHERE %s);" % (where, where)) != '0|0':
            raise AssertionError('corrupt origin history claimed V1 batch')
        execute('BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM contour.' + table + ' WHERE ' + where + '; COMMIT;')
    check('Processed')
    check('AlreadyProcessed')
    print('V1 origin absence before catalog claim passed', flush=True)


def run_origin_zero_canonical_cases(execute, body, port, directory, environment):
    """Origin-created unattributed bytes stay canonical on claim and replay."""
    import subprocess

    target = json.loads(subprocess.check_output(
        ['cargo','metadata','--format-version','1','--no-deps','--offline'],
        text=True,timeout=15))['target_directory']
    probe = str(Path(target)/'debug/examples/catalog_probe')
    where = "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (
        body['tenant_id'],body['collector_id'],body['batch_id'])
    acl = execute("SELECT has_function_privilege('contour_catalog_tls','contour.catalog_origin_requires_canonical(uuid,uuid,uuid)','EXECUTE'),has_function_privilege('contour_origin_ingress_test','contour.catalog_origin_requires_canonical(uuid,uuid,uuid)','EXECUTE'),has_function_privilege('contour_v2_ingress','contour.catalog_origin_requires_canonical(uuid,uuid,uuid)','EXECUTE');")
    if acl != 't|f|f':
        raise AssertionError('catalog provenance helper role boundary differs')
    result = execute("BEGIN; SET LOCAL ROLE contour_catalog_tls; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.catalog_origin_requires_canonical('%s','%s','%s'); ROLLBACK;" % (body['tenant_id'],body['tenant_id'],body['collector_id'],body['batch_id']))
    if result.splitlines()[-1] != 't':
        raise AssertionError('Origin wire provenance was not retained')
    other = 'bbbbbbbb-0000-0000-0000-000000000000' if body['tenant_id'] != 'bbbbbbbb-0000-0000-0000-000000000000' else 'aaaaaaaa-0000-0000-0000-000000000000'
    execute("""BEGIN; SET LOCAL ROLE contour_catalog_tls;
      SELECT set_config('apicontour.tenant_id','%s',true);
      DO $$ DECLARE rejected boolean:=false; BEGIN
        BEGIN PERFORM contour.catalog_origin_requires_canonical('%s','%s','%s');
        EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'cross-tenant provenance read accepted'; END IF;
      END $$; ROLLBACK;""" % (body['tenant_id'],other,body['collector_id'],body['batch_id']))
    row = execute("SELECT encode(p.checked_batch,'hex'),encode(b.request_digest,'hex'),p.origin_writer_provenance FROM contour.ingestion_payloads p JOIN contour.ingestion_batches b USING(tenant_id,collector_id,batch_id) WHERE p." + where.replace(' AND ',' AND p.'))
    original_hex,digest,provenance = row.split('|')
    original = bytes.fromhex(original_hex)
    wire = json.dumps(body,indent=2,ensure_ascii=False).encode()
    canonical = json.dumps(body,sort_keys=True,separators=(',', ':'),ensure_ascii=False).encode()
    if provenance != 't' or original != canonical or wire == canonical or json.loads(wire) != body:
        raise AssertionError('origin zero canonical corruption reproducer invalid')
    if hashlib.sha256(b'apicontour/batch/2\n'+canonical).hexdigest() != digest:
        raise AssertionError('origin zero semantic digest mismatch')

    def check(expected):
        process = subprocess.run([probe,str(port),str(directory/'ca.crt'),body['batch_id'],expected,
            body['tenant_id'],body['collector_id'],'5000'],input='\n',capture_output=True,text=True,env=environment,timeout=15)
        if process.returncode or process.stderr or process.stdout.strip() != expected:
            raise AssertionError('origin zero catalog outcome mismatch: ' + process.stdout + process.stderr)
    def counts(expected):
        actual = execute("SELECT (SELECT count(*) FROM contour.catalog_processed_batches WHERE %s),(SELECT count(*) FROM contour.observation_windows WHERE %s),(SELECT count(*) FROM contour.catalog_origin_projection WHERE %s);" % (where,where,where))
        if actual != expected:
            raise AssertionError('origin zero catalog atomic counts differ')
    def rewrite(value):
        execute("BEGIN; SET LOCAL session_replication_role=replica; UPDATE contour.ingestion_payloads SET checked_batch=decode('%s','hex') WHERE %s; COMMIT;" % (value.hex(),where))

    counts('0|0|0')
    rewrite(wire)
    try:
        check('Corrupt'); counts('0|0|0')
    finally:
        rewrite(original)
    check('Processed'); counts('1|%d|0' % len(body['records']))
    check('AlreadyProcessed')
    rewrite(wire)
    try:
        check('Corrupt'); counts('1|%d|0' % len(body['records']))
    finally:
        rewrite(original)
    check('AlreadyProcessed')
    print('Origin zero-witness canonical integrity before claim and on replay passed',flush=True)
