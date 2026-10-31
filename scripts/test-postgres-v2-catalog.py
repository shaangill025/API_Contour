"""Opt-in synthetic storage fixtures; run from the existing catalog TLS harness.

Call run_cases(execute, accepted, check, counts) after standard migrations 1 through 4 (or later). These
fixtures bypass ingress to exercise corruption detection, and prove no admission.
"""
import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
