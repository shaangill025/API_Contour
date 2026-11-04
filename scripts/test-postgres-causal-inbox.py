"""Generate SQL parser assertions from the checked-in Core causal vectors.

Usage: python3 scripts/test-postgres-causal-inbox.py > /tmp/inbox-vectors.sql
Run the generated script against a disposable database migrated through 20.
This only tests the SQL codec, not transport, session races, quota or retention.
"""
import json
from pathlib import Path


def emit_vectors():
    root = Path(__file__).resolve().parent.parent
    fixtures = json.loads((root / 'docs/specification/fixtures/causal-events.json').read_text())
    print('SET ROLE contour_owner;')
    for fixture in fixtures:
        body = fixture.get('canonical') or json.dumps(fixture['body'], separators=(',', ':'), sort_keys=True, ensure_ascii=False)
        literal = "convert_to(" + "'" + body.replace("'", "''") + "','UTF8')"
        if fixture['expected'] == 'accept':
            print('DO $$ DECLARE j jsonb; BEGIN')
            print(f' j:=contour.causal_parse({literal});')
            print(f" IF encode(sha256(convert_to(E'apicontour/causal-events/1\\n','UTF8')||{literal}),'hex') <> '{fixture['sha256']}' THEN RAISE EXCEPTION 'batch digest {fixture['id']}'; END IF;")
            for i, event in enumerate(fixture['events']):
                print(f" IF encode((SELECT event_digest FROM contour.causal_decoded_events(j) OFFSET {i} LIMIT 1),'hex') <> '{event['sha256']}' THEN RAISE EXCEPTION 'event digest {fixture['id']} {i}'; END IF;")
            print('END $$;')
        else:
            print(f"DO $$ BEGIN BEGIN PERFORM contour.causal_parse({literal}); RAISE EXCEPTION 'accepted invalid fixture {fixture['id']}' USING ERRCODE='P0001'; EXCEPTION WHEN data_exception OR check_violation THEN NULL; END; END $$;")
    print('RESET ROLE;')


def _blocking_policy_after_inbox(psql_argv, execute, inbox_sql, policy_sql):
    """Observe the legacy policy writer wait for C until inbox commit."""
    import os
    import selectors
    import subprocess
    import time
    import uuid
    marker = 'inbox_barrier_' + uuid.uuid4().hex
    app = 'inbox_policy_' + uuid.uuid4().hex
    winner = subprocess.Popen(psql_argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    rival = None
    selector = selectors.DefaultSelector()
    try:
        selector.register(winner.stdout, selectors.EVENT_READ)
        winner.stdin.write(('BEGIN; ' + inbox_sql + '\n\\echo ' + marker + '\n').encode())
        winner.stdin.flush()
        deadline = time.monotonic() + 15
        output = b''
        while marker.encode() not in output.splitlines():
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise TimeoutError('inbox barrier not reached')
            part = os.read(winner.stdout.fileno(), 65536)
            if not part:
                raise RuntimeError('inbox writer exited before barrier')
            output += part
            if len(output) > 65536:
                raise RuntimeError('inbox barrier output limit')
        rival = subprocess.Popen(psql_argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        rival.stdin.write(("SET application_name='" + app + "'; BEGIN; " + policy_sql + " COMMIT;\n").encode())
        rival.stdin.close()
        rival.stdin = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            waiting = execute("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name='" + app + "' AND wait_event_type='Lock';")
            if waiting.strip() == '1':
                break
            if rival.poll() is not None:
                raise AssertionError('policy writer exited without waiting on C')
            time.sleep(0.05)
        else:
            raise TimeoutError('policy lock wait not observed')
        _, errors = winner.communicate(b'COMMIT;\n', timeout=15)
        if winner.returncode:
            raise RuntimeError('inbox commit failed: ' + errors.decode(errors='replace'))
        _, errors = rival.communicate(timeout=15)
        if rival.returncode:
            raise RuntimeError('policy commit failed: ' + errors.decode(errors='replace'))
    finally:
        selector.close()
        for process in (winner, rival):
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


def run_session_races(fresh):
    """Test Q-serialized session issue and terminal races in disposable databases.

    fresh() creates a separate fixture database through migration 20 and returns
    (psql_argv, execute). execute(sql) executes SQL with errors propagated.
    This does not provision a database or test an actual 17 proof write.
    """
    import runpy
    helpers = runpy.run_path(str(Path(__file__).resolve().parent / 'test-postgres-causal-sessions.py'))
    race, issue, terminal, setup, policy = (helpers[k] for k in ('race', '_issue', '_terminal', '_setup', '_policy_change'))
    tenant = helpers['TENANT']
    runtime = helpers['RUNTIME']
    body = ('{"batch_id":"aa000000-0000-4000-8000-000000000001",'
            '"events":[{"event_id":"11111111111111111111111111111111","kind":"root",'
            '"root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","seq":1}],"first_seq":1,"last_seq":1,'
            '"runtime_id":"' + runtime + '","session_epoch":1,"tenant_id":"' + tenant + '","wire_version":1}')
    accept = (setup('contour_causal_inbox_writer') + "SELECT * FROM contour.accept_causal_batch('" + tenant + "','" + runtime + "',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),convert_to('" + body + "','UTF8')); ")
    original = 'fe000000-0000-4000-8000-000000000001'
    next_nonce = 'fe000000-0000-4000-8000-000000000002'
    for event in ('issue', 'runtime_closed', 'export_revoked', 'credential_revoked', 'lifecycle_closed', 'cas', 'disable', 'revoke'):
        for inbox_first in (True, False):
            argv, execute = fresh()
            execute('BEGIN; ' + issue(original) + ' COMMIT;')
            other = issue(next_nonce) if event == 'issue' else (policy(event) if event in ('cas', 'disable', 'revoke') else terminal(event))
            if inbox_first and event in ('cas', 'disable', 'revoke'):
                _blocking_policy_after_inbox(argv, execute, accept, other)
                denied = setup('contour_causal_inbox_writer') + ("DO $$ DECLARE ok boolean:=false; BEGIN BEGIN "
                    + accept.removeprefix(setup('contour_causal_inbox_writer')).replace('SELECT * FROM ', 'PERFORM ')
                    + " EXCEPTION WHEN check_violation THEN ok:=true; END; IF NOT ok THEN RAISE EXCEPTION 'old policy still admitted'; END IF; END $$;")
                execute('BEGIN; ' + denied + ' COMMIT;')
            else:
                race(argv, accept if inbox_first else other,
                     other if inbox_first else accept,
                     other if inbox_first else accept,
                     retry_sqlstate=None if inbox_first else '23514')
            expected = 1 if inbox_first else 0
            result = execute("SELECT count(*) FROM contour.causal_inbox_batches WHERE batch_id='aa000000-0000-4000-8000-000000000001';")
            if int(result) != expected:
                raise AssertionError('race committed unexpected inbox row')


if __name__ == '__main__':
    emit_vectors()


def run_shared_quota_races(fresh, core_example):
    """Exercise genuine restricted 17 and 20 writers against the same Q/ledger.

    fresh() returns (psql_argv, execute) for a new 1..20 DB initialized with
    causal_runtime_registry_pre.sql, 18, causal_session_setup.sql, 19, 20.
    core_example is the locally built fixture_v2_canonical executable. execute
    must stop on SQL errors and return the final scalar for scalar queries.
    This function starts no database, listener or network service.
    """
    import copy
    import runpy
    import subprocess
    helpers = runpy.run_path(str(Path(__file__).resolve().parent / 'test-postgres-causal-sessions.py'))
    tenant, runtime, collector = (helpers[k] for k in ('TENANT', 'RUNTIME', 'COLLECTOR'))
    source = 'f7000000-0000-4000-8000-000000000001'
    project = 'f1000000-0000-4000-8000-000000000001'
    service = 'f2000000-0000-4000-8000-000000000001'
    environment = 'f3000000-0000-4000-8000-000000000001'
    deployment = 'f4000000-0000-4000-8000-000000000001'
    batch = 'de000000-0000-4000-8000-000000000001'
    record_id = 'de000000-0000-4000-8000-000000000002'
    root = Path(__file__).resolve().parent.parent
    body = copy.deepcopy(json.loads((root / 'docs/specification/fixtures/batches-v2.json').read_text())[0]['body'])
    body.update(tenant_id=tenant, collector_id=collector, batch_id=batch)
    item = copy.deepcopy(body['records'][0]); body['records'] = [item]
    item['record'].update(record_id=record_id, source_id=source, project_id=project,
                          service_id=service, environment_id=environment, deployment_id=deployment)
    item['origin_witness'] = {'kind': 'downstream_mtls_leaf_sha256_v1', 'leaf_sha256': '11' * 32}
    encoded = json.loads(subprocess.run([str(core_example)], input=json.dumps(body).encode(),
                                        capture_output=True, check=True).stdout)
    canonical, digest = encoded['canonical_hex'], encoded['digest']
    if any(c not in '0123456789abcdef' for c in canonical + digest) or len(digest) != 64:
        raise AssertionError('invalid Core fixture output')
    second_batch = 'de000000-0000-4000-8000-000000000004'
    second_record = 'de000000-0000-4000-8000-000000000005'
    second_body = copy.deepcopy(body)
    second_body['batch_id'] = second_batch
    second_body['records'][0]['record']['record_id'] = second_record
    second_encoded = json.loads(subprocess.run([str(core_example)], input=json.dumps(second_body).encode(),
                                               capture_output=True, check=True).stdout)
    second_canonical, second_digest = second_encoded['canonical_hex'], second_encoded['digest']
    if any(c not in '0123456789abcdef' for c in second_canonical + second_digest) or len(second_digest) != 64:
        raise AssertionError('invalid second Core fixture output')
    parsed = json.loads(bytes.fromhex(canonical))
    if parsed['tenant_id'] != tenant or parsed['batch_id'] != batch or parsed['records'][0]['record']['record_id'] != record_id:
        raise AssertionError('Core fixture scope mismatch')
    setup_sql = f"""
      SELECT set_config('apicontour.tenant_id','{tenant}',false);
      SET ROLE contour_admin;
      SELECT contour.grant_origin_observer('{tenant}','de000000-0000-4000-8000-000000000003','f9000000-0000-4000-8000-000000000001','{source}','{collector}','{project}','{service}','{environment}','{deployment}');
      RESET ROLE;
      CREATE SCHEMA IF NOT EXISTS fixture;
      CREATE TABLE fixture.causal_origin_payload(batch_id uuid PRIMARY KEY,record_id uuid NOT NULL,canonical bytea NOT NULL,digest bytea NOT NULL);
      INSERT INTO fixture.causal_origin_payload VALUES
       ('{batch}','{record_id}',decode('{canonical}','hex'),decode('{digest}','hex')),
       ('{second_batch}','{second_record}',decode('{second_canonical}','hex'),decode('{second_digest}','hex'));
      GRANT USAGE ON SCHEMA fixture TO contour_origin_ingress;
      GRANT SELECT ON fixture.causal_origin_payload TO contour_origin_ingress;
      CREATE FUNCTION fixture.causal_origin_insert(p_batch uuid) RETURNS void LANGUAGE plpgsql SECURITY INVOKER AS $$$$
      BEGIN
       INSERT INTO contour.ingestion_batches(tenant_id,collector_id,batch_id,request_digest,digest_version,record_count)
        SELECT '{tenant}','{collector}',p_batch,digest,2,1 FROM fixture.causal_origin_payload WHERE batch_id=p_batch;
       INSERT INTO contour.ingestion_payloads(tenant_id,collector_id,batch_id,payload_format,checked_batch)
        SELECT '{tenant}','{collector}',p_batch,2,canonical FROM fixture.causal_origin_payload WHERE batch_id=p_batch;
       INSERT INTO contour.ingestion_v2_metadata
        SELECT b.tenant_id,b.collector_id,b.batch_id,p.record_id,2,b.request_digest,b.accepted_at,
         '{source}'::uuid,'{project}'::uuid,'{service}'::uuid,'{environment}'::uuid,'{deployment}'::uuid,1,'http_json_v1','verified_origin_v1'
        FROM contour.ingestion_batches b JOIN fixture.causal_origin_payload p ON p.batch_id=b.batch_id WHERE (b.tenant_id,b.collector_id,b.batch_id)=('{tenant}'::uuid,'{collector}'::uuid,p_batch);
      END $$$$;
      GRANT EXECUTE ON FUNCTION fixture.causal_origin_insert(uuid) TO contour_origin_ingress;
    """.replace('$$$$', '$$')
    origin_prefix = helpers['_setup']('contour_origin_ingress') + f"SELECT contour.begin_origin_ingress('{tenant}','{collector}'); "
    origin = origin_prefix + f"SELECT fixture.causal_origin_insert('{batch}'); SELECT contour.write_origin_batch_proofs('{tenant}','{collector}','{batch}',canonical) FROM fixture.causal_origin_payload WHERE batch_id='{batch}';"
    origin_retry = origin_prefix + f"DO $$$$ DECLARE n integer; BEGIN SELECT contour.write_origin_batch_proofs('{tenant}','{collector}','{batch}',canonical) INTO n FROM fixture.causal_origin_payload WHERE batch_id='{batch}'; IF n<>0 THEN RAISE EXCEPTION 'origin retry charged'; END IF; END $$$$;".replace('$$$$', '$$')
    inbox_body = ('{"batch_id":"aa000000-0000-4000-8000-000000000001",'
                  '"events":[{"event_id":"11111111111111111111111111111111","kind":"root",'
                  '"root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","seq":1}],"first_seq":1,"last_seq":1,'
                  '"runtime_id":"' + runtime + '","session_epoch":1,"tenant_id":"' + tenant + '","wire_version":1}')
    inbox = helpers['_setup']('contour_causal_inbox_writer') + f"SELECT * FROM contour.accept_causal_batch('{tenant}','{runtime}',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),convert_to('{inbox_body}','UTF8'));"
    retry = helpers['_setup']('contour_causal_inbox_writer') + f"DO $$$$ DECLARE d boolean; BEGIN SELECT duplicate INTO d FROM contour.accept_causal_batch('{tenant}','{runtime}',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),convert_to('{inbox_body}','UTF8')); IF NOT d THEN RAISE EXCEPTION 'inbox retry charged'; END IF; END $$$$;".replace('$$$$', '$$')
    ledger_sql = f"SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='{tenant}';"
    measured_sql = f"SELECT coalesce((SELECT sum(octet_length(canonical_proof)) FROM contour.origin_proofs WHERE tenant_id='{tenant}'),0)+coalesce((SELECT sum(octet_length(canonical_batch)) FROM contour.causal_inbox_batches WHERE tenant_id='{tenant}'),0);"
    for inbox_first in (True, False):
        argv, execute = fresh()
        execute(setup_sql)
        execute('BEGIN; ' + helpers['_issue']('fe000000-0000-4000-8000-000000000001') + ' COMMIT;')
        helpers['race'](argv, inbox if inbox_first else origin, origin if inbox_first else inbox,
                        origin if inbox_first else inbox)
        proofs = int(execute(f"SELECT count(*) FROM contour.origin_proofs WHERE tenant_id='{tenant}' AND batch_id='{batch}';"))
        batches = int(execute(f"SELECT count(*) FROM contour.causal_inbox_batches WHERE tenant_id='{tenant}';"))
        before = int(execute(ledger_sql)); measured = int(execute(measured_sql))
        if proofs != 1 or batches != 1 or before != measured or before <= len(inbox_body):
            raise AssertionError('real proof/inbox quota accounting mismatch')
        execute('BEGIN; ' + origin_retry + ' COMMIT;')
        execute('BEGIN; ' + retry + ' COMMIT;')
        if int(execute(ledger_sql)) != before or int(execute(measured_sql)) != measured:
            raise AssertionError('exact retry changed shared quota')
        # The seed only creates the near-cap condition; the controls above are
        # genuine restricted origin and inbox writes in both lock orders.
        execute(f"UPDATE contour.origin_logical_usage SET used_bytes=1073741824 WHERE tenant_id='{tenant}';")
        execute('BEGIN; ' + origin_retry + ' COMMIT;')
        execute('BEGIN; ' + retry + ' COMMIT;')
        new_body = inbox_body.replace('aa000000-0000-4000-8000-000000000001','aa000000-0000-4000-8000-000000000002').replace('11111111111111111111111111111111','22222222222222222222222222222222').replace('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb').replace('"seq":1','"seq":2').replace('"first_seq":1','"first_seq":2').replace('"last_seq":1','"last_seq":2')
        inbox_reject = helpers['_setup']('contour_causal_inbox_writer') + f"DO $$$$ DECLARE ok boolean:=false; cn text; BEGIN BEGIN PERFORM contour.accept_causal_batch('{tenant}','{runtime}',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),convert_to('{new_body}','UTF8')); EXCEPTION WHEN program_limit_exceeded THEN GET STACKED DIAGNOSTICS cn=CONSTRAINT_NAME; ok:=(cn='origin_logical_quota_exhausted'); END; IF NOT ok THEN RAISE EXCEPTION 'inbox quota diagnostic missing'; END IF; END $$$$;".replace('$$$$', '$$')
        origin_reject = origin_prefix + f"DO $$$$ DECLARE ok boolean:=false; cn text; BEGIN BEGIN PERFORM fixture.causal_origin_insert('{second_batch}'); PERFORM contour.write_origin_batch_proofs('{tenant}','{collector}','{second_batch}',canonical) FROM fixture.causal_origin_payload WHERE batch_id='{second_batch}'; EXCEPTION WHEN program_limit_exceeded THEN GET STACKED DIAGNOSTICS cn=CONSTRAINT_NAME; ok:=(cn='origin_logical_quota_exhausted'); END; IF NOT ok THEN RAISE EXCEPTION 'origin quota diagnostic missing'; END IF; END $$$$;".replace('$$$$', '$$')
        execute('BEGIN; ' + inbox_reject + ' COMMIT;')
        execute('BEGIN; ' + origin_reject + ' COMMIT;')
        if int(execute(ledger_sql)) != 1073741824 or int(execute(measured_sql)) != measured:
            raise AssertionError('quota exhaustion changed retained facts')
        if int(execute(f"SELECT count(*) FROM contour.ingestion_batches WHERE batch_id='{second_batch}';")) != 0:
            raise AssertionError('quota rejection leaked origin ingestion')
        execute(f"UPDATE contour.origin_logical_usage SET used_bytes={before} WHERE tenant_id='{tenant}';")
