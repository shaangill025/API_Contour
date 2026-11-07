"""Generate SQL parser assertions from the checked-in Core causal vectors.

Run without arguments to qualify the complete internal inbox on a disposable
network-isolated PostgreSQL. --emit-vectors emits codec assertions only.
Synthetic assertions do not prove transport, producer, graph or retention.
"""
import json
from pathlib import Path


def emit_vectors():
    fixtures = json.loads(checked_source('docs/specification/fixtures/causal-events.json'))
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
                                        capture_output=True, check=True, timeout=15).stdout)
    canonical, digest = encoded['canonical_hex'], encoded['digest']
    if any(c not in '0123456789abcdef' for c in canonical + digest) or len(digest) != 64:
        raise AssertionError('invalid Core fixture output')
    second_batch = 'de000000-0000-4000-8000-000000000004'
    second_record = 'de000000-0000-4000-8000-000000000005'
    second_body = copy.deepcopy(body)
    second_body['batch_id'] = second_batch
    second_body['records'][0]['record']['record_id'] = second_record
    second_encoded = json.loads(subprocess.run([str(core_example)], input=json.dumps(second_body).encode(),
                                               capture_output=True, check=True, timeout=15).stdout)
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

# Complete, disposable qualification driver. Reuse the 18/19 safety helpers;
# never import the root-only qualification harness or modify the older driver.
import hashlib
import os
import re
import runpy
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).absolute().parent.parent
PROVISIONS = ('approval','authority','catalog','comparison','declared','human','origin_ingress','review','v2_ingress')
MIGRATIONS = ('0001_identity','0002_policy','0003_ingestion','0004_catalog','0005_declared',
              '0006_approval','0007_comparison','0008_review','0009_human','0010_public_contracts',
              '0011_import_selectors','0012_public_comparisons','0013_instance_registry','0014_observation_evidence')
OPT_INS = ('0015_origin_lifecycle','0016_v2_unattributed','0017_origin_proofs',
           '0018_causal_runtime_registry','0019_causal_sessions','0020_causal_inbox')
EXTRA_SOURCE_MIGRATIONS = ('0021_origin_admission','0022_causal_generation')
GROUPS = {
    'vectors': ('causal_inbox_vectors.sql',),
    'basic': ('causal_inbox_basic.sql','causal_inbox_stored_parse.sql','causal_inbox_malleability.sql',
              'causal_inbox_quota.sql','causal_inbox_corruption.sql','causal_inbox_clock.sql'),
    'cross-batches': ('causal_inbox_basic.sql','causal_inbox_cross_batches.sql'),
    'history-limit': ('causal_inbox_basic.sql','causal_inbox_history_limit.sql'),
    'history-work': ('causal_inbox_basic.sql','causal_inbox_history_work.sql'),
}
SOURCE_PATHS = (('Cargo.toml','Cargo.lock','crates/contour-core/examples/fixture_v2_canonical.rs','db/bootstrap.sql')
    + tuple('crates/'+x+'/Cargo.toml' for x in ('contour-platform','contour-auth','contour-core','contour-postgres','contour-ingress','contour-delivery','contour-abi','contour-wasm'))
    + tuple('db/provision_'+x+'.sql' for x in PROVISIONS)
    + tuple('db/migrations/'+x+'.sql' for x in MIGRATIONS)
    + tuple('db/opt-in-migrations/'+x+'.sql' for x in OPT_INS + EXTRA_SOURCE_MIGRATIONS)
    + ('db/tests/causal_runtime_registry_pre.sql','db/tests/causal_session_setup.sql',
       'scripts/test-postgres-causal-registry.py','scripts/test-postgres-causal-sessions.py',
       'scripts/test-postgres-causal-inbox.py','tests/fixtures/causal-inbox/test_inbox_driver.py',
       'collectors/nodered/qualified-runtime-profile.json','collectors/nodered/error-integration/profile.js',
       'docs/specification/fixtures/causal-events.json','docs/specification/fixtures/batches-v2.json',
       '.github/workflows/native.yml')
    + tuple('db/tests/'+name for name in dict.fromkeys(n for group in GROUPS.values() for n in group)))


def checked_source(relative):
    path = ROOT / relative
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError('symlink in qualification source')
    if not path.is_file():
        raise ValueError('qualification source missing')
    return path.read_bytes()


def verify_vector_sync():
    import contextlib
    import io
    output=io.StringIO()
    with contextlib.redirect_stdout(output):
        emit_vectors()
    if output.getvalue().encode() != checked_source('db/tests/causal_inbox_vectors.sql'):
        raise ValueError('causal vector fixture differs from Core vectors')


def source_snapshot():
    for pattern, expected in (
        ('db/provision_*.sql', {'db/provision_'+x+'.sql' for x in PROVISIONS}),
        ('db/migrations/*.sql', {'db/migrations/'+x+'.sql' for x in MIGRATIONS}),
        ('db/opt-in-migrations/*.sql', {'db/opt-in-migrations/'+x+'.sql' for x in OPT_INS + EXTRA_SOURCE_MIGRATIONS}),
    ):
        if {str(p.relative_to(ROOT)) for p in ROOT.glob(pattern)} != expected:
            raise ValueError('qualification source list changed')
    # Cargo can compile any workspace crate, build script, manifest or fixture.
    # Refuse symlinked trees and snapshot every file; additions also change the map.
    cargo = []
    def walk_error(_error):
        raise ValueError('qualification source unavailable')
    for directory, dirs, files in os.walk(ROOT / 'crates', followlinks=False, onerror=walk_error):
        base = Path(directory)
        for name in dirs + files:
            path = base / name
            if path.is_symlink():
                raise ValueError('symlink in qualification source')
        cargo.extend(str((base/name).relative_to(ROOT)) for name in files)
    if not cargo or not (ROOT/'crates').is_dir():
        raise ValueError('qualification source missing')
    return {name: hashlib.sha256(checked_source(name)).hexdigest() for name in sorted(set(SOURCE_PATHS) | set(cargo))}


def helpers():
    checked_source('scripts/test-postgres-causal-registry.py')
    checked_source('scripts/test-postgres-causal-sessions.py')
    registry = runpy.run_path(str(ROOT/'scripts/test-postgres-causal-registry.py'))
    session = runpy.run_path(str(ROOT/'scripts/test-postgres-causal-sessions.py'))
    return registry, session


def build_core(run):
    # Cargo's JSON artifact is authoritative even with CARGO_TARGET_DIR or a
    # configured target triple. --offline never falls back to network access.
    output = run(['cargo','build','--locked','--offline','--manifest-path',str(ROOT/'Cargo.toml'),
                  '-p','contour-core','--example','fixture_v2_canonical','--message-format=json'], timeout=300)
    executables=[]
    for line in output.splitlines():
        try:
            item=json.loads(line)
        except ValueError:
            raise RuntimeError('invalid Core build output') from None
        target=item.get('target') or {}
        if item.get('reason')=='compiler-artifact' and target.get('name')=='fixture_v2_canonical' and item.get('executable'):
            executables.append(Path(item['executable']))
    if len(executables)!=1 or not executables[0].is_file() or executables[0].is_symlink():
        raise RuntimeError('Core fixture executable unavailable')
    return executables[0]


def assert_fresh(execute, database):
    probe=execute(database,"SELECT current_database() || '|' || (SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations) || '|' || (SELECT count(*) FROM contour.causal_sessions) || '|' || (SELECT count(*) FROM contour.causal_inbox_batches) || '|' || (SELECT count(*) FROM contour.origin_proofs);")
    expected=database+'|{'+','.join(str(x) for x in range(1,21))+'}|0|0|0'
    if probe!=expected:
        raise AssertionError('clone identity, ledger or initial state mismatch')


def qualify_cases(container, execute, session, core):
    """One checked clone per fixture group and per race; drop between cases."""
    if tuple(GROUPS)!=('vectors','basic','cross-batches','history-limit','history-work'):
        raise RuntimeError('invalid inbox qualification groups')
    active=None
    count=0
    def drop():
        nonlocal active
        if active is not None:
            execute('postgres','DROP DATABASE IF EXISTS '+active+';')
            active=None
    def fresh():
        nonlocal count, active
        drop()
        count+=1
        active='inbox_case_'+str(count)
        execute('postgres','CREATE DATABASE '+active+' TEMPLATE contour_local;')
        assert_fresh(execute,active)
        database=active
        return session['psql_args'](container,database), lambda sql:execute(database,sql)
    try:
        for label, files in GROUPS.items():
            _, run_sql=fresh()
            output=run_sql('\n'.join(checked_source('db/tests/'+name).decode() for name in files))
            if label=='history-work':
                # The fixture's final scalar is elapsed milliseconds for the
                # largest admissible cross-batch comparison; disclose only it.
                elapsed=output.splitlines()[-1] if output else ''
                if not re.fullmatch(r'[0-9]{1,12}(?:\.[0-9]{1,9})?',elapsed):
                    raise RuntimeError('history work timing unavailable')
                print('history work elapsed milliseconds:',elapsed,flush=True)
            print('PASS:',label,flush=True)
        phase_start=count
        run_session_races(fresh)
        if count-phase_start!=16:
            raise RuntimeError('incomplete session races')
        print('PASS: all 16 session and policy races',flush=True)
        phase_start=count
        run_shared_quota_races(fresh,core)
        if count-phase_start!=2:
            raise RuntimeError('incomplete shared quota races')
        print('PASS: real origin and inbox shared quota in both orders',flush=True)
        if count!=23:
            raise RuntimeError('incomplete inbox qualification')
    finally:
        drop()


def inspect_owned_name(container_name):
    result=subprocess.run(['docker','inspect',container_name],text=True,capture_output=True,timeout=30)
    if result.returncode:
        # Match only known Docker absence messages for the exact requested name.
        if re.fullmatch(r'(?:Error: No such object: |error: no such object: )'+re.escape(container_name)+r'(?:\r?\n)?',result.stderr):
            return None
        raise RuntimeError('container inspection failed')
    try:
        return json.loads(result.stdout)
    except (ValueError,TypeError):
        raise RuntimeError('invalid container inspection') from None


def main():
    if sys.argv[1:]==['--emit-vectors']:
        emit_vectors()
        return
    if len(sys.argv)!=1:
        raise ValueError('expected no arguments or --emit-vectors')
    os.umask(0o077)
    before=None
    registry=None
    run=None
    run_id=uuid.uuid4().hex
    name='contour-causal-inbox-'+run_id
    cid=None
    create_attempted=False
    def deadline_handler(_signum,_frame):
        raise TimeoutError('inbox qualification exceeded overall deadline')
    previous=signal.signal(signal.SIGALRM,deadline_handler)
    signal.setitimer(signal.ITIMER_REAL,900)
    try:
        before=source_snapshot()
        verify_vector_sync()
        registry,session=helpers()
        registry['verify_qualified_profile']()
        run=session['_run']
        core=build_core(run)
        run(['docker','image','inspect',registry['IMAGE']])
        create_attempted=True
        candidate=run(['docker','create','--pull=never','--name',name,'--label','org.apicontour.registry-run='+run_id,
                       '--network','none','--memory','512m','--cpus','1','--pids-limit','128',
                       '--tmpfs','/var/lib/postgresql/data:rw,nosuid,noexec,size=256m',
                       '-e','POSTGRES_DB=contour_local','-e','POSTGRES_PASSWORD=isolated-fixture-only',
                       '-e','POSTGRES_HOST_AUTH_METHOD=reject','-e','POSTGRES_INITDB_ARGS=--auth-local=trust --auth-host=reject',
                       registry['IMAGE'],'-c','listen_addresses=','-c','unix_socket_directories=/var/run/postgresql'])
        if not re.fullmatch(r'[0-9a-f]{64}',candidate):
            raise RuntimeError('invalid container identity')
        cid=candidate
        run(['docker','start',cid])
        deadline=time.monotonic()+60
        while True:
            ready=subprocess.run(['docker','exec',cid,'sh','-c','test "$(cat /proc/1/comm)" = postgres && pg_isready -h /var/run/postgresql -U postgres -d contour_local'],capture_output=True,timeout=5)
            if ready.returncode==0:
                break
            if time.monotonic()>=deadline:
                raise TimeoutError('PostgreSQL readiness deadline')
            time.sleep(.2)
        def execute(database,sql):
            return run(session['psql_args'](cid,database),input=sql,timeout=120)
        execute('contour_local',checked_source('db/bootstrap.sql').decode())
        for x in PROVISIONS:
            execute('contour_local',checked_source('db/provision_'+x+'.sql').decode())
        for x in MIGRATIONS:
            execute('contour_local',checked_source('db/migrations/'+x+'.sql').decode())
        for x in OPT_INS[:3]:
            execute('contour_local',checked_source('db/opt-in-migrations/'+x+'.sql').decode())
        execute('contour_local',checked_source('db/tests/causal_runtime_registry_pre.sql').decode())
        execute('contour_local',checked_source('db/opt-in-migrations/'+OPT_INS[3]+'.sql').decode())
        execute('contour_local',checked_source('db/tests/causal_session_setup.sql').decode())
        for x in OPT_INS[4:]:
            execute('contour_local',checked_source('db/opt-in-migrations/'+x+'.sql').decode())
        assert_fresh(execute,'contour_local')
        qualify_cases(cid,execute,session,core)
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        signal.signal(signal.SIGALRM,previous)
        try:
            if create_attempted and not cid:
                cid=registry['recover_owned_container'](inspect_owned_name,name,run_id)
            if cid:
                registry['cleanup_owned'](run,cid,name,run_id)
        finally:
            if before is not None and source_snapshot()!=before:
                raise RuntimeError('qualification source changed')
    print('PASS: complete internal causal inbox qualification; no transport or retention proof')


def safe_failure(error):
    # Never expose command arguments, SQL, server messages, paths or source.
    state=getattr(error,'sqlstate',None)
    detail=(' SQLSTATE '+state) if isinstance(state,str) and re.fullmatch(r'[0-9A-Z]{5}',state) else ''
    categories={'database unavailable','role unavailable','server starting','server stopping',
                'authentication failed','postgres fatal','connection refused','connection socket unavailable',
                'connection closed','connection timeout','command failure'}
    category=getattr(error,'category',None)
    if isinstance(category,str) and category in categories:
        detail+=' '+category
    return 'FAIL: internal causal inbox qualification ('+type(error).__name__+detail+')'


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(safe_failure(error),file=sys.stderr)
        raise SystemExit(1) from None
