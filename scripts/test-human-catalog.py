"""Synthetic human catalog cases, run within the owned PostgreSQL TLS fixture."""
import concurrent.futures
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
ITEM = '00000000-0000-0000-0000-000000000001'
OTHER = '00000000-0000-0000-0000-000000000002'
APPROVED = '00000000-0000-0000-0000-00000000071c'  # 1820 decimal


def run_cases(execute, port, directory, environment, normal_token, unknown_token,
              token, holder, wait_for, import_check, source, approved_operation):
    execute('GRANT contour_catalog_reader, contour_approval_reader, contour_comparison_reader, contour_review_reader TO contour_human_reader_tls')
    target = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--format-version', '1', '--no-deps', '--offline'],
        text=True, timeout=15))['target_directory']
    probe = Path(target) / 'debug/examples/human_catalog_probe'

    def check(mode='list', limit=1, cursor='-', scope=None, credential=normal_token, origin=None):
        result = subprocess.run(
            [str(probe), str(port), str(directory / 'ca.crt'), *(scope or [ITEM] * 4),
             mode, str(limit), cursor],
            env=dict(environment, CONTOUR_FIXTURE_ID_TOKEN=str(credential), CONTOUR_FIXTURE_ORIGIN=','.join(origin or [ITEM] * 5)),
            capture_output=True, text=True, timeout=15, check=True)
        return json.loads(result.stdout)

    # A second real import creates a distinct canonical operation, without writing
    # raw operation rows or inventing observation evidence.
    original = source.read_text()
    try:
        artifact = json.loads(original)
        # The import policy only admits /source, so use an alternate method there.
        artifact['paths']['/source']['get'] = artifact['paths']['/source']['post']
        source.write_text(json.dumps(artifact))
        import_check('Stored', number=1900)
    finally:
        source.write_text(original)

    uid = lambda n: '00000000-0000-0000-0000-%012x' % n
    for mode, number in [('lookup-comparison',700),('lookup-review',820)]:
        assert check(mode=mode,cursor=uid(number)) == {'outcome':'Read','operation':approved_operation}
        assert check(mode=mode,cursor=uid(number),scope=[OTHER,ITEM,ITEM,ITEM])['outcome'] == 'Forbidden'
        assert check(mode=mode,cursor=uid(number),scope=[ITEM,ITEM,ITEM,OTHER])['outcome'] == 'NotFound'
        assert check(mode=mode,cursor=uid(number),credential=unknown_token)['outcome'] == 'Forbidden'
    assert check(mode='lookup-comparison',cursor=uid(600))['outcome'] == 'NotFound'
    assert check(mode='lookup-review',cursor=uid(610))['outcome'] == 'NotFound'
    # Standard schema 14 cannot honor origin filtering and must fail closed.
    assert check(mode='origin')['outcome'] == 'Database'
    assert check(mode='origin', credential=unknown_token)['outcome'] == 'Forbidden'
    optional = check(mode='with-origin')
    assert optional['outcome'] == 'Read' and all(not item['origin_evidence_available'] and item['origins'] == [] and not item['origins_truncated'] for item in optional['items'])
    first = check()
    assert first['outcome'] == 'Read' and len(first['items']) == 1
    ids, items = [], []
    page = first
    while True:
        assert page['outcome'] == 'Read' and len(page['items']) == 1
        item = page['items'][0]
        ids.append(item['id']); items.append(item)
        cursor = page['next_cursor']
        if cursor is None:
            break
        assert cursor == item['id'] and len(ids) <= 200
        page = check(cursor=cursor)
    assert len(ids) >= 2 and ids == sorted(set(ids)), 'pagination did not traverse distinct operations'
    approved = next(item for item in items if item['id'] == approved_operation)
    assert approved['approved_contract_id'] == APPROVED
    declared = next(item for item in items if item['id'] != approved_operation)
    assert declared['approved_contract_id'] is None
    for item in items:
        assert item['last_seen'] is None and item['visibility'] is None and item['completeness'] is None
        detail = check(mode='detail', cursor=item['id'])
        assert detail['outcome'] == 'Read' and detail['item'] == item
    assert check(mode='detail', cursor=OTHER)['outcome'] == 'NotFound'
    assert check(cursor='not-a-uuid')['outcome'] == 'Scope'
    for limit in (0, 201):
        assert check(limit=limit)['outcome'] == 'Limit'
    assert check(credential=unknown_token)['outcome'] == 'Forbidden'
    for index in range(3):
        scope = [ITEM] * 4
        scope[index] = OTHER
        assert check(scope=scope)['outcome'] == 'Forbidden'
        assert check(mode='detail', cursor=approved_operation, scope=scope)['outcome'] == 'Forbidden'
    wrong_environment = [ITEM, ITEM, ITEM, OTHER]
    assert check(scope=wrong_environment)['items'] == []
    assert check(mode='detail', cursor=approved_operation, scope=wrong_environment)['outcome'] == 'NotFound'
    for table in ['human_identities', 'human_actors', 'human_tenant_memberships', 'human_project_memberships', 'human_service_roles']:
        # Only mutate the original active identity; another issuer is disabled in this fixture.
        where = " WHERE issuer='https://idp.example.test/realms/demo'" if table == 'human_identities' else ''
        execute('SET ROLE contour_human_provisioner; UPDATE contour.' + table + ' SET enabled=false' + where)
        try:
            assert check()['outcome'] == 'Forbidden', table
        finally:
            execute('SET ROLE contour_human_provisioner; UPDATE contour.' + table + ' SET enabled=true' + where)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        short, expiry = token(lifetime=3)
        with holder('DO $$ BEGIN PERFORM 1 FROM contour.human_actors FOR UPDATE; END $$') as release:
            pending = pool.submit(check, credential=short)
            wait_for("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_human_reader_tls' AND wait_event_type='Lock'", '1')
            while time.time() < expiry + .05:
                time.sleep(.02)
            release()
            assert pending.result()['outcome'] == 'Forbidden'
    print('Human catalog authorization, current approval, null evidence, scoped detail and pagination passed.')


def run_origin_cases(execute, port, directory, environment, normal_token, unknown_token,
                     target_scope, actor, origins, expected_operations):
    """Run after 17 and projected origin admission, with a fully authorized actor.

    `origins` contains two dicts with project_id/service_id/environment_id/
    deployment_id/instance_id, and collector_id/batch_id/record_id/operation_id.
    Both observations must target the same operation. `expected_operations` is
    the sorted list of at least two operations for the first origin so that a
    one-item page proves cursor continuation. The caller provisions active
    owner/viewer memberships for target and both origin scopes. The test changes
    only synthetic fixture rows and restores them even on failure.
    """
    assert len(origins) == 2 and origins[0]['operation_id'] == origins[1]['operation_id']
    assert len(expected_operations) >= 2 and expected_operations == sorted(set(expected_operations))
    target = json.loads(subprocess.check_output(
        ['cargo','metadata','--format-version','1','--no-deps','--offline'], text=True, timeout=15))['target_directory']
    probe = Path(target) / 'debug/examples/human_catalog_probe'
    fields = ('project_id','service_id','environment_id','deployment_id','instance_id')
    def check(mode='list', origin=None, cursor='-', scope=target_scope, credential=normal_token, limit=1):
        args = [str(probe),str(port),str(directory/'ca.crt'),*scope,mode,str(limit),cursor]
        proc = subprocess.run(args, env=dict(environment, CONTOUR_FIXTURE_ID_TOKEN=str(credential),
            CONTOUR_FIXTURE_ORIGIN=','.join(origin or [origins[0][k] for k in fields])),
            capture_output=True,text=True,timeout=30,check=True)
        return json.loads(proc.stdout)
    def role(origin, enabled):
        execute("SET ROLE contour_human_provisioner; UPDATE contour.human_service_roles SET enabled=%s WHERE actor_id='%s' AND tenant_id='%s' AND project_id='%s' AND service_id='%s';" %
            ('true' if enabled else 'false',actor,target_scope[0],origin['project_id'],origin['service_id']))
    first = [origins[0][k] for k in fields]
    second = [origins[1][k] for k in fields]
    assert check(mode='origin',origin=first,credential=unknown_token)['outcome'] == 'Forbidden'
    wrong_tenant = list(target_scope); wrong_tenant[0] = OTHER
    assert check(mode='origin',origin=first,scope=wrong_tenant)['outcome'] == 'Forbidden'
    seen = []; cursor = '-'; target_item = None
    while True:
        page = check(mode='origin',origin=first,cursor=cursor)
        assert page['outcome'] == 'Read' and len(page['items']) <= 1
        for item in page['items']:
            seen.append(item['id'])
            if item['id'] == origins[0]['operation_id']: target_item = item
        if page['next_cursor'] is None: break
        assert page['items'] and page['next_cursor'] == page['items'][-1]['id'] and len(seen) <= len(expected_operations)
        cursor = page['next_cursor']
    assert seen == expected_operations
    assert target_item is not None
    assert (target_item['last_seen'],target_item['visibility'],target_item['completeness']) == (origins[0]['last_seen'],origins[0]['visibility'],origins[0]['completeness'])
    assert first in [[o[k] for k in fields] for o in target_item['origins']]
    page = check(mode='origin',origin=second)
    while page['next_cursor'] is not None and not any(o['id'] == origins[1]['operation_id'] for o in page['items']):
        page = check(mode='origin',origin=second,cursor=page['next_cursor'])
    matching = next(item for item in page['items'] if item['id'] == origins[1]['operation_id'])
    assert (matching['last_seen'],matching['visibility'],matching['completeness']) == (origins[1]['last_seen'],origins[1]['visibility'],origins[1]['completeness'])
    # A same-instance UUID paired with the other origin scope must never
    # accidentally match the first origin's rows.
    mixed = second[:4] + [first[4]]
    if mixed != second:
        assert check(mode='origin',origin=mixed)['items'] == []
    # Poison an unrelated origin's target window with text that PostgreSQL
    # cannot cast to timestamptz. A filtered read must not run the legacy
    # all-history lateral sort; it selects only the verified matching head.
    unrelated = origins[1]
    condition = "tenant_id='%s' AND collector_id='%s' AND batch_id='%s' AND record_id='%s'" % (target_scope[0],unrelated['collector_id'],unrelated['batch_id'],unrelated['record_id'])
    execute("BEGIN; SET LOCAL session_replication_role=replica; UPDATE contour.observation_windows SET last_seen='not-a-valid-timestamp' WHERE %s; COMMIT;" % condition)
    try:
        bounded = check(mode='origin',origin=first,limit=200)
        assert bounded['outcome'] == 'Read' and any(item['id'] == origins[0]['operation_id'] for item in bounded['items'])
    finally:
        execute("BEGIN; SET LOCAL session_replication_role=replica; UPDATE contour.observation_windows SET last_seen='%s' WHERE %s; COMMIT;" % (unrelated['last_seen'],condition))
    # A dangling lookahead HEAD must not vanish when the operations query is
    # joined back to the target table. Place it after the other real operation.
    selected = origins[0]
    head_condition = "tenant_id='%s' AND collector_id='%s' AND batch_id='%s' AND record_id='%s'" % (target_scope[0],selected['collector_id'],selected['batch_id'],selected['record_id'])
    execute("BEGIN; SET LOCAL session_replication_role=replica; UPDATE contour.catalog_origin_heads SET operation_id='ffffffff-ffff-ffff-ffff-ffffffffffff' WHERE %s; COMMIT;" % head_condition)
    try:
        assert check(mode='origin',origin=first,limit=1)['outcome'] == 'Corrupt'
    finally:
        execute("BEGIN; SET LOCAL session_replication_role=replica; UPDATE contour.catalog_origin_heads SET operation_id='%s' WHERE %s; COMMIT;" % (selected['operation_id'],head_condition))
    role(origins[1],False)
    try:
        assert check(mode='origin',origin=second)['outcome'] == 'Forbidden'
        unfiltered = check(mode='origin-detail',cursor=origins[0]['operation_id'])
        assert unfiltered['outcome'] == 'Read'
        assert second not in [[o[k] for k in fields] for o in unfiltered['item']['origins']]
        assert first in [[o[k] for k in fields] for o in unfiltered['item']['origins']]
    finally: role(origins[1],True)
    target_role = {'project_id':target_scope[1],'service_id':target_scope[2]}
    role(target_role,False)
    try: assert check(mode='origin',origin=first)['outcome'] == 'Forbidden'
    finally: role(target_role,True)
    print('Human origin authorization, full-scope filter, latest observation and pagination passed.')
