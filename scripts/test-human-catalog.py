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

    def check(mode='list', limit=1, cursor='-', scope=None, credential=normal_token):
        result = subprocess.run(
            [str(probe), str(port), str(directory / 'ca.crt'), *(scope or [ITEM] * 4),
             mode, str(limit), cursor],
            env=dict(environment, CONTOUR_FIXTURE_ID_TOKEN=str(credential)),
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
