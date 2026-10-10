"""Restricted reader: actual accepted inbox -> consumer -> bounded history pages."""
import copy
import hashlib
import json
from pathlib import Path
import queue
import re
import runpy
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def run_cases(container, execute, setup, submit, consume, port, directory, environment, first, second):
    execute("CREATE ROLE contour_catalog_reader_tls LOGIN PASSWORD '%s'; GRANT contour_catalog_reader TO contour_catalog_reader_tls; ALTER ROLE contour_catalog_reader_tls SET log_statement='all';" % environment['CONTOUR_FIXTURE_PASSWORD'])
    target = json.loads(subprocess.check_output(['cargo', 'metadata', '--format-version', '1', '--no-deps', '--offline'], text=True, timeout=15))['target_directory']
    probe = str(Path(target) / 'debug/examples/catalog_reader_probe')
    operation = execute("SELECT operation_id::text FROM contour.observation_windows WHERE tenant_id='%s' AND collector_id='%s' LIMIT 1;" % (first['tenant_id'], first['collector_id']))
    scope = [first['tenant_id'], first['records'][0]['project_id'], first['records'][0]['service_id'], operation]

    def read(wanted='Read', limit='default', selected=None, deadline=10000):
        process = subprocess.Popen([probe, str(port), str(directory/'ca.crt'), *(selected or scope), str(limit), wanted, str(deadline)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
        output = queue.Queue()
        thread = threading.Thread(target=lambda: output.put(process.stdout.readline()), daemon=True)
        thread.start()
        try:
            line = output.get(timeout=30)
            if not line:
                process.wait(timeout=3)
                safe={'reader TLS setup failed','reader cancel did not remain pending','catalog reader probe failed'}
                stages=[line for line in process.stderr.read().splitlines() if line in safe]
                raise AssertionError('reader failed before result: expected '+wanted+'; '+','.join(stages))
            if not line.startswith('{'):
                raise AssertionError('reader closed-enum outcome mismatch: '+line.strip())
            result = json.loads(line)
            until = time.monotonic()+5
            while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_catalog_reader_tls';") != '0':
                if time.monotonic()>until:
                    raise AssertionError('reader backend survived while runtime alive')
                time.sleep(0.02)
            if process.poll() is not None:
                raise AssertionError('reader runtime exited before cleanup proof')
            out, errors = process.communicate(input='\n', timeout=3)
            if process.returncode or out or errors:
                raise AssertionError('reader probe failed')
            for page in result['pages']:
                assert page['bytes']+512 <= 1048576, 'serialized page/cursor budget exceeded'
            return result
        finally:
            if process.poll() is None:
                process.kill(); process.wait(timeout=3)
            thread.join(2)
            for pipe in [process.stdin, process.stdout, process.stderr]:
                pipe.close()

    def items(result):
        return [item for page in result['pages'] for item in page['page']['items']]

    expected = {(body['collector_id'], body['batch_id'], record['record_id']): record for body in [first, second] for record in body['records']}
    initial = read(limit=1)
    actual = items(initial)
    assert len(initial['pages']) == 3 and len(actual) == 3
    for item in actual:
        assert item['canonicalization_version']==1
        assert item['structure_fingerprint']==execute("SELECT encode(structure_hash,'hex') FROM contour.variants WHERE tenant_id='%s' AND variant_id='%s';" % (scope[0],item['variant_id'])), 'checked structure fingerprint lost'
        assert item['record'] == expected[(item['collector_id'], item['batch_id'], item['record']['record_id'])], 'reader changed original evidence'
    assert len({item['variant_id'] for item in actual}) == 2, 'repeated variant IDs lost evidence'
    tuples = [(item['variant_id'], item['record']['source_id'], item['batch_id'], item['record']['record_id']) for item in actual]
    assert tuples == sorted(set(tuples)), 'pagination is not unique keyset order'
    read('Cursor', 1)
    for limit in [0, 201]:
        read('Limit', limit)
    for index in range(4):
        wrong = list(scope); wrong[index] = '00000000-0000-0000-0000-000000ffffff'
        read('NotFound', selected=wrong)
    before = subprocess.run(['docker','logs',container],capture_output=True,text=True,check=True,timeout=5)
    read(limit=200)
    after = subprocess.run(['docker','logs',container],capture_output=True,text=True,check=True,timeout=5)
    queries = re.findall(r'execute (\w+): SELECT row_to_json\(w\)',(after.stdout+after.stderr)[len(before.stdout+before.stderr):])
    assert len(queries)==3 and len(set(queries))==1, 'reader prepared evidence SQL per row'
    forbidden = "SELECT has_table_privilege(current_user,'contour.ingestion_payloads','SELECT'),has_table_privilege(current_user,'contour.catalog_processed_batches','SELECT'),has_table_privilege(current_user,'contour.operations','INSERT'),has_table_privilege(current_user,'contour.collector_authorization','SELECT');"
    result = subprocess.run(['docker', 'exec', '-i', container, 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-U', 'contour_catalog_reader_tls', '-d', 'contour_fixture'], input=forbidden, text=True, capture_output=True, timeout=5, check=True)
    assert result.stdout.strip() == 'f|f|f|f', 'reader privileges expanded'
    for sql in ['SELECT * FROM contour.ingestion_payloads;', 'SELECT * FROM contour.catalog_processed_batches;',
                'INSERT INTO contour.operations DEFAULT VALUES;', 'SELECT * FROM contour.collector_authorization;']:
        denied = subprocess.run(['docker','exec','-i',container,'psql','-XAtq','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-U','contour_catalog_reader_tls','-d','contour_fixture'],input=sql,text=True,capture_output=True,timeout=5)
        assert denied.returncode!=0 and '42501' in denied.stderr, 'restricted reader forbidden SQL did not fail with insufficient privilege'
    # Processed evidence survives terminal capture revocation.
    execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); UPDATE contour.collector_authorization SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id='%s' AND collector_id='%s'; COMMIT;" % (first['tenant_id'], first['tenant_id'], first['collector_id'], first['tenant_id'], first['collector_id']))
    assert items(read()) == actual

    # Privileged corruption is fixture-only; production roles cannot update rows.
    record_where = "tenant_id='%s' AND collector_id='%s' AND batch_id='%s' AND record_id='%s'" % (first['tenant_id'], first['collector_id'], first['batch_id'], first['records'][0]['record_id'])
    def damage(table, column, where, replacement, wanted='Corrupt', preflight=False):
        original = execute("SELECT encode(convert_to(%s::text,'UTF8'),'hex') FROM contour.%s WHERE %s;" % (column, table, where))
        execute("BEGIN; ALTER TABLE contour.%s DISABLE TRIGGER immutable_catalog; UPDATE contour.%s SET %s=%s WHERE %s; ALTER TABLE contour.%s ENABLE TRIGGER immutable_catalog; COMMIT;" % (table, table, column, replacement, where, table))
        try:
            before = subprocess.run(['docker', 'logs', container], capture_output=True, text=True, check=True, timeout=5) if preflight else None
            result = read(wanted)
            assert not result['pages'], 'corruption returned a partial page'
            if before is not None:
                after = subprocess.run(['docker', 'logs', container], capture_output=True, text=True, check=True, timeout=5)
                emitted = (after.stdout+after.stderr)[len(before.stdout+before.stderr):]
                assert 'octet_length(v.canonical_structure)' in emitted and 'SELECT row_to_json(w)' not in emitted, 'oversized structure fetched before metadata rejection'
        finally:
            cast = 'bytea' if column in ['canonical_key','operation_hash','canonical_structure','structure_wire','structure_hash'] else 'text'
            execute("BEGIN; ALTER TABLE contour.%s DISABLE TRIGGER immutable_catalog; UPDATE contour.%s SET %s=convert_from(decode('%s','hex'),'UTF8')::%s WHERE %s; ALTER TABLE contour.%s ENABLE TRIGGER immutable_catalog; COMMIT;" % (table, table, column, original, cast, where, table))
    operation_where = "tenant_id='%s' AND operation_id='%s'" % (scope[0], operation)
    variant_where = "tenant_id='%s' AND variant_id='%s'" % (scope[0], actual[0]['variant_id'])
    for table, column, where, value in [
        ('operations','canonical_key',operation_where,"convert_to('[]','UTF8')"),
        ('operations','operation_hash',operation_where,"decode(repeat('00',32),'hex')"),
        ('variants','structure_wire',variant_where,"convert_to('{}','UTF8')"),
        ('variants','canonical_structure',variant_where,"convert_to('[]','UTF8')"),
        ('variants','structure_hash',variant_where,"decode(repeat('00',32),'hex')"),
    ]:
        damage(table,column,where,value)
    damage('variants','structure_wire',variant_where,"decode(repeat('00',65537),'hex')",preflight=True)
    # Recompute a changed key's hash, so this failure specifically proves workload
    # comparison, not merely the separate hash check.
    original_key = execute("SELECT encode(canonical_key,'hex') FROM contour.operations WHERE %s;" % operation_where)
    original_hash = execute("SELECT encode(operation_hash,'hex') FROM contour.operations WHERE %s;" % operation_where)
    key = json.loads(bytes.fromhex(original_key)); key[1]='00000000-0000-0000-0000-000000ffffff'
    changed = json.dumps(key,separators=(',',':')).encode()
    changed_hash = hashlib.sha256(b'apicontour/operation/1\n'+changed).hexdigest()
    execute("BEGIN; ALTER TABLE contour.operations DISABLE TRIGGER immutable_catalog; UPDATE contour.operations SET canonical_key=decode('%s','hex'),operation_hash=decode('%s','hex') WHERE %s; ALTER TABLE contour.operations ENABLE TRIGGER immutable_catalog; COMMIT;" % (changed.hex(),changed_hash,operation_where))
    try:
        assert not read('Corrupt')['pages']
    finally:
        execute("BEGIN; ALTER TABLE contour.operations DISABLE TRIGGER immutable_catalog; UPDATE contour.operations SET canonical_key=decode('%s','hex'),operation_hash=decode('%s','hex') WHERE %s; ALTER TABLE contour.operations ENABLE TRIGGER immutable_catalog; COMMIT;" % (original_key,original_hash,operation_where))

    # Store exact original text, but compare timestamps as instants through core.
    stamp_pairs = [
        ('2000-02-29T12:00:00.000000001Z','2000-02-29T12:00:00.000000002Z'),
        ('2000-02-29T23:59:00+23:59','2000-02-29T00:00:00Z'),
        ('2000-02-28T00:01:00-23:59','2000-02-29T00:00:00.0+00:00'),
        ('0001-01-01T00:00:00+23:59','0001-01-01T00:00:00Z'),
        ('9999-12-31T23:59:59Z','9999-12-31T23:59:59-23:59'),
        ('1900-02-28T00:00:00-00:00','1900-03-01T00:00:00.123456789Z'),
    ]
    stamp_pairs += [('2000-02-29T12:00:00.'+'123456789'[:digits]+'Z','2000-02-29T12:00:01Z') for digits in range(1,10)]
    original = first['records'][0]
    for first_seen,last_seen in stamp_pairs:
        execute("BEGIN; ALTER TABLE contour.observation_windows DISABLE TRIGGER immutable_catalog; UPDATE contour.observation_windows SET first_seen='%s',last_seen='%s' WHERE %s; ALTER TABLE contour.observation_windows ENABLE TRIGGER immutable_catalog; COMMIT;" % (first_seen,last_seen,record_where))
        found = next(item['record'] for item in items(read()) if item['collector_id']==first['collector_id'] and item['record']['record_id']==original['record_id'])
        assert found['first_seen']==first_seen and found['last_seen']==last_seen, 'timestamp original lost'
    execute("BEGIN; ALTER TABLE contour.observation_windows DISABLE TRIGGER immutable_catalog; UPDATE contour.observation_windows SET first_seen='%s',last_seen='%s' WHERE %s; ALTER TABLE contour.observation_windows ENABLE TRIGGER immutable_catalog; COMMIT;" % (original['first_seen'],original['last_seen'],record_where))
    for invalid in ['1900-02-29T00:00:00Z','0000-01-01T00:00:00Z','2000-01-01T00:00:60Z','2000-01-01T00:00:00+24:00']:
        damage('observation_windows','first_seen',record_where,"'%s'" % invalid)
    damage('observation_windows','first_seen',record_where,"'9999-12-31T23:59:59Z'")
    damage('observation_windows','queued_at',record_where,"'9999-12-31T23:59:59Z'")
    damage('observation_windows','expires_at',record_where,"'9999-12-31T23:59:59Z'")

    # A real full-size row page, not merely passing 200 for a tiny result.
    small,_,_=setup('reader_row_limit',current=1)
    expected_small=[]
    # Prepare all 201 rows through real submissions with the unchanged consumer
    # deadline. Reader pagination does not require one large consumer transaction.
    for start in range(0,201,50):
        body=copy.deepcopy(small);body['batch_id']='00000000-0000-4000-8000-%012x' % (0xbeef000+start)
        body['records']=[dict(body['records'][0],record_id='00000000-0000-4000-8000-%012x' % (index+1)) for index in range(start,min(start+50,201))]
        submit(body,status='accepted');consume(body)
        expected_small.extend((body['batch_id'],record['record_id']) for record in body['records'])
    full=read(limit=200)
    assert [len(page['page']['items']) for page in full['pages']]==[200,4]
    assert len(items(full))==204
    assert sorted((item['batch_id'],item['record']['record_id']) for item in items(full) if item['collector_id']==small['collector_id'])==sorted(expected_small), 'row-limit traversal lost or duplicated evidence'
    default=read()
    assert [len(page['page']['items']) for page in default['pages']]==[50,50,50,50,4]

    # Construct a maximum 65,536-byte valid normalized wire shape. Names are
    # approved and bounded; canonical encoding is smaller than this wire encoding.
    names = ['f%03d' % index + '😀'*56 for index in range(256)]
    def shape():
        return {'kind':'object','fields':{name:{'kind':'string'} for name in names},'additional':None}
    compact = lambda value: json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
    remaining = 65536-len(compact(shape()))
    for index in range(len(names)):
        while len(names[index])<64 and remaining:
            extra='😀' if remaining>=4 else 'a'; names[index]+=extra; remaining-=len(extra.encode())
    assert remaining==0 and len(compact(shape()))==65536
    large,_,_=setup('reader_large',lambda policy:policy.update(approved_names=policy['approved_names']+names),current=1)
    large['records'][0]['structure']=shape()
    large['records'][0]['request_header_names']=['GET']
    expected_large=[]
    # Compact UTF-8 preserves the exact 65,536-byte raw shape boundary.
    # Four records per batch stay below the complete inbox cap.
    for batch_index in range(6):
        body=copy.deepcopy(large); body['batch_id']='00000000-0000-4000-8000-%012x' % (0xdead000+batch_index)
        body['records']=[dict(body['records'][0],record_id='00000000-0000-4000-8000-%012x' % (index+1)) for index in range(4)]
        submit(body,status='accepted',compact_utf8=True);consume(body)
        expected_large.extend((body['batch_id'],record['record_id']) for record in body['records'])
    all_pages=read(limit=200)
    large_items=[item for item in items(all_pages) if item['collector_id']==large['collector_id']]
    assert len(all_pages['pages'])>=2 and len(large_items)==24, 'byte-budget continuation lost large items'
    assert sorted((item['batch_id'],item['record']['record_id']) for item in large_items)==sorted(expected_large)
    assert all(item['record']['structure']==shape() for item in large_items)

    # Force a real read lock wait. Drop the owned future and then exercise deadline.
    for wanted,deadline in [('Cancel',5000),('Deadline',300)]:
        holder=subprocess.Popen(['docker','exec','-i',container,'psql','-XAtq','-v','ON_ERROR_STOP=1','-U','postgres','-d','contour_fixture'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        marker=queue.Queue();thread=threading.Thread(target=lambda:[marker.put(line.strip()) for line in holder.stdout],daemon=True);thread.start()
        try:
            holder.stdin.write('BEGIN; LOCK TABLE contour.observation_windows IN ACCESS EXCLUSIVE MODE;\n\\echo HELD\n');holder.stdin.flush()
            until=time.monotonic()+3
            while marker.get(timeout=max(0.01,until-time.monotonic()))!='HELD': pass
            read(wanted,deadline=deadline)
        finally:
            holder.stdin.write('ROLLBACK;\n\\q\n');holder.stdin.flush()
            try: holder.wait(timeout=3)
            except subprocess.TimeoutExpired: holder.kill();holder.wait(timeout=3)
            thread.join(2)
            for pipe in [holder.stdin,holder.stdout,holder.stderr]: pipe.close()
    print('Restricted reader exact source evidence, scope/keyset/byte bounds, NUL/max shape, nanosecond offsets, corruption preflight, cancellation and history passed',flush=True)
    runpy.run_path(str(ROOT / 'scripts/test-observed-comparison.py'))['run_cases'](execute, setup, submit, consume, read, items, target)
