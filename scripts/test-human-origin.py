"""Opt-in synthetic 17 human catalog fixture; called only by --human-origin."""
import base64
import copy
import json
import os
import re
from pathlib import Path
import runpy
import subprocess
import time
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
ACTOR = '00000000-0000-0000-0000-00000000ef01'
ISSUER = 'https://idp.example.test/realms/demo'


HISTORICAL_MIGRATIONS=('0018_causal_runtime_registry','0019_causal_sessions','0020_causal_inbox',
                       '0021_origin_admission','0022_causal_generation','0023_causal_marker_bindings',
                       '0024_causal_live_profile','0025_historical_origin')


def apply_historical_profile(execute):
    if execute("SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;") != '{'+','.join(map(str,range(1,18)))+'}':
        raise RuntimeError('historical fixture input ledger mismatch')
    for name in HISTORICAL_MIGRATIONS:
        execute((ROOT/'db/opt-in-migrations'/(name+'.sql')).read_text())
    if execute("SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;") != '{'+','.join(map(str,range(1,26)))+'}':
        raise RuntimeError('historical fixture output ledger mismatch')


def run_smoke(execute, body):
    """Restricted reader privileges and tenant/argument guards, before data tests."""
    reader = 'contour_catalog_reader_tls'
    assert execute("SELECT has_table_privilege('%s','contour.origin_proofs','SELECT'),has_table_privilege('%s','contour.ingestion_payloads','SELECT'),has_table_privilege('%s','contour.catalog_origin_projection','SELECT'),has_table_privilege('%s','contour.catalog_origin_heads','SELECT,INSERT,UPDATE,DELETE,TRUNCATE');" % (reader,reader,reader,reader)) == 'f|f|f|f'
    tenant = body['tenant_id']; item = '00000000-0000-0000-0000-000000000001'
    other = 'bbbbbbbb-0000-0000-0000-000000000000' if tenant != 'bbbbbbbb-0000-0000-0000-000000000000' else 'aaaaaaaa-0000-0000-0000-000000000000'
    # Real reader role, tenant-local context, no private-table access or
    # unbounded/partial helper arguments. Exception blocks require 42501.
    execute("""BEGIN; SET LOCAL ROLE contour_catalog_reader_tls;
      SELECT set_config('apicontour.tenant_id','%(tenant)s',true);
      DO $$ DECLARE rejected boolean; BEGIN
        rejected:=false; BEGIN DELETE FROM contour.catalog_origin_heads; EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'head delete granted'; END IF;
        rejected:=false; BEGIN UPDATE contour.catalog_origin_heads SET observed_at=observed_at; EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'head update granted'; END IF;
        rejected:=false; BEGIN PERFORM * FROM contour.human_origin_candidates('%(other)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s',NULL,1); EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'cross tenant accepted'; END IF;
        rejected:=false; BEGIN PERFORM * FROM contour.human_origin_candidates('%(tenant)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s',NULL,NULL); EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'unbounded candidate request accepted'; END IF;
        rejected:=false; BEGIN PERFORM * FROM contour.human_origin_operation('%(tenant)s','%(id)s','%(id)s','%(id)s','%(id)s','%(id)s',NULL,NULL,NULL,NULL); EXCEPTION WHEN insufficient_privilege THEN rejected:=true; END;
        IF NOT rejected THEN RAISE EXCEPTION 'partial origin scope accepted'; END IF;
      END $$; ROLLBACK;""" % dict(tenant=tenant,other=other,id=item))


def run_cases(execute, submit, body, expected_origins, port, directory, environment):
    # The authority fixture deliberately starts with a sparse component schema.
    # Extend only this opt-in mode with the ordinary human business schema.
    for name in ['declared','approval','comparison','review','human']:
        execute((ROOT / ('db/provision_' + name + '.sql')).read_text())
    for version in range(5, 13):
        path = next((ROOT / 'db/migrations').glob('%04d_*.sql' % version))
        execute(path.read_text())
    execute("CREATE ROLE contour_human_reader_tls LOGIN PASSWORD '%s'; GRANT contour_catalog_reader,contour_approval_reader,contour_human_lookup TO contour_human_reader_tls;" % environment['CONTOUR_FIXTURE_PASSWORD'])
    tenant = body['tenant_id']; target = body['records'][0]['record']
    target_scope = [tenant,target['project_id'],target['service_id'],target['environment_id']]
    scopes = [(target['project_id'],target['service_id'])] + [(o['origin_project_id'],o['origin_service_id']) for o in expected_origins]
    execute("SET ROLE contour_human_provisioner; INSERT INTO contour.human_actors VALUES ('%s',true); INSERT INTO contour.human_identities VALUES ('%s','synthetic-user','%s',true); INSERT INTO contour.human_tenant_memberships VALUES ('%s','%s',true);" % (ACTOR,ISSUER,ACTOR,tenant,ACTOR))
    for project in sorted({p for p,_ in scopes}):
        execute("SET ROLE contour_human_provisioner; INSERT INTO contour.human_project_memberships VALUES ('%s','%s','%s',true);" % (tenant,project,ACTOR))
    for project,service in sorted(set(scopes)):
        execute("SET ROLE contour_human_provisioner; INSERT INTO contour.human_service_roles VALUES ('%s','%s','%s','%s','viewer',true);" % (tenant,project,service,ACTOR))

    def token(subject,lifetime=600):
        now = int(time.time()); claims = {'iss':ISSUER,'sub':subject,'aud':'apicontour','iat':now,'exp':now+lifetime,'nonce':'server-generated-one-use-nonce'}
        enc = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b'=')
        data = enc({'alg':'RS256','kid':'synthetic-rsa'}) + b'.' + enc(claims)
        sig = subprocess.run(['openssl','dgst','-sha256','-keyform','DER','-sign',str(ROOT/'crates/contour-auth/tests/fixtures/synthetic-rsa.der')], input=data,capture_output=True,timeout=5,check=True).stdout
        path = directory / ('human-origin-token-'+subject+'-'+str(lifetime)); path.write_bytes(data+b'.'+base64.urlsafe_b64encode(sig).rstrip(b'=')); return path
    normal, unknown = token('synthetic-user'), token('unknown-user')

    # Origin 0 was closed by the enclosing fixture. Origin 1 remains active:
    # use it for a second operation to test keyset pagination for one origin.
    second = copy.deepcopy(body)
    second['batch_id'] = '00000000-0000-4000-8000-00000000be01'
    second['records'] = [copy.deepcopy(body['records'][1])]
    second['records'][0]['record']['record_id'] = '00000000-0000-4000-8000-00000000be02'
    second['records'][0]['record']['direction'] = 'request'
    submit(second,status='accepted')
    target_dir = json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps','--offline'],text=True,timeout=15))['target_directory']
    probe = Path(target_dir)/'debug/examples/catalog_probe'
    process = subprocess.run([str(probe),str(port),str(directory/'ca.crt'),second['batch_id'],'Processed',tenant,body['collector_id'],'5000'], input='\n',capture_output=True,text=True,env=environment,timeout=15,check=True)
    assert process.stdout.strip() == 'Processed' and not process.stderr
    where = "p.tenant_id='%s' AND p.collector_id='%s' AND p.batch_id='%s'" % (tenant,body['collector_id'],body['batch_id'])
    records = json.loads(execute("SELECT json_agg(row_to_json(x) ORDER BY record_id) FROM (SELECT p.origin_project_id AS project_id,p.origin_service_id AS service_id,p.origin_environment_id AS environment_id,p.origin_deployment_id AS deployment_id,p.instance_id,p.collector_id,p.batch_id,p.record_id,w.operation_id,w.last_seen,w.visibility,w.completeness FROM contour.catalog_origin_projection p JOIN contour.observation_windows w USING(tenant_id,collector_id,batch_id,record_id) WHERE %s) x;" % where))
    assert len(records) == 2
    if environment.get('CONTOUR_HISTORICAL_ORIGIN_FIXTURE') == '1':
        # Complete only this disposable fixture's exact 1..25 ledger. The
        # established sparse fixture has now applied core 5..12 and 13..17.
        apply_historical_profile(execute)
        execute((ROOT/'db/tests/historical_origin.sql').read_text())
        historical_rows=json.loads(execute("SELECT json_agg(row_to_json(x) ORDER BY record_id) FROM (SELECT p.record_id,p.origin_project_id,p.origin_service_id,p.origin_environment_id,p.origin_deployment_id,p.instance_id,w.observation_id,w.operation_id,w.project_id,w.service_id,w.environment_id,w.deployment_id FROM contour.catalog_origin_projection p JOIN contour.observation_windows w USING(tenant_id,collector_id,batch_id,record_id) WHERE %s) x;" % where))
        if type(historical_rows) is not list or len(historical_rows)!=2: raise RuntimeError('historical fixture rows unavailable')
        runpy.run_path(str(ROOT/'scripts/test-postgres-v2-catalog.py'))['run_historical_cases'](execute,body,historical_rows)
    records.reverse()  # Active origin first; the closed origin remains historically visible.
    first = records[0]
    keys = [tenant,target['project_id'],target['service_id'],target['environment_id'],*[first[k] for k in ('project_id','service_id','environment_id','deployment_id','instance_id')]]
    predicate = "(tenant_id,project_id,service_id,environment_id,origin_project_id,origin_service_id,origin_environment_id,origin_deployment_id,instance_id)=(%s)" % ','.join("'%s'" % key for key in keys)
    expected_operations = json.loads(execute("SELECT json_agg(operation_id::text ORDER BY operation_id) FROM contour.catalog_origin_heads WHERE %s;" % predicate))
    runpy.run_path(str(ROOT/'scripts/test-human-catalog.py'))['run_origin_cases'](execute,port,directory,environment,normal,unknown,target_scope,ACTOR,records,expected_operations,token)
    run_business_cases(execute,port,directory,environment,normal,unknown,target_scope,records,expected_operations,target_dir)
    if environment.get('CONTOUR_HISTORICAL_ORIGIN_FIXTURE') == '1':
        with (directory/'historical-origin.done').open('xb') as receipt:
            receipt.write(b'historical-origin-complete\n')


def run_business_cases(execute, port, directory, environment, normal, unknown, scope, records, expected_operations, target_dir):
    """Exercise real Business::handle with synthetic verified identities and PG.

    This is in-process handler-to-database evidence, not HTTP/TLS/session evidence.
    The optional evidence file contains only allowlisted synthetic response JSON.
    """
    password_path = directory/'business-fixture-password'
    password_path.write_text(environment['CONTOUR_FIXTURE_PASSWORD'])
    config_path = directory/'business-fixture.json'
    config_path.write_text(json.dumps(dict(database_host='localhost',database_port=int(port),database_name='contour_fixture',
        database_user='contour_human_reader_tls',database_password_file=str(password_path),database_ca_file=str(directory/'ca.crt'),
        tenant_id=scope[0],project_id=scope[1],service_id=scope[2],environment_id=scope[3],
        routes=[['/source','/orders']],approved_names=['id','quantity'],approved_media=['application/json'])))
    probe = Path(target_dir)/'debug/examples/human_origin_business_probe'
    keys = ('project_id','service_id','environment_id','deployment_id','instance_id')
    origin = records[0]
    query = {'include_origin':'true', **{'origin_'+key:origin[key] for key in keys}}
    operation_id = records[0]['operation_id']
    uuid = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    old_fields = {'id','project_id','service_id','environment_id','protocol','direction','operation','route_template',
                  'approved_contract_id','last_seen','visibility','completeness'}
    new_fields = {'origin_evidence_available','origins','origins_truncated'}

    def get(uri, credential=normal):
        result = subprocess.run([str(probe),str(config_path),uri],
            env=dict(environment,CONTOUR_FIXTURE_ID_TOKEN=str(credential)),capture_output=True,text=True,timeout=35,check=True)
        assert not result.stderr, 'handler probe wrote an error'
        value = json.loads(result.stdout)
        assert set(value) == {'status','body'} and type(value['status']) is int and isinstance(value['body'],dict)
        return value

    def validate_operation(op, include):
        assert isinstance(op,dict) and set(op) == old_fields | (new_fields if include else set())
        for key in ('id','project_id','service_id','environment_id'):
            assert isinstance(op[key],str) and uuid.fullmatch(op[key])
        assert [op['project_id'],op['service_id'],op['environment_id']] == scope[1:]
        assert op['approved_contract_id'] is None or isinstance(op['approved_contract_id'],str) and uuid.fullmatch(op['approved_contract_id'])
        for key,maximum in (('protocol',32),('direction',32),('operation',32),('route_template',256)):
            assert isinstance(op[key],str) and 0 < len(op[key]) <= maximum
        for key in ('last_seen','visibility','completeness'):
            assert op[key] is None or isinstance(op[key],str) and len(op[key]) <= 64
        assert op['direction'] in ('request','response','publish','consume','operation','connection')
        assert op['visibility'] in (None,'structure','operation','connection')
        assert op['completeness'] in (None,'complete','partial','unavailable')
        assert all(op[k] is None for k in ('last_seen','visibility','completeness')) or all(isinstance(op[k],str) for k in ('last_seen','visibility','completeness'))
        if include:
            assert type(op['origin_evidence_available']) is bool and type(op['origins_truncated']) is bool
            assert isinstance(op['origins'],list) and len(op['origins']) <= 32
            if not op['origin_evidence_available']: assert not op['origins'] and not op['origins_truncated']
            for entry in op['origins']:
                assert isinstance(entry,dict) and set(entry) == set(keys) | {'proof_status'}
                assert entry['proof_status'] == 'verified'
                assert all(isinstance(entry[key],str) and uuid.fullmatch(entry[key]) for key in keys)
        return op

    def validate_page(response, include):
        assert response['status'] == 200 and set(response['body']) == {'items','next_cursor'}
        body = response['body']; assert isinstance(body['items'],list) and len(body['items']) <= 200
        assert body['next_cursor'] is None or isinstance(body['next_cursor'],str) and uuid.fullmatch(body['next_cursor'])
        for op in body['items']: validate_operation(op,include)
        return body

    def error(response, status, code):
        assert response['status'] == status
        value = response['body']; assert set(value) == {'code','message','request_id','retryable'}
        assert value['code'] == code and isinstance(value['message'],str) and uuid.fullmatch(value['request_id'])
        assert type(value['retryable']) is bool

    legacy = validate_page(get('/v1/operations?limit=200'),False)
    included = validate_page(get('/v1/operations?limit=200&include_origin=true'),True)
    assert operation_id in [v['id'] for v in legacy['items']]
    assert [v['id'] for v in legacy['items']] == [v['id'] for v in included['items']]
    assert legacy['items'] == [{key:item[key] for key in old_fields} for item in included['items']]
    filtered = validate_page(get('/v1/operations?limit=200&'+urlencode(query)),True)
    assert [item['id'] for item in filtered['items']] == expected_operations
    selected = next(item for item in filtered['items'] if item['id'] == operation_id)
    assert (selected['last_seen'],selected['visibility'],selected['completeness']) == (origin['last_seen'],origin['visibility'],origin['completeness'])
    assert any(all(entry[key] == origin[key] for key in keys) for entry in selected['origins'])
    first = validate_page(get('/v1/operations?limit=1&'+urlencode(query)),True)
    assert len(first['items']) == 1 and first['next_cursor'] == first['items'][0]['id']
    second = validate_page(get('/v1/operations?limit=1&cursor='+first['next_cursor']+'&'+urlencode(query)),True)
    assert [first['items'][0]['id'],second['items'][0]['id']] == expected_operations and second['next_cursor'] is None
    old_detail = get('/v1/operations/'+operation_id); assert old_detail['status'] == 200
    validate_operation(old_detail['body'],False)
    detail = get('/v1/operations/'+operation_id+'?include_origin=true'); assert detail['status'] == 200
    validate_operation(detail['body'],True)
    assert detail['body']['id'] == operation_id
    assert old_detail['body'] == next(item for item in legacy['items'] if item['id'] == operation_id)
    assert detail['body'] == next(item for item in included['items'] if item['id'] == operation_id)
    assert {tuple(entry[key] for key in keys) for entry in detail['body']['origins']} == {tuple(item[key] for key in keys) for item in records}
    mixed = {'include_origin':'true', **{'origin_'+key:records[1][key] for key in keys}}
    mixed['origin_instance_id'] = origin['instance_id']
    assert validate_page(get('/v1/operations?limit=200&'+urlencode(mixed)),True)['items'] == []
    error(get('/v1/operations?include_origin=true&origin_instance_id='+origin['instance_id']),400,'invalid_request')
    error(get('/v1/operations?include_origin=true&include_origin=true'),400,'invalid_request')
    error(get('/v1/operations/'+operation_id+'?cursor=x'),400,'invalid_request')
    error(get('/v1/operations?limit=200',unknown),403,'forbidden')
    error(get('/v1/operations/'+operation_id+'?include_origin=true',unknown),403,'forbidden')

    def role(project,service,enabled):
        execute("SET ROLE contour_human_provisioner; UPDATE contour.human_service_roles SET enabled=%s WHERE actor_id='%s' AND tenant_id='%s' AND project_id='%s' AND service_id='%s';" % ('true' if enabled else 'false',ACTOR,scope[0],project,service))
    if environment.get('CONTOUR_HISTORICAL_ORIGIN_FIXTURE') == '1':
        for item in records:
            observation=execute("SELECT observation_id::text FROM contour.observation_windows WHERE tenant_id='%s' AND collector_id='%s' AND batch_id='%s' AND record_id='%s';" % (scope[0],item['collector_id'],item['batch_id'],item['record_id']))
            uri='/v1/observations/'+observation+'/origin?operation_id='+item['operation_id']
            value=get(uri); assert value['status']==200
            body=value['body']; assert set(body)=={'observation_id','operation_id','status','origin'}
            assert body['observation_id']==observation and body['operation_id']==item['operation_id'] and body['status']=='verified'
            assert set(body['origin'])==set(keys)|{'lifecycle_id','credential_id','grant_id'}
            assert all(body['origin'][key]==item[key] for key in keys)
            assert all(uuid.fullmatch(body['origin'][key]) for key in body['origin'])
            error(get(uri,unknown),403,'forbidden')
            role(item['project_id'],item['service_id'],False)
            try:
                denied=get(uri); assert denied['status']==200 and denied['body']=={'observation_id':observation,'operation_id':item['operation_id'],'status':'unavailable','origin':None}
            finally: role(item['project_id'],item['service_id'],True)
    role(origin['project_id'],origin['service_id'],False)
    try: error(get('/v1/operations?limit=200&'+urlencode(query)),403,'forbidden')
    finally: role(origin['project_id'],origin['service_id'],True)
    role(scope[1],scope[2],False)
    try: error(get('/v1/operations?limit=200'),403,'forbidden')
    finally: role(scope[1],scope[2],True)

    # Reconstruct the export from validated public fields only; no inputs,
    # tokens, proof identifiers, hashes, headers or captured payloads are saved.
    evidence = {'legacy_list':legacy,'included_list':included,'filtered_list':filtered,
                'legacy_detail':old_detail['body'],'included_detail':detail['body']}
    path = environment.get('CONTOUR_HUMAN_ORIGIN_EVIDENCE_PATH')
    if path:
        fd = os.open(path,os.O_WRONLY | os.O_CREAT | os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as output: json.dump(evidence,output,sort_keys=True,indent=2)
    if environment.get('CONTOUR_HUMAN_OBSERVATION_HISTORY_FIXTURE') == '1':
        # Two independent fixed configurations exercise denial without changing
        # the existing reader credentials or the original positive scope.
        config=json.loads(config_path.read_text()); other=dict(config); other['service_id']='ffffffff-ffff-4fff-8fff-ffffffffffff'
        other_env=dict(config); other_env['environment_id']='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
        other_path=directory/'history-other-scope.json'; other_env_path=directory/'history-other-environment.json'
        other_path.write_text(json.dumps(other)); other_env_path.write_text(json.dumps(other_env))
        result=runpy.run_path(str(ROOT/'scripts/test-postgres-tls.py'))['checked_history_loader']()['run_cases'](execute,config_path,other_path,other_env_path,normal,unknown,scope,operation_id,target_dir,environment)
        if type(result) is not dict or set(result)!={'stored_observations','handler_authorization','historical_origin'} or type(result['stored_observations']) is not int or result['stored_observations']<1 or result['handler_authorization'] is not True or result['historical_origin']!='unavailable': raise AssertionError('history fixture did not complete')
        receipt=directory/'human-observation-history.done'
        fd=os.open(receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as out: out.write('history-fixture-complete\n'); out.flush(); os.fsync(out.fileno())
        print('Real Business handler stored observation history and human authorization passed (not HTTP/session evidence).',flush=True)
    print('Real Business handler synthetic catalog/filter/authorization assertions passed (not HTTP/session evidence).',flush=True)
