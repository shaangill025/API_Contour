"""Checked identity projection, plus actual mTLS/inbox isolation evidence."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def run_cases(execute, setup, server, request, directory, environment, probe):
    item = '00000000-0000-0000-0000-000000000001'
    service2 = '00000000-0000-0000-0000-000000000002'
    deployments = [item, '00000000-0000-0000-0000-000000000003',
                   '00000000-0000-0000-0000-000000000004']

    def reference(body, record=None):
        record = body['records'][0] if record is None else record
        parts = [body['tenant_id']] + [record[key] for key in
            ['project_id', 'service_id', 'environment_id', 'protocol', 'direction', 'operation', 'route_template']]
        def quote(text):
            # Decode each scalar independently so literal backslash sequences
            # never get mistaken for JSON short escapes.
            return '"' + ''.join(('\\u%04x' % ord(char)) if ord(char) < 32 else
                json.dumps(char, ensure_ascii=False)[1:-1] for char in text) + '"'
        canonical = '[' + ','.join(quote(part) for part in parts) + ']'
        return canonical, hashlib.sha256(b'apicontour/operation/1\n' + canonical.encode()).hexdigest()

    def structure_tree(node):
        kind = node['kind']
        if kind == 'unknown': return [kind,node['reason']]
        if kind == 'object':
            return [kind,[[name,structure_tree(value)] for name,value in
                sorted(node['fields'].items(),key=lambda pair:pair[0].encode())],
                None if node['additional'] is None else structure_tree(node['additional'])]
        if kind == 'array': return [kind,structure_tree(node['items'])]
        if kind == 'union': return [kind,[structure_tree(value) for value in node['alternatives']]]
        return [kind]

    def project_rows(body):
        result = subprocess.run([probe], input=json.dumps(body).encode(), capture_output=True,
                                timeout=5, env=environment)
        assert result.returncode == 0 and not result.stderr, 'operation probe failed'
        rows = json.loads(result.stdout)
        assert len(rows) == len(body['records'])
        for record,row in zip(body['records'],rows):
            canonical, fingerprint = reference(body,record)
            assert len(canonical.encode()) <= 2048, 'operation encoding exceeded bound'
            assert row['canonical'] == canonical and row['fingerprint'] == fingerprint, 'operation identity encoding mismatch'
            for key in ['record_id','deployment_id','source_id','parser_profile','policy_revision',
                        'visibility','route_uncertain','completeness','reasons','structure','count',
                        'first_seen','last_seen','sample_numerator','sample_denominator','status_code',
                        'request_header_names','response_header_names','query_parameter_names',
                        'queued_at','expires_at']:
                assert row[key] == record[key], 'operation evidence changed: '+key
            assert row['collector_id'] == body['collector_id'] and row['canonicalization_version'] == 1
            shape = json.dumps(structure_tree(record['structure']),ensure_ascii=False,separators=(',',':'))
            assert row['structure_canonical'] == shape
            assert row['structure_fingerprint'] == hashlib.sha256(b'apicontour/structure/1\n'+shape.encode()).hexdigest()
        return rows

    def project(body):
        rows = project_rows(body)
        assert len(rows) == 1
        return rows[0]

    baseline = next(row['body'] for row in json.loads((ROOT / 'docs/specification/fixtures/batches.json').read_text()) if row['id'] == 'valid_structure')
    golden = json.loads((ROOT / 'docs/specification/fixtures/operation-keys.json').read_text())
    projected = {}
    for vector in golden:
        body = copy.deepcopy(baseline)
        body.update(vector['envelope_changes'])
        body['records'][0].update(vector['record_changes'])
        row = project(body)
        assert row['canonical'] == vector['canonical'] and row['fingerprint'] == vector['fingerprint'], 'operation golden mismatch'
        projected[vector['id']] = row['fingerprint']
    for name in ['deployment', 'source', 'collector', 'uncertain', 'policy_profile']:
        assert projected[name] == projected['base'], 'provenance split stable operation identity'
    distinct = [key for name, key in projected.items() if name not in ['deployment', 'source', 'collector', 'uncertain', 'policy_profile']]
    assert len(set(distinct)) == len(distinct), 'operation scopes or exact Unicode merged'

    results = []
    for index, service in enumerate([item, service2, item]):
        body, collector, _ = setup('operation_identity', current=1, history=(1,),
                                  change=lambda policy: policy.update(service_ids=[item, service2]))
        tenant = body['tenant_id']
        deployment = deployments[index]
        if index:
            source = '00000000-0000-0000-0000-%012x' % (800 + index)
            execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); " % (tenant, tenant, collector) +
                "INSERT INTO contour.services VALUES ('%s','%s','%s') ON CONFLICT DO NOTHING; " % (tenant, service, item) +
                "INSERT INTO contour.deployments VALUES ('%s','%s','%s','%s','%s'); " % (tenant, deployment, item, service, item) +
                "INSERT INTO contour.workload_assignments VALUES ('%s','%s','%s','%s','%s','%s'); " % (tenant, collector, item, service, item, deployment) +
                "INSERT INTO contour.sources VALUES ('%s','%s','%s','%s','%s','%s','%s','%s'); " % (tenant, source, collector, item, service, item, deployment, source) +
                "INSERT INTO contour.source_authorization VALUES ('%s','%s','%s','runtime',ARRAY['http_json_v1']); COMMIT;" % (tenant, source, collector))
            body['records'][0].update(service_id=service, deployment_id=deployment, source_id=source)
        with server(body) as port:
            receipt = request(port, body)
            assert receipt['status'] == 'accepted'
            where = "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (tenant, collector, body['batch_id'])
            stored = json.loads(bytes.fromhex(execute("SELECT encode(checked_batch,'hex') FROM contour.ingestion_payloads WHERE " + where + ';')))
            assert project(stored) == project(body), 'durable operation projection changed'
            results.append(project(stored))
            denied_sources = [('ffffffff-0000-0000-0000-000000000001', 403)]
            if index:
                # Setup registered this collector/source for the original workload.
                # It remains known and assigned, but cannot assert the new workload.
                denied_sources.append((collector, 422))
            for offset, (denied_source, status) in enumerate(denied_sources):
                foreign = copy.deepcopy(body)
                foreign['batch_id'] = '00000000-0000-0000-0000-%012x' % (900 + index * 2 + offset)
                foreign['records'][0]['source_id'] = denied_source
                request(port, foreign, status)
                rejected = "tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (tenant, collector, foreign['batch_id'])
                for table in ['ingestion_batches', 'ingestion_payloads']:
                    assert execute('SELECT count(*) FROM contour.' + table + ' WHERE ' + rejected + ';') == '0'
    assert results[0]['fingerprint'] != results[1]['fingerprint'], 'equal paths merged different services'
    assert results[0]['fingerprint'] == results[2]['fingerprint'], 'deployment split stable identity'
    assert len({row['deployment_id'] for row in results}) == 3
    assert len({row['source_id'] for row in results}) == 3
    assert len({row['collector_id'] for row in results}) == 3
    # Preserve mixed evidence and repeated source windows as separate records.
    body,collector,source=setup('operation_evidence',current=1,history=(1,))
    first=body['records'][0]
    records=[copy.deepcopy(first) for _ in range(4)]
    second_source='00000000-0000-0000-0002-000000000001'
    tenant=body['tenant_id']
    execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); " % (tenant,tenant,collector)+
        "INSERT INTO contour.sources VALUES('%s','%s','%s','%s','%s','%s','%s','%s'); " % (tenant,second_source,collector,item,item,item,item,second_source)+
        "INSERT INTO contour.source_authorization VALUES('%s','%s','%s','runtime',ARRAY['http_json_v1']); COMMIT;" % (tenant,second_source,collector))
    for index,record in enumerate(records):
        record['record_id']='00000000-0000-4000-8000-%012x' % (1000+index)
    records[0].update(count=1000000000,status_code=599,request_header_names=['id'],response_header_names=['quantity'],query_parameter_names=['id'])
    records[1].update(source_id=second_source,count=7,sample_numerator=1,sample_denominator=1000000,reasons=['sampled'],status_code=None,route_uncertain=True)
    records[2].update(count=3,completeness='partial',reasons=['limit'],structure={'kind':'unknown','reason':'limit'},status_code=None)
    records[3].update(source_id=second_source,direction='request',count=1,visibility='connection',completeness='unavailable',reasons=['encrypted'],structure={'kind':'unknown','reason':'encrypted'},status_code=None)
    body['records']=records
    with server(body) as port:
        accepted=request(port,body)
        assert accepted['status']=='accepted'
        where="tenant_id='%s' AND collector_id='%s' AND batch_id='%s'" % (tenant,collector,body['batch_id'])
        raw=bytes.fromhex(execute('SELECT encode(checked_batch,\'hex\') FROM contour.ingestion_payloads WHERE '+where+';'))
        observed=project_rows(json.loads(raw))
        assert observed==project_rows(body) and len(observed)==4
        assert observed[0]['fingerprint']==observed[1]['fingerprint']==observed[2]['fingerprint']
        assert observed[3]['fingerprint']!=observed[0]['fingerprint']
        assert observed[0]['structure_fingerprint']==observed[1]['structure_fingerprint']
        assert observed[2]['structure_fingerprint']!=observed[3]['structure_fingerprint']
        assert [row['count'] for row in observed]==[1000000000,7,3,1]
        assert [row['source_id'] for row in observed]==[source,second_source,source,second_source]
        assert request(port,body)['status']=='duplicate'
        assert bytes.fromhex(execute('SELECT encode(checked_batch,\'hex\') FROM contour.ingestion_payloads WHERE '+where+';'))==raw
        for index,update in enumerate([{'completeness':'complete'},{'sample_denominator':0}]):
            invalid=copy.deepcopy(body)
            invalid['batch_id']='00000000-0000-4000-8000-%012x' % (1100+index)
            invalid['records'][2].update(update)
            request(port,invalid,400)
            assert execute("SELECT count(*) FROM contour.ingestion_batches WHERE tenant_id='%s' AND collector_id='%s' AND batch_id='%s';" % (tenant,collector,invalid['batch_id']))=='0'
    print('Actual inbox evidence projection preserves shape, uncertainty, exact source counts, timestamps, sampling and approved names without aggregation')
    print('Operation golden/isolation checks and actual HTTPS-to-durable-inbox service/deployment/source evidence passed')
