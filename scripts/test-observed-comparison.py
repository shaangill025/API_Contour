"""Observed comparison of records reloaded through the restricted catalog reader."""
import copy
import json
from pathlib import Path
import subprocess


def run_cases(execute, setup, submit, consume, read, items, target):
    probe = str(Path(target) / 'debug/examples/comparison_probe')

    def names(shape):
        found = set(shape.get('fields', {}))
        for child in shape.get('fields', {}).values():
            found.update(names(child))
        for key in ['items', 'additional']:
            if shape.get(key) is not None:
                found.update(names(shape[key]))
        for child in shape.get('alternatives', []):
            found.update(names(child))
        return found

    def persist(label, shape, completeness='complete', reasons=(), direction='response', operation='POST', other_deployment=False, parser_profile='http_json_v1'):
        approved = sorted(names(shape) | {'POST', 'PUT'})
        body, _, _ = setup('compare_' + label, lambda policy: policy.update(approved_names=sorted(set(policy['approved_names'] + approved)),parser_profiles=sorted(set(policy['parser_profiles']+[parser_profile]))), current=1)
        record = body['records'][0]
        record.update(structure=shape, completeness=completeness, reasons=list(reasons), direction=direction, operation=operation, parser_profile=parser_profile, status_code=200 if direction == 'response' else None)
        if completeness == 'unavailable':
            record['visibility'] = 'connection'
        if other_deployment:
            tenant, collector = body['tenant_id'], body['collector_id']
            deployment = '00000000-0000-4000-8000-00000c0ffee1'
            project, service, environment = record['project_id'], record['service_id'], record['environment_id']
            execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); INSERT INTO contour.deployments VALUES('%s','%s','%s','%s','%s'); INSERT INTO contour.workload_assignments VALUES('%s','%s','%s','%s','%s','%s'); INSERT INTO contour.sources VALUES('%s','%s','%s','%s','%s','%s','%s','%s'); INSERT INTO contour.source_authorization VALUES('%s','%s','%s','runtime',ARRAY['http_json_v1']); COMMIT;" % (tenant,tenant,collector,tenant,deployment,project,service,environment,tenant,collector,project,service,environment,deployment,tenant,deployment,collector,project,service,environment,deployment,deployment,tenant,deployment,collector))
            record.update(source_id=deployment, deployment_id=deployment)
        if parser_profile != 'http_json_v1':
            # A synthetic, explicitly signed and source-authorized profile tests
            # comparison isolation; it does not claim a shipped parser exists.
            assert parser_profile == 'fixture_other_profile'
            execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SELECT contour.lock_collector('%s','%s'); UPDATE contour.source_authorization SET parser_profiles=ARRAY['http_json_v1','fixture_other_profile'] WHERE tenant_id='%s' AND collector_id='%s' AND source_id='%s'; COMMIT;" % (body['tenant_id'],body['tenant_id'],body['collector_id'],body['tenant_id'],body['collector_id'],record['source_id']))
        submit(body, status='accepted', compact_utf8=True)
        consume(body)
        operation_id = execute("SELECT operation_id::text FROM contour.observation_windows WHERE tenant_id='%s' AND collector_id='%s' AND batch_id='%s';" % (body['tenant_id'],body['collector_id'],body['batch_id']))
        scope = [body['tenant_id'],record['project_id'],record['service_id'],operation_id]

        def reload():
            evidence = next(item for item in items(read(limit=200, selected=scope)) if item['collector_id']==body['collector_id'] and item['batch_id']==body['batch_id'])
            assert evidence['record'] == record, 'comparison input did not match persisted checked evidence'
            return dict(wire_version=1,tenant_id=scope[0],collector_id=evidence['collector_id'],batch_id=evidence['batch_id'],created_at=evidence['record']['queued_at'],records=[evidence['record']])
        return reload

    def compare(left, right):
        output = subprocess.run([probe], input=json.dumps(dict(left=left(),right=right()),ensure_ascii=False,separators=(',',':')),capture_output=True,text=True,timeout=5,check=True)
        return json.loads(output.stdout)

    def differences(left, right):
        result = compare(left,right)
        assert result.get('compatibility') == 'Inconclusive', 'observed evidence became a compatibility claim'
        assert result == compare(left,right), 'reloaded comparison was not deterministic'
        assert all(diff['kind'] != 'RequirednessChanged' for diff in result['differences'])
        return result['differences']

    def object_shape(fields, additional=None):
        return dict(kind='object',fields=fields,additional=additional)

    string, integer = {'kind':'string'}, {'kind':'integer'}
    baseline = persist('baseline',object_shape({'id':string}))
    candidate = persist('type',object_shape({'id':integer}),other_deployment=True)
    delta = differences(baseline,candidate)
    assert [(diff['path'],diff['kind'],diff['left_kind'],diff['right_kind']) for diff in delta] == [('#/fields/id','TypeChanged','String','Integer')]
    assert differences(baseline,baseline) == [], 'equal known structures invented a change'
    other_profile=persist('profile',object_shape({'id':string}),parser_profile='fixture_other_profile')
    assert compare(baseline,other_profile)==dict(error='ParserProfile'), 'source-authorized parser profiles were mixed'

    partial = persist('partial',object_shape({'quantity':integer}),'partial',['limit'])
    delta = differences(baseline,partial)
    assert [(diff['path'],diff['kind']) for diff in delta] == [('#','InsufficientEvidence'),('#/fields/id','FieldAbsent'),('#/fields/quantity','FieldAdded')]
    nullable = persist('nullable',object_shape({'id':dict(kind='union',alternatives=[{'kind':'null'},string])}))
    for left,right,wanted in [(baseline,nullable,(False,True)),(nullable,baseline,(True,False))]:
        delta=differences(left,right)
        assert len(delta)==1 and delta[0]['kind']=='NullMembershipChanged' and delta[0]['path']=='#/fields/id'
        assert (delta[0]['left_includes_null'],delta[0]['right_includes_null'])==wanted

    null=persist('null',{'kind':'null'})
    scalar=persist('scalar',string)
    for left,right,wanted in [(null,scalar,(True,False)),(scalar,null,(False,True))]:
        delta=differences(left,right)
        assert [diff['kind'] for diff in delta]==['NullMembershipChanged','TypeChanged']
        assert (delta[0]['left_includes_null'],delta[0]['right_includes_null'])==wanted

    nullable_scalar=persist('nullable_scalar',dict(kind='union',alternatives=[{'kind':'null'},string]))
    for left,right in [(null,nullable_scalar),(nullable_scalar,null)]:
        delta=differences(left,right)
        assert any(diff['kind']=='UnsupportedConstruct' for diff in delta)
        assert not any(diff['kind']=='NullMembershipChanged' for diff in delta), 'nullable-base alignment lost an existing null member'

    for reason,completeness in [('encrypted','unavailable'),('limit','partial'),('unsupported','unavailable')]:
        shape=dict(kind='unknown',reason=reason)
        observed=persist(reason,shape,completeness,[reason])
        delta=differences(observed,observed)
        assert any(diff['kind']=='InsufficientEvidence' and diff['left_unknown']==reason.capitalize() for diff in delta), 'unknown treated as compatible/equal known evidence'
    uncertain_union=persist('uncertain_union',dict(kind='union',alternatives=[string,dict(kind='unknown',reason='encrypted')]),'partial',['encrypted'])
    delta=differences(uncertain_union,null)
    assert not any(diff['kind']=='NullMembershipChanged' for diff in delta), 'unknown union asserted known null absence'
    assert any(diff['kind']=='InsufficientEvidence' for diff in delta)
    empty=persist('empty',dict(kind='array',items=dict(kind='unknown',reason='empty')))
    assert any(diff['path']=='#/items' and diff['kind']=='InsufficientEvidence' and diff['left_unknown']=='Empty' for diff in differences(empty,empty)), 'empty array guessed its item type'

    # Submit canonical alternative order so exact persisted-record equality holds.
    union_a=persist('union_a',dict(kind='union',alternatives=[integer,string]))
    union_b=persist('union_b',dict(kind='union',alternatives=[{'kind':'boolean'},string]))
    assert any(diff['kind']=='UnsupportedConstruct' for diff in differences(union_a,union_b)), 'general union relationship invented'
    assert differences(union_a,union_a)==[]

    tricky=['雪','nul\x00name','/','~','*','items','additional','$']
    left=persist('paths_left',object_shape({name:string for name in tricky},string))
    right=persist('paths_right',object_shape({name:integer for name in reversed(tricky)},integer))
    delta=differences(left,right)
    expected=['#/fields/'+name.replace('~','~0').replace('/','~1') for name in sorted(tricky,key=lambda name:name.encode())]+['#/additional']
    assert [diff['path'] for diff in delta]==expected and len(set(expected))==len(expected), 'path escaping/order/reserved names collided'
    assert all(diff['kind']=='TypeChanged' for diff in delta)

    request=persist('request',object_shape({'id':string}),direction='request')
    other_operation=persist('other_operation',object_shape({'id':string}),operation='PUT')
    assert compare(baseline,request)==dict(error='OperationScope'), 'request/response directions mixed'
    assert compare(baseline,other_operation)==dict(error='OperationScope'), 'different operations mixed'

    def nested(depth,name):
        shape=copy.deepcopy(string)
        for _ in range(depth-1):
            shape=object_shape({name:shape})
        return shape
    deepest=persist('depth',nested(32,'n'))
    assert differences(deepest,deepest)==[], 'maximum checked depth did not compare safely'
    long_path=persist('path_limit',nested(18,'x'*64))
    assert compare(long_path,long_path)==dict(error='PathLimit'), 'long paths silently truncated or claimed compatibility'
    # Isolate aggregate UTF-8 path bytes: every path has only 887 scalars, all
    # nodes are known, with fewer than 2,000 traversal steps and 1,000 differences.
    prefix='雪'*64
    sample_path='#'+('/fields/'+prefix)*12+'/fields/g0/fields/f000'
    path_bytes=len(sample_path.encode())
    boundary_count=1048576//path_bytes
    assert len(sample_path)==887 and path_bytes==2423 and boundary_count==432
    def aggregate_shape(count, leaf):
        groups={}
        for group in range((count+255)//256):
            groups['g%d' % group]=object_shape({'f%03d' % index:leaf for index in range(min(256,count-group*256))})
        shape=object_shape(groups)
        for _ in range(12):
            shape=object_shape({prefix:shape})
        assert len(json.dumps(shape,ensure_ascii=False,separators=(',',':')).encode()) <= 65536
        return shape
    safe_left=persist('aggregate_safe_left',aggregate_shape(boundary_count,string))
    safe_right=persist('aggregate_safe_right',aggregate_shape(boundary_count,integer))
    delta=differences(safe_left,safe_right)
    assert len(delta)==boundary_count and sum(len(diff['path'].encode()) for diff in delta)==1046736
    assert all(diff['kind']=='TypeChanged' and len(diff['path'])==887 for diff in delta)
    over_left=persist('aggregate_over_left',aggregate_shape(boundary_count+1,string))
    over_right=persist('aggregate_over_right',aggregate_shape(boundary_count+1,integer))
    assert (boundary_count+1)*path_bytes==1049159
    assert compare(over_left,over_right)==dict(error='PathLimit'), 'aggregate UTF-8 path bytes bypassed the result budget'

    # Exact nested-union alignment must charge recursive equality work as well
    # as the final diff walk. The shape stays within the existing wire/depth caps.
    work_shape=object_shape({'g%d' % group:object_shape({'f%03d' % index:{'kind':'null'} for index in range(200)}) for group in range(12)})
    for _ in range(14):
        work_shape=dict(kind='union',alternatives=[object_shape({'n':work_shape}),string])
    assert len(json.dumps(work_shape,ensure_ascii=False,separators=(',',':')).encode()) <= 65536
    bounded_work=persist('work_limit',work_shape)
    assert compare(bounded_work,bounded_work)==dict(error='WorkLimit'), 'recursive union equality bypassed the work budget'
    print('Actual ingestion/consumer/reader observed comparison preserves typed differences, unknowns, scope/direction, normalized paths and explicit path limits',flush=True)
