"""Explicit bounded product-to-catalog verification, not a UI readiness claim."""
import json
import time
from deploy.local import origin21_evidence, origin21_products, origin21_profile, origin21_setup, origin21_transport, provision


def snapshot(psql):
    t=provision.sql_quote(provision.IDS[0]); c=provision.sql_quote(origin21_profile.PROFILE.collector)
    sql=f"""SELECT coalesce(json_agg(json_build_array(m.record_id::text,m.source_id::text,m.project_id::text,m.service_id::text,m.environment_id::text,m.deployment_id::text,
 r.value->'record'->>'direction',r.value->'record'->>'status_code',r.value->'record'->'structure',
 encode(p.leaf_sha256,'hex'),p.instance_id::text,p.lifecycle_id::text,p.credential_id::text,p.grant_id::text,encode(p.platform_evidence_sha256,'hex'),
 w.record_id::text,w.completeness,w.visibility,w.status_code,convert_from(v.structure_wire,'UTF8')::jsonb,convert_from(o.canonical_key,'UTF8')::jsonb,cp.proof_id::text,p.proof_id::text,
 p.origin_project_id::text,p.origin_service_id::text,p.origin_environment_id::text,p.origin_deployment_id::text,
 cp.instance_id::text,cp.origin_project_id::text,cp.origin_service_id::text,cp.origin_environment_id::text,cp.origin_deployment_id::text,
 m.parser_profile,m.policy_revision,w.source_id::text,w.project_id::text,w.service_id::text,w.environment_id::text,w.deployment_id::text,
 w.observation_count,w.sample_numerator,w.sample_denominator,w.route_uncertain,v.parser_profile,v.policy_revision,to_jsonb(w.reasons))), '[]'::json)::text
FROM contour.ingestion_v2_metadata m JOIN contour.ingestion_payloads b USING(tenant_id,collector_id,batch_id)
CROSS JOIN LATERAL jsonb_array_elements(convert_from(b.checked_batch,'UTF8')::jsonb->'records') r(value)
LEFT JOIN contour.origin_proofs p USING(tenant_id,collector_id,batch_id,record_id)
LEFT JOIN contour.observation_windows w USING(tenant_id,collector_id,batch_id,record_id)
LEFT JOIN contour.variants v ON (v.tenant_id,v.variant_id,v.operation_id,v.collector_id)=(w.tenant_id,w.variant_id,w.operation_id,w.collector_id)
LEFT JOIN contour.operations o ON (o.tenant_id,o.operation_id)=(w.tenant_id,w.operation_id)
LEFT JOIN contour.catalog_origin_projection cp ON (cp.tenant_id,cp.collector_id,cp.batch_id,cp.record_id)=(m.tenant_id,m.collector_id,m.batch_id,m.record_id)
WHERE m.tenant_id={t} AND m.collector_id={c} AND r.value->'record'->>'record_id'=m.record_id::text;"""
    raw=psql(sql)
    if not isinstance(raw,str) or len(raw.encode('utf-8'))>8*1024*1024: raise RuntimeError('catalog verification output bound')
    value=json.loads(raw)
    if not isinstance(value,list) or len(value)>10000 or any(not isinstance(row,list) or len(row)!=46 for row in value): raise RuntimeError('invalid catalog verification result')
    ids=[row[0] for row in value]
    if len(set(ids))!=len(ids): raise RuntimeError('duplicate catalog records')
    return value


def validate_fresh(rows,before,index,leaf,evidence,revision):
    fresh=[row for row in rows if row[0] not in before]
    if len(fresh)>2: raise RuntimeError('unexpected concurrent observations')
    if len(fresh)<2 or any(row[15] is None for row in fresh): return False
    profile=origin21_profile.PROFILE; slot=profile.origins[index-1]
    shapes={'request':{'kind':'object','fields':{'probe':{'kind':'boolean'}},'additional':None},
            'response':{'kind':'object','fields':{'result':{'kind':'string'}},'additional':None}}
    if {row[6] for row in fresh}!={'request','response'}: raise RuntimeError('catalog direction mismatch')
    for row in fresh:
        direction=row[6]; status=None if direction=='request' else '200'
        key=[*provision.IDS,'http',direction,'POST','/pilot']
        if (row[1:6]!=[profile.source,*provision.IDS[1:],profile.deployment] or row[7]!=status or row[8]!=shapes[direction] or
            row[9:15]!=[leaf,slot.instance,slot.lifecycle,slot.credential,slot.grant,evidence.hex()] or
            row[15]!=row[0] or row[16:18]!=['complete','structure'] or row[18]!=(None if direction=='request' else 200) or
            row[19]!=shapes[direction] or row[20]!=key or not row[21] or row[21]!=row[22] or
            row[23:27]!=[*provision.IDS[1:],slot.deployment] or row[27:32]!=[slot.instance,*provision.IDS[1:],slot.deployment] or
            row[32:34]!=['http_json_v1',revision] or row[34:39]!=[profile.source,*provision.IDS[1:],profile.deployment] or
            row[39:46]!=[1,1,1,False,'http_json_v1',revision,[]]):
            raise RuntimeError('catalog verification mismatch')
    return True


def check(expected, *, psql, sensitive_execute, authenticate):
    if type(expected) is not tuple or len(expected)!=2 or any(type(x) is not bytes or len(x)!=32 for x in expected): raise ValueError('fixed operator evidence required')
    if not all(callable(x) for x in (psql,sensitive_execute,authenticate)) or psql is sensitive_execute: raise ValueError('trusted callbacks required')
    origin21_setup.prepare(psql=psql,sensitive_execute=sensitive_execute,
        authenticate=authenticate,inspect_slot=origin21_products.inspect_slot,
        expected_evidence=expected,check_only=True)
    revision=origin21_products.require_current_policy(psql,sensitive_execute)
    # The inspector rechecks all fixed companion/product ownership and generation.
    descriptors=[origin21_products.inspect_slot(i) for i in (1,2)]
    if any(origin21_evidence.digest(v)!=expected[i] for i,v in enumerate(descriptors)): raise ValueError('operator evidence drift')
    record=origin21_products._read_record('companions.json')
    worker=record['services']['origin21-capture-worker']['id']
    origin21_products._command(['docker','exec',worker,'/usr/local/bin/local_capture','check','/run/capture/worker.json'],20)
    for index,desc in enumerate(descriptors,1):
        # Quiesce existing asynchronous projections before selecting fresh IDs.
        previous={row[0] for row in snapshot(psql)}; stable=time.monotonic(); deadline=stable+15
        while time.monotonic()<deadline:
            time.sleep(.25); now={row[0] for row in snapshot(psql)}
            if now!=previous: previous,stable=now,time.monotonic()
            if time.monotonic()-stable>=2: break
        else: raise RuntimeError('catalog did not quiesce')
        raw=origin21_products._command(['docker','exec',desc['container_id'],'node','/pilot/probe.js','normal'],10)
        if len(raw)>1024: raise RuntimeError('product probe output bound')
        result=json.loads(raw)
        if not isinstance(result,dict) or set(result)!={'status','expected_body','exception','admin_status','admin_exception'} or result['status']!=200 or result['expected_body'] is not True or result['exception']!='none' or result['admin_status'] not in (400,404) or result['admin_exception']!='none': raise RuntimeError('product probe failed')
        until=time.monotonic()+30
        while time.monotonic()<until:
            if validate_fresh(snapshot(psql),previous,index,desc['leaf_sha256'],expected[index-1],revision): break
            time.sleep(.25)
        else: raise RuntimeError('catalog projection deadline')
        origin21_products.inspect_slot(index)
    if origin21_products.require_current_policy(psql,sensitive_execute)!=revision: raise RuntimeError('policy changed during verification')
    return {'product_tls_and_catalog_verified':True,'ui_verified':False}
