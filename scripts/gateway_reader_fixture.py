"""Fixed synthetic SQL30 TLS observation scenario; not peer or deployment proof."""
import datetime
import json
import re

T='f0000000-0000-4000-8000-000000000001'
C='f6000000-0000-4000-8000-000000000020'
S='f7000000-0000-4000-8000-000000000020'
P='f1000000-0000-4000-8000-000000000001'
V='f2000000-0000-4000-8000-000000000001'
E='f3000000-0000-4000-8000-000000000001'
D='f4000000-0000-4000-8000-000000000001'
I='f5000000-0000-4000-8000-000000000020'
G='fe000000-0000-4000-8000-000000000020'
L='f9000000-0000-4000-8000-000000000020'
CHECKS=('gateway-current','gateway-selectors','gateway-role-denial','gateway-closed','gateway-latest','gateway-revoked','gateway-table-denied')


def run(*,execute,probe_call,ca_pem,port,passwords):
    if set(passwords)!={'reader','wrong','mixed','transitive'} or any(type(v) is not str or not re.fullmatch('[0-9a-f]{64}',v) for v in passwords.values()): raise ValueError('gateway credentials')
    if not isinstance(ca_pem,bytes) or not re.fullmatch('[0-9]{1,5}',str(port)): raise ValueError('gateway TLS')
    roles=[]
    for name,group in (('reader','contour_causal_gateway_reader'),('wrong','contour_causal_provisioner'),('mixed','contour_causal_gateway_reader,contour_causal_provisioner'),('transitive','gateway_bridge_role')):
        roles.append("CREATE ROLE gateway_%s_login LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD '%s'; GRANT %s TO gateway_%s_login; GRANT CONNECT ON DATABASE contour_local TO gateway_%s_login;"%(name,passwords[name],group,name,name))
    execute('CREATE ROLE gateway_bridge_role NOLOGIN INHERIT; GRANT contour_causal_gateway_reader TO gateway_bridge_role; '+''.join(roles))
    execute("INSERT INTO contour.workload_instances VALUES ('%s','%s','%s','%s','%s','%s');"%(T,P,V,E,D,I))
    execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SET LOCAL ROLE contour_admin; SELECT contour.lock_collector('%s','%s'); INSERT INTO contour.collectors VALUES ('%s','%s'); INSERT INTO contour.workload_assignments VALUES ('%s','%s','%s','%s','%s','%s'); SELECT contour.register_instance_source('%s','%s','%s','%s','%s','%s','%s','f8000000-0000-4000-8000-000000000020','%s'); INSERT INTO contour.source_authorization VALUES ('%s','%s','%s','gateway',ARRAY['http_json_v1']); INSERT INTO contour.policy_revisions VALUES ('%s','%s',1,decode('01','hex')); UPDATE contour.collector_authorization SET active_revision=1,enabled=true WHERE tenant_id='%s' AND collector_id='%s'; COMMIT;"%(T,T,C,T,C,T,C,P,V,E,D,T,S,C,P,V,E,D,I,T,S,C,T,C,T,C))
    execute("SELECT set_config('apicontour.tenant_id','%s',false); SET ROLE contour_admin; SELECT contour.enroll_origin('%s','%s','%s','%s','%s','%s','%s','trusted_platform_v1',decode(repeat('c7',32),'hex')); RESET ROLE;"%(T,T,L,P,V,E,D,I))
    now=datetime.datetime.now(datetime.timezone.utc);stamp=lambda t:t.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    start=stamp(now-datetime.timedelta(minutes=1));end=stamp(now+datetime.timedelta(minutes=8))
    def enroll(nonce,observer,backend):
        sql="SELECT set_config('apicontour.tenant_id','%s',false); SET ROLE contour_causal_evidence_provisioner; SELECT * FROM contour.enroll_causal_gateway(ROW('%s'::uuid,'%s'::uuid,'%s'::uuid,'%s'::uuid,'%s'::uuid,'%s'::uuid,'%s'::uuid,'%s'::uuid,'%s'::uuid,decode(repeat('%s',32),'hex'),decode(repeat('%s',32),'hex'),decode(repeat('%s',32),'hex'),1,decode('01','hex'),'%s'::timestamptz,'%s'::timestamptz,300000000)::contour.gateway_enrollment_claim); RESET ROLE;"%(T,T,G,C,S,P,V,E,D,I,nonce,observer,backend,start,end)
        execute(sql)
        result=execute("SELECT json_build_object('generation',generation,'metadata_sha256',encode(sha256(metadata),'hex'),'expires_at',to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'))::text FROM contour.causal_gateway_enrollments WHERE tenant_id='%s' AND gateway_id='%s' AND (claim).provision_nonce=decode(repeat('%s',32),'hex');"%(T,G,nonce))
        selected=json.loads(result.splitlines()[-1]);
        if type(selected) is not dict or set(selected)!={'generation','metadata_sha256','expires_at'} or not re.fullmatch('[0-9a-f]{32}',selected['generation']) or not re.fullmatch('[0-9a-f]{64}',selected['metadata_sha256']): raise ValueError('gateway selection')
        return dict(selected,ca_pem=ca_pem.decode('ascii'),leaf=backend*32,tenant=T,gateway=G,port=str(port))
    def call(base,mode,role):
        data=dict(base,mode=mode,user='gateway_'+role+'_login',password=passwords[role]);probe_call(json.dumps(data,sort_keys=True,separators=(',',':')).encode())
    first=enroll('c1','c2','c3')
    call(first,'positive','reader')
    for role in ('wrong','mixed','transitive'): call(first,'denied',role)
    execute("SET ROLE gateway_reader_login; DO $$ BEGIN BEGIN PERFORM count(*) FROM contour.causal_gateway_enrollments; RAISE EXCEPTION 'raw read accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$; RESET ROLE;")
    execute("SELECT set_config('apicontour.tenant_id','%s',false); SET ROLE contour_causal_evidence_provisioner; SELECT contour.close_causal_gateway('%s','%s','%s','operator_revoked'); RESET ROLE;"%(T,T,G,first['generation']))
    call(first,'unavailable','reader')
    second=enroll('c4','c5','c6')
    if second['generation']==first['generation']: raise RuntimeError('gateway generation')
    call(second,'positive','reader');call(first,'unavailable','reader')
    execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SET LOCAL ROLE contour_admin; SELECT contour.lock_collector('%s','%s'); UPDATE contour.source_authorization SET technique='runtime' WHERE tenant_id='%s' AND source_id='%s' AND collector_id='%s'; COMMIT;"%(T,T,C,T,S,C))
    call(second,'unavailable','reader')
    return CHECKS
