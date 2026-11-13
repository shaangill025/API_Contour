"""Fixed disposable SQL28 public-operation races. No peer or deployment proof."""
import re
import concurrent.futures
import time

T1='f0000000-0000-4000-8000-000000000001'
T2='f0000000-0000-4000-8000-000000000002'
RUNTIME='fc000000-0000-4000-8000-000000000008'
LIFECYCLE='f9000000-0000-4000-8000-000000000003'
PRODUCT='fa000000-0000-4000-8000-000000000003'
MANIFEST='af3171bdf0ca4bfc70c63aaf998fdfd4cf988b4409e7f7f47e015325608b302d'
RESULTS=('exact_retry','backend_receiver_first','backend_product_first','evidence_receiver_first','evidence_product_first','hash_collision')


def _hex(n):
    if type(n) is not int or not 0<=n<2**256: raise ValueError('invalid race identity')
    return format(n,'064x')


def _timestamp(value):
    if type(value) is not str or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z',value): raise ValueError('invalid fixture time')
    return "'"+value+"'::timestamptz"


def _session_claim(epoch, when):
    if type(epoch) is not int or not 2<=epoch<=7: raise ValueError('invalid race epoch')
    now=_timestamp(when)
    ids=[T1,RUNTIME,'f6000000-0000-4000-8000-000000000003','f7000000-0000-4000-8000-000000000003',
         'f1000000-0000-4000-8000-000000000001','f2000000-0000-4000-8000-000000000001',
         'f3000000-0000-4000-8000-000000000001','f4000000-0000-4000-8000-000000000001',
         'f5000000-0000-4000-8000-000000000003',LIFECYCLE]
    return ('ROW('+','.join("'%s'::uuid"%v for v in ids)+",decode(repeat('b8',32),'hex'),"
            "'nodered_5_0_9_receiver_v1',decode('%s','hex'),'%s'::uuid,1,decode(repeat('ab',32),'hex'),"
            "%s-interval '1 minute',%s+interval '10 minutes',1,decode('01','hex'),%s-interval '1 minute',%s+interval '10 minutes',"
            "900000000,10,1024,1024,60)::contour.causal_session_claim"%(MANIFEST,'fe000000-0000-4000-8000-'+format(epoch+100,'012d'),now,now,now,now))


def _receiver(epoch,when,backend,evidence):
    now=_timestamp(when)
    if type(epoch) is not int or not 2<=epoch<=7 or any(not re.fullmatch('[0-9a-f]{64}',x) for x in (backend,evidence)): raise ValueError('invalid receiver identity')
    return ("contour.enroll_causal_receiver(ROW('%s'::uuid,'%s'::uuid,%d::numeric,"
            "'f5000000-0000-4000-8000-000000000003'::uuid,'%s'::uuid,'%s'::uuid,"
            "decode(repeat('03',32),'hex'),decode(repeat('b8',32),'hex'),decode('%s','hex'),decode('%s','hex'),decode('%s','hex'),"
            "%s-interval '1 minute',%s+interval '10 minutes',%s-interval '1 minute',%s+interval '10 minutes',300000000::bigint)::contour.receiver_enrollment_claim)"
            %(T1,RUNTIME,epoch,LIFECYCLE,PRODUCT,backend,evidence,_hex(91000+epoch),now,now,now,now))


def _product(ident,leaf):
    if type(ident) is not int or not 1<=ident<=5 or not re.fullmatch('[0-9a-f]{64}',leaf): raise ValueError('invalid product identity')
    cid='fa000000-0000-4000-8000-'+format(200+ident,'012d')
    return "contour.enroll_origin_credential('%s'::uuid,'%s'::uuid,'f9000000-0000-4000-8000-000000000002'::uuid,decode('%s','hex'))"%(T2,cid,leaf)


def _role(tenant,call):
    if tenant==T1 and call.startswith('contour.enroll_causal_receiver('): return 'contour_causal_evidence_provisioner'
    if tenant==T2 and call.startswith('contour.enroll_origin_credential('): return 'contour_admin'
    raise ValueError('invalid race actor')


def _actor(tenant,call,tail=''):
    role=_role(tenant,call)
    return ("BEGIN; SET LOCAL statement_timeout='15s'; DO $context$ BEGIN PERFORM set_config('apicontour.tenant_id','%s',true); END $context$; SET LOCAL ROLE %s; SELECT %s; RESET ROLE; %s COMMIT;"%(tenant,role,call,tail))


def _classify(tenant,call,state,message,marker=None):
    role=_role(tenant,call)
    if state not in ('40001','23505') or message not in ('origin gate busy','credential gate busy','credential unavailable','receiver enrollment unavailable'): raise ValueError('invalid race classification')
    barrier=''
    if marker is not None:
        if marker not in ('gateway_product','product_gateway','collision'): raise ValueError('invalid race marker')
        barrier=("FOR i IN 1..150 LOOP PERFORM pg_catalog.pg_stat_clear_snapshot(); IF EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity WHERE datname='contour_local' AND usename='postgres' AND wait_event_type='Lock' AND wait_event='advisory' AND query LIKE '%%race_winner_%s%%') THEN observed:=true; EXIT; END IF; PERFORM pg_sleep(0.02); END LOOP; IF NOT observed THEN result:='BARRIER_UNAVAILABLE'; END IF;"%marker)
    return ("BEGIN; SET LOCAL statement_timeout='8s'; DO $barrier$ DECLARE observed boolean:=false; result text:='READY'; BEGIN PERFORM set_config('apicontour.tenant_id','%s',true); %s PERFORM set_config('apicontour.race_result',result,true); END $barrier$; "
            "SET LOCAL ROLE %s; DO $actor$ DECLARE accepted boolean:=false; result text:=current_setting('apicontour.race_result'); code text; msg text; BEGIN IF result='READY' THEN result:='UNEXPECTED_SUCCESS'; BEGIN PERFORM %s; accepted:=true; RAISE EXCEPTION 'fixture rollback' USING ERRCODE='P0001'; EXCEPTION WHEN query_canceled OR OTHERS THEN GET STACKED DIAGNOSTICS code=RETURNED_SQLSTATE,msg=MESSAGE_TEXT; IF NOT accepted AND code='%s' AND msg='%s' THEN result:='%s'; ELSE result:='WRONG_OUTCOME'; END IF; END; END IF; PERFORM set_config('apicontour.race_result',result,true); END $actor$; RESET ROLE; SELECT current_setting('apicontour.race_result'); COMMIT;"
            %(tenant,barrier,role,call,state,message,'BUSY' if state=='40001' else 'DUPLICATE'))


def _held(execute,existing,tenant,holder,contender,marker):
    if marker not in ('gateway_product','product_gateway','collision'): raise ValueError('invalid barrier')
    control_marker='race_control_'+marker
    identity_sql=("SELECT pid::text||'|'||(extract(epoch FROM backend_start)*1000000)::numeric(20,0)::text FROM pg_catalog.pg_stat_activity WHERE datname='contour_local' AND usename='postgres' AND wait_event='PgSleep' AND query LIKE '%%%s%%';"%control_marker)
    control=("BEGIN; SELECT pg_advisory_xact_lock(1330792272,1); DO $control$ BEGIN BEGIN PERFORM pg_sleep(15); /* %s */ EXCEPTION WHEN query_canceled THEN NULL; END; END $control$; COMMIT;"%control_marker)
    winner=_actor(tenant,holder,"SELECT pg_advisory_xact_lock(1330792272,1) /* race_winner_%s */;"%marker)
    pool=concurrent.futures.ThreadPoolExecutor(max_workers=2); futures=[pool.submit(execute,control)]; identity=None; cancelled=False
    try:
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            found=execute(identity_sql)
            if found:
                if not re.fullmatch(r'[1-9][0-9]{0,9}\|[0-9]{1,20}',found): raise RuntimeError('control identity invalid')
                identity=found; break
            if futures[0].done(): raise RuntimeError('control ended before barrier')
        if identity is None: raise RuntimeError('control barrier unavailable')
        futures.append(pool.submit(execute,winner))
        existing.require_classification(execute,contender,'BUSY',marker)
    finally:
        errors=[]
        try:
            try:
                if identity is not None:
                    pid,started=identity.split('|')
                    cancel=("SELECT CASE WHEN count(*)=1 THEN bool_and(pg_cancel_backend(pid)) ELSE false END::text FROM pg_catalog.pg_stat_activity WHERE datname='contour_local' AND usename='postgres' AND wait_event='PgSleep' AND query LIKE '%%%s%%' AND pid=%s AND (extract(epoch FROM backend_start)*1000000)::numeric(20,0)=%s;"%(control_marker,pid,started))
                    cancelled=execute(cancel)=='true'
            except Exception as error: errors.append(error)
            for future in futures:
                try: future.result(timeout=150)
                except Exception as error: errors.append(error)
            if errors or (identity is not None and not cancelled): raise RuntimeError('control cleanup unavailable')
        finally: pool.shutdown(wait=all(f.done() for f in futures),cancel_futures=True)


def _issue(execute,epoch,when):
    sql="BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SET LOCAL ROLE contour_causal_issuer; SELECT epoch FROM contour.issue_causal_session(%s); RESET ROLE; COMMIT;"%(T1,_session_claim(epoch,when))
    result=execute(sql).splitlines()
    if not result or result[-1]!=str(epoch): raise RuntimeError('receiver race session unavailable')


def run_races(execute,existing):
    """Returns fixed labels only after each live public race and its postchecks."""
    when=execute("SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"');")
    _timestamp(when); complete=[]
    def held(tenant,holder,contender,marker): _held(execute,existing,tenant,holder,contender,marker)
    def classified(sql,want,phase): existing.require_classification(execute,sql,want,phase)
    _issue(execute,2,when)
    call=_receiver(2,when,_hex(92001),_hex(92002))
    held(T1,call,_classify(T1,call,'40001','origin gate busy','gateway_product'),'gateway_product')
    quota=execute("SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='%s';"%T1)
    if not re.fullmatch('[0-9]{1,12}',quota): raise RuntimeError('receiver quota unavailable')
    stored=execute("SELECT json_build_array(enrollment_generation,evidence_credential_id::text,to_char(issued_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),encode(commitment,'hex'))::text FROM contour.causal_receiver_enrollments WHERE (tenant_id,runtime_id,session_epoch)=('%s'::uuid,'%s'::uuid,2);"%(T1,RUNTIME))
    retry=("BEGIN; DO $context$ BEGIN PERFORM set_config('apicontour.tenant_id','%s',true); END $context$; SET LOCAL ROLE contour_causal_evidence_provisioner; SELECT json_build_array(generation,credential_id::text,to_char(issued_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),encode(commitment,'hex'))::text FROM %s; RESET ROLE; COMMIT;"%(T1,call))
    returned=execute(retry)
    if not stored or returned!=stored or execute("SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='%s';"%T1)!=quota: raise RuntimeError('receiver exact retry changed')
    complete.append('exact_retry')
    for epoch,kind,first in ((3,'backend','receiver'),(4,'backend','product'),(5,'evidence','receiver'),(6,'evidence','product')):
        _issue(execute,epoch,when); shared=_hex(93000+epoch); other=_hex(94000+epoch)
        recv=_receiver(epoch,when,shared if kind=='backend' else other,shared if kind=='evidence' else other); prod=_product(epoch-2,shared)
        if first=='receiver':
            marker='gateway_product'; held(T1,recv,_classify(T2,prod,'40001','credential gate busy',marker),marker)
            saved=execute("SELECT coalesce((SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='%s'),0)::text;"%T2)
            classified(_classify(T2,prod,'23505','credential unavailable'),'DUPLICATE','product_duplicate')
            if execute("SELECT coalesce((SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='%s'),0)::text;"%T2)!=saved: raise RuntimeError('loser quota changed')
        else:
            marker='product_gateway'; held(T2,prod,_classify(T1,recv,'40001','credential gate busy',marker),marker)
            saved=execute("SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='%s';"%T1)
            classified(_classify(T1,recv,'23505','receiver enrollment unavailable'),'DUPLICATE','gateway_duplicate')
            if execute("SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='%s';"%T1)!=saved: raise RuntimeError('loser quota changed')
        # Receiver or product loser must not leave its other leaf, enrollment, or charge.
        verify=("SELECT (NOT EXISTS(SELECT 1 FROM contour.causal_leaf_reservations WHERE leaf_sha256=decode('%s','hex')) AND NOT EXISTS(SELECT 1 FROM contour.causal_receiver_enrollments WHERE tenant_id='%s' AND runtime_id='%s' AND session_epoch=%d))::text;"%(other,T1,RUNTIME,epoch)) if first=='product' else ("SELECT (NOT EXISTS(SELECT 1 FROM contour.origin_credentials WHERE leaf_sha256=decode('%s','hex')))::text;"%shared)
        if execute(verify)!='true': raise RuntimeError('receiver race partial mutation')
        complete.append(kind+'_'+first+'_first')
    _issue(execute,7,when)
    pair=execute(existing.COLLISION_SQL); m=re.fullmatch(r'([0-9a-f]{64})\|([0-9a-f]{64})\|(-?[0-9]{1,10})',pair)
    if not m or m[1]==m[2] or execute("SELECT (hashtext('%s')=hashtext('%s'))::text;"%(m[1],m[2]))!='true': raise RuntimeError('credential hash collision unavailable')
    recv=_receiver(7,when,m[1],_hex(95007)); prod=_product(5,m[2]); marker='collision'
    held(T1,recv,_classify(T2,prod,'40001','credential gate busy',marker),marker)
    execute(_actor(T2,prod))
    if execute("SELECT (EXISTS(SELECT 1 FROM contour.causal_leaf_reservations WHERE leaf_sha256=decode('%s','hex') AND leaf_class='receiver_backend') AND EXISTS(SELECT 1 FROM contour.origin_credentials WHERE tenant_id='%s' AND leaf_sha256=decode('%s','hex')))::text;"%(m[1],T2,m[2]))!='true': raise RuntimeError('collision retry unavailable')
    complete.append('hash_collision')
    if tuple(complete)!=RESULTS: raise RuntimeError('receiver race sequence incomplete')
    return tuple(complete)
