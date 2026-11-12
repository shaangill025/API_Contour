#!/usr/bin/env python3
"""Closed disposable schema25/gateway26 SQL fixture; no mTLS or issuer claim."""
import concurrent.futures
import hashlib
import re
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
LEDGER='SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;'
FILES={'seed':'db/tests/causal_runtime_registry_pre.sql',
       'migration':'db/opt-in-migrations/0026_causal_evidence_enrollment.sql',
       'fixture':'db/tests/causal_evidence_enrollment.sql'}


def origin_inventory_sql():
    from deploy.local import origin21_schema
    return origin21_schema.inventory_sql()


def guard_probe(migration):
    """Re-execute the exact migration guard in a fresh psql, assert SQLSTATE 42501."""
    text=migration.decode('utf-8')
    head='DO $$ BEGIN\n'; end='\nEND $$;'
    if text.count(head)!=1 or head not in text or end not in text: raise ValueError('migration guard shape')
    body=text.split(head,1)[1].split(end,1)[0]
    if "ERRCODE='42501'" not in body or 'generate_series(1,25)' not in body: raise ValueError('migration guard identity')
    return ("DO $origin25_retry$ BEGIN BEGIN\n"+body+"\nRAISE EXCEPTION 'guard accepted reapplication' USING ERRCODE='P0001';\n"
            "EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $origin25_retry$;\nSELECT '42501';")


# These constants are synthetic fixture identities. No caller-supplied SQL is accepted.
T1='f0000000-0000-4000-8000-000000000001'
T2='f0000000-0000-4000-8000-000000000002'
LIFECYCLE='f9000000-0000-4000-8000-000000000002'
COLLISION_SQL="""WITH groups AS (
 SELECT hashtext(lpad(to_hex(i),64,'0')) AS h,min(i) AS a,max(i) AS b
 FROM generate_series(1000000,1499999) i GROUP BY 1 HAVING count(*)>1
 ORDER BY min(i) LIMIT 1)
 SELECT lpad(to_hex(a),64,'0')||'|'||lpad(to_hex(b),64,'0')||'|'||h::text FROM groups;"""

def leaf(n):
    if type(n) is not int or not 0<=n<2**256: raise ValueError('invalid fixed leaf')
    return format(n,'064x')

def gateway(gateway_id,nonce,observer,backend):
    if not all(re.fullmatch('[0-9a-f]{64}',x) for x in (nonce,observer,backend)): raise ValueError('invalid fixed gateway leaf')
    if gateway_id not in ('fe000000-0000-4000-8000-000000000011','fe000000-0000-4000-8000-000000000012','fe000000-0000-4000-8000-000000000013'): raise ValueError('invalid fixture gateway')
    fields=[T1,gateway_id]+[f'f{x}000000-0000-4000-8000-000000000001' for x in (6,7,1,2,3,4,5)]
    return ("contour.enroll_causal_gateway(ROW("+','.join("'%s'::uuid"%x for x in fields)+
        ",decode('%s','hex'),decode('%s','hex'),decode('%s','hex'),1::numeric,decode('01','hex'),n-interval '1 minute',n+interval '10 minutes',900000000::bigint)::contour.gateway_enrollment_claim)"%(nonce,observer,backend))

def product(credential,sha):
    if credential not in ('fa000000-0000-4000-8000-000000000011','fa000000-0000-4000-8000-000000000012','fa000000-0000-4000-8000-000000000013') or not re.fullmatch('[0-9a-f]{64}',sha): raise ValueError('invalid fixture credential')
    return "contour.enroll_origin_credential('%s'::uuid,'%s'::uuid,'%s'::uuid,decode('%s','hex'))"%(T2,credential,LIFECYCLE,sha)

def session(tenant,call,tail=''):
    return ("BEGIN; SET LOCAL statement_timeout='15s'; DO $race$ DECLARE n timestamptz:=clock_timestamp(); BEGIN "
        "PERFORM set_config('apicontour.tenant_id','%s',true); PERFORM %s; END $race$; %s COMMIT;"%(tenant,call,tail))

def classify(tenant,call,kind,marker=None):
    if kind not in ('busy','duplicate'): raise ValueError('invalid classification')
    barrier=''
    if marker is not None:
        if marker not in ('gateway_product','product_gateway','collision'): raise ValueError('invalid barrier')
        barrier=("FOR i IN 1..150 LOOP IF EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity "
          "WHERE datname='contour_local' AND usename='postgres' AND wait_event_type='Lock' AND wait_event='advisory' AND query LIKE '%%race_winner_%s%%') THEN observed:=true; EXIT; END IF; PERFORM pg_sleep(0.02); END LOOP; "
          "IF NOT observed THEN result:='BARRIER_UNAVAILABLE'; END IF; " % marker)
    state='40001' if kind=='busy' else '23505'
    expected='credential gate busy' if kind=='busy' else ('gateway enrollment unavailable' if tenant==T1 else 'credential unavailable')
    return ("BEGIN; SET LOCAL statement_timeout='8s'; DO $race$ DECLARE n timestamptz:=clock_timestamp(); m text; code text; observed boolean:=false; accepted boolean:=false; result text:='UNEXPECTED_SUCCESS'; BEGIN "
      "PERFORM set_config('apicontour.tenant_id','%s',true); %s IF result<>'BARRIER_UNAVAILABLE' THEN BEGIN PERFORM %s; accepted:=true; RAISE EXCEPTION 'fixture rollback' USING ERRCODE='P0001'; "
      "EXCEPTION WHEN query_canceled OR OTHERS THEN GET STACKED DIAGNOSTICS m=MESSAGE_TEXT, code=RETURNED_SQLSTATE; "
      "IF accepted THEN result:='UNEXPECTED_SUCCESS'; ELSIF code='%s' THEN IF m IS DISTINCT FROM '%s' THEN result:='WRONG_MESSAGE'; ELSE result:='%s'; END IF; "
      "ELSE result:='SQLSTATE_'||code; END IF; END; END IF; "
      "PERFORM set_config('apicontour.race_result',result,true); END $race$; SELECT current_setting('apicontour.race_result'); COMMIT;"
      %(tenant,barrier,call,state,expected,kind.upper()))

def require_classification(execute,sql,expected,phase):
    if expected not in ('BUSY','DUPLICATE') or phase not in ('gateway_product','product_gateway','collision','product_duplicate','gateway_duplicate'): raise ValueError('invalid classification phase')
    result=execute(sql)
    if result==expected: return
    reason=result if result in ('BARRIER_UNAVAILABLE','WRONG_MESSAGE','UNEXPECTED_SUCCESS') or re.fullmatch(r'SQLSTATE_[0-9A-Z]{5}',result or '') else 'INVALID_RESULT'
    print('race-result phase='+phase+' reason='+reason,file=sys.stderr,flush=True)
    raise RuntimeError('race classification failed')

def held_case(execute,tenant,holder,contender,marker):
    if marker not in ('gateway_product','product_gateway','collision'): raise ValueError('invalid barrier')
    control_marker='race_control_'+marker
    identity_sql=("SELECT pid::text||'|'||(extract(epoch FROM backend_start)*1000000)::numeric(20,0)::text "
      "FROM pg_catalog.pg_stat_activity WHERE datname='contour_local' AND usename='postgres' "
      "AND wait_event='PgSleep' AND query LIKE '%%%s%%';"%control_marker)
    # Namespace 1330792272 belongs exclusively to this disposable test.
    control=("BEGIN; SELECT pg_advisory_xact_lock(1330792272,1); "
      "DO $control$ BEGIN BEGIN PERFORM pg_sleep(15); /* %s */ "
      "EXCEPTION WHEN query_canceled THEN NULL; END; END $control$; COMMIT;"%control_marker)
    winner=session(tenant,holder,"SELECT pg_advisory_xact_lock(1330792272,1) /* race_winner_%s */;"%marker)
    pool=concurrent.futures.ThreadPoolExecutor(max_workers=2)
    futures=[pool.submit(execute,control)]; identity=None; cancelled=False
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
        require_classification(execute,contender,'BUSY',marker)
    finally:
        errors=[]
        try:
            try:
                if identity is not None:
                    pid,started=identity.split('|')
                    cancel=("SELECT CASE WHEN count(*)=1 THEN bool_and(pg_cancel_backend(pid)) ELSE false END::text "
                      "FROM pg_catalog.pg_stat_activity WHERE datname='contour_local' AND usename='postgres' "
                      "AND wait_event='PgSleep' AND query LIKE '%%%s%%' AND pid=%s "
                      "AND (extract(epoch FROM backend_start)*1000000)::numeric(20,0)=%s;"%(control_marker,pid,started))
                    cancelled=execute(cancel)=='true'
            except Exception as error: errors.append(error)
            # Reap both even if cancellation or one callback fails; a missed
            # cancellation falls back to the control's finite sleep.
            for future in futures:
                try: future.result(timeout=150)
                except Exception as error: errors.append(error)
            if errors or (identity is not None and not cancelled): raise RuntimeError('control cleanup unavailable')
        finally: pool.shutdown(wait=all(f.done() for f in futures),cancel_futures=True)


def run_races(execute):
    # Each winner is committed before the loser retries in a new psql session.
    g1='fe000000-0000-4000-8000-000000000011'; g2='fe000000-0000-4000-8000-000000000012'; g3='fe000000-0000-4000-8000-000000000013'
    c1='fa000000-0000-4000-8000-000000000011'; c2='fa000000-0000-4000-8000-000000000012'; c3='fa000000-0000-4000-8000-000000000013'
    first=leaf(10001); second=leaf(10002); other=leaf(10003); nonce=leaf(10004)
    p1=product(c1,first); gw1=gateway(g1,leaf(10005),first,leaf(10006))
    held_case(execute,T1,gw1,classify(T2,p1,'busy','gateway_product'),'gateway_product')
    require_classification(execute,classify(T2,p1,'duplicate'),'DUPLICATE','product_duplicate')
    quota=execute("SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='%s';"%T1)
    if not re.fullmatch('[0-9]{1,12}',quota): raise RuntimeError('quota unavailable')
    p2=product(c2,second);gw2=gateway(g2,nonce,second,other)
    held_case(execute,T2,p2,classify(T1,gw2,'busy','product_gateway'),'product_gateway')
    require_classification(execute,classify(T1,gw2,'duplicate'),'DUPLICATE','gateway_duplicate')
    check=("SELECT ((SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='%s')=%s "
      "AND NOT EXISTS(SELECT 1 FROM contour.origin_credentials WHERE credential_id='%s') "
      "AND NOT EXISTS(SELECT 1 FROM contour.causal_gateway_enrollments WHERE gateway_id='%s' OR (claim).provision_nonce=decode('%s','hex')) "
      "AND NOT EXISTS(SELECT 1 FROM contour.causal_leaf_reservations WHERE leaf_sha256=decode('%s','hex')))::text;"%(T1,quota,c1,g2,nonce,other))
    if execute(check)!='true': raise RuntimeError('losing mutation remained')
    pair=execute(COLLISION_SQL)
    match=re.fullmatch(r'([0-9a-f]{64})\|([0-9a-f]{64})\|(-?[0-9]{1,10})',pair)
    if not match or match[1]==match[2]: raise RuntimeError('collision unavailable')
    a,b=match[1],match[2]
    if execute("SELECT (hashtext('%s')=hashtext('%s'))::text;"%(a,b))!='true': raise RuntimeError('collision invalid')
    gw3=gateway(g3,leaf(10007),a,leaf(10008));p3=product(c3,b)
    held_case(execute,T1,gw3,classify(T2,p3,'busy','collision'),'collision')
    execute(session(T2,p3))
    if execute("SELECT (EXISTS(SELECT 1 FROM contour.causal_leaf_reservations WHERE leaf_sha256=decode('%s','hex') AND leaf_class='gateway_observer') AND EXISTS(SELECT 1 FROM contour.origin_credentials WHERE credential_id='%s' AND leaf_sha256=decode('%s','hex')))::text;"%(a,c3,b))!='true': raise RuntimeError('collision retry failed')


class QualificationHooks:
    def __init__(self,mode,schema,files=None):
        if mode not in ('schema25','gateway26','gateway26-races'): raise ValueError('unsupported qualification mode')
        self.mode,self.schema,self.files=mode,schema,files
        self.seeded=False;self.next_stage=22;self.complete=False
    def preflight(self,sources):
        required=['scripts/test-causal-evidence-enrollment.py','deploy/local/origin25_schema.py',
                  *['deploy/local/origin25_reference_%d_enrolled.json'%n for n in (22,23,24,25)]]
        if self.mode in ('gateway26','gateway26-races'): required+=list(FILES.values())
        if any(name not in sources for name in required): raise ValueError('qualification source missing')
        if self.mode in ('gateway26','gateway26-races'):
            self.files={}
            for key,name in FILES.items():
                path=ROOT/name
                if not path.is_file() or any(part.is_symlink() for part in (path,*path.parents)): raise ValueError('qualification source unavailable')
                raw=path.read_bytes()
                if hashlib.sha256(raw).hexdigest()!=sources[name]: raise ValueError('qualification source changed')
                self.files[key]=raw
    def after_stage17(self,execute):
        if self.seeded: raise ValueError('duplicate qualification seed')
        self.seeded=True
        if self.mode in ('gateway26','gateway26-races'): execute(self.files['seed'].decode('utf-8'))
    def after_forward(self,stage,execute):
        if not self.seeded or stage!=self.next_stage: raise ValueError('qualification stage order')
        if stage in (22,23,24): self.schema._require_migration_stage(execute,stage)
        elif stage==25:
            self.schema.require_ready(execute)
            from deploy.local import origin21_schema
            try: origin21_schema.require_ledger(list(range(1,26)))
            except ValueError: pass
            else: raise RuntimeError('legacy 21 accepted stage 25')
            if self.mode in ('gateway26','gateway26-races'): self._gateway(execute)
            if self.mode=='gateway26-races': run_races(execute)
            self.complete=True
        else: raise ValueError('invalid qualification stage')
        self.next_stage+=1
    def receipt(self):
        if not self.complete: raise RuntimeError('qualification incomplete')
        return {'mode':self.mode,'schema_stage':25 if self.mode=='schema25' else 26,
                'scope':'synthetic-sql-races-only' if self.mode=='gateway26-races' else 'synthetic-sql-only','authenticated_transport':False}
    def _gateway(self,execute):
        migration=self.files['migration'];fixture=self.files['fixture']
        # One execute is one fresh psql session: temp fixture state cannot leak
        # into a separate backend and ON_ERROR_STOP remains enabled.
        execute(migration.decode('utf-8')+'\n'+fixture.decode('utf-8'))
        if execute(LEDGER)!='{'+','.join(map(str,range(1,27)))+'}': raise RuntimeError('stage 26 ledger mismatch')
        before=execute(origin_inventory_sql())
        if type(before) is not str or len(before.encode('utf-8'))>8*1024*1024: raise RuntimeError('stage 26 metadata invalid')
        inventory=json.loads(before)
        if (type(inventory) is not dict or set(inventory)!={'version','server_major','items'} or
            type(inventory['version']) is not int or inventory['version']!=1 or
            type(inventory['server_major']) is not int or inventory['server_major']!=16 or
            type(inventory['items']) is not list or not inventory['items']): raise RuntimeError('stage 26 metadata invalid')
        if execute(guard_probe(migration))!='42501': raise RuntimeError('stage 26 reapply guard accepted')
        if execute(LEDGER)!='{'+','.join(map(str,range(1,27)))+'}' or execute(origin_inventory_sql())!=before:
            raise RuntimeError('stage 26 metadata changed after guard')


def load_capture():
    path=ROOT/'scripts/capture-origin25-reference.py'
    if not path.is_file() or any(part.is_symlink() for part in (path,*path.parents)): raise ValueError('capture source unavailable')
    status=subprocess.run(['git','status','--porcelain','--untracked-files=all'],cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=True)
    if status.stdout or status.stderr: raise ValueError('clean reviewed source required')
    result=subprocess.run(['git','show','HEAD:scripts/capture-origin25-reference.py'],cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=True)
    raw=path.read_bytes()
    if result.stderr or len(raw)>2_000_000 or raw!=result.stdout: raise ValueError('capture source changed')
    namespace={'__file__':str(path),'__name__':'causal_evidence_capture'}
    exec(compile(raw,str(path),'exec'),namespace)
    if path.read_bytes()!=raw: raise ValueError('capture source changed')
    return namespace


def main(argv):
    if len(argv)!=2 or argv[0] not in ('schema25','gateway26','gateway26-races'): raise ValueError('expected closed mode and private output')
    path=Path(argv[1])
    if not path.is_absolute() or '..' in path.parts or any(part.is_symlink() for part in (path,*path.parents)): raise ValueError('invalid output')
    if path.exists(): raise ValueError('output already exists')
    sys.dont_write_bytecode=True
    if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
    capture=load_capture()
    from deploy.local import origin25_schema
    hooks=QualificationHooks(argv[0],origin25_schema)
    capture['main']([str(path)],_hooks=hooks)
    if not hooks.complete: raise RuntimeError('qualification incomplete')
    print('PASS: '+argv[0]+' synthetic SQL qualification; no mTLS claim',flush=True)


def failure_location(error):
    allowed={'test-causal-evidence-enrollment.py','capture-origin25-reference.py',
             'origin25_schema.py','fixture_psql_transport.py'}
    frames=[]; trace=error.__traceback__
    while trace is not None:
        name=Path(trace.tb_frame.f_code.co_filename).name
        if name in allowed: frames.append(name+':'+str(trace.tb_lineno))
        trace=trace.tb_next
    return ','.join(frames[-6:]) or 'unavailable'


if __name__=='__main__':
    try: main(sys.argv[1:])
    except Exception as error:
        print('qualification-location='+failure_location(error),file=sys.stderr,flush=True)
        print('Causal evidence qualification failed; private state retained.',file=sys.stderr,flush=True)
        raise SystemExit(1) from None
