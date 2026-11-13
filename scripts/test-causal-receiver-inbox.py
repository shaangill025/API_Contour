#!/usr/bin/env python3
"""Opt-in SQL29 synthetic observer/receiver fixture; no mTLS or edge proof."""
import hashlib
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
FILES=('db/opt-in-migrations/0028_causal_receiver_enrollment.sql',
       'db/opt-in-migrations/0029_causal_receiver_inbox.sql',
       'db/tests/causal_observer_inbox.sql',
       'tests/fixtures/causal-receiver-inbox/seed.sql',
       'db/tests/causal_receiver_inbox.sql',
       'tests/fixtures/causal-receiver-inbox/post-race.sql')


def source(name):
    if name not in FILES: raise ValueError('unsupported fixture source')
    path=ROOT/name
    if any(x.is_symlink() for x in (path,*path.parents)): raise ValueError('fixture source')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=2000000: raise ValueError('fixture source')
        with os.fdopen(fd,'rb',closefd=False) as f: raw=f.read(2000001)
        tracked=subprocess.run(['git','show','HEAD:'+name],cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=True)
        after=os.fstat(fd)
        if tracked.stderr or tracked.stdout!=raw or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) or hashlib.sha256(path.read_bytes()).digest()!=hashlib.sha256(raw).digest(): raise ValueError('fixture source changed')
        return raw.decode('utf-8','strict')
    finally: os.close(fd)


def require_applicable(raw):
    if type(raw) is not str or 'receiver inbox candidate incomplete; do not apply' in raw or not raw.rstrip().endswith('COMMIT;'):
        raise ValueError('receiver inbox deliberately inactive')


def scenario_sql(original_observer_fixture):
    values=[source(name) for name in FILES]
    require_applicable(values[1])
    if original_observer_fixture!=values[2]: raise ValueError('observer fixture changed')
    old='ARRAY(SELECT generate_series(1,27))'
    new='ARRAY(SELECT generate_series(1,29))'
    if original_observer_fixture.count(old)!=1 or new in original_observer_fixture: raise ValueError('observer ledger boundary')
    adapted=original_observer_fixture.replace(old,new,1)
    if adapted.replace(new,old,1)!=original_observer_fixture: raise ValueError('observer fixture changed')
    prefix='\\echo receiver29-step=migration28\n'+values[0]+'\n\\echo receiver29-step=migration29\n'+values[1]+'\n\\echo receiver29-step=observer-regression\n'
    suffix='\\echo receiver29-step=seed\n'+values[3]+'\n\\echo receiver29-step=cases\n\\echo receiver-case=parser\n'+values[4]
    return (prefix,adapted,suffix)


def after_scenario(execute):
    """Race two exact owned SQL requests; no raw SQL output escapes."""
    import concurrent.futures
    import threading
    if not callable(execute): raise ValueError('fixture executor')
    barrier=threading.Barrier(2,timeout=10)
    def attempt(name):
        if name not in ('left','right'): raise ValueError('race case')
        barrier.wait()
        sql="""SELECT set_config('apicontour.tenant_id',(SELECT convert_from(raw,'UTF8')::jsonb->>'tenant_id' FROM public.receiver29_race_seed WHERE name='left'),false);
        CREATE TEMP TABLE receiver29_race_result(value text); GRANT INSERT ON receiver29_race_result TO contour_causal_receiver_writer;
        SET ROLE contour_causal_receiver_writer;
        DO $$ DECLARE r record; BEGIN
         SELECT * INTO STRICT r FROM public.receiver29_race_seed WHERE name='"""+name+"""';
         BEGIN PERFORM contour.accept_causal_receiver(r.raw,r.proof); INSERT INTO receiver29_race_result VALUES('accepted');
         EXCEPTION WHEN serialization_failure THEN INSERT INTO receiver29_race_result VALUES('busy');
                   WHEN unique_violation OR check_violation THEN INSERT INTO receiver29_race_result VALUES('unavailable'); END;
        END $$; RESET ROLE; SELECT value FROM receiver29_race_result;"""
        result=execute(sql,timeout=30)
        if type(result) is not str or not result.splitlines(): raise RuntimeError('receiver race unavailable')
        state=result.splitlines()[-1]
        if state not in ('accepted','busy','unavailable'): raise RuntimeError('receiver race unavailable')
        return state
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures=[pool.submit(attempt,name) for name in ('left','right')]
        states=[f.result(timeout=45) for f in futures]
    if states.count('accepted')!=1 or not any(x in ('busy','unavailable') for x in states): raise RuntimeError('receiver race failed')
    checked=execute("SELECT (count(*)=1 AND EXISTS(SELECT 1 FROM contour.causal_receiver_inbox i WHERE (i.tenant_id,i.gateway_id,i.gateway_generation,i.delivery_handle)=(a.tenant_id,a.gateway_id,a.gateway_generation,a.delivery_handle)) AND EXISTS(SELECT 1 FROM contour.causal_receiver_tombstones t WHERE (t.tenant_id,t.gateway_id,t.gateway_generation,t.delivery_handle)=(a.tenant_id,a.gateway_id,a.gateway_generation,a.delivery_handle)))::text FROM contour.causal_receiver_assignments a WHERE a.delivery_handle=repeat('fb',16) AND a.tenant_id=(SELECT (convert_from(raw,'UTF8')::jsonb->>'tenant_id')::uuid FROM public.receiver29_race_seed WHERE name='left') GROUP BY a.tenant_id,a.gateway_id,a.gateway_generation,a.delivery_handle;")
    if checked.strip()!='true': raise RuntimeError('receiver race failed')
    control=execute("SELECT set_config('apicontour.tenant_id',(SELECT convert_from(raw,'UTF8')::jsonb->>'tenant_id' FROM public.receiver29_race_seed WHERE name='control'),false); SET ROLE contour_causal_receiver_writer; SELECT (contour.accept_causal_receiver(raw,proof) IS NOT NULL)::text FROM public.receiver29_race_seed WHERE name='control'; RESET ROLE;")
    if not control.splitlines() or control.splitlines()[-1]!='true': raise RuntimeError('receiver race authority unavailable')
    execute("\\set VERBOSITY verbose\n"+source(FILES[5]))
    execute('DROP TABLE public.receiver29_race_seed;')


def require_receipt(directory):
    path=Path(directory)/'causal-receiver.done'
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size!=len(b'causal-receiver-complete\n'): raise ValueError('receiver fixture receipt')
        if os.read(fd,128)!=b'causal-receiver-complete\n' or os.read(fd,1): raise ValueError('receiver fixture receipt')
    finally: os.close(fd)


_ERROR_TYPES=frozenset(('ValueError','RuntimeError','TimeoutError','OSError','PermissionError','FileNotFoundError','ReceiverInboxQueryError','ObserverQueryError','TransportError'))
_ERROR_FILES=frozenset(('test-causal-receiver-inbox.py','test-causal-observer-inbox.py','test-human-origin.py','test-postgres-origin-submit.py','test-postgres-v2-submit.py','test-postgres-submit.py','test-postgres-authority.py','test-postgres-tls.py','fixture_psql_transport.py'))
_ERROR_STEPS=frozenset(('migration28','migration29','observer-regression','seed','cases'))
_ERROR_CASES=frozenset(('parser','observer-first','receiver-first','receiver-first-mismatch','quota','revoked-product'))
_ERROR_STATES=frozenset(('23502','23503','23505','23514','40001','42501','42601','42702','42703','42804','42883','42P01','42P07','42710','55000','54000','P0001','XX000'))
_ERROR_FUNCTIONS=frozenset(('inline_code_block','contour.accept_causal_observer','contour.observer_wire','contour.human_observation_origin','contour.catalog_origin_mapping','contour.receiver_inbox_wire','contour.receiver_enrollment_current','contour.receiver_assignment_current','contour.receiver_assignment_metadata','contour.receiver_tombstone_metadata','contour.receiver_observer_current','contour.accept_causal_receiver','contour.enroll_causal_receiver','contour.current_causal_receiver','contour.receiver_claim_current','contour.causal_session_locked','contour.gateway_claim_current','contour.begin_origin_operation','contour.lock_origin_credential','contour.lock_origin_collector','contour.causal_json_canonical'))

def failure_lines(error):
    """Bounded labels only; never emit exception text, SQL or private values."""
    lines=[];seen=set()
    def visit(exc,role,depth):
        if len(lines)>=12 or depth>=8 or id(exc) in seen:return
        seen.add(id(exc))
        if isinstance(exc,BaseExceptionGroup):
            for index,child in enumerate(exc.exceptions[:8]):visit(child,role if index==0 else 'cleanup',depth+1)
            return
        kind=type(exc).__name__;kind=kind if kind in _ERROR_TYPES else 'OtherError'
        frames=[];tb=exc.__traceback__;count=0
        while tb is not None and count<128:
            path=Path(tb.tb_frame.f_code.co_filename)
            if path.parent==ROOT/'scripts' and path.name in _ERROR_FILES and 1<=tb.tb_lineno<=999999:frames.append(path.name+':'+str(tb.tb_lineno))
            tb=tb.tb_next;count+=1
        label=lambda name,allowed: getattr(exc,name,None) if type(getattr(exc,name,None)) is str and getattr(exc,name,None) in allowed else 'unavailable'
        step=label('step',_ERROR_STEPS);case=label('case',_ERROR_CASES);state=label('sqlstate',_ERROR_STATES);function=label('function',_ERROR_FUNCTIONS)
        number=lambda name,maximum: str(getattr(exc,name,None)) if type(getattr(exc,name,None)) is int and 1<=getattr(exc,name,None)<=maximum else 'unavailable'
        line=number('line',9999) if function!='unavailable' else 'unavailable';source_line=number('source_line',999999)
        lines.append('receiver-failure role='+role+' type='+kind+' location='+(','.join(frames[-6:]) or 'unavailable')+' step='+step+' case='+case+' sqlstate='+state+' function='+function+' line='+line+' input_line='+source_line)
        if exc.__cause__ is not None:visit(exc.__cause__,'cause',depth+1)
    visit(error,'primary',0)
    return lines


def main():
    if len(sys.argv)!=1: raise ValueError('no arguments')
    require_applicable(source(FILES[1]))
    sys.argv=[str(ROOT/'scripts/test-postgres-tls.py'),'--causal-receiver']
    runpy.run_path(str(ROOT/'scripts/test-postgres-tls.py'),run_name='__main__')


if __name__=='__main__':
    try: main()
    except BaseException as error:
        for line in failure_lines(error): print(line,file=sys.stderr)
        print('FAIL: receiver inbox synthetic fixture',file=sys.stderr)
        raise SystemExit(1) from None
