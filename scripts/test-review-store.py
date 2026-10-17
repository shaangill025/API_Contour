"""Actual restricted review transactions, CAS, retries and transport faults."""
import concurrent.futures
import json
from pathlib import Path
import queue
import runpy
import socket
import subprocess
import threading
import time
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
ITEM='00000000-0000-0000-0000-000000000001'
OTHER='00000000-0000-0000-0000-000000ffffff'
def identity(number):return '00000000-0000-0000-0000-%012x'%number

def bootstrap(sql, port, directory, environment):
    """Minimal real import/store/approval setup, independent of catalog regressions."""
    def execute(text):
        result=subprocess.run(sql,input=text,text=True,capture_output=True,timeout=10,env=environment)
        assert result.returncode==0,'review bootstrap SQL failed'
        return result.stdout.strip()
    for name in ['bootstrap.sql','provision_authority.sql','provision_catalog.sql','provision_declared.sql','provision_approval.sql',
                 'migrations/0001_identity.sql','migrations/0002_policy.sql','migrations/0003_ingestion.sql','migrations/0004_catalog.sql','migrations/0005_declared.sql','migrations/0006_approval.sql']:
        execute((ROOT/'db'/name).read_text())
    for group in ['declared_writer','declared_reader','approval_writer']:
        execute("CREATE ROLE contour_%s_tls LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%s'; GRANT contour_%s TO contour_%s_tls;"%(group,environment['CONTOUR_FIXTURE_PASSWORD'],group,group))
    execute("INSERT INTO contour.tenants VALUES ('%s'); INSERT INTO contour.projects VALUES ('%s','%s'); INSERT INTO contour.services VALUES ('%s','%s','%s'); INSERT INTO contour.environments VALUES ('%s','%s','%s');"%((ITEM,)*9))
    target=json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps','--offline'],text=True,timeout=15))['target_directory']
    examples=Path(target)/'debug/examples';scope=[ITEM]*4
    document={'openapi':'3.0.3','paths':{'/source':{'post':{'requestBody':{'content':{'application/json':{'schema':{'type':'object','properties':{'é':{'type':'string','example':'SECRET-MUST-NOT-PERSIST'}},'required':['é']}}}}}}}}
    imported=subprocess.run([str(examples/'import_probe'),'openapi_json','request','POST','/source','application/json','-','é'],input=json.dumps(document).encode(),capture_output=True,timeout=5)
    assert imported.returncode==0 and not imported.stderr and b'SECRET-MUST-NOT-PERSIST' not in imported.stdout
    path=directory/'declared-wire.json';path.write_bytes(imported.stdout)
    for number in [0x81,0x82,0x90]:
        selected=path
        if number==0x90:
            graph=json.loads(imported.stdout);graph['operation'][-1]='/other'
            selected=directory/'other-declared.json';selected.write_text(json.dumps(graph))
        result=subprocess.run([str(examples/'declared_store_probe'),str(port),str(directory/'ca.crt'),str(selected),*scope,identity(number),'store','Stored','10000','0'],input='\n',text=True,capture_output=True,timeout=15,env=environment)
        assert result.returncode==0 and not result.stderr,'checked bootstrap declared write failed'
    operation=execute("SELECT operation_id FROM contour.declared_versions WHERE version_id='%s'"%identity(0x81))
    for number,version,prior in [(106,0x81,'-'),(113,0x82,identity(106))]:
        result=subprocess.run([str(examples/'approval_probe'),str(port),str(directory/'ca.crt'),*scope,operation,identity(number),identity(version),prior,ITEM,'approve','Approved','10000','0'],input='\n',text=True,capture_output=True,timeout=15,env=environment)
        assert result.returncode==0 and not result.stderr,'checked bootstrap approval failed'

def run_cases(container,sql,port,directory,environment):
    def execute(text):
        result=subprocess.run(sql,input=text,text=True,capture_output=True,timeout=10,env=environment)
        assert result.returncode==0,'review fixture SQL failed'
        return result.stdout.strip()
    for name in ['provision_comparison.sql','migrations/0007_comparison.sql','provision_review.sql','migrations/0008_review.sql']:
        execute((ROOT/'db'/name).read_text())
    for role,groups in [('writer','contour_review_writer,contour_approval_writer'),('reader','contour_review_reader')]:
        execute("CREATE ROLE contour_review_%s_tls LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%s'; GRANT %s TO contour_review_%s_tls;"%(role,environment['CONTOUR_FIXTURE_PASSWORD'],groups,role))
        for table in ['declared_versions','ingestion_payloads']:
            assert execute("SELECT has_table_privilege('contour_review_%s_tls','contour.%s','SELECT')"%(role,table))=='f'
    target=json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps','--offline'],text=True,timeout=15))['target_directory']
    probe=Path(target)/'debug/examples/review_store_probe';scope=[ITEM]*4
    operation=execute("SELECT operation_id FROM contour.declared_versions WHERE version_id='%s'"%identity(0x81))
    comparison=identity(701);candidate=identity(0x81);baseline=identity(113)
    execute("INSERT INTO contour.comparisons(tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,left_kind,left_version_id,left_event_id,right_kind,right_version_id,evaluator_version,result_codec_version,result_wire) VALUES('%s','%s','%s','%s','%s','%s','approved','%s','%s','declared','%s',1,1,decode('00','hex'))"%(ITEM,comparison,operation,ITEM,ITEM,ITEM,identity(0x82),baseline,candidate))
    # Storage adapter checks exact metadata, without claiming graph/result validation.
    execute("INSERT INTO contour.comparisons SELECT tenant_id,'%s',operation_id,project_id,service_id,environment_id,left_kind,left_version_id,left_event_id,'approved',right_version_id,'%s',evaluator_version,result_codec_version,result_wire,created_at FROM contour.comparisons WHERE comparison_id='%s'"%(identity(702),identity(106),comparison))
    EofRelay=runpy.run_path(str(ROOT/'scripts/test-declared-store.py'))['EofRelay']
    def check(wanted='Stored',review=None,mode='store',reference=None,version=candidate,expected=baseline,actor=ITEM,revision=1,selected=None,operation_id=operation,budget=10000,via=port,unblock=None):
        review=review or identity(710);reference=reference or comparison
        control=relay=process=thread=None
        try:
            if mode.startswith('cancel-'):
                control=socket.socket();control.bind(('127.0.0.1',0));control.listen(1);control.settimeout(3)
                relay=EofRelay(via);via=relay.port
            process=subprocess.Popen([str(probe),str(via),str(directory/'ca.crt'),*(selected or scope),operation_id,review,reference,version,expected or '-',actor,str(revision),mode,wanted,str(budget),str(control.getsockname()[1] if control else 0)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
            output=queue.Queue();thread=threading.Thread(target=lambda:output.put(process.stdout.readline()),daemon=True);thread.start()
            if control:
                peer,_=control.accept()
                with peer:
                    time.sleep(0.8);until=time.monotonic()+3
                    while execute("SELECT count(*) FROM pg_stat_activity WHERE usename LIKE 'contour_review_%_tls' AND wait_event_type='Lock'")!='1':
                        assert time.monotonic()<until,'review future never reached real lock';time.sleep(0.01)
                    assert not relay.eof.is_set();peer.sendall(b'C')
            line=output.get(timeout=25)
            assert line.startswith('{'),'review expected '+wanted+' got '+(line.strip() if line.strip() in ['Conflict','NotFound','Stored','Decided','Duplicate','Read','Database','Corrupt','Deadline','Invalidated','OutcomeUnknown'] else 'no closed result')
            result=json.loads(line)
            if relay:
                assert not result['reusable'] and process.poll() is None;relay.finish();assert unblock is not None;unblock()
            until=time.monotonic()+5
            while execute("SELECT count(*) FROM pg_stat_activity WHERE usename LIKE 'contour_review_%_tls'")!='0':
                assert time.monotonic()<until,'review backend survived while runtime alive';time.sleep(0.02)
            assert process.poll() is None,'runtime exited before cleanup proof'
            out,errors=process.communicate('\n',timeout=3)
            assert process.returncode==0 and not out and not errors,'review probe failed'
            return result
        finally:
            try:
                if control:control.close()
                if relay:relay.close()
            finally:
                if process is not None:
                    if process.poll() is None:process.kill();process.wait(timeout=3)
                    if thread:thread.join(2)
                    for pipe in [process.stdin,process.stdout,process.stderr]:pipe.close()
    # Launch failures must close the real accept thread before any child exists.
    with mock.patch.object(subprocess,'Popen',side_effect=FileNotFoundError('fixture launch failure')):
        try:check(mode='cancel-store')
        except FileNotFoundError:pass
        else:raise AssertionError('startup failure lost')
    first=check();assert first['value']['revision']==1 and first['value']['status']=='Pending'
    assert check('Duplicate')['value']==first['value']
    assert check('Read',mode='read')['value']==first['value']
    for changes in [dict(actor=OTHER),dict(version=identity(0x82)),dict(expected=identity(106)),dict(reference=identity(702))]:check('Conflict',**changes)
    for index in range(4):
        wrong=scope.copy();wrong[index]=OTHER
        check('NotFound',selected=wrong);check('NotFound',selected=wrong,mode='read');check('NotFound',selected=wrong,mode='reject')
    check('NotFound',operation_id=OTHER);check('NotFound',operation_id=OTHER,mode='read');check('NotFound',reference=OTHER)
    check('Conflict',mode='reject',revision=2)
    check('Conflict',mode='approve',reference=baseline)
    approved=check('Decided',mode='approve',reference=identity(801),actor=OTHER)
    assert approved['value']['revision']==2 and approved['value']['status']=='Approved' and approved['value']['creator']==ITEM and approved['value']['actor']==OTHER
    assert execute("SELECT current_event_id FROM contour.approval_heads WHERE operation_id='%s'"%operation)==identity(801)
    # Later baseline advancement does not invalidate an exact terminal receipt.
    execute("UPDATE contour.approval_heads SET current_event_id='%s' WHERE operation_id='%s'"%(baseline,operation))
    assert check('Duplicate',mode='approve',reference=identity(801),actor=OTHER)['value']==approved['value']
    for changes in [dict(mode='reject',actor=OTHER),dict(mode='approve',reference=identity(802),actor=OTHER),dict(mode='approve',reference=identity(801)),dict(mode='approve',reference=identity(801),actor=OTHER,revision=2)]:check('Conflict',**changes)
    assert check('Duplicate')['value']==approved['value']
    def create(number):return check(review=identity(number))
    def reset():execute("UPDATE contour.approval_heads SET current_event_id='%s' WHERE operation_id='%s'"%(baseline,operation))
    create(711)
    rejected=check('Decided',review=identity(711),mode='reject',actor=OTHER)
    assert rejected['value']['event'] is None and rejected['value']['status']=='Rejected'
    assert check('Duplicate',review=identity(711),mode='reject',actor=OTHER)['value']==rejected['value']
    create(712);execute("UPDATE contour.approval_heads SET current_event_id='%s' WHERE operation_id='%s'"%(identity(801),operation))
    for mode in ['approve','reject']:check('Conflict',review=identity(712),mode=mode,reference=identity(803))
    reset()
    # Existing matching event801 belongs to an earlier decision, never a new one.
    check('Conflict',review=identity(712),mode='approve',reference=identity(801),actor=OTHER)
    def held(statement,body):
        holder=subprocess.Popen(sql,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
        marker=queue.Queue()
        def ready():
            for line in holder.stdout:
                if line.strip()=='HELD':marker.put('HELD');return
            marker.put('EOF')
        listener=threading.Thread(target=ready,daemon=True);listener.start();released=False
        def release():
            nonlocal released
            if not released:holder.stdin.write('ROLLBACK;\n');holder.stdin.flush();released=True
        try:
            holder.stdin.write('BEGIN; '+statement+';\n\\echo HELD\n');holder.stdin.flush();assert marker.get(timeout=3)=='HELD'
            return body(release)
        finally:
            try:holder.communicate('' if released else 'ROLLBACK;\n',timeout=3)
            except subprocess.TimeoutExpired:holder.kill();holder.wait(timeout=3)
            listener.join(2)
            for pipe in [holder.stdin,holder.stdout,holder.stderr]:pipe.close()
    def race(calls,lock):
        def body(release):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures=[pool.submit(check,**call) for call in calls];until=time.monotonic()+3
                try:
                    while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_review_writer_tls' AND wait_event_type='Lock'")!='2':
                        assert time.monotonic()<until,'both review transactions did not reach locks';time.sleep(0.01)
                finally:release()
                return [f.result(timeout=25) for f in futures]
        return held(lock,body)
    create(720)
    rows=race([dict(wanted='Either',review=identity(720),mode='approve',reference=identity(820)),dict(wanted='Either',review=identity(720),mode='reject')],"SELECT 1 FROM contour.review_requests WHERE review_id='%s' FOR UPDATE"%identity(720))
    assert sorted(r['outcome'] for r in rows)==['Conflict','Decided'];reset()
    create(725)
    rows=race([dict(wanted='Either',review=identity(725),mode='approve',reference=identity(825)) for _ in range(2)],"SELECT 1 FROM contour.review_requests WHERE review_id='%s' FOR UPDATE"%identity(725))
    assert sorted(r['outcome'] for r in rows)==['Decided','Duplicate'] and rows[0]['value']==rows[1]['value'];reset()
    for number in [721,722]:create(number)
    rows=race([dict(wanted='Either',review=identity(721+i),mode='approve',reference=identity(821+i)) for i in range(2)],"SELECT 1 FROM contour.approval_heads WHERE operation_id='%s' FOR UPDATE"%operation)
    assert sorted(r['outcome'] for r in rows)==['Conflict','Decided'];reset()
    create(723)
    # Inject failure after event/head changes, before decision insertion completes.
    execute("CREATE FUNCTION contour.fail_review_decision() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END $$; CREATE TRIGGER fail_review_decision BEFORE INSERT ON contour.review_decisions FOR EACH ROW EXECUTE FUNCTION contour.fail_review_decision()")
    try:check('Database',review=identity(723),mode='approve',reference=identity(823))
    finally:execute('DROP TRIGGER fail_review_decision ON contour.review_decisions; DROP FUNCTION contour.fail_review_decision()')
    assert execute("SELECT count(*) FROM contour.approval_events WHERE event_id='%s'"%identity(823))=='0'
    assert check('Read',review=identity(723),mode='read')['value']['status']=='Pending'
    assert execute("SELECT current_event_id FROM contour.approval_heads WHERE operation_id='%s'"%operation)==baseline
    for mode,wanted,budget in [('cancel-store','Invalidated',10000),('cancel-read','Invalidated',10000),('cancel-approve','Invalidated',10000),('cancel-reject','Invalidated',10000),('read','Deadline',150),('read','Deadline',20000)]:
        started=time.monotonic()
        reference=comparison if mode=='cancel-store' else identity(824)
        held('LOCK TABLE contour.review_requests IN ACCESS EXCLUSIVE MODE',lambda release:check(wanted,review=identity(723),mode=mode,reference=reference,budget=budget,unblock=release))
        if budget==20000:assert time.monotonic()-started<15,'caller extended configured deadline'
    # Cancellation during the second lock also rolls back first-lock ownership.
    held("SELECT 1 FROM contour.approval_heads WHERE operation_id='%s' FOR UPDATE"%operation,lambda release:check('Invalidated',review=identity(723),mode='cancel-approve',reference=identity(824),unblock=release))
    assert check('Read',review=identity(723),mode='read')['value']['status']=='Pending'
    CommitProxy=runpy.run_path(str(ROOT/'scripts/test-postgres-recovery.py'))['CommitProxy']
    for number,mode,wanted in [(730,'drop','OutcomeUnknown'),(731,'cleanup','Decided')]:
        create(number);proxy=CommitProxy(port,directory,mode)
        try:
            faulted=check(wanted,review=identity(number),mode='approve',reference=identity(number+100),via=proxy.port);proxy.finish();assert not faulted['reusable']
        finally:proxy.close()
        retry=check('Duplicate',review=identity(number),mode='approve',reference=identity(number+100))
        assert check('Read',review=identity(number),mode='read')['value']==retry['value']
        if mode=='cleanup':assert faulted['value']==retry['value']
        reset()
    # First-baseline path uses a declared left input and an absent head.
    execute("DELETE FROM contour.approval_heads WHERE operation_id='%s'"%operation)
    execute("INSERT INTO contour.comparisons SELECT tenant_id,'%s',operation_id,project_id,service_id,environment_id,'declared',left_version_id,NULL,right_kind,right_version_id,NULL,evaluator_version,result_codec_version,result_wire,created_at FROM contour.comparisons WHERE comparison_id='%s'"%(identity(703),comparison))
    check(review=identity(740),reference=identity(703),expected=None)
    check('Decided',review=identity(740),mode='approve',reference=identity(840))
    assert execute("SELECT current_event_id FROM contour.approval_heads WHERE operation_id='%s'"%operation)==identity(840)
    print('Checked review creation, exact receipts, atomic decisions/head CAS, races, rollback, cancellation and COMMIT faults passed',flush=True)
