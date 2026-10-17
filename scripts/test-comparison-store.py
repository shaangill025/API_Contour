"""Actual checked comparison persistence, input binding and transport faults."""
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

def identity(number):
    return '00000000-0000-0000-0000-%012x' % number

def run_cases(container, sql, port, directory, environment):
    def execute(text):
        result=subprocess.run(sql,input=text,text=True,capture_output=True,timeout=10,env=environment)
        assert result.returncode==0,'comparison fixture SQL failed'
        return result.stdout.strip()
    for name in ['provision_comparison.sql','migrations/0007_comparison.sql']:
        execute((ROOT/'db'/name).read_text())
    for role in ['writer','reader']:
        execute("CREATE ROLE contour_comparison_%s_tls LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%s'; GRANT contour_comparison_%s,contour_declared_reader TO contour_comparison_%s_tls;" % (role,environment['CONTOUR_FIXTURE_PASSWORD'],role,role))
    for role in ['writer','reader']:
        login='contour_comparison_'+role+'_tls'
        for table,privilege in [('declared_versions','INSERT'),('approval_events','INSERT'),('approval_heads','SELECT'),('ingestion_payloads','SELECT')]:
            assert execute("SELECT has_table_privilege('%s','contour.%s','%s')"%(login,table,privilege))=='f','comparison login unexpectedly gained authority'
    assert execute("SELECT has_table_privilege('contour_comparison_reader_tls','contour.comparisons','INSERT')")=='f'
    target=json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps','--offline'],text=True,timeout=15))['target_directory']
    examples=Path(target)/'debug/examples'
    scope=[ITEM]*4
    version_a=identity(0x81); version_b=identity(0x82)
    operation=execute("SELECT operation_id FROM contour.declared_versions WHERE tenant_id='%s' AND version_id='%s';" % (ITEM,version_a))
    assert operation
    EofRelay=runpy.run_path(str(ROOT/'scripts/test-declared-store.py'))['EofRelay']
    def check(wanted='Stored', comparison=None, left=None, right=None, operation_id=None, selected=None, mode='store', budget=10000, via=port, unblock=None):
        comparison=comparison or identity(301)
        left=left or ('declared',version_a);right=right or ('declared',version_c)
        control = relay = process = thread = None
        try:
            control = socket.socket() if mode.startswith('cancel') else None
            if control:
                control.bind(('127.0.0.1',0)); control.listen(1); control.settimeout(3)
                relay = EofRelay(via)
                via = relay.port
            process = subprocess.Popen([str(examples/'comparison_store_probe'), str(via), str(directory/'ca.crt'), *(selected or scope), operation_id or operation, comparison, *left, *right, mode, wanted, str(budget), str(control.getsockname()[1] if control else 0)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
            output = queue.Queue()
            thread = threading.Thread(target=lambda: output.put(process.stdout.readline()), daemon=True)
            thread.start()
            if control:
                peer, _ = control.accept()
                with peer:
                    # Delayed observation must still find an actually pending
                    # operation before the explicit cancellation marker.
                    time.sleep(0.8)
                    until = time.monotonic()+3
                    while execute("SELECT count(*) FROM pg_stat_activity WHERE usename IN ('contour_comparison_writer_tls','contour_comparison_reader_tls') AND wait_event_type='Lock';") != '1':
                        assert time.monotonic()<until, 'comparison future did not reach real lock wait'
                        time.sleep(0.01)
                    assert not relay.eof.is_set(), 'transport closed before cancellation signal'
                    peer.sendall(b'C')
            line = output.get(timeout=25)
            assert line.startswith('{'), 'comparison probe expected '+wanted+'; got '+(line.strip() if line.strip() in ['Scope','NotFound','Conflict','Corrupt','Database','Deadline','Invalidated','OutcomeUnknown','Stored','Duplicate','Read','Limit','UnsupportedDirection'] else 'no closed result')
            result = json.loads(line)
            if relay:
                assert not result['reusable'] and process.poll() is None
                relay.finish()
                # PostgreSQL may remain lock-blocked after client EOF. Release
                # only after independent local transport closure, then prove
                # backend cleanup within the existing five-second bound.
                assert unblock is not None
                unblock()
            until = time.monotonic()+5
            while execute("SELECT count(*) FROM pg_stat_activity WHERE usename IN ('contour_comparison_writer_tls','contour_comparison_reader_tls');") != '0':
                if time.monotonic()>until:
                    raise AssertionError('comparison backend survived while runtime alive')
                time.sleep(0.02)
            assert process.poll() is None, 'runtime exited before backend cleanup proof'
            out, errors = process.communicate(input='\n', timeout=3)
            assert process.returncode == 0 and not out and not errors, 'comparison probe failed'
            return result
        finally:
            try:
                if control:
                    control.close()
                if relay:
                    relay.close()
            finally:
                if process is not None:
                    if process.poll() is None:
                        process.kill(); process.wait(timeout=3)
                    if thread is not None:thread.join(2)
                    for pipe in [process.stdin, process.stdout, process.stderr]:
                        pipe.close()

    # Exercise startup cleanup with the actual relay before any child exists.
    with mock.patch.object(subprocess,'Popen',side_effect=FileNotFoundError('fixture launch failure')):
        try:check(mode='cancel-store',right=('declared',version_a))
        except FileNotFoundError:pass
        else:raise AssertionError('startup failure lost')

    def declared(graph, version):
        path=directory/'comparison-source.json';path.write_text(json.dumps(graph))
        result=subprocess.run([str(examples/'declared_store_probe'),str(port),str(directory/'ca.crt'),str(path),*scope,version,'store','Stored','10000','0'],input='\n',text=True,capture_output=True,timeout=15,env=environment)
        assert result.returncode==0 and not result.stderr,'comparison source store failed'
    def approve(event, version, prior):
        result=subprocess.run([str(examples/'approval_probe'),str(port),str(directory/'ca.crt'),*scope,operation,event,version,prior,ITEM,'approve','Approved','10000','0'],input='\n',text=True,capture_output=True,timeout=15,env=environment)
        assert result.returncode==0 and not result.stderr,'comparison approval fixture failed'
    graph=json.loads((directory/'declared-wire.json').read_text())
    next(node for node in graph['nodes'] if node['kind']=='object')['properties'][0]['required']=False
    version_c=identity(0x10a);declared(graph,version_c)
    approve(identity(114),version_c,identity(113))
    first=check()
    assert first['value']['result']['differences'] and first['reusable']
    assert first['value']['versions']==[version_a,version_c]
    assert check('Duplicate')['value']==first['value']
    assert check('Read',mode='read')['value']==first['value']
    combinations=[]
    for i,(left,right) in enumerate([(('declared',version_a),('declared',version_c)),(('approved',identity(106)),('declared',version_c)),(('declared',version_a),('approved',identity(114))),(('approved',identity(106)),('approved',identity(114)))]):
        args=dict(comparison=identity(310+i),left=left,right=right)
        stored=check(**args);combinations.append((args,stored))
        assert stored['value']['result']==first['value']['result']
        assert stored['value']['inputs']==[list(left),list(right)]
    approve(identity(115),version_a,identity(114))
    for args,stored in combinations:
        assert check('Read',mode='read',**args)['value']==stored['value'],'head advancement changed historical comparison'
        assert check('Duplicate',**args)['value']==stored['value']
    check('Conflict',comparison=identity(310),left=('approved',identity(106)))
    check('Conflict',left=('declared',version_c),right=('declared',version_a))
    # Equal results do not permit identity, side or approval event substitutions.
    same=check(comparison=identity(320),left=('declared',version_a),right=('declared',version_b))
    reversed_result=check(comparison=identity(321),left=('declared',version_b),right=('declared',version_a))
    assert same['value']['result']==reversed_result['value']['result'],'equal-result fixture inputs differ'
    check('Conflict',comparison=identity(320),left=('declared',version_b),right=('declared',version_a))
    check('Conflict',comparison=identity(311),left=('approved',identity(115)))
    for index in range(4):
        wrong=scope.copy();wrong[index]=OTHER
        check('NotFound',selected=wrong);check('NotFound',selected=wrong,mode='read')
    check('NotFound',operation_id=OTHER);check('NotFound',operation_id=OTHER,mode='read')
    check('NotFound',left=('declared',OTHER));check('NotFound',left=('approved',OTHER))
    check('NotFound',left=('declared',identity(0x90)))
    check('NotFound',mode='read',comparison=OTHER)
    # Privileged corruption must never be normalized into an accepted result.
    where="tenant_id='%s' AND comparison_id='%s'"%(ITEM,identity(301))
    original=execute('SELECT encode(result_wire,\'hex\') FROM contour.comparisons WHERE '+where)
    def update(expression):
        execute('BEGIN; ALTER TABLE contour.comparisons DISABLE TRIGGER immutable_comparison; UPDATE contour.comparisons SET '+expression+' WHERE '+where+'; ALTER TABLE contour.comparisons ENABLE TRIGGER immutable_comparison; COMMIT;')
    def damage(expression):
        try:
            update('result_wire='+expression)
            check('Corrupt',mode='read');check('Corrupt')
        finally:update("result_wire=decode('%s','hex')"%original)
    damage("(SELECT result_wire FROM contour.comparisons WHERE comparison_id='%s')"%identity(320))
    damage("decode('20%s','hex')"%original)
    for column,constraint,value in [('result_codec_version','comparisons_result_codec_version_check','2'),('evaluator_version','comparisons_evaluator_version_check','2')]:
        execute('ALTER TABLE contour.comparisons DROP CONSTRAINT '+constraint)
        try:
            update(column+'='+value);check('Corrupt',mode='read');check('Corrupt')
        finally:
            update(column+'=1');execute('ALTER TABLE contour.comparisons ADD CONSTRAINT '+constraint+' CHECK ('+column+'=1)')
    execute('ALTER TABLE contour.comparisons DROP CONSTRAINT comparisons_result_wire_check')
    try:damage("decode(repeat('00',1048577),'hex')")
    finally:execute('ALTER TABLE contour.comparisons ADD CONSTRAINT comparisons_result_wire_check CHECK (octet_length(result_wire) BETWEEN 1 AND 1048576)')
    source_where="tenant_id='%s' AND version_id='%s'"%(ITEM,version_c)
    original_graph=execute("SELECT encode(declared_wire,'hex') FROM contour.declared_versions WHERE "+source_where)
    try:
        execute("BEGIN; ALTER TABLE contour.declared_versions DISABLE TRIGGER immutable_declared; UPDATE contour.declared_versions SET declared_wire=decode('20%s','hex') WHERE %s; ALTER TABLE contour.declared_versions ENABLE TRIGGER immutable_declared; COMMIT;"%(original_graph,source_where))
        check('Corrupt',mode='read');check('Corrupt')
    finally:
        execute("BEGIN; ALTER TABLE contour.declared_versions DISABLE TRIGGER immutable_declared; UPDATE contour.declared_versions SET declared_wire=decode('%s','hex') WHERE %s; ALTER TABLE contour.declared_versions ENABLE TRIGGER immutable_declared; COMMIT;"%(original_graph,source_where))
    assert check('Read',mode='read')['value']==first['value']
    def simultaneous(calls):
        # Both actual insert transactions wait before racing the unique identity.
        execute("CREATE FUNCTION contour.comparison_rendezvous() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(208,1); RETURN NEW; END $$; CREATE TRIGGER comparison_rendezvous BEFORE INSERT ON contour.comparisons FOR EACH ROW EXECUTE FUNCTION contour.comparison_rendezvous();")
        holder=subprocess.Popen(sql,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
        marker=queue.Queue();listener=threading.Thread(target=lambda:marker.put(holder.stdout.readline().strip()),daemon=True);listener.start()
        pool=concurrent.futures.ThreadPoolExecutor(max_workers=2)
        released=False
        def release():
            nonlocal released
            if released:return
            released=True
            try:holder.communicate('ROLLBACK;\n',timeout=3)
            except subprocess.TimeoutExpired:
                holder.kill();holder.wait(timeout=3)
                raise
        try:
            holder.stdin.write('BEGIN; DO $$ BEGIN PERFORM pg_advisory_xact_lock(208,1); END $$;\n\\echo HELD\n');holder.stdin.flush()
            assert marker.get(timeout=3)=='HELD','rendezvous holder not ready'
            futures=[pool.submit(check,**call) for call in calls]
            until=time.monotonic()+3
            while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_comparison_writer_tls' AND wait_event_type='Lock';")!='2':
                assert time.monotonic()<until,'both comparison transactions did not reach real locks'
                time.sleep(0.01)
            assert execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_comparison_writer_tls' AND wait_event='advisory';")=='2','comparison inserts did not both reach rendezvous'
            release()
            return [future.result(timeout=25) for future in futures]
        finally:
            try:
                release()
            finally:
                try:
                    pool.shutdown(wait=True)
                finally:
                    try:
                        listener.join(2)
                        for pipe in [holder.stdin,holder.stdout,holder.stderr]:pipe.close()
                    finally:
                        execute('DROP TRIGGER comparison_rendezvous ON contour.comparisons; DROP FUNCTION contour.comparison_rendezvous();')
    for offset,second in [(330,dict()),(331,dict(left=('declared',version_c),right=('declared',version_a)))]:
        common=dict(wanted='Either',comparison=identity(offset))
        changed=dict(common);changed.update(second)
        rows=simultaneous([common,changed])
        assert sorted(row['outcome'] for row in rows)==(['Duplicate','Stored'] if offset==330 else ['Conflict','Stored'])
        if offset==330:assert rows[0]['value']==rows[1]['value']
        assert execute("SELECT count(*) FROM contour.comparisons WHERE comparison_id='%s'"%identity(offset))=='1'
    # A real table lock holds the future pending. Dropping it must close its backend
    # while the probe runtime remains alive, and release all transaction ownership.
    for mode, wanted, budget in [('cancel-store','Invalidated',10000),('cancel-read','Invalidated',10000),('read','Deadline',150),('read','Deadline',20000)]:
        holder = subprocess.Popen(sql, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
        marker = queue.Queue()
        listener = threading.Thread(target=lambda: marker.put(holder.stdout.readline().strip()), daemon=True)
        listener.start()
        released = False
        def unblock():
            nonlocal released
            holder.stdin.write('ROLLBACK;\n'); holder.stdin.flush(); released = True
        try:
            holder.stdin.write('BEGIN; LOCK TABLE contour.comparisons IN ACCESS EXCLUSIVE MODE;\n\\echo HELD\n');holder.stdin.flush()
            assert marker.get(timeout=3) == 'HELD'
            started = time.monotonic()
            assert not check(wanted,mode=mode,budget=budget,unblock=unblock)['reusable']
            if budget == 20000:
                assert time.monotonic()-started < 15, 'caller extended configured 10s deadline'
        finally:
            try:
                holder.communicate('' if released else 'ROLLBACK;\n',timeout=3)
            except subprocess.TimeoutExpired:
                holder.kill(); holder.wait(timeout=3)
            listener.join(2)
            for pipe in [holder.stdin, holder.stdout, holder.stderr]:
                pipe.close()
        assert check('Read',mode='read')['value'] == first['value']

    CommitProxy = runpy.run_path(str(ROOT/'scripts/test-postgres-recovery.py'))['CommitProxy']
    for offset, mode, wanted in [(340,'drop','OutcomeUnknown'),(341,'cleanup','Stored')]:
        comparison = identity(offset)
        proxy = CommitProxy(port,directory,mode)
        try:
            faulted = check(wanted,comparison=comparison,via=proxy.port)
            proxy.finish()
            assert not faulted['reusable']
        finally:
            proxy.close()
        retry = check('Duplicate',comparison=comparison)
        assert check('Read',mode='read',comparison=comparison)['value'] == retry['value']
        if mode == 'cleanup':
            assert faulted['value'] == retry['value'], 'known commit receipt lost on cleanup failure'
        assert execute("SELECT count(*) FROM contour.comparisons WHERE comparison_id='%s';" % comparison) == '1'
    for number,direction,deep,wanted in [(350,'publish',False,'UnsupportedDirection'),(351,'request',True,'Limit')]:
        source=json.loads((directory/'declared-wire.json').read_text())
        source['operation'][5]=direction;source['operation'][-1]='/comparison-limit'
        if deep:source=dict(version=1,operation=source['operation'],root=0,definitions=[],omissions=[],nodes=[dict(id=i,kind='array',items=i+1,omissions=[]) for i in range(200)]+[dict(id=200,kind='string',omissions=[])])
        version=identity(number);declared(source,version)
        operation_id=execute("SELECT operation_id FROM contour.declared_versions WHERE version_id='%s'"%version)
        check(wanted,comparison=identity(number),operation_id=operation_id,left=('declared',version),right=('declared',version))
        assert execute("SELECT count(*) FROM contour.comparisons WHERE comparison_id='%s'"%identity(number))=='0'
    print('Checked comparison exact input binding, historical events, races, corruption, limits, live cancellation and COMMIT faults passed',flush=True)

def bootstrap(sql, port, directory, environment):
    """Minimal real import/store/approval setup, independent of catalog regressions."""
    def execute(text):
        result=subprocess.run(sql,input=text,text=True,capture_output=True,timeout=10,env=environment)
        assert result.returncode==0,'comparison bootstrap SQL failed'
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
