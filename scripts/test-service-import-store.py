"""Restricted-login whole-service import persistence through real PostgreSQL TLS."""
import concurrent.futures
import copy
import json
from pathlib import Path
import queue
import runpy
import socket
import subprocess
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
ITEM='00000000-0000-0000-0000-000000000001'
OTHER='00000000-0000-0000-0000-000000ffffff'

def identity(number):
    return '00000000-0000-0000-0000-%012x' % number

def run_cases(container,sql,port,directory,environment):
    def execute(text):
        result=subprocess.run(sql,input=text,text=True,capture_output=True,timeout=10,env=environment)
        assert result.returncode==0,'service import fixture SQL failed'
        return result.stdout.strip()
    execute((ROOT/'db/bootstrap.sql').read_text())
    for name in ['authority','catalog','declared','approval','comparison','review','human']:
        execute((ROOT/('db/provision_'+name+'.sql')).read_text())
    for path in sorted((ROOT/'db/migrations').glob('*.sql')):
        execute(path.read_text())
    for role in ['writer','reader']:
        execute("CREATE ROLE contour_declared_%s_tls LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%s'; GRANT contour_declared_%s TO contour_declared_%s_tls;"%(role,environment['CONTOUR_FIXTURE_PASSWORD'],role,role))
    execute("INSERT INTO contour.tenants VALUES ('%s'); INSERT INTO contour.projects VALUES ('%s','%s'); INSERT INTO contour.services VALUES ('%s','%s','%s'); INSERT INTO contour.environments VALUES ('%s','%s','%s');"%((ITEM,)*9))
    execute("INSERT INTO contour.environments VALUES ('%s','%s','%s');"%(ITEM,OTHER,ITEM))
    target=json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps','--offline'],text=True,timeout=15))['target_directory']
    probe=Path(target)/'debug/examples/service_import_probe'
    body={'content':{'application/json':{'schema':{'type':'string','example':'SECRET-DO-NOT-STORE'}}}}
    body['content']['text/plain']=copy.deepcopy(body['content']['application/json'])
    document={'openapi':'3.0.3','paths':{'/source':{'post':{'requestBody':body,'responses':{'200':body,'404':body}}}}}
    path=directory/'whole-import.json';path.write_text(json.dumps(document))
    empty=directory/'empty-import.json';empty.write_text(json.dumps({'openapi':'3.0.3','paths':{}}))
    changed=directory/'changed-import.json'
    other=copy.deepcopy(document);other['paths']['/source']['post']['responses']['default']=other['paths']['/source']['post']['responses'].pop('404')
    changed.write_text(json.dumps(other))
    EofRelay=runpy.run_path(str(ROOT/'scripts/test-declared-store.py'))['EofRelay']
    def check(wanted='Stored',number=401,mode='store',scope=None,source=path,budget=10000,via=None,unblock=None):
        if via is None:via=port
        control=relay=None
        if mode.startswith('cancel'):
            control=socket.socket();control.bind(('127.0.0.1',0));control.listen(1);control.settimeout(3)
            relay=EofRelay(via);via=relay.port
        process=subprocess.Popen([str(probe),str(via),str(directory/'ca.crt'),str(source),*(scope or [ITEM]*4),identity(number),mode,str(budget),wanted,str(control.getsockname()[1] if control else 0)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
        output=queue.Queue()
        reader=threading.Thread(target=lambda:output.put(process.stdout.readline()),daemon=True);reader.start()
        try:
            if control:
                peer,_=control.accept()
                with peer:
                    time.sleep(.8)
                    until=time.monotonic()+3
                    while execute("SELECT count(*) FROM pg_stat_activity WHERE usename IN ('contour_declared_writer_tls','contour_declared_reader_tls') AND wait_event_type='Lock'")!='1':
                        assert time.monotonic()<until,'import cancellation did not reach lock wait';time.sleep(.01)
                    assert not relay.eof.is_set(),'transport closed before cancellation'
                    peer.sendall(b'C')
            line=output.get(timeout=15)
            assert line.startswith('{'),'service import unexpected outcome: '+line.strip()
            value=json.loads(line)
            if relay:relay.finish()
            if unblock:unblock()
            # Keep this runtime alive until its own transport has been closed. For
            # concurrent probes, other sessions may legitimately remain connected.
            assert process.poll() is None,'probe runtime exited before acknowledgement'
            out,err=process.communicate(input='\n',timeout=3)
            assert process.returncode==0 and not out and not err,'service import probe failed'
            return value
        finally:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
            reader.join(2)
            for pipe in [process.stdin,process.stdout,process.stderr]:pipe.close()
            if relay:relay.close()
            if control:control.close()
    check('MissingDefault',mode='resolve');check('MissingDefault')
    assert execute('SELECT count(*) FROM contour.public_declared_contracts')=='0'
    execute("INSERT INTO contour.service_import_defaults VALUES ('%s','%s','%s','%s');"%((ITEM,)*4))
    assert check('Resolved',mode='resolve')['value']==[ITEM]*4
    first=check()['value'];assert first['revision']==1 and len(first['members'])==6
    assert len({m['version'] for m in first['members']})==6
    assert {m['media'] for m in first['members']}=={'application/json','text/plain'}
    responses=[m for m in first['members'] if 'Response' in m['selector']]
    assert len(responses)==4 and all(m['graph']==responses[0]['graph'] for m in responses)
    assert 'SECRET' not in json.dumps(first)
    assert check('Duplicate')['value']==first
    assert check('Read',mode='read')['value']==first
    check('Conflict',source=changed)
    for index in range(3):
        scope=[ITEM]*4;scope[index]=OTHER
        check('NotFound',mode='read',scope=scope)
    def race(numbers):
        holder=subprocess.Popen(sql,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
        marker=queue.Queue();listener=threading.Thread(target=lambda:marker.put(holder.stdout.readline().strip()),daemon=True);listener.start()
        try:
            holder.stdin.write("BEGIN; DO $$ BEGIN PERFORM 1 FROM contour.service_import_defaults FOR UPDATE; END $$;\n\\echo HELD\n");holder.stdin.flush()
            assert marker.get(timeout=3)=='HELD'
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures=[pool.submit(check,'Either',number) for number in numbers]
                until=time.monotonic()+3
                while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_declared_writer_tls' AND wait_event_type='Lock'")!='2':
                    assert time.monotonic()<until,'two imports did not wait on locked default';time.sleep(.01)
                assert not any(f.done() for f in futures),'import bypassed default lock'
                holder.stdin.write('ROLLBACK;\n');holder.stdin.flush()
                return [f.result() for f in futures]
        finally:
            try:holder.communicate('ROLLBACK;\n',timeout=3)
            except subprocess.TimeoutExpired:holder.kill();holder.wait(timeout=3)
            listener.join(2)
            for pipe in [holder.stdin,holder.stdout,holder.stderr]:pipe.close()
    retries=race([402,402])
    assert sorted(r['outcome'] for r in retries)==['Duplicate','Stored']
    assert retries[0]['value']==retries[1]['value'] and retries[0]['value']['revision']==2
    fresh=race([403,404])
    assert sorted(r['value']['revision'] for r in fresh)==[3,4]
    execute("UPDATE contour.service_import_defaults SET environment_id='%s';"%OTHER)
    check('DefaultChanged',number=405)
    assert check('Duplicate')['value']==first
    blank=check(number=405,scope=[ITEM,ITEM,ITEM,OTHER],source=empty)['value']
    assert blank['revision']==5 and blank['scope'][-1]==OTHER and not blank['members']
    assert 'PartialImport' in blank['warnings']
    execute('DELETE FROM contour.service_import_defaults')
    assert check('Duplicate')['value']==first
    check('MissingDefault',number=406)
    assert execute('SELECT count(*) FROM contour.public_declared_contracts')=='5'
    # Canonical generic declared graphs are not necessarily this import projection.
    request=next(m['graph'] for m in first['members'] if m['selector']=='Request')
    for number,protocol,method in [(410,'grpc','POST'),(411,'http','CONNECT')]:
        graph=copy.deepcopy(request);graph['operation'][4]=protocol;graph['operation'][6]=method
        generic=directory/('generic-%d.json'%number);generic.write_text(json.dumps(graph))
        result=subprocess.run([str(probe.parent/'declared_store_probe'),str(port),str(directory/'ca.crt'),str(generic),*([ITEM]*4),identity(number),'store','Stored','10000','0'],input='\n',text=True,capture_output=True,timeout=15,env=environment)
        assert result.returncode==0 and not result.stderr,'generic checked graph fixture failed'
        execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); INSERT INTO contour.public_declared_contracts(tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count,projection_version) VALUES('%s','%s','%s','%s','%s',%d,1,2); INSERT INTO contour.public_declared_members SELECT tenant_id,'%s',version_id,operation_id,project_id,service_id,environment_id,'request','application/json' FROM contour.declared_versions WHERE version_id='%s'; COMMIT;"%(ITEM,ITEM,identity(number),ITEM,ITEM,ITEM,number,identity(number),identity(number)))
        check('Corrupt',number=number,mode='read')
    execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); INSERT INTO contour.public_declared_contracts(tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count) VALUES('%s','%s','%s','%s','%s',415,0); COMMIT;"%(ITEM,ITEM,identity(415),ITEM,ITEM,ITEM))
    check('UnsupportedProjection',number=415,mode='read')
    # Each opaque payload fits its row limit, but the manifest exceeds 8 MiB.
    # Server statement logs prove rejection precedes fetching any graph payload.
    execute("ALTER ROLE contour_declared_reader_tls SET log_statement='all'")
    original_version=next(m['version'] for m in first['members'] if m['selector']=='Request')
    execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); INSERT INTO contour.public_declared_contracts(tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count,projection_version) VALUES('%s','%s','%s','%s','%s',430,9,2); INSERT INTO contour.declared_versions(tenant_id,version_id,operation_id,project_id,service_id,environment_id,codec_version,declared_wire) SELECT tenant_id,('00000000-0000-0000-0000-'||lpad(to_hex(n),12,'0'))::uuid,operation_id,project_id,service_id,environment_id,1,decode(repeat('00',1048576),'hex') FROM contour.declared_versions CROSS JOIN generate_series(4300,4308) n WHERE version_id='%s'; INSERT INTO contour.public_declared_members SELECT tenant_id,'%s',version_id,operation_id,project_id,service_id,environment_id,'request','application/x-'||version_id::text FROM contour.declared_versions WHERE version_id BETWEEN '%s' AND '%s'; COMMIT;"%(ITEM,ITEM,identity(430),ITEM,ITEM,ITEM,original_version,identity(430),identity(4300),identity(4308)))
    before_log=subprocess.run(['docker','logs',container],capture_output=True,text=True,check=True,timeout=5)
    check('Corrupt',number=430,mode='read')
    after_log=subprocess.run(['docker','logs',container],capture_output=True,text=True,check=True,timeout=5)
    delta=(after_log.stdout+after_log.stderr)[len(before_log.stdout+before_log.stderr):]
    assert 'FROM contour.public_declared_members m JOIN' in delta,'aggregate preflight not reached'
    assert 'SELECT d.declared_wire,o.canonical_key' not in delta,'aggregate payload fetched before rejection'
    # A late member failure must roll back all new graphs and operation identities.
    execute("INSERT INTO contour.service_import_defaults VALUES ('%s','%s','%s','%s');"%(ITEM,ITEM,ITEM,OTHER))
    before=execute('SELECT (SELECT count(*) FROM contour.public_declared_contracts),(SELECT count(*) FROM contour.declared_versions),(SELECT count(*) FROM contour.operations)')
    execute("CREATE SEQUENCE contour.fixture_member_reached; GRANT USAGE ON SEQUENCE contour.fixture_member_reached TO contour_declared_writer; CREATE FUNCTION contour.fixture_reject_member() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.body_selector='response:404' THEN PERFORM nextval('contour.fixture_member_reached'); RAISE EXCEPTION 'fixture late member failure' USING ERRCODE='23514'; END IF; RETURN NEW; END $$; CREATE TRIGGER fixture_reject_member BEFORE INSERT ON contour.public_declared_members FOR EACH ROW EXECUTE FUNCTION contour.fixture_reject_member();")
    check('Database',number=412,scope=[ITEM,ITEM,ITEM,OTHER])
    assert execute('SELECT is_called AND last_value=1 FROM contour.fixture_member_reached')=='t','late member failure was not reached'
    assert execute('SELECT (SELECT count(*) FROM contour.public_declared_contracts),(SELECT count(*) FROM contour.declared_versions),(SELECT count(*) FROM contour.operations)')==before,'failed import retained partial writes'
    execute('DROP TRIGGER fixture_reject_member ON contour.public_declared_members; DROP FUNCTION contour.fixture_reject_member(); DROP SEQUENCE contour.fixture_member_reached')
    for mode,wanted,budget in [('cancel-store','Invalidated',10000),('cancel-read','Invalidated',10000),('read','Deadline',150)]:
        holder=subprocess.Popen(sql,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
        marker=queue.Queue();listener=threading.Thread(target=lambda:marker.put(holder.stdout.readline().strip()),daemon=True);listener.start()
        def unblock():holder.stdin.write('ROLLBACK;\n');holder.stdin.flush()
        try:
            holder.stdin.write('BEGIN; LOCK TABLE contour.public_declared_contracts IN ACCESS EXCLUSIVE MODE;\n\\echo HELD\n');holder.stdin.flush()
            assert marker.get(timeout=3)=='HELD'
            assert not check(wanted,mode=mode,budget=budget,unblock=unblock)['reusable']
        finally:
            try:holder.communicate('ROLLBACK;\n',timeout=3)
            except subprocess.TimeoutExpired:holder.kill();holder.wait(timeout=3)
            listener.join(2)
            for pipe in [holder.stdin,holder.stdout,holder.stderr]:pipe.close()
        assert check('Read',mode='read')['value']==first
    CommitProxy=runpy.run_path(str(ROOT/'scripts/test-postgres-recovery.py'))['CommitProxy']
    for number,mode,wanted in [(420,'drop','OutcomeUnknown'),(421,'cleanup','Stored')]:
        proxy=CommitProxy(port,directory,mode)
        try:
            faulted=check(wanted,number=number,scope=[ITEM,ITEM,ITEM,OTHER],via=proxy.port)
            proxy.finish();assert not faulted['reusable']
        finally:proxy.close()
        retry=check('Duplicate',number=number,scope=[ITEM,ITEM,ITEM,OTHER])
        assert check('Read',number=number,mode='read')['value']==retry['value']
        if mode=='cleanup':assert faulted['value']==retry['value'],'confirmed commit result lost'
    subprocess.run(['docker','restart',container],capture_output=True,check=True,timeout=30)
    inspect=subprocess.run(['docker','inspect',container],capture_output=True,text=True,check=True,timeout=5)
    bindings=json.loads(inspect.stdout)[0]['NetworkSettings']['Ports']['5432/tcp']
    assert len(bindings)==1 and bindings[0]['HostIp']=='127.0.0.1','restart binding is not loopback-only'
    port=bindings[0]['HostPort']
    until=time.monotonic()+10
    while True:
        ready=subprocess.run(['docker','exec',container,'pg_isready','-U','postgres','-d','contour_fixture'],capture_output=True,timeout=5)
        if ready.returncode==0:break
        assert time.monotonic()<until,'restarted import database not ready';time.sleep(.05)
    assert check('Read',mode='read')['value']==first,'restart changed historical contract'
    assert check('Read',number=405,mode='read')['value']==blank,'restart changed empty import'
    assert check('Duplicate',number=421,scope=[ITEM,ITEM,ITEM,OTHER])['value']==retry['value'],'restart changed committed retry identity'
    execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); INSERT INTO contour.public_declared_contracts(tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count,projection_version) VALUES('%s','%s','%s','%s','%s',9007199254740991,0,2); COMMIT;"%(ITEM,ITEM,identity(413),ITEM,ITEM,OTHER))
    check('RevisionExhausted',number=414,scope=[ITEM,ITEM,ITEM,OTHER])
    check('Deadline',number=414,scope=[ITEM,ITEM,ITEM,OTHER],budget=0)
    until=time.monotonic()+3
    while execute("SELECT count(*) FROM pg_stat_activity WHERE usename IN ('contour_declared_writer_tls','contour_declared_reader_tls');")!='0':
        assert time.monotonic()<until,'service import backend leaked';time.sleep(.01)
    print('Whole-service restricted TLS persistence, status/media identity, exact retries, observed concurrent locks, defaults, empty imports, scope, malformed projection, marked late rollback, cancellation EOF, COMMIT faults, database restart and revision exhaustion passed')
