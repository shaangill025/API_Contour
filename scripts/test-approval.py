"""Actual internal approval CAS, audit association and transport-fault assertions."""
import concurrent.futures
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

def run_cases(container, sql, port, directory, environment):
    def execute(text):
        result=subprocess.run(sql,input=text,text=True,capture_output=True,timeout=10,env=environment)
        assert result.returncode==0,'approval fixture SQL failed'
        return result.stdout.strip()
    for name in ['provision_approval.sql','migrations/0006_approval.sql']:
        execute((ROOT/'db'/name).read_text())
    execute("CREATE ROLE contour_approval_writer_tls LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%s'; GRANT contour_approval_writer TO contour_approval_writer_tls;" % environment['CONTOUR_FIXTURE_PASSWORD'])
    target=json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps','--offline'],text=True,timeout=15))['target_directory']
    examples=Path(target)/'debug/examples'
    scope=[ITEM]*4
    version_a=identity(0x81); version_b=identity(0x82)
    operation=execute("SELECT operation_id FROM contour.declared_versions WHERE tenant_id='%s' AND version_id='%s';" % (ITEM,version_a))
    assert operation
    EofRelay=runpy.run_path(str(ROOT/'scripts/test-declared-store.py'))['EofRelay']
    def check(wanted='Approved', event=None, version=None, expected=None, actor=ITEM, operation_id=None, selected=None, mode='approve', budget=10000, via=port, unblock=None):
        assert event and version
        control = socket.socket() if mode.startswith('cancel') else None
        relay = EofRelay(via) if control else None
        if control:
            control.bind(('127.0.0.1',0)); control.listen(1); control.settimeout(3)
            via = relay.port
        process = subprocess.Popen([str(examples/'approval_probe'), str(via), str(directory/'ca.crt'), *(selected or scope), operation_id or operation, event, version, expected or '-', actor, mode, wanted, str(budget), str(control.getsockname()[1] if control else 0)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
        output = queue.Queue()
        thread = threading.Thread(target=lambda: output.put(process.stdout.readline()), daemon=True)
        thread.start()
        try:
            if control:
                peer, _ = control.accept()
                with peer:
                    # Delayed observation must still find an actually pending
                    # operation before the explicit cancellation marker.
                    time.sleep(0.8)
                    until = time.monotonic()+3
                    while execute("SELECT count(*) FROM pg_stat_activity WHERE usename IN ('contour_approval_writer_tls') AND wait_event_type='Lock';") != '1':
                        assert time.monotonic()<until, 'approval future did not reach real lock wait'
                        time.sleep(0.01)
                    assert not relay.eof.is_set(), 'transport closed before cancellation signal'
                    peer.sendall(b'C')
            line = output.get(timeout=25)
            assert line.startswith('{'), 'approval probe expected '+wanted+'; got '+(line.strip() if line.strip() in ['Scope','NotFound','Conflict','Corrupt','Database','Deadline','Invalidated','OutcomeUnknown','Approved','Duplicate'] else 'no closed result')
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
            while execute("SELECT count(*) FROM pg_stat_activity WHERE usename IN ('contour_approval_writer_tls');") != '0':
                if time.monotonic()>until:
                    raise AssertionError('approval backend survived while runtime alive')
                time.sleep(0.02)
            assert process.poll() is None, 'runtime exited before backend cleanup proof'
            out, errors = process.communicate(input='\n', timeout=3)
            assert process.returncode == 0 and not out and not errors, 'approval probe failed'
            return result
        finally:
            try:
                if control:
                    control.close()
                if relay:
                    relay.close()
            finally:
                if process.poll() is None:
                    process.kill(); process.wait(timeout=3)
                thread.join(2)
                for pipe in [process.stdin, process.stdout, process.stderr]:
                    pipe.close()

    def head():
        return execute("SELECT current_event_id FROM contour.approval_heads WHERE tenant_id='%s' AND operation_id='%s';" % (ITEM,operation))
    def events():
        return execute("SELECT count(*) FROM contour.approval_events WHERE tenant_id='%s';" % ITEM)
    def simultaneous(calls):
        # One event insert waits on our advisory lock; the peer must wait on
        # the operation head, never reach the event insertion concurrently.
        execute("CREATE FUNCTION contour.approval_rendezvous() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(207,1); RETURN NEW; END $$; CREATE TRIGGER approval_rendezvous BEFORE INSERT ON contour.approval_events FOR EACH ROW EXECUTE FUNCTION contour.approval_rendezvous();")
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
            holder.stdin.write('BEGIN; DO $$ BEGIN PERFORM pg_advisory_xact_lock(207,1); END $$;\n\\echo HELD\n');holder.stdin.flush()
            assert marker.get(timeout=3)=='HELD','rendezvous holder not ready'
            futures=[pool.submit(check,**call) for call in calls]
            until=time.monotonic()+3
            while execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_approval_writer_tls' AND wait_event_type='Lock';")!='2':
                assert time.monotonic()<until,'both approval transactions did not reach real locks'
                time.sleep(0.01)
            assert execute("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_approval_writer_tls' AND wait_event='advisory';")=='1','replacement head locking did not serialize event inserts'
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
                        execute('DROP TRIGGER approval_rendezvous ON contour.approval_events; DROP FUNCTION contour.approval_rendezvous();')
    # Concurrent first and replacement approvals must each have exactly one winner.
    first=None
    for numbers,expected in [((101,102),None),((103,104),'first')]:
        expected=first['value']['id'] if expected else None
        results=simultaneous([dict(wanted='Either',event=identity(number),version=version_a,expected=expected) for number in numbers])
        assert sorted(row['outcome'] for row in results)==['Approved','Conflict'],'same-baseline approvals both succeeded'
        winner=next(row for row in results if row['outcome']=='Approved')
        assert head()==winner['value']['id']
        if first is None:
            first=winner
        else:
            current=winner['value']['id']
    assert events()=='2'
    assert check('Duplicate',event=first['value']['id'],version=version_a)['value']==first['value'],'old exact retry changed receipt after head moved'
    # Version A -> B -> A never revives the old event baseline.
    check(event=identity(105),version=version_b,expected=current)
    check(event=identity(106),version=version_a,expected=identity(105))
    check('Conflict',event=identity(107),version=version_b,expected=current)
    assert head()==identity(106) and events()=='4'
    for changes in [dict(version=version_b),dict(actor=OTHER),dict(expected=identity(105))]:
        args=dict(event=first['value']['id'],version=version_a);args.update(changes)
        check('Conflict',**args)
    for index in range(4):
        wrong=scope.copy();wrong[index]=OTHER
        check('NotFound',event=identity(108),version=version_a,selected=wrong)
    check('NotFound',event=identity(108),version=OTHER)
    check('NotFound',event=identity(108),version=version_a,operation_id=OTHER)
    assert events()=='4' and head()==identity(106)
    # Use the actual checked declared writer to create a second operation/version.
    graph=json.loads((directory/'declared-wire.json').read_text());graph['operation'][-1]='/approval-other'
    path=directory/'approval-other.json';path.write_text(json.dumps(graph))
    other_version=identity(0x90)
    imported=subprocess.run([str(examples/'declared_store_probe'),str(port),str(directory/'ca.crt'),str(path),*scope,other_version,'store','Stored','10000','0'],input='\n',text=True,capture_output=True,timeout=15,env=environment)
    assert imported.returncode==0 and not imported.stderr,'second checked declared operation failed'
    other_operation=execute("SELECT operation_id FROM contour.declared_versions WHERE tenant_id='%s' AND version_id='%s';" % (ITEM,other_version))
    assert other_operation and other_operation!=operation
    # A failed head update rolls back the initial lock row, event and actor audit.
    execute("CREATE FUNCTION contour.fail_approval_head() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE TRIGGER fail_approval_head BEFORE UPDATE ON contour.approval_heads FOR EACH ROW EXECUTE FUNCTION contour.fail_approval_head();")
    try:
        check('Database',event=identity(109),version=other_version,operation_id=other_operation)
        assert execute("SELECT count(*) FROM contour.approval_heads WHERE operation_id='%s';" % other_operation)=='0'
        assert events()=='4'
    finally:
        execute('DROP TRIGGER fail_approval_head ON contour.approval_heads; DROP FUNCTION contour.fail_approval_head();')
    check('Conflict',event=first['value']['id'],version=other_version,operation_id=other_operation)
    # Identical concurrent requests converge to the same server timestamp.
    results=simultaneous([dict(wanted='Either',event=identity(110),version=other_version,operation_id=other_operation)]*2)
    assert sorted(row['outcome'] for row in results)==['Approved','Duplicate']
    assert results[0]['value']==results[1]['value']
    assert events()=='5'
    # Real pending head-lock cancellation proves frontend EOF before releasing lock.
    for mode,wanted,budget in [('cancel','Invalidated',10000),('approve','Deadline',150),('approve','Deadline',20000)]:
        holder=subprocess.Popen(sql,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
        marker=queue.Queue();listener=threading.Thread(target=lambda:marker.put(holder.stdout.readline().strip()),daemon=True);listener.start()
        released=False
        def unblock():
            nonlocal released
            holder.stdin.write('ROLLBACK;\n');holder.stdin.flush();released=True
        try:
            holder.stdin.write('BEGIN; LOCK TABLE contour.approval_heads IN ACCESS EXCLUSIVE MODE;\n\\echo HELD\n');holder.stdin.flush()
            assert marker.get(timeout=3)=='HELD'
            started=time.monotonic()
            assert not check(wanted,event=identity(111),version=version_a,expected=identity(106),mode=mode,budget=budget,unblock=unblock)['reusable']
            if budget==20000:
                assert time.monotonic()-started<15,'caller extended configured deadline'
        finally:
            try:
                holder.communicate('' if released else 'ROLLBACK;\n',timeout=3)
            except subprocess.TimeoutExpired:
                holder.kill();holder.wait(timeout=3)
            listener.join(2)
            for pipe in [holder.stdin,holder.stdout,holder.stderr]:pipe.close()
        assert head()==identity(106) and events()=='5'
    CommitProxy=runpy.run_path(str(ROOT/'scripts/test-postgres-recovery.py'))['CommitProxy']
    current=identity(106)
    for number,mode,wanted in [(112,'drop','OutcomeUnknown'),(113,'cleanup','Approved')]:
        event=identity(number);proxy=CommitProxy(port,directory,mode)
        try:
            result=check(wanted,event=event,version=version_b,expected=current,via=proxy.port)
            proxy.finish();assert not result['reusable']
        finally:
            proxy.close()
        retry=check('Duplicate',event=event,version=version_b,expected=current)
        if mode=='cleanup':assert retry['value']==result['value']
        assert head()==event
        audit=execute("SELECT version_id::text||'|'||expected_event_id::text||'|'||actor_id::text FROM contour.approval_events WHERE tenant_id='%s' AND event_id='%s';" % (ITEM,event))
        assert audit=='|'.join([version_b,current,ITEM]),'exact immutable audit association lost'
        current=event
    assert events()=='7'
    print('Internal approval initial/replacement CAS, exact retries, stale ABA, scoped actor audit, atomic rollback, live cancellation and COMMIT faults passed',flush=True)
