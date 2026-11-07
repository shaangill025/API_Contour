#!/usr/bin/env python3
"""Isolated synthetic PostgreSQL transport smoke check, not onboarding proof."""
import hashlib
import array
import json
import os
from pathlib import Path
import re
import runpy
import select
import secrets
import signal
import socket
import stat
import subprocess
import sys
import threading
import time

LABEL='org.apicontour.fixture-owner'
IMAGE='postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4'
ROOT=Path(__file__).resolve().parents[1]
RELAY_DEADLINE_SECONDS=35


def failure_location(error):
    """Only fixed source locations; never exception text, locals or SQL."""
    frames=[]; current=error.__traceback__
    allowed={'test-origin21-onboarding.py','origin21_sql_runner.py','origin21_transport.py'}
    while current is not None:
        name=Path(current.tb_frame.f_code.co_filename).name
        if name in allowed: frames.append(name+':'+str(current.tb_lineno))
        current=current.tb_next
    return ','.join(frames[-6:]) or 'unavailable'


def validate_network(item, token, expected_id, members):
    if not re.fullmatch('[0-9a-f]{32}',token) or not re.fullmatch('[0-9a-f]{64}',expected_id):
        raise ValueError('invalid fixture ownership')
    if (type(item) is not dict or item.get('Id')!=expected_id or
        item.get('Name')!='contour-origin21-qual-'+token or item.get('Internal') is not True or
        (item.get('Labels') or {}).get(LABEL)!=token or
        type(item.get('Containers')) is not dict or set(item['Containers'])!=set(members)):
        raise RuntimeError('fixture network identity drift')


def validate_postgres(item, token, cid, image_id, network_id):
    if not re.fullmatch('[0-9a-f]{64}',cid) or not re.fullmatch('sha256:[0-9a-f]{64}',image_id):
        raise ValueError('invalid fixture identity')
    config=item.get('Config') or {}; labels=config.get('Labels') or {}; host=item.get('HostConfig') or {}; state=item.get('State') or {}
    networks=(item.get('NetworkSettings') or {}).get('Networks') or {}
    name='contour-origin21-qual-'+token; entry=networks.get(name) or {}
    if (item.get('Id')!=cid or item.get('Name')!='/'+name+'-postgres' or item.get('Image')!=image_id or config.get('Image')!=IMAGE or
        labels.get(LABEL)!=token or host.get('Init') is not True or host.get('Privileged') is not False or host.get('PublishAllPorts') is not False or (host.get('PortBindings') or {}) or host.get('NetworkMode')!=network_id or set(networks)!={name} or
        'postgres' not in (entry.get('Aliases') or [])):
        raise RuntimeError('fixture postgres identity drift')
    if state.get('Status')=='created' and state.get('Running') is False and state.get('Pid')==0:
        if entry.get('NetworkID')!='' or entry.get('EndpointID','')!='': raise RuntimeError('unexpected created endpoint')
        return 'created'
    if state.get('Status')=='running' and state.get('Running') is True and entry.get('NetworkID')==network_id:
        return 'running'
    raise RuntimeError('unexpected fixture process or endpoint state')


def durable_intent(directory, value):
    """Create the operator-readable, no-clobber pre-creation intent."""
    directory=Path(directory)
    info=os.lstat(directory)
    if not directory.is_absolute() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise ValueError('unsafe fixture directory')
    path=directory/'intent.json'
    raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    if len(raw)>4096: raise ValueError('fixture intent bound')
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:
        out.write(raw); out.flush(); os.fsync(out.fileno())
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def cleanup_owned(call,inspect,token,network_id,cid,image_id,network_attempted,container_attempted):
    if container_attempted and cid is None: raise RuntimeError('ambiguous postgres ownership')
    if network_attempted and network_id is None: raise RuntimeError('ambiguous network ownership')
    if cid is not None:
        phase=validate_postgres(inspect(['docker','inspect',cid]),token,cid,image_id,network_id)
        validate_network(inspect(['docker','network','inspect',network_id]),token,network_id,[] if phase=='created' else [cid])
        call(['docker','rm','-f',cid])
        if call(['docker','ps','-aq','--no-trunc','--filter','label='+LABEL+'='+token]): raise RuntimeError('fixture container cleanup incomplete')
    if network_id is not None:
        validate_network(inspect(['docker','network','inspect',network_id]),token,network_id,[])
        call(['docker','network','rm',network_id])
        if call(['docker','network','ls','-q','--no-trunc','--filter','label='+LABEL+'='+token]): raise RuntimeError('fixture network cleanup incomplete')


CRASH_LOG=re.compile(rb'(?i)(?:server process .*?(?:terminated by signal|exited with exit code|terminated by exception)|abnormal termination of server process|terminating any other active server processes|terminating connection because of crash of another server process|all server processes terminated; reinitializing|received immediate shutdown request|PANIC:|database system (?:was interrupted|was not properly shut down|is in recovery mode|is starting up|is not yet accepting connections)|consistent recovery state has not been yet reached)')


class ContinuityGuard:
    """Track a single unrelated session and postmaster across fault cleanup."""
    def __init__(self,cid,execute,read_logs):
        self.cid,self.execute,self.read_logs=cid,execute,read_logs
        self.name='origin21_guard_'+secrets.token_hex(16)
        self.child=None; self.identity=None; self.closed=False

    def postmaster(self):
        result=self.execute('SELECT floor(extract(epoch FROM pg_catalog.pg_postmaster_start_time())*1000000)::bigint::text;')
        if not re.fullmatch('[0-9]{1,20}',result): raise RuntimeError('invalid postmaster start')
        return result

    def predicate(self):
        if self.identity is None: raise RuntimeError('guard backend identity unavailable')
        pid,started=self.identity
        return ("pid="+str(pid)+" AND floor(extract(epoch FROM backend_start)*1000000)::bigint="+str(started)+
                " AND application_name='"+self.name+"' AND usename='postgres' AND datname='contour_local' AND backend_type='client backend' AND client_addr IS NULL")

    def start(self):
        self.postmaster_start=self.postmaster(); self.logs=self.read_logs()
        if type(self.logs) is not tuple or len(self.logs)!=2 or any(type(x) is not bytes for x in self.logs): raise RuntimeError('invalid fixture log snapshot')
        self.child=subprocess.Popen(['docker','exec','-i','-u','postgres','-e','PGAPPNAME='+self.name,self.cid,'psql','-XqAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','contour_local'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
        print('fixture phase=continuity-guard pid='+str(self.child.pid),flush=True)
        self.child.stdin.write(b"SELECT pg_backend_pid()::text||'|'||floor(extract(epoch FROM backend_start)*1000000)::bigint::text FROM pg_catalog.pg_stat_activity WHERE pid=pg_catalog.pg_backend_pid(); SELECT pg_sleep(120);\n"); self.child.stdin.flush()
        data=bytearray(); end=time.monotonic()+15
        while b'\n' not in data:
            if self.child.poll() is not None: raise RuntimeError('guard exited before identity')
            remaining=end-time.monotonic()
            if remaining<=0: raise TimeoutError('guard identity deadline')
            ready,_,_=select.select([self.child.stdout],[],[],remaining)
            if not ready: raise TimeoutError('guard identity deadline')
            part=os.read(self.child.stdout.fileno(),128-len(data))
            if not part: raise RuntimeError('guard identity missing')
            data.extend(part)
            if len(data)>=128: raise RuntimeError('guard output bound')
        match=re.fullmatch(rb'([1-9][0-9]{0,9})\|([1-9][0-9]{0,19})\n',data)
        if not match: raise RuntimeError('guard identity malformed')
        self.identity=tuple(map(int,match.groups()))
        end=time.monotonic()+10
        while self.execute('SELECT count(*)::text FROM pg_catalog.pg_stat_activity WHERE '+self.predicate()+" AND wait_event='PgSleep';")!='1':
            if self.child.poll() is not None: raise RuntimeError('guard process ended')
            if time.monotonic()>=end: raise TimeoutError('guard sleep deadline')
            time.sleep(.02)
        self.check()

    def check(self):
        if self.child is None or self.child.poll() is not None: raise RuntimeError('guard process ended')
        if self.postmaster()!=self.postmaster_start: raise RuntimeError('postmaster restarted')
        self.check_logs()
        if self.execute('SELECT count(*)::text FROM pg_catalog.pg_stat_activity WHERE '+self.predicate()+" AND wait_event='PgSleep';")!='1': raise RuntimeError('guard backend changed')

    def check_logs(self):
        current=self.read_logs()
        if type(current) is not tuple or len(current)!=2 or any(type(x) is not bytes for x in current): raise RuntimeError('invalid fixture log snapshot')
        for old,new in zip(self.logs,current):
            if not new.startswith(old) or len(CRASH_LOG.findall(new))!=len(CRASH_LOG.findall(old)): raise RuntimeError('postgres crash diagnostic detected')
        self.logs=current

    def close(self):
        if self.closed: raise RuntimeError('guard cleanup already attempted')
        self.closed=True
        if self.child is None: return
        if self.identity is None:
            if self.child.poll() is None: self.child.kill(); self.child.wait(timeout=5)
            raise RuntimeError('guard identity unavailable for exact cleanup')
        self.check()
        if self.execute('SELECT pg_catalog.pg_terminate_backend(pid)::text FROM pg_catalog.pg_stat_activity WHERE '+self.predicate()+';')!='true': raise RuntimeError('guard termination not confirmed')
        self.child.stdin.close(); self.child.wait(timeout=10)
        if self.execute('SELECT count(*)::text FROM pg_catalog.pg_stat_activity WHERE '+self.predicate()+';')!='0': raise RuntimeError('guard backend remains')
        if self.postmaster()!=self.postmaster_start: raise RuntimeError('postgres changed during guard cleanup')
        self.check_logs()
        os.set_blocking(self.child.stdout.fileno(),False)
        try: trailing=os.read(self.child.stdout.fileno(),129)
        except BlockingIOError: raise RuntimeError('guard output did not close') from None
        if trailing: raise RuntimeError('unexpected guard output')
        self.child.stdout.close()


def pending_identity(directory,target):
    from deploy.local import capture_renew, origin21_sql_runner
    value=capture_renew.exact_json(capture_renew.read_file(Path(directory)/'pending.json',4096))
    origin21_sql_runner._validate_intent(value,target)
    if value['identity'] is None: raise RuntimeError('supervisor has not reached durable READY')
    return value


def assert_group_absent(call,cid,pgid):
    if type(pgid) is not int or pgid<=1: raise ValueError('invalid supervisor group')
    script=('set -eu; group=$1; for p in /proc/[0-9]*/stat; do '
            'if ! s=$(cat "$p" 2>/dev/null); then [ ! -e "$p" ] && continue; exit 1; fi; '
            'r=${s##*) }; set -- $r; [ "$#" -ge 3 ] && [ "$3" != "$group" ] || exit 1; done')
    call(['docker','exec','-u','postgres',cid,'sh','-c',script,'origin21-group-check',str(pgid)],timeout=15)


def blocked_transaction(runner,directory,execute,call,cid,guard):
    """Require independent evidence of query entry before the parent deadline."""
    outcome=[]
    sql=guard+"BEGIN; SELECT nextval('public.origin21_qual_seq'); SELECT pg_sleep(30); INSERT INTO public.origin21_qual_rows VALUES (1); COMMIT;"
    def issue():
        try: runner.run(sql.encode(),'sql','postgres',deadline=2)
        except BaseException as error: outcome.append(error)
        else: outcome.append(None)
    thread=threading.Thread(target=issue,name='origin21-blocked',daemon=True); thread.start()
    evidence=None; end=time.monotonic()+15
    try:
        while time.monotonic()<end and thread.is_alive():
            try: pending=pending_identity(directory,runner.target)
            except FileNotFoundError:
                time.sleep(.01); continue
            except RuntimeError as error:
                if str(error)!='supervisor has not reached durable READY': raise
                time.sleep(.01); continue
            nonce=pending['nonce']
            sequence=execute("SELECT (last_value=1 AND is_called)::text FROM public.origin21_qual_seq;")
            sleeping=execute("SELECT count(*)::text FROM pg_catalog.pg_stat_activity WHERE application_name='origin21_"+nonce+"' AND usename='postgres' AND datname='contour_local' AND wait_event='PgSleep';")
            if sequence=='true' and sleeping=='1': evidence=pending; break
            time.sleep(.01)
    finally:
        thread.join(timeout=40)
        if thread.is_alive(): raise TimeoutError('blocked supervisor cleanup deadline')
    if evidence is None or len(outcome)!=1 or not isinstance(outcome[0],RuntimeError): raise RuntimeError('blocked query evidence missing')
    if os.path.lexists(Path(directory)/'pending.json'): raise RuntimeError('blocked supervisor unresolved')
    if execute('SELECT count(*)::text FROM public.origin21_qual_rows;')!='0': raise RuntimeError('blocked transaction did not roll back')
    if execute("SELECT count(*)::text FROM pg_catalog.pg_stat_activity WHERE application_name='origin21_"+evidence['nonce']+"' AND usename='postgres' AND datname='contour_local';")!='0': raise RuntimeError('blocked backend remains')
    assert_group_absent(call,cid,evidence['identity']['pgid'])
    if runner.run((guard+'SELECT 1;').encode(),'sql','postgres')!='1': raise RuntimeError('blocked recovery failed')


def private_case(argv):
    """Child accepts only a fixed synthetic query and fixture-owned descriptor."""
    if not argv or argv[0] not in ('crash-sleep','ack-loss') or len(argv)!=(4 if argv[0]=='ack-loss' else 2): raise ValueError('unsupported private fixture case')
    if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
    from deploy.local import capture_renew, origin21_sql_runner, origin21_transport
    folder=Path(argv[1]); state=(ROOT/'.local-mvp').resolve(strict=True)
    expected={'crash-sleep':'crash-case','ack-loss':'ack-case'}[argv[0]]
    if not folder.is_absolute() or folder.is_symlink() or folder.parent.parent!=state or not re.fullmatch('contour-origin21-qual-[0-9a-f]{32}',folder.parent.name) or folder.name!=expected: raise ValueError('invalid private fixture directory')
    capture_renew.safe_dir(folder); capture_renew.safe_dir(folder.parent)
    value=capture_renew.exact_json(capture_renew.read_file(folder/'intent.json',4096))
    if type(value) is not dict or set(value)!={'deployment'}: raise ValueError('invalid private fixture descriptor')
    transport=folder/'transport'; capture_renew.safe_dir(transport)
    runner=origin21_sql_runner.for_deployment(transport,value['deployment'])
    if argv[0]=='ack-loss':
        if any(not re.fullmatch('[0-9]{1,10}',x) or int(x)<3 for x in argv[2:]) or argv[2]==argv[3]: raise ValueError('invalid private relay descriptors')
        payload_fd,control_fd=map(int,argv[2:])
        control=socket.socket(fileno=control_fd)
        launch=runner.launch
        def hold_ack(nonce,mode,role,size):
            process=launch(nonce,mode,role,size)
            rights=array.array('i',[process.stdin.fileno()])
            if control.sendmsg([size.to_bytes(8,'big')],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,rights)])!=8: raise RuntimeError('private relay handoff failed')
            control.close(); process.stdin.close(); process.stdin=os.fdopen(payload_fd,'wb',buffering=0)
            return process
        runner.launch=hold_ack
        sql=origin21_transport.GUARD+'BEGIN; INSERT INTO public.origin21_qual_rows VALUES (2); COMMIT; SELECT 1;'
    else:
        sql=origin21_transport.GUARD+"BEGIN; SELECT nextval('public.origin21_qual_seq'); SELECT pg_sleep(30); INSERT INTO public.origin21_qual_rows VALUES (1); COMMIT;"
    runner.run(sql.encode(),'sql','postgres',deadline=60)
    raise RuntimeError('private crash case unexpectedly returned')


def relay_case(argv):
    """Forward exactly the private payload, record and hold its ACK, then exit."""
    if len(argv)!=3 or any(not re.fullmatch('[0-9]{1,10}',x) or int(x)<3 for x in argv[:2]): raise ValueError('invalid relay arguments')
    source,control_fd=map(int,argv[:2]); folder=Path(argv[2]); state=(ROOT/'.local-mvp').resolve(strict=True)
    if source==control_fd or not folder.is_absolute() or folder.is_symlink() or folder.parent.parent!=state or not re.fullmatch('contour-origin21-qual-[0-9a-f]{32}',folder.parent.name) or folder.name!='ack-case': raise ValueError('invalid relay scope')
    # This process is a direct child of the qualification driver, which retains
    # its Popen identity and reaps it on every path, including before publication.
    def expired(*_): raise TimeoutError('private relay absolute deadline')
    previous=signal.signal(signal.SIGALRM,expired)
    signal.setitimer(signal.ITIMER_REAL,RELAY_DEADLINE_SECONDS)
    control=socket.socket(fileno=control_fd); targets=[]
    try:
        started=folder/'relay'; os.mkdir(started,0o700)
        durable_intent(started,{'event':'relay-started','pid':os.getpid()})
        raw,ancillary,flags,_=control.recvmsg(8,socket.CMSG_SPACE(array.array('i').itemsize))
        for level,kind,data in ancillary:
            if level!=socket.SOL_SOCKET or kind!=socket.SCM_RIGHTS or len(data)%array.array('i').itemsize: raise RuntimeError('invalid relay rights')
            descriptors=array.array('i'); descriptors.frombytes(data); targets.extend(descriptors)
        if flags or len(raw)!=8 or len(targets)!=1: raise RuntimeError('invalid relay handoff')
        target=targets[0]; size=int.from_bytes(raw,'big')
        if not 1<=size<=8*1024*1024: raise RuntimeError('invalid relay size')
        left=size
        while left:
            chunk=os.read(source,min(65536,left))
            if not chunk: raise RuntimeError('private relay input truncated')
            offset=0
            while offset<len(chunk): offset+=os.write(target,chunk[offset:])
            left-=len(chunk)
        ack=b''
        while len(ack)<4:
            chunk=os.read(source,4-len(ack))
            if not chunk: raise RuntimeError('private relay ACK absent')
            ack+=chunk
        if ack!=b'ACK!': raise RuntimeError('invalid private relay ACK')
        marker=folder/'ack'; os.mkdir(marker,0o700)
        durable_intent(marker,{'event':'ACK-held','pid':os.getpid()})
        time.sleep(13)
    finally:
        signal.setitimer(signal.ITIMER_REAL,0); signal.signal(signal.SIGALRM,previous)
        control.close(); os.close(source)
        for target in targets: os.close(target)


def wait_for_sleep(process,directory,target,execute,timeout=15):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if process.poll() is not None: raise RuntimeError('private case exited before query entry')
        try: pending=pending_identity(directory,target)
        except FileNotFoundError:
            time.sleep(.02); continue
        except RuntimeError as error:
            if str(error)!='supervisor has not reached durable READY': raise
            time.sleep(.02); continue
        seq=execute('SELECT (last_value=1 AND is_called)::text FROM public.origin21_qual_seq;')
        sleeping=execute("SELECT count(*)::text FROM pg_catalog.pg_stat_activity WHERE application_name='origin21_"+pending['nonce']+"' AND usename='postgres' AND datname='contour_local' AND wait_event='PgSleep';")
        if seq=='true' and sleeping=='1': return pending
        time.sleep(.02)
    raise TimeoutError('private query entry deadline')


def crashed_parent(folder,deployment,execute,call,cid,guard):
    from deploy.local import origin21_sql_runner
    case=Path(folder)/'crash-case'; os.mkdir(case,0o700)
    durable_intent(case,{'deployment':deployment})
    transport=case/'transport'; os.mkdir(transport,0o700)
    execute('ALTER SEQUENCE public.origin21_qual_seq RESTART WITH 1;')
    child=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--private-case','crash-sleep',str(case)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    print('fixture phase=local-death pid='+str(child.pid),flush=True)
    try:
        target={'container_id':cid,'image_id':deployment['postgres_image_id'],'network_id':deployment['id']}
        pending=wait_for_sleep(child,transport,target,execute)
        child.kill(); child.wait(timeout=5)
        if child.returncode!=-9: raise RuntimeError('private case kill failed')
        if pending_identity(transport,target)!=pending: raise RuntimeError('crash intent changed')
        runner=origin21_sql_runner.for_deployment(transport,deployment)
        if runner.run((guard+'SELECT 1;').encode(),'sql','postgres')!='1': raise RuntimeError('crash recovery query failed')
        if os.path.lexists(transport/'pending.json'): raise RuntimeError('crash intent unresolved')
        if execute('SELECT count(*)::text FROM public.origin21_qual_rows;')!='0': raise RuntimeError('crash transaction did not roll back')
        if execute("SELECT count(*)::text FROM pg_catalog.pg_stat_activity WHERE application_name='origin21_"+pending['nonce']+"' AND usename='postgres' AND datname='contour_local';")!='0': raise RuntimeError('crash backend remains')
        assert_group_absent(call,cid,pending['identity']['pgid'])
    finally:
        if child.poll() is None:
            child.kill(); child.wait(timeout=5)


def lost_ack(folder,deployment,execute,call,cid,guard):
    from deploy.local import capture_renew, origin21_sql_runner
    case=Path(folder)/'ack-case'; os.mkdir(case,0o700)
    durable_intent(case,{'deployment':deployment})
    transport=case/'transport'; os.mkdir(transport,0o700)
    target={'container_id':cid,'image_id':deployment['postgres_image_id'],'network_id':deployment['id']}
    source,sink=os.pipe(); control,relay_control=socket.socketpair(type=socket.SOCK_DGRAM)
    relay=child=None
    try:
        relay=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--private-relay',str(source),str(relay_control.fileno()),str(case)],pass_fds=(source,relay_control.fileno()),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        os.close(source); source=None; relay_control.close()
        child=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--private-case','ack-loss',str(case),str(sink),str(control.fileno())],pass_fds=(sink,control.fileno()),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        os.close(sink); sink=None; control.close()
        print('fixture phase=ack-loss pid='+str(child.pid)+' relay_pid='+str(relay.pid),flush=True)
        end=time.monotonic()+20; marker=case/'ack'/'intent.json'
        while not marker.exists():
            if child.poll() is not None: raise RuntimeError('ACK fixture exited early')
            if relay.poll() is not None: raise RuntimeError('ACK relay exited early')
            if time.monotonic()>=end: raise TimeoutError('ACK hold deadline')
            time.sleep(.02)
        held=capture_renew.exact_json(capture_renew.read_file(marker,4096))
        if type(held) is not dict or set(held)!={'event','pid'} or held['event']!='ACK-held' or held['pid']!=relay.pid: raise RuntimeError('invalid ACK hold marker')
        pending=pending_identity(transport,target)
        if execute('SELECT count(*)::text FROM public.origin21_qual_rows WHERE id=2;')!='1': raise RuntimeError('ACK fixture did not commit once')
        child.kill(); child.wait(timeout=5)
        if child.returncode!=-9: raise RuntimeError('ACK fixture kill failed')
        # The relay keeps the ACK pipe open while the remote supervisor's
        # ten-second ACK deadline elapses; never infer absence from the sleep.
        earliest=time.monotonic()+10.5; deadline=time.monotonic()+25
        while True:
            try:
                assert_group_absent(call,cid,pending['identity']['pgid']); absent=True
            except RuntimeError: absent=False
            if absent and time.monotonic()>=earliest: break
            if time.monotonic()>=deadline: raise TimeoutError('ACK supervisor exit deadline')
            time.sleep(.1)
        relay.wait(timeout=max(.01,deadline-time.monotonic()))
        if relay.returncode!=0: raise RuntimeError('ACK relay failed')
        if pending_identity(transport,target)!=pending: raise RuntimeError('ACK intent changed')
        runner=origin21_sql_runner.for_deployment(transport,deployment)
        if runner.run((guard+'SELECT 1;').encode(),'sql','postgres')!='1': raise RuntimeError('ACK recovery query failed')
        if os.path.lexists(transport/'pending.json'): raise RuntimeError('ACK intent unresolved')
        if execute('SELECT count(*)::text FROM public.origin21_qual_rows WHERE id=2;')!='1': raise RuntimeError('ACK recovery changed commit count')
        if execute("SELECT count(*)::text FROM pg_catalog.pg_stat_activity WHERE application_name='origin21_"+pending['nonce']+"' AND usename='postgres' AND datname='contour_local';")!='0': raise RuntimeError('ACK backend remains')
        assert_group_absent(call,cid,pending['identity']['pgid'])
    finally:
        primary=sys.exc_info()[1]; failures=[]
        # Popen handles retained by this parent remain the cleanup authority even
        # when either child's first durable marker was never published.
        for process in (child,relay):
            if process is None: continue
            try:
                if process.poll() is None: process.kill()
                process.wait(timeout=5)
            except BaseException as cleanup: failures.append(cleanup)
        for fd in (source,sink):
            if fd is not None:
                try: os.close(fd)
                except BaseException as cleanup: failures.append(cleanup)
        for channel in (control,relay_control):
            try: channel.close()
            except BaseException as cleanup: failures.append(cleanup)
        if failures: raise BaseExceptionGroup('ACK case and owned child cleanup failure',([primary] if primary is not None else [])+failures) from None


def foreign_session(runner,directory,execute,call,cid,guard):
    """A TLS TCP login with the same public app name must survive cleanup."""
    password=secrets.token_hex(32); role='origin21_qual_foreign'
    execute("CREATE ROLE "+role+" LOGIN PASSWORD '"+password+"'; GRANT CONNECT ON DATABASE contour_local TO "+role+";")
    execute('ALTER SEQUENCE public.origin21_qual_seq RESTART WITH 1;')
    real_launch=runner.launch; foreign={}; primary=None
    def launch(nonce,mode,dbrole,size):
        if mode!='sql' or dbrole!='postgres': raise RuntimeError('invalid foreign-session launch')
        if foreign: return real_launch(nonce,mode,dbrole,size)
        script=('IFS= read -r PGPASSWORD; export PGPASSWORD PGSSLMODE=verify-full PGSSLROOTCERT=/run/local-ca.crt; '
                'export PGAPPNAME="$1"; exec psql -X -qAt -w -h localhost -U origin21_qual_foreign -d contour_local')
        child=subprocess.Popen(['docker','exec','-i','-u','postgres',cid,'sh','-c',script,'origin21-foreign','origin21_'+nonce],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        foreign.update(child=child,nonce=nonce)
        print('fixture phase=foreign-tcp pid='+str(child.pid),flush=True)
        child.stdin.write((password+'\nSELECT pg_sleep(30);\n').encode()); child.stdin.flush()
        end=time.monotonic()+10
        while time.monotonic()<end:
            if child.poll() is not None: raise RuntimeError('foreign session exited early')
            rows=execute("SELECT pid::text||'|'||floor(extract(epoch FROM backend_start)*1000000)::bigint::text FROM pg_catalog.pg_stat_activity WHERE application_name='origin21_"+nonce+"' AND usename='"+role+"' AND backend_type='client backend' AND client_addr IN ('127.0.0.1'::inet,'::1'::inet) AND wait_event='PgSleep';")
            if re.fullmatch('[0-9]+\\|[0-9]+',rows):
                foreign['pid'],foreign['start']=map(int,rows.split('|')); break
            time.sleep(.02)
        else: raise TimeoutError('foreign session entry deadline')
        return real_launch(nonce,mode,dbrole,size)
    runner.launch=launch
    try:
        blocked_transaction(runner,directory,execute,call,cid,guard)
        if not foreign or foreign['child'].poll() is not None: raise RuntimeError('foreign session did not survive')
        predicate=foreign_predicate(foreign,role)
        if execute('SELECT count(*)::text FROM pg_catalog.pg_stat_activity WHERE '+predicate+';')!='1': raise RuntimeError('foreign backend did not survive')
    except BaseException as error:
        primary=error
    finally:
        runner.launch=real_launch
        child=foreign.get('child')
        try:
            if child is not None and 'pid' in foreign:
                predicate=foreign_predicate(foreign,role)
                execute('SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE '+predicate+';')
                child.wait(timeout=10)
                if execute('SELECT count(*)::text FROM pg_catalog.pg_stat_activity WHERE '+predicate+';')!='0': raise RuntimeError('foreign backend cleanup incomplete')
            elif child is not None:
                if child.poll() is None:
                    child.kill(); child.wait(timeout=5)
                raise RuntimeError('foreign backend identity unavailable')
            execute('REVOKE CONNECT ON DATABASE contour_local FROM '+role+'; DROP ROLE '+role+';')
        except BaseException as cleanup:
            if primary is not None: raise BaseExceptionGroup('foreign case and cleanup failure',[primary,cleanup]) from None
            raise
    if primary is not None: raise primary


def foreign_predicate(foreign,role):
    if role!='origin21_qual_foreign' or not re.fullmatch('[0-9a-f]{32}',foreign.get('nonce','')) or type(foreign.get('pid')) is not int or foreign['pid']<=1 or type(foreign.get('start')) is not int or foreign['start']<=0: raise ValueError('invalid foreign backend identity')
    return ("pid="+str(foreign['pid'])+" AND floor(extract(epoch FROM backend_start)*1000000)::bigint="+str(foreign['start'])+
            " AND application_name='origin21_"+foreign['nonce']+"' AND usename='"+role+"' AND datname='contour_local' AND backend_type='client backend' AND client_addr IN ('127.0.0.1'::inet,'::1'::inet)")


def main(argv):
    if argv!=['--transport-only']: raise ValueError('expected --transport-only')
    os.umask(0o077)
    if not (ROOT/'.git').is_file() or (ROOT/'.git').is_symlink(): raise ValueError('isolated git worktree required')
    if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
    from deploy.local import capture_renew, origin21_schema, origin21_sql_runner, origin21_state, origin21_transport, provision
    state=ROOT/'.local-mvp'
    try: os.mkdir(state,0o700)
    except FileExistsError: pass
    capture_renew.safe_dir(state)
    if any(os.path.lexists(state/name) for name in ('ca.crt','ca.key')): raise ValueError('fixture CA already exists')
    helper=ROOT/'scripts/test-postgres-causal-bridge.py'
    sources=[ROOT/name for name in origin21_state.SOURCE_FILES]+[Path(__file__).resolve(),helper,ROOT/'tests/fixtures/origin21-onboarding/test_driver.py',ROOT/'db/bootstrap.sql']
    sources += sorted((ROOT/'db/migrations').glob('*.sql'))+[ROOT/('db/provision_'+name+'.sql') for name in provision.PROVISION]
    def snapshot():
        return {str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}
    before=snapshot(); helpers=runpy.run_path(str(helper)); run=helpers['run_process']
    if snapshot()!=before: raise RuntimeError('fixture source changed')
    def call(args, data=None, timeout=30):
        result=run(args,data=data,timeout=timeout,limit=8*1024*1024)
        if result.returncode: raise RuntimeError('fixture command failed')
        return result.stdout.strip()
    def inspect(args):
        value=json.loads(call(args))
        if not isinstance(value,list) or len(value)!=1 or not isinstance(value[0],dict): raise RuntimeError('fixture inspection failed')
        return value[0]
    token=secrets.token_hex(16); name='contour-origin21-qual-'+token
    folder=state/name; os.mkdir(folder,0o700)
    dfd=os.open(state,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(dfd)
    finally: os.close(dfd)
    durable_intent(folder,{'version':1,'owner':token,'network':name,'image':IMAGE,'scope':'transport-smoke'})
    print('Private fixture state: '+str(folder),flush=True)
    network_id=cid=image_id=None; network_attempted=container_attempted=False; ca_owned=None
    failure=None; phase='fixture-setup'; guard=None
    previous_handler=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('fixture absolute deadline')))
    signal.setitimer(signal.ITIMER_REAL,120)
    try:
        image=inspect(['docker','image','inspect',IMAGE]); image_id=image.get('Id','')
        if not re.fullmatch('sha256:[0-9a-f]{64}',image_id): raise RuntimeError('fixture image unavailable')
        ca=state/'ca.crt'; generated_ca=folder/'ca.crt'; cakey=folder/'ca.key'; cert=folder/'server.crt'; key=folder/'server.key'
        req=folder/'request.cnf'; req.write_text('[req]\ndistinguished_name=dn\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
        extensions=folder/'extensions'; extensions.write_text('subjectAltName=DNS:localhost,DNS:postgres\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n')
        call(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-sha256','-config',str(req),'-extensions','ca','-subj','/CN=origin21 synthetic CA','-keyout',str(cakey),'-out',str(generated_ca)],timeout=30)
        ca_bytes=generated_ca.read_bytes()
        fd=os.open(ca,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as out:
            ca_owned=(os.fstat(out.fileno()).st_ino,hashlib.sha256(ca_bytes).hexdigest())
            out.write(ca_bytes); out.flush(); os.fsync(out.fileno())
        fd=os.open(state,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
        call(['openssl','req','-new','-newkey','rsa:2048','-nodes','-sha256','-subj','/CN=localhost','-keyout',str(key),'-out',str(folder/'server.csr')],timeout=30)
        call(['openssl','x509','-req','-in',str(folder/'server.csr'),'-CA',str(ca),'-CAkey',str(cakey),'-CAcreateserial','-days','1','-extfile',str(extensions),'-out',str(cert)],timeout=30)
        password=folder/'initial-secret'; password.write_text(secrets.token_hex(32)); os.chmod(password,0o600)
        network_attempted=True
        network_id=call(['docker','network','create','--internal','--label',LABEL+'='+token,name]).decode('ascii')
        if not re.fullmatch('[0-9a-f]{64}',network_id): network_id=None; raise RuntimeError('ambiguous network creation')
        durable_id(folder,'network',network_id)
        validate_network(inspect(['docker','network','inspect',network_id]),token,network_id,[])
        container_attempted=True
        cid=call(['docker','create','--init','--pull=never','--name',name+'-postgres','--label',LABEL+'='+token,'--network',network_id,'--network-alias','postgres','--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql/data:rw,nosuid,noexec,size=256m','-e','POSTGRES_DB=contour_local','-e','POSTGRES_PASSWORD_FILE=/tmp/initial-secret',IMAGE,'sh','-c','chown postgres:postgres /tmp/server.key /tmp/server.crt /run/local-ca.crt && chmod 600 /tmp/server.key /run/local-ca.crt && exec docker-entrypoint.sh postgres -c listen_addresses=* -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key']).decode('ascii')
        if not re.fullmatch('[0-9a-f]{64}',cid): cid=None; raise RuntimeError('ambiguous postgres creation')
        durable_id(folder,'postgres',cid)
        if validate_postgres(inspect(['docker','inspect',cid]),token,cid,image_id,network_id)!='created': raise RuntimeError('fixture started before explicit command')
        validate_network(inspect(['docker','network','inspect',network_id]),token,network_id,[])
        for source,dest in ((ca,'/run/local-ca.crt'),(cert,'/tmp/server.crt'),(key,'/tmp/server.key'),(password,'/tmp/initial-secret')):
            call(['docker','cp',str(source),cid+':'+dest])
        call(['docker','start',cid])
        deadline=time.monotonic()+60
        while True:
            result=run(['docker','exec',cid,'sh','-c','test "$(cat /proc/1/comm)" = docker-init && p=$(head -n 1 /var/lib/postgresql/data/postmaster.pid) && case "$p" in *[!0-9]*|\'\') exit 1;; esac && test "$p" -gt 1 && test "$(cat /proc/$p/comm)" = postgres && pg_isready -U postgres -d contour_local'],timeout=5)
            if result.returncode==0: break
            if time.monotonic()>=deadline: raise TimeoutError('postgres startup deadline')
            time.sleep(.2)
        if validate_postgres(inspect(['docker','inspect',cid]),token,cid,image_id,network_id)!='running': raise RuntimeError('fixture not running')
        validate_network(inspect(['docker','network','inspect',network_id]),token,network_id,[cid])
        def execute(sql):
            return call(['docker','exec','-i','-u','postgres',cid,'psql','-XqAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','contour_local'],data=sql.encode(),timeout=120).decode().strip()
        execute((ROOT/'db/bootstrap.sql').read_text())
        for kind in provision.PROVISION: execute((ROOT/('db/provision_'+kind+'.sql')).read_text())
        migrations=sorted((ROOT/'db/migrations').glob('*.sql'))
        if [int(path.name[:4]) for path in migrations]!=list(range(1,15)): raise RuntimeError('baseline migration drift')
        for path in migrations: execute(path.read_text())
        def login(role,groups):
            return 'CREATE ROLE '+role+" LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD '"+secrets.token_hex(32)+"'; GRANT "+','.join(groups)+' TO '+role+'; GRANT CONNECT ON DATABASE contour_local TO '+role+'; '
        execute('BEGIN; '+login('contour_app',provision.GROUPS)+login('contour_local_ingress',['contour_ingestion'])+login('contour_local_worker',['contour_catalog_worker'])+'COMMIT;')
        t,p,s,e=map(provision.sql_quote,provision.IDS)
        execute(f'BEGIN; INSERT INTO contour.tenants VALUES ({t}); INSERT INTO contour.projects VALUES ({t},{p}); INSERT INTO contour.services VALUES ({t},{s},{p}); INSERT INTO contour.environments VALUES ({t},{e},{p}); COMMIT;')
        origin21_schema.require_ready(list(range(1,15)),execute,stage=14,phase='pre')
        deployment={'name':name,'id':network_id,'owner_kind':'fixture','owner_token':token,'postgres_id':cid,'postgres_image_id':image_id,'ca_sha256':ca_owned[1]}
        transport=folder/'transport'; os.mkdir(transport,0o700)
        runner=origin21_sql_runner.for_deployment(transport,deployment)
        phase='select-one'
        if runner.run((origin21_transport.GUARD+'SELECT 1;').encode(),'sql','postgres')!='1': raise RuntimeError('transport smoke mismatch')
        execute('CREATE SEQUENCE public.origin21_qual_seq; CREATE TABLE public.origin21_qual_rows (id integer NOT NULL);')
        def logs():
            result=run(['docker','logs',cid],timeout=20,limit=8*1024*1024)
            if result.returncode: raise RuntimeError('fixture logs unavailable')
            return result.stdout,result.stderr
        phase='continuity-guard'; guard=ContinuityGuard(cid,execute,logs); guard.start()
        phase='blocked-transaction'
        blocked_transaction(runner,transport,execute,call,cid,origin21_transport.GUARD)
        guard.check()
        phase='local-death'
        crashed_parent(folder,deployment,execute,call,cid,origin21_transport.GUARD)
        guard.check()
        phase='lost-ack'
        lost_ack(folder,deployment,execute,call,cid,origin21_transport.GUARD)
        guard.check()
        execute('TRUNCATE TABLE public.origin21_qual_rows;')
        phase='foreign-tcp'
        foreign_session(runner,transport,execute,call,cid,origin21_transport.GUARD)
        guard.check()
        phase='fixture-final-check'
        guard.close(); guard=None
        execute('DROP TABLE public.origin21_qual_rows; DROP SEQUENCE public.origin21_qual_seq;')
        origin21_schema.require_ready(list(range(1,15)),execute,stage=14,phase='pre')
        if snapshot()!=before: raise RuntimeError('fixture source changed')
    except BaseException as error:
        failure=error
        print('fixture failure phase='+phase+' type='+type(error).__name__+' location='+failure_location(error),file=sys.stderr,flush=True)
    finally:
        signal.setitimer(signal.ITIMER_REAL,0); signal.signal(signal.SIGALRM,previous_handler)
    cleanup_failures=[]
    if guard is not None and not guard.closed:
        try: guard.close()
        except BaseException as error: cleanup_failures.append(error)
    try:
        cleanup_owned(call,inspect,token,network_id,cid,image_id,network_attempted,container_attempted)
        if ca_owned is not None:
            if (os.lstat(state/'ca.crt').st_ino,hashlib.sha256((state/'ca.crt').read_bytes()).hexdigest())!=ca_owned: raise RuntimeError('fixture CA identity changed')
            capture_renew.remove_durable(state/'ca.crt')
    except BaseException as cleanup:
        cleanup_failures.append(cleanup)
    if guard is not None and guard.child is not None:
        try:
            if guard.child.poll() is None: guard.child.kill()
            guard.child.wait(timeout=5)
            for stream in (guard.child.stdin,guard.child.stdout):
                if stream is not None and not stream.closed: stream.close()
        except BaseException as cleanup:
            cleanup_failures.append(cleanup)
    if cleanup_failures:
        print('fixture failure phase=owned-cleanup type=CleanupFailure',file=sys.stderr,flush=True)
        raise BaseExceptionGroup('fixture and cleanup failure',([failure] if failure is not None else [])+cleanup_failures) from None
    if failure is not None: raise RuntimeError('fixture transport smoke failed') from None
    print('PASS: synthetic transport SELECT 1, timeout rollback, local-death, lost-ACK and foreign-session controls; onboarding not verified')


def durable_id(folder,kind,value):
    if kind not in ('network','postgres') or not re.fullmatch('[0-9a-f]{64}',value): raise ValueError('invalid fixture identity')
    child=Path(folder)/kind; os.mkdir(child,0o700)
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
    durable_intent(child,{'id':value})


if __name__=='__main__':
    try:
        if len(sys.argv)>1 and sys.argv[1]=='--private-case': private_case(sys.argv[2:])
        elif len(sys.argv)>1 and sys.argv[1]=='--private-relay': relay_case(sys.argv[2:])
        else: main(sys.argv[1:])
    except Exception:
        print('origin21 qualification incomplete or failed',file=sys.stderr)
        raise SystemExit(1) from None
