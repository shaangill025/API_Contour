#!/usr/bin/env python3
"""Owned, synthetic SQL28 TLS reader fixture preparation; no peer proof."""
import re

LABEL='org.apicontour.fixture-owner'
NETWORK_OPTIONS={'com.docker.network.bridge.enable_ip_masquerade':'false','com.docker.network.enable_ipv4':'true','com.docker.network.enable_ipv6':'false'}
IMAGE='postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4'
HEX64=re.compile(r'[0-9a-f]{64}\Z')
TOKEN=re.compile(r'[0-9a-f]{32}\Z')

PHASE='arguments'
PHASES=frozenset(('arguments','source','tls','build','image','network','container','start','readiness','schema','seed','probe','closed','revoked','issuer','gateway','cleanup'))
ERROR_TYPES=frozenset(('ValueError','RuntimeError','TimeoutError','OSError','PermissionError','FileNotFoundError','BaseExceptionGroup','ExceptionGroup'))
LOCATION_FILES=frozenset(('test-postgres-causal-receiver-reader.py','receiver_issuer_fixture.py','gateway_reader_fixture.py','fixture_psql_transport.py','capture-origin25-reference.py','test-causal-receiver-enrollment.py','test-causal-evidence-enrollment.py','origin25_schema.py'))

def failure_diagnostic(error,phase):
    kind=type(error).__name__; kind=kind if kind in ERROR_TYPES else 'OtherError'
    phase=phase if phase in PHASES else 'other'
    frames=[];tb=error.__traceback__
    while tb is not None:
        from pathlib import Path
        name=Path(tb.tb_frame.f_code.co_filename).name
        if name in LOCATION_FILES and 1<=tb.tb_lineno<=99999: frames.append(name+':'+str(tb.tb_lineno))
        tb=tb.tb_next
    return 'FAIL receiver_reader_fixture phase='+phase+' type='+kind+' location='+(','.join(frames[-6:]) or 'unavailable')

START=re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z\Z')


def validate_network(item, token, network_id, members):
    if not TOKEN.fullmatch(token) or not HEX64.fullmatch(network_id): raise ValueError('identity')
    if (type(item) is not dict or item.get('Id')!=network_id or item.get('Name')!='contour-origin21-qual-'+token
        or item.get('Internal') is not False or item.get('Driver')!='bridge'
        or item.get('Options')!=NETWORK_OPTIONS or (item.get('Labels') or {}).get(LABEL)!=token
        or type(item.get('Containers')) is not dict or set(item['Containers'])!=set(members)):
        raise ValueError('network')


def validate_container(item,token,cid,image_id,network_id,expected_cmd,expected_env,started=None,*,allow_stopped=False):
    if (not TOKEN.fullmatch(token) or not HEX64.fullmatch(cid) or not HEX64.fullmatch(network_id)
        or not re.fullmatch(r'sha256:[0-9a-f]{64}',image_id)): raise ValueError('identity')
    if type(item) is not dict: raise ValueError('container')
    cfg=item.get('Config') or {}; host=item.get('HostConfig') or {}; state=item.get('State') or {}
    ns=item.get('NetworkSettings') or {}; networks=ns.get('Networks') or {}; name='contour-origin21-qual-'+token
    entry=networks.get(name) or {}; bindings=host.get('PortBindings') or {}
    if (item.get('Id')!=cid or item.get('Name')!='/'+name+'-postgres' or item.get('Image')!=image_id
        or cfg.get('Image')!=IMAGE or (cfg.get('Labels') or {}).get(LABEL)!=token or cfg.get('Cmd')!=expected_cmd
        or sorted(cfg.get('Env') or [])!=sorted(expected_env) or host.get('Init') is not True
        or host.get('Privileged') is not False or host.get('PublishAllPorts') is not False
        or host.get('NetworkMode')!=network_id or set(networks)!={name} or 'postgres' not in (entry.get('Aliases') or [])
        or bindings!={'5432/tcp':[{'HostIp':'127.0.0.1','HostPort':''}]}
        or item.get('Mounts')!=[] or host.get('Binds') not in (None,[]) or host.get('CapAdd') not in (None,[])
        or host.get('Memory')!=536870912 or host.get('NanoCpus')!=1000000000 or host.get('PidsLimit')!=128
        or host.get('Tmpfs')!={'/var/lib/postgresql/data':'rw,nosuid,noexec,size=256m'}):
        raise ValueError('container')
    if started is None:
        if state.get('Status')!='created' or state.get('Running') is not False or state.get('Pid')!=0 or entry.get('NetworkID')!='' or entry.get('EndpointID','')!='': raise ValueError('created')
        return None
    stopped=allow_stopped and state.get('Status')=='exited' and state.get('Running') is False and state.get('Pid')==0
    if not isinstance(started,str) or not START.fullmatch(started) or started.startswith('0001-') or state.get('StartedAt')!=started or entry.get('NetworkID')!=network_id: raise ValueError('generation')
    if not stopped and (state.get('Status')!='running' or state.get('Running') is not True or type(state.get('Pid')) is not int or state['Pid']<2): raise ValueError('generation')
    import datetime
    try: datetime.datetime.fromisoformat(started.replace('Z','+00:00'))
    except ValueError: raise ValueError('generation') from None
    if stopped:return None
    ports=ns.get('Ports') or {}; ports5432=ports.get('5432/tcp')
    if set(ports)!={'5432/tcp'} or type(ports5432) is not list or len(ports5432)!=1 or ports5432[0].get('HostIp')!='127.0.0.1': raise ValueError('port')
    port=ports5432[0].get('HostPort');
    if not isinstance(port,str) or not re.fullmatch('[0-9]{1,5}',port) or not 1<=int(port)<=65535: raise ValueError('port')
    return int(port)


class ToolFence:
    """Bind each qualified Docker invocation to the same tool, socket and config."""
    def __init__(self, metadata, config, process, env):
        self.metadata=metadata; self.config=config; self.process=process; self.env=dict(env)
        self.tool=metadata._tool(metadata.DOCKER,True)
        self.socket=metadata._socket(metadata.SOCKET)
        self.config_identity=metadata._config(config)
    def check(self):
        m=self.metadata
        if (m._tool(m.DOCKER,True)!=self.tool or m._socket(m.SOCKET)!=self.socket
            or m._config(self.config)!=self.config_identity): raise RuntimeError('fixture tool context changed')
    def call(self, args, *, data=None, timeout=30, limit=8*1024*1024):
        if type(args) is not list or not args or args[0]!='docker': raise ValueError('unsupported fixture command')
        self.check()
        result=self.process([self.metadata.DOCKER,'--config',str(self.config),'--host','unix://'+self.metadata.SOCKET,*args[1:]],
                            data=data,timeout=timeout,env=self.env,limit=limit)
        self.check()
        if result.returncode or result.stderr: raise RuntimeError('fixture command failed')
        return result.stdout.strip()


def select_probe(lines, target, source, *, issuer=False, gateway=False):
    """Select exactly one executable emitted by this build in its private target."""
    import hashlib, json, os, stat
    from pathlib import Path
    if type(issuer) is not bool or type(gateway) is not bool or (issuer and gateway): raise ValueError('artifact')
    target=Path(target); source=Path(source); found=[]
    expected='causal_gateway_reader_probe' if gateway else ('causal_receiver_issuer_probe' if issuer else 'causal_receiver_reader_probe')
    if not target.is_absolute() or target.is_symlink() or not target.is_dir(): raise ValueError('target')
    for line in lines:
        try: item=json.loads(line)
        except (ValueError,UnicodeDecodeError): raise ValueError('cargo output') from None
        t=item.get('target') or {}
        if (item.get('reason')!='compiler-artifact' or t.get('name')!=expected
            or t.get('kind')!=['example'] or t.get('src_path')!=str(source) or (item.get('profile') or {}).get('test',False)):
            continue
        name=item.get('executable')
        if type(name) is not str: raise ValueError('artifact')
        path=Path(name)
        if not path.is_absolute() or '..' in path.parts: raise ValueError('artifact')
        for part in (path,*path.parents):
            if part.is_symlink(): raise ValueError('artifact')
        path.resolve(strict=True).relative_to(target.resolve(strict=True))
        info=path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or not os.access(path,os.X_OK): raise ValueError('artifact')
        with path.open('rb') as f:
            digest=hashlib.file_digest(f,'sha256').hexdigest()
        found.append((path,digest))
    if len(found)!=1: raise ValueError('artifact')
    return found[0]


def configuration_snapshot(item):
    import copy
    keys=('Id','Name','Image','Config','HostConfig','Mounts')
    if type(item) is not dict or any(k not in item for k in keys): raise ValueError('container')
    return {k:copy.deepcopy(item[k]) for k in keys}


def exact_json_equal(left,right):
    import json
    try:
        return json.dumps(left,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')==json.dumps(right,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')
    except (ValueError,TypeError,UnicodeError):
        return False


def validate_start_transition(created,running):
    """Permit only Docker's observed env ordering and false-to-null OOM form."""
    import copy
    before=copy.deepcopy(created);after=copy.deepcopy(running)
    if type(before) is not dict or type(after) is not dict: raise ValueError('transition')
    a=before.get('Config');b=after.get('Config');h1=before.get('HostConfig');h2=after.get('HostConfig')
    if any(type(x) is not dict for x in (a,b,h1,h2)): raise ValueError('transition')
    def entries(value):
        if type(value) is not list: raise ValueError('transition')
        result={}
        for item in value:
            if type(item) is not str or '=' not in item: raise ValueError('transition')
            key=item.split('=',1)[0]
            if not key or key in result: raise ValueError('transition')
            result[key]=item
        return result
    if entries(a.get('Env'))!=entries(b.get('Env')): raise ValueError('transition')
    if h1.get('OomKillDisable') is not False or 'OomKillDisable' not in h2 or not (h2['OomKillDisable'] is False or h2['OomKillDisable'] is None): raise ValueError('transition')
    a['Env']=b['Env'];h1['OomKillDisable']=h2['OomKillDisable']
    if not exact_json_equal(before,after): raise ValueError('transition')


def probe_snapshot(path, target, metadata):
    """Fence a no-follow private regular executable and its complete bytes."""
    import hashlib, os, stat
    from pathlib import Path
    path=Path(path);target=Path(target)
    if not path.is_absolute() or not target.is_absolute() or '..' in path.parts: raise ValueError('probe')
    path.resolve(strict=True).relative_to(target.resolve(strict=True))
    chain=metadata._path(path); fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_nlink!=1
            or before.st_mode&0o022 or not before.st_mode&0o100 or not 0<before.st_size<=268435456
            or metadata._identity(before)!=chain[-1]): raise ValueError('probe')
        digest=hashlib.sha256()
        while part:=os.read(fd,1048576): digest.update(part)
        if metadata._identity(os.fstat(fd))!=metadata._identity(before) or metadata._path(path)!=chain: raise ValueError('probe drift')
        return (tuple(chain),digest.hexdigest())
    finally: os.close(fd)


def qualified_transport(fresh, shell, cid, token, env, tool, ownership, record_intent):
    """Existing FreshPsqlTransport with owner-fenced exact exec/containment."""
    import subprocess
    if not HEX64.fullmatch(cid) or not TOKEN.fullmatch(token): raise ValueError('identity')
    record_intent()
    exec_args=['docker','exec','-i',cid,'sh','-c',shell]
    inspect_args=['docker','inspect',cid]
    kill_args=['docker','kill',cid]
    state_args=['docker','inspect','--format','{{.State.Running}}',cid]
    def fenced_args(args):
        if args not in (exec_args,inspect_args,kill_args,state_args): raise ValueError('transport command')
        ownership(allow_stopped=args != exec_args);tool.check()
        return [tool.metadata.DOCKER,'--config',str(tool.config),'--host','unix://'+tool.metadata.SOCKET,*args[1:]]
    def popen(args,**kwargs):
        command=fenced_args(args)
        proc=subprocess.Popen(command,**kwargs)
        try: ownership(allow_stopped=False);tool.check()
        except BaseException:
            try: proc.kill();proc.wait(timeout=5)
            except BaseException: pass
            raise RuntimeError('fixture exec outcome unknown') from None
        return proc
    def run(args,**kwargs):
        command=fenced_args(args)
        result=subprocess.run(command,**kwargs)
        ownership(allow_stopped=True);tool.check()
        return result
    sql=['docker','exec','-i',cid,'psql','-XAtq','-v','ON_ERROR_STOP=1','-U','postgres','-d','contour_fixture']
    return fresh(sql,env,token,popen=popen,run=run,diagnostic_context='receiver-v1')


class OwnershipFence:
    """Recheck exact source, container generation, topology and tool on use."""
    def __init__(self, tool, fixture, source_call, output, head, sources, token, cid, image_id, network_id, command, env, started, frozen):
        self.tool=tool;self.fixture=fixture;self.source_call=source_call;self.output=output;self.head=head;self.sources=sources
        self.token=token;self.cid=cid;self.image_id=image_id;self.network_id=network_id
        self.command=command;self.env=env;self.started=started;self.frozen=frozen
    def inspect(self,args):
        import json
        value=json.loads(self.tool.call(args))
        if type(value) is not list or len(value)!=1 or type(value[0]) is not dict: raise RuntimeError('fixture inspect')
        return value[0]
    def __call__(self, *, allow_stopped=False):
        self.output.verify()
        if self.fixture['clean_head'](self.source_call)!=self.head or self.fixture['tracked_snapshot'](self.source_call)!=self.sources: raise RuntimeError('fixture source changed')
        item=self.inspect(['docker','inspect',self.cid])
        if not exact_json_equal(configuration_snapshot(item),self.frozen): raise RuntimeError('fixture configuration changed')
        validate_container(item,self.token,self.cid,self.image_id,self.network_id,self.command,self.env,self.started,allow_stopped=allow_stopped)
        validate_network(self.inspect(['docker','network','inspect',self.network_id]),self.token,self.network_id,[self.cid])
        self.tool.check();self.output.verify()


def dedicated_sensitive_executor(execute):
    """FreshPsqlTransport starts a new psql per execute after role logging setup."""
    if not callable(execute): raise ValueError('fixture executor')
    def sensitive(text): return execute(text)
    return sensitive


def bootstrap_schema(execute, root, hooks, capture, modules, passwords, fence):
    """Apply the established SQL14..28 fixture on the already fenced owner."""
    from pathlib import Path
    root=Path(root)
    provision=modules['provision']; schema=modules['schema']; setup=modules['setup']; logins_module=modules['logins']; profile=modules['profile']
    if set(passwords)!={'app','ingress','worker'} or any(type(x) is not str or not re.fullmatch('[0-9a-f]{64}',x) for x in passwords.values()): raise ValueError('synthetic credentials')
    execute((root/'db/bootstrap.sql').read_text())
    for kind in provision.PROVISION: execute((root/('db/provision_'+kind+'.sql')).read_text())
    migrations=sorted((root/'db/migrations').glob('*.sql'))
    if [int(path.name[:4]) for path in migrations]!=list(range(1,15)): raise ValueError('baseline migration drift')
    for path in migrations: execute(path.read_text())
    # These fixed disposable logins are required by the reviewed schema checks.
    def role(name,groups):
        secret=passwords[{'contour_app':'app','contour_local_ingress':'ingress','contour_local_worker':'worker'}[name]]
        return 'CREATE ROLE '+name+" LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD '"+secret+"'; GRANT "+','.join(groups)+' TO '+name+'; GRANT CONNECT ON DATABASE contour_local TO '+name+'; '
    execute('BEGIN; '+role('contour_app',provision.GROUPS)+role('contour_local_ingress',['contour_ingestion'])+role('contour_local_worker',['contour_catalog_worker'])+'COMMIT;')
    schema.require_ready(list(range(1,15)),execute,stage=14,phase='pre')
    context={'login':False};setup.Groups(execute,context).apply()
    for version in range(15,22):
        setup.Migration(execute,version,(root/setup.MIGRATIONS[version]).read_bytes(),context).apply()
        if version==17: hooks.after_stage17(execute)
    class SyntheticLogins(logins_module.Logins):
        def _password(self,name):
            if name not in ('ingress','worker'): raise ValueError('synthetic role')
            return passwords[name]
    fixture_logins=SyntheticLogins(profile.PROFILE,execute,dedicated_sensitive_executor(execute),lambda *_:False)
    fixture_logins._synthetic={key:passwords[key] for key in ('ingress','worker')}
    fixture_logins.apply()
    capture['capture_forward'](execute,lambda version:(root/'db/opt-in-migrations'/(capture['MIGRATIONS'][version]+'.sql')).read_bytes(),
       lambda _version,_raw:None,fence,verify21=lambda cb:schema.require_ready(list(range(1,22)),cb,stage=21,phase='enrolled'),
       ledger_sql=capture['LEDGER_SQL'],inventory_sql=schema.inventory_sql(),_after_stage=hooks.after_forward,_before_stage=hooks.before_forward)
    if not hooks.complete: raise RuntimeError('fixture stage incomplete')


class ReaderHooks:
    """Reuse the reviewed SQL28 sources without replaying independent races."""
    def __init__(self, receiver_hooks):
        self.delegate=receiver_hooks;self.complete=False
    def preflight(self,sources): self.delegate.preflight(sources)
    def after_stage17(self,execute): self.delegate.after_stage17(execute)
    def before_forward(self,stage): self.delegate.before_forward(stage)
    def after_forward(self,stage,execute):
        self.delegate.base.after_forward(stage,execute)
        if stage!=25:return
        if self.complete or self.delegate.files is None: raise RuntimeError('fixture stage')
        for key in ('m26','m27','m28','fixture'):
            execute(self.delegate.files[key].decode('utf-8','strict'))
        if execute('SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;')!='{'+','.join(map(str,range(1,29)))+'}': raise RuntimeError('fixture ledger')
        self.complete=True


def build_environment(clean_env,target,rustc,source_env):
    """No PATH lookup for rustc; retain only the fixed Cargo configuration keys."""
    from pathlib import Path
    if not Path(rustc).is_absolute() or not Path(target).is_absolute(): raise ValueError('build tool')
    env=dict(clean_env,CARGO_TARGET_DIR=str(target),RUSTC=str(rustc))
    for key in ('CARGO_HOME','RUSTUP_HOME','RUSTUP_TOOLCHAIN'):
        if key in source_env: env[key]=source_env[key]
    return env


def raise_failures(primary,cleanup):
    if cleanup: raise BaseExceptionGroup('fixture and cleanup failure',([primary] if primary else [])+cleanup)
    if primary is not None: raise primary


def revocation_seed(seed):
    """Fixed second enrollment, distinct from the independently closed one."""
    replacements=(("<>2", "<>3"), ("000000000018'::uuid", "000000000019'::uuid"),
                  ("repeat('d1',32)", "repeat('e2',32)"), ("repeat('d2',32)", "repeat('e3',32)"),
                  ("repeat('d3',32)", "repeat('e4',32)"))
    for old,new in replacements:
        if seed.count(old)!=1: raise ValueError('seed drift')
        seed=seed.replace(old,new)
    return seed


def reader_login_sql(passwords):
    """Return SQL only for three fixed disposable least-privilege identities."""
    if (type(passwords) is not dict or set(passwords)!={'reader','wrong','mixed'}
        or any(type(v) is not str or not re.fullmatch('[0-9a-f]{64}',v) for v in passwords.values())
        or len(set(passwords.values()))!=3): raise ValueError('synthetic login')
    grants=(('receiver_reader_login','reader','contour_causal_receiver_reader'),
            ('receiver_wrong_login','wrong','contour_causal_issuer'),
            ('receiver_mixed_login','mixed','contour_causal_receiver_reader,contour_causal_issuer'))
    clauses=[]
    for name,key,roles in grants:
        clauses.append('CREATE ROLE '+name+" LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD '"+passwords[key]+"'; GRANT "+roles+' TO '+name+'; GRANT CONNECT ON DATABASE contour_local TO '+name+';')
    return 'BEGIN; '+''.join(clauses)+' COMMIT;'


def main(argv):
    global PHASE
    import hashlib, json, os, runpy, secrets, signal, stat, subprocess, sys, time
    from pathlib import Path
    if len(argv)!=2: raise ValueError('private output and TLS input required')
    PHASE='source'
    root=Path(__file__).resolve().parents[1];os.umask(0o077);sys.dont_write_bytecode=True
    if str(root) not in sys.path: sys.path.insert(0,str(root))
    from deploy.local import capture_renew, docker_metadata as metadata, origin21_schema, origin21_setup, origin21_logins, origin21_profile, provision, origin21_transport, origin25_schema
    def tracked(name):
        path=root/name
        if not path.is_file() or any(p.is_symlink() for p in (path,*path.parents)): raise ValueError('source')
        before=path.read_bytes(); result=subprocess.run(['git','show','HEAD:'+name],cwd=root,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=True)
        if result.stderr or result.stdout!=before: raise ValueError('source')
        module=runpy.run_path(str(path))
        if path.read_bytes()!=before: raise ValueError('source changed')
        return module
    status=subprocess.run(['git','status','--porcelain','--untracked-files=all'],cwd=root,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=True)
    if status.stdout or status.stderr: raise ValueError('source not clean')
    capture=tracked('scripts/capture-origin25-reference.py');fixture=tracked('scripts/test-origin21-onboarding.py');bridge=tracked('scripts/test-postgres-causal-bridge.py');transport=tracked('scripts/fixture_psql_transport.py');receiver=tracked('scripts/test-causal-receiver-enrollment.py');issuer_fixture=tracked('scripts/receiver_issuer_fixture.py');gateway_fixture=tracked('scripts/gateway_reader_fixture.py')
    process=bridge['run_process']
    def source_call(args,data=None,timeout=30):
        result=process(args,data=data,cwd=root,timeout=timeout,limit=8*1024*1024)
        if result.returncode or result.stderr: raise RuntimeError('source command')
        return result.stdout.strip()
    head=fixture['clean_head'](source_call);sources=fixture['tracked_snapshot'](source_call)
    required=('scripts/test-postgres-causal-receiver-reader.py','crates/contour-postgres/examples/causal_receiver_reader_probe.rs','tests/fixtures/causal-receiver-reader/seed.sql','tests/fixtures/causal-receiver-reader/test_qualifier.py','scripts/receiver_issuer_fixture.py','crates/contour-postgres/examples/causal_receiver_issuer_probe.rs','tests/fixtures/causal-receiver-issuer/test_fixture.py','tests/fixtures/causal-receiver-issuer/README.md','db/opt-in-migrations/0029_causal_receiver_inbox.sql','db/opt-in-migrations/0030_causal_gateway_reader.sql','scripts/gateway_reader_fixture.py','crates/contour-postgres/examples/causal_gateway_reader_probe.rs','tests/fixtures/causal-gateway-reader/test_fixture.py')
    if any(x not in sources for x in required): raise ValueError('source missing')
    hooks=ReaderHooks(receiver['Hooks'](receiver['load_existing'](),origin25_schema));hooks.preflight(sources)
    output=capture['PrivateOutput'](argv[0]); token=secrets.token_hex(16);name='contour-origin21-qual-'+token
    tls=Path(argv[1]); initial=None; runner=None; network_id=cid=image_id=started=None; owner=None; success=False; tool=None; private_files={}
    def record(value): return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    def write_private(name,data):
        if '/' in name or type(data) is not bytes or len(data)>65536: raise ValueError('private input')
        output.verify();fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=output.fd)
        with os.fdopen(fd,'wb') as stream: stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.fsync(output.fd);output.verify()
        private_files[name]=metadata._identity(os.stat(name,dir_fd=output.fd,follow_symlinks=False))
    def qualified_program(name):
        path=Path(os.environ.get('READER_'+name+'_PATH','')); digest=os.environ.get('READER_'+name+'_SHA256','')
        if not path.is_absolute() or not HEX64.fullmatch(digest): raise ValueError('qualified tool')
        chain=metadata._path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0,os.geteuid()) or st.st_mode&0o022 or st.st_nlink!=1 or not 0<st.st_size<=268435456: raise ValueError('qualified tool')
            h=hashlib.sha256()
            while chunk:=os.read(fd,1048576): h.update(chunk)
            if h.hexdigest()!=digest or metadata._path(path)!=chain or metadata._identity(os.fstat(fd))!=metadata._identity(st): raise ValueError('qualified tool')
        finally: os.close(fd)
        return str(path),tuple(chain)
    def checked_process(program,chain,args,*,data=None,env=None,timeout=30,limit=1048576):
        if tuple(metadata._path(program))!=chain: raise RuntimeError('tool drift')
        result=process([program,*args],data=data,cwd=root,env=env,timeout=timeout,limit=limit)
        if tuple(metadata._path(program))!=chain or result.returncode: raise RuntimeError('qualified command')
        return result.stdout
    primary=None; cleanup=[]
    previous=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('fixture deadline')));signal.setitimer(signal.ITIMER_REAL,900)
    try:
        output.write('intent.json',record({'version':1,'owner':token,'source_head':head,'kind':'receiver-reader-synthetic'}))
        PHASE='tls'
        for name_ in ('ca.pem','server.pem','server.key'): metadata._path(tls/name_)
        ca=capture_renew.read_file(tls/'ca.pem',65536);cert=capture_renew.read_file(tls/'server.pem',65536);key=capture_renew.read_file(tls/'server.key',65536)
        for name_,body in (('ca.pem',ca),('server.pem',cert),('server.key',key)): write_private(name_,body)
        openssl,openssl_id=qualified_program('OPENSSL');cargo,cargo_id=qualified_program('CARGO');rustc,rustc_id=qualified_program('RUSTC')
        clean_env={'HOME':os.path.expanduser('~'),'PATH':os.defpath}
        checked_process(openssl,openssl_id,['verify','-CAfile',str(output.path/'ca.pem'),'-verify_hostname','localhost','-purpose','sslserver',str(output.path/'server.pem')],env=clean_env)
        checked_process(openssl,openssl_id,['verify','-CAfile',str(output.path/'ca.pem'),str(output.path/'ca.pem')],env=clean_env)
        cert_key=checked_process(openssl,openssl_id,['x509','-in',str(output.path/'server.pem'),'-pubkey','-noout'],env=clean_env)
        private_key=checked_process(openssl,openssl_id,['pkey','-in',str(output.path/'server.key'),'-pubout'],env=clean_env)
        ca_ext=checked_process(openssl,openssl_id,['x509','-in',str(output.path/'ca.pem'),'-noout','-ext','basicConstraints'],env=clean_env)
        if not cert_key or cert_key!=private_key or b'CA:TRUE' not in ca_ext: raise ValueError('TLS material')
        PHASE='build'
        target=output.path/'target';target.mkdir(mode=0o700)
        build_env=build_environment(clean_env,target,rustc,os.environ)
        source=root/'crates/contour-postgres/examples/causal_receiver_reader_probe.rs'
        if tuple(metadata._path(rustc))!=rustc_id: raise RuntimeError('rustc drift')
        try:
            lines=checked_process(cargo,cargo_id,['build','-p','contour-postgres','--example','causal_receiver_reader_probe','--example','causal_receiver_issuer_probe','--example','causal_gateway_reader_probe','--locked','--offline','--message-format=json'],env=build_env,timeout=300,limit=16777216).splitlines()
        finally:
            if tuple(metadata._path(rustc))!=rustc_id: raise RuntimeError('rustc drift')
        probe,probe_hash=select_probe(lines,target,source)
        probe_identity=probe_snapshot(probe,target,metadata)
        if probe_identity[1]!=probe_hash: raise RuntimeError('probe drift')
        issuer_source=root/'crates/contour-postgres/examples/causal_receiver_issuer_probe.rs'
        issuer_probe,issuer_hash=select_probe(lines,target,issuer_source,issuer=True)
        issuer_identity=probe_snapshot(issuer_probe,target,metadata)
        if issuer_identity[1]!=issuer_hash or issuer_probe==probe: raise RuntimeError('issuer probe drift')
        gateway_source=root/'crates/contour-postgres/examples/causal_gateway_reader_probe.rs'
        gateway_probe,gateway_hash=select_probe(lines,target,gateway_source,gateway=True)
        gateway_identity=probe_snapshot(gateway_probe,target,metadata)
        if gateway_identity[1]!=gateway_hash or gateway_probe in (probe,issuer_probe): raise RuntimeError('gateway probe drift')
        config=output.path/'docker-config';config.mkdir(mode=0o700)
        tool=ToolFence(metadata,config,process,clean_env)
        def inspect(args):
            value=json.loads(tool.call(args))
            if type(value) is not list or len(value)!=1 or type(value[0]) is not dict: raise RuntimeError('inspect')
            return value[0]
        PHASE='image'
        image=inspect(['docker','image','inspect',IMAGE]);image_id=image.get('Id','')
        if not re.fullmatch('sha256:[0-9a-f]{64}',image_id) or not any(x in ('postgres@'+IMAGE.split('@',1)[1],'docker.io/library/postgres@'+IMAGE.split('@',1)[1]) for x in image.get('RepoDigests',[])): raise ValueError('image')
        PHASE='network'
        network_id=tool.call(['docker','network','create','--driver','bridge','--opt','com.docker.network.bridge.enable_ip_masquerade=false','--label',LABEL+'='+token,name]).decode('ascii')
        if not HEX64.fullmatch(network_id): raise RuntimeError('network outcome unknown')
        fixture['durable_id'](output.path,'network',network_id);network_created=inspect(['docker','network','inspect',network_id]);write_private('network-created.json',record({'version':1,'observation':network_created}));validate_network(network_created,token,network_id,[])
        initial=secrets.token_hex(32).encode();output.write('initial-secret',initial);private_files['initial-secret']=metadata._identity(os.stat('initial-secret',dir_fd=output.fd,follow_symlinks=False))
        cmd=['sh','-c','chown postgres:postgres /tmp/server.key /tmp/server.crt && chmod 600 /tmp/server.key && exec docker-entrypoint.sh postgres -c listen_addresses=* -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key']
        PHASE='container'
        cid=tool.call(['docker','create','--init','--pull=never','--name',name+'-postgres','--label',LABEL+'='+token,'--network',network_id,'--network-alias','postgres','--publish','127.0.0.1::5432','--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/var/lib/postgresql/data:rw,nosuid,noexec,size=256m','-e','POSTGRES_DB=contour_fixture','-e','POSTGRES_PASSWORD_FILE=/tmp/initial-secret','-e','POSTGRES_HOST_AUTH_METHOD=scram-sha-256',IMAGE,*cmd]).decode('ascii')
        if not HEX64.fullmatch(cid): raise RuntimeError('container outcome unknown')
        fixture['durable_id'](output.path,'postgres',cid)
        expected_env={x.split('=',1)[0]:x for x in (image.get('Config') or {}).get('Env',[])}
        for entry in ('POSTGRES_DB=contour_fixture','POSTGRES_PASSWORD_FILE=/tmp/initial-secret','POSTGRES_HOST_AUTH_METHOD=scram-sha-256'):expected_env[entry.split('=',1)[0]]=entry
        expected_env=list(expected_env.values())
        created=inspect(['docker','inspect',cid]);validate_container(created,token,cid,image_id,network_id,cmd,expected_env)
        frozen=configuration_snapshot(created)
        write_private('container-created.json',record({'version':1,'configuration':frozen}))
        def created_fence():
            output.verify();tool.check()
            if fixture['clean_head'](source_call)!=head or fixture['tracked_snapshot'](source_call)!=sources: raise RuntimeError('source changed')
            current=inspect(['docker','inspect',cid])
            if not exact_json_equal(configuration_snapshot(current),frozen): raise RuntimeError('fixture configuration changed')
            validate_container(current,token,cid,image_id,network_id,cmd,expected_env)
            validate_network(inspect(['docker','network','inspect',network_id]),token,network_id,[])
        for local,remote in (('initial-secret','initial-secret'),('server.key','server.key'),('server.pem','server.crt')):
            created_fence();tool.call(['docker','cp',str(output.path/local),cid+':/tmp/'+remote]);created_fence()
        write_private('sql-exec.intent',record({'version':1,'operation':'owned-psql-and-readiness'}))
        created_fence()
        PHASE='start'
        if tool.call(['docker','start',cid]).decode('ascii')!=cid: raise RuntimeError('start outcome unknown')
        item=inspect(['docker','inspect',cid])
        write_private('container-started.json',record({'version':1,'observation':item}))
        running=configuration_snapshot(item);validate_start_transition(frozen,running)
        started=(item.get('State') or {}).get('StartedAt');port=validate_container(item,token,cid,image_id,network_id,cmd,expected_env,started)
        frozen=running
        validate_network(inspect(['docker','network','inspect',network_id]),token,network_id,[cid]);output.write('generation.json',record({'version':1,'started_at':started}))
        owner=OwnershipFence(tool,fixture,source_call,output,head,sources,token,cid,image_id,network_id,cmd,expected_env,started,frozen);owner()
        def readiness_process(args,**kwargs):
            if args[:3]!=['docker','exec',cid]: raise ValueError('readiness')
            owner();result=process([metadata.DOCKER,'--config',str(config),'--host','unix://'+metadata.SOCKET,*args[1:]],env=clean_env,**kwargs);owner();return result
        PHASE='readiness'
        until=time.monotonic()+60
        while not capture['postgres_ready'](readiness_process,cid):
            tool.check()
            if time.monotonic()>=until: raise TimeoutError('readiness')
            time.sleep(.2)
        def record_exec():
            output.verify()
            if metadata._identity(os.stat('sql-exec.intent',dir_fd=output.fd,follow_symlinks=False))!=private_files['sql-exec.intent']: raise RuntimeError('exec intent changed')
        runner=qualified_transport(transport['FreshPsqlTransport'],transport['SHELL'],cid,token,clean_env,tool,owner,record_exec)
        def raw_execute(sql):
            owner();value=runner.execute(sql,timeout=120);owner();return value
        PHASE='schema'
        raw_execute('CREATE DATABASE contour_local;')
        settings=('log_statement=none','log_min_duration_statement=-1','log_min_duration_sample=-1','log_min_error_statement=panic','log_min_messages=panic','log_duration=off','log_statement_sample_rate=0','log_transaction_sample_rate=0')
        raw_execute(''.join('ALTER ROLE postgres SET '+x+';' for x in settings))
        def execute(sql): return raw_execute('\\connect contour_local\n'+origin21_transport.GUARD+sql)
        modules={'provision':provision,'schema':origin21_schema,'setup':origin21_setup,'logins':origin21_logins,'profile':origin21_profile}
        bootstrap_schema(execute,root,hooks,capture,modules,{k:secrets.token_hex(32) for k in ('app','ingress','worker')},owner)
        for version,name in ((29,'0029_causal_receiver_inbox.sql'),(30,'0030_causal_gateway_reader.sql')):
            execute((root/'db/opt-in-migrations'/name).read_text())
            if execute('SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;')!='{'+','.join(map(str,range(1,version+1)))+'}': raise RuntimeError('fixture ledger')
        passwords={k:secrets.token_hex(32) for k in ('reader','wrong','mixed')};execute(reader_login_sql(passwords))
        PHASE='seed'
        seed=execute((root/'tests/fixtures/causal-receiver-reader/seed.sql').read_text());selected=json.loads(seed.splitlines()[-1])
        if type(selected) is not dict or set(selected)!={'epoch','generation','credential_id','commitment','expires_at'} or selected['epoch']!='2':raise ValueError('seed')
        base=dict(selected,ca_pem=ca.decode('ascii'),leaf='d2'*32,tenant='f0000000-0000-4000-8000-000000000001',runtime='fc000000-0000-4000-8000-000000000008',port=str(port))
        def probe_call(payload,*,issuer=False,gateway=False):
            if type(issuer) is not bool or type(gateway) is not bool or (issuer and gateway): raise ValueError('probe kind')
            path,identity,expected=(gateway_probe,gateway_identity,b'PASS gateway_reader_probe\n') if gateway else ((issuer_probe,issuer_identity,b'PASS receiver-issuer-probe\n') if issuer else (probe,probe_identity,b'PASS receiver_reader_probe\n'))
            owner()
            if probe_snapshot(path,target,metadata)!=identity: raise RuntimeError('probe drift')
            try: result=process([str(path)],data=payload,cwd=root,env=clean_env,timeout=30,limit=1024)
            finally:
                if probe_snapshot(path,target,metadata)!=identity: raise RuntimeError('probe drift')
                owner()
            if result.returncode or result.stdout!=expected or result.stderr: raise RuntimeError('probe failed')
        PHASE='probe'
        for mode,user,password in (('positive','receiver_reader_login',passwords['reader']),('denied','receiver_wrong_login',passwords['wrong']),('denied','receiver_mixed_login',passwords['mixed'])):
            payload=json.dumps(dict(base,mode=mode,user=user,password=password),sort_keys=True,separators=(',',':')).encode();probe_call(payload)
        PHASE='closed'
        execute("SELECT set_config('apicontour.tenant_id','f0000000-0000-4000-8000-000000000001',false); SET ROLE contour_causal_evidence_provisioner; SELECT contour.close_causal_receiver('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000008',2,'"+selected['generation']+"','operator_revoked'); RESET ROLE;")
        closed=dict(base,mode='unavailable',user='receiver_reader_login',password=passwords['reader'])
        probe_call(json.dumps(closed,sort_keys=True,separators=(',',':')).encode())
        # Create a distinct active credential on the same lifecycle before
        # revoking product03, then issue a new still-latest receiver epoch.
        PHASE='revoked'
        execute("SELECT set_config('apicontour.tenant_id','f0000000-0000-4000-8000-000000000001',false); SET ROLE contour_admin; SELECT contour.enroll_origin_credential('f0000000-0000-4000-8000-000000000001','fa000000-0000-4000-8000-000000000018','f9000000-0000-4000-8000-000000000003',decode(repeat('e1',32),'hex')); RESET ROLE;")
        later=json.loads(execute(revocation_seed((root/'tests/fixtures/causal-receiver-reader/seed.sql').read_text())).splitlines()[-1])
        if type(later) is not dict or set(later)!={'epoch','generation','credential_id','commitment','expires_at'} or later['epoch']!='3': raise ValueError('seed')
        latest=dict(base,**later,leaf='e3'*32,mode='positive',user='receiver_reader_login',password=passwords['reader'])
        probe_call(json.dumps(latest,sort_keys=True,separators=(',',':')).encode())
        execute("SELECT set_config('apicontour.tenant_id','f0000000-0000-4000-8000-000000000001',false); SET ROLE contour_admin; SELECT contour.end_origin('f0000000-0000-4000-8000-000000000001','credential_revoked','fa000000-0000-4000-8000-000000000003'); RESET ROLE;")
        execute("DO $$ BEGIN IF (SELECT max(epoch) FROM contour.causal_sessions WHERE tenant_id='f0000000-0000-4000-8000-000000000001' AND runtime_id='fc000000-0000-4000-8000-000000000008')<>3 OR NOT EXISTS(SELECT 1 FROM contour.origin_credentials c WHERE c.tenant_id='f0000000-0000-4000-8000-000000000001' AND c.lifecycle_id='f9000000-0000-4000-8000-000000000003' AND c.credential_id='fa000000-0000-4000-8000-000000000018' AND NOT EXISTS(SELECT 1 FROM contour.origin_terminal_events z WHERE z.tenant_id=c.tenant_id AND z.credential_id=c.credential_id AND z.event_kind='credential_revoked')) THEN RAISE EXCEPTION 'revocation control'; END IF; END $$;")
        latest['mode']='unavailable';probe_call(json.dumps(latest,sort_keys=True,separators=(',',':')).encode())
        execute("SET ROLE receiver_reader_login; DO $$ BEGIN BEGIN PERFORM count(*) FROM contour.causal_receiver_enrollments; RAISE EXCEPTION 'raw read accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$; RESET ROLE;")
        PHASE='issuer'
        def issuer_openssl(args):
            owner()
            try: return checked_process(openssl,openssl_id,args,env=clean_env,timeout=30,limit=65536)
            finally: owner()
        issuer_checks=issuer_fixture['run'](execute=execute,openssl=issuer_openssl,write_private=write_private,private_dir=output.path,
            probe_call=lambda payload:probe_call(payload,issuer=True),ca_pem=ca,port=port,
            passwords={k:secrets.token_hex(32) for k in ('issuer','wrong')},fixture_bytes=(root/'crates/contour-postgres/tests/fixtures/causal_bridge.json').read_bytes())
        if issuer_checks!=issuer_fixture['CHECKS']: raise RuntimeError('issuer fixture incomplete')
        PHASE='gateway'
        gateway_checks=gateway_fixture['run'](execute=execute,probe_call=lambda payload:probe_call(payload,gateway=True),ca_pem=ca,port=port,passwords={k:secrets.token_hex(32) for k in ('reader','wrong','mixed','transitive')})
        if gateway_checks!=gateway_fixture['CHECKS']: raise RuntimeError('gateway fixture incomplete')
        if bridge['digest_file'](probe)!=probe_hash or bridge['digest_file'](issuer_probe)!=issuer_hash or bridge['digest_file'](gateway_probe)!=gateway_hash: raise RuntimeError('probe changed')
        PHASE='cleanup'
        runner.close();runner=None;owner()
        if tool.call(['docker','rm','-f',cid]).decode('ascii')!=cid:raise RuntimeError('cleanup outcome unknown')
        if tool.call(['docker','ps','-aq','--no-trunc','--filter','label='+LABEL+'='+token]):raise RuntimeError('container cleanup')
        cid=None;validate_network(inspect(['docker','network','inspect',network_id]),token,network_id,[])
        if tool.call(['docker','network','rm',network_id]).decode('ascii')!=network_id:raise RuntimeError('network cleanup unknown')
        if tool.call(['docker','network','ls','-q','--no-trunc','--filter','label='+LABEL+'='+token]):raise RuntimeError('network cleanup')
        network_id=None
        if fixture['clean_head'](source_call)!=head or fixture['tracked_snapshot'](source_call)!=sources:raise RuntimeError('source changed')
        for filename,identity in private_files.items():
            output.verify();current=os.stat(filename,dir_fd=output.fd,follow_symlinks=False)
            if metadata._identity(current)!=identity or not stat.S_ISREG(current.st_mode) or current.st_uid!=os.geteuid() or stat.S_IMODE(current.st_mode)!=0o600 or current.st_nlink!=1: raise RuntimeError('private input drift')
            os.unlink(filename,dir_fd=output.fd)
        os.fsync(output.fd);output.verify()
        success=True;output.write('receipt.json',record({'version':1,'scope':'synthetic-sql30-reader-and-issuer-tls-data','checks':['reader','wrong-role','mixed-role','revoked','closed','table-denied',*issuer_checks,*gateway_checks],'status':'passed'}))
    except BaseException as error:
        primary=error
    finally:
        if initial is not None: initial=b''
        if runner is not None:
            try: runner.close()
            except BaseException as error: cleanup.append(error)
        try: output.close()
        except BaseException as error: cleanup.append(error)
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
    raise_failures(primary,cleanup)
    if not success: raise RuntimeError('fixture retained')


if __name__=='__main__':
    import sys
    try: main(sys.argv[1:])
    except BaseException as error:
        print(failure_diagnostic(error,PHASE),file=sys.stderr)
        raise SystemExit(1) from None
    print('PASS receiver_reader_fixture synthetic TLS data only')
