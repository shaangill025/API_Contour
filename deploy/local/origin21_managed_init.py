"""Fresh, separately owned managed-Origin PostgreSQL and CA initializer.

No operation executes at import. Partial or unknown outcomes are retained and
cannot be adopted, retried, replaced or cleaned by this initializer.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from deploy.local import capture_renew,origin21_products,origin21_profile,origin21_schema,origin21_sql_runner,origin21_state,origin21_transport,provision
from deploy.pilot import origin_credentials

ROOT=origin21_profile.ROOT
SELECTED=origin21_profile.MANAGED
BASE=SELECTED.profile.state.parent
NETWORK='apicontour-origin21-managed-db_default'
PROJECT='apicontour-origin21-managed-db'
VOLUME='apicontour-origin21-managed-db-data'
POSTGRES='postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4'
LABEL='org.apicontour.managed-db-owner'
SOURCE='deploy/local/origin21_managed_init.py'
PG_COMMAND='chown postgres:postgres /tmp/server.key /tmp/server.crt /run/local-ca.crt /tmp/pg_hba.conf && chmod 600 /tmp/server.key /run/local-ca.crt && exec docker-entrypoint.sh postgres -c listen_addresses=* -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key -c hba_file=/tmp/pg_hba.conf'
PG_ENV={'PGDATA':'/var/lib/postgresql/data/pgdata','POSTGRES_DB':'contour_local','POSTGRES_PASSWORD_FILE':'/tmp/initial-secret'}


def _settings(selected):
    if selected is SELECTED:
        return BASE, NETWORK, PROJECT, VOLUME
    if selected is origin21_profile.HUMAN:
        return (selected.profile.state.parent, 'apicontour-origin21-managed-human-db_default',
                'apicontour-origin21-managed-human-db', 'apicontour-origin21-managed-human-db-data')
    raise ValueError('unsupported managed initializer context')


def _context_call(selected, function, *args, **kwargs):
    if selected is SELECTED:
        return function(*args, **kwargs)
    if selected is origin21_profile.HUMAN:
        return function(*args, selected=selected, **kwargs)
    raise ValueError('unsupported managed initializer context')


def _bytes(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


def _source(head, *, selected=SELECTED):
    _settings(selected)
    if SOURCE not in origin21_state._source_files(selected): raise RuntimeError('managed initializer source not pinned')
    if not re.fullmatch('[0-9a-f]{40}',head): raise ValueError('invalid source head')
    from deploy.local import qualification_git
    fresh=qualification_git.clean_status_if_active(ROOT,head) if selected is SELECTED else False
    if not fresh and (origin21_transport._run(['git','rev-parse','HEAD'],'',deadline=15)!=head or origin21_transport._run(['git','status','--porcelain','--untracked-files=all'],'',deadline=15)): raise ValueError('clean source required')
    names=['db/bootstrap.sql']+['db/provision_'+kind+'.sql' for kind in provision.PROVISION]
    migrations=sorted((ROOT/'db/migrations').glob('*.sql'))
    if [int(path.name[:4]) for path in migrations]!=list(range(1,15)): raise ValueError('baseline migration drift')
    names += [str(path.relative_to(ROOT)) for path in migrations]
    digest=hashlib.sha256(origin21_state._source_identity(context=selected).encode('ascii'))
    for name in names:
        path=ROOT/name
        if any(part.is_symlink() for part in (path,*list(path.parents)[:len(Path(name).parts)-1])) or not path.is_file(): raise ValueError('initializer source unavailable')
        digest.update(name.encode()+b'\0'+hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _build(image,head,receipt,digest):
    path=Path(receipt)
    if not path.is_absolute() or '..' in path.parts or any(p.is_symlink() for p in (path,*path.parents)) or not re.fullmatch('[0-9a-f]{64}',digest): raise ValueError('invalid build receipt')
    raw=capture_renew.read_file(path,4096)
    if hashlib.sha256(raw).hexdigest()!=digest: raise ValueError('build receipt changed')
    value=capture_renew.exact_json(raw)
    if (type(value) is not dict or set(value)!={'version','head','image_id','status','owner_token','tag'} or type(value['version']) is not int or value['version']!=1 or value['head']!=head or value['image_id']!=image or value['status']!='passed' or not re.fullmatch(r'sha256:[0-9a-f]{64}',image) or not isinstance(value['owner_token'],str) or not re.fullmatch('[0-9a-f]{32}',value['owner_token']) or value['tag']!='apicontour-origin21-build:'+value['owner_token'] or _bytes(value)!=raw): raise ValueError('build receipt invalid')
    item=origin21_products._objects(['docker','image','inspect',value['tag']]); labels=(item.get('Config') or {}).get('Labels') or {}
    if item.get('Id')!=image or value['tag'] not in (item.get('RepoTags') or []) or labels.get('org.apicontour.build-owner')!=value['owner_token'] or labels.get('org.apicontour.build-head')!=head: raise ValueError('build image changed')
    return value


def _write(path,value): origin_credentials._write(path,_bytes(value))


def _run_openssl(*args):
    return origin21_transport._run(['openssl',*map(str,args)],'',deadline=30).encode('utf-8')


def _fresh_ca(base):
    conf=base/'ca.cnf'; ext=base/'postgres.ext'; csr=base/'postgres.csr'
    origin_credentials._write(conf,b'[req]\ndistinguished_name=dn\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
    origin_credentials._write(ext,b'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:postgres\n')
    _run_openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','7','-sha256','-config',conf,'-extensions','ca','-subj','/CN=managed origin CA','-keyout',base/'ca.key','-out',base/'ca.crt')
    _run_openssl('req','-new','-newkey','rsa:2048','-nodes','-sha256','-subj','/CN=postgres','-keyout',base/'postgres.key','-out',csr)
    _run_openssl('x509','-req','-in',csr,'-CA',base/'ca.crt','-CAkey',base/'ca.key','-set_serial',str(secrets.randbits(127)+1),'-days','7','-sha256','-extfile',ext,'-out',base/'postgres.crt')
    for name in ('ca.key','ca.crt','postgres.key','postgres.crt'):
        path=base/name; os.chmod(path,0o600); data=capture_renew.read_file(path,65536)
        if not data: raise ValueError('issuer output unavailable')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    if _run_openssl('x509','-in',base/'ca.crt','-pubkey','-noout')!=_run_openssl('pkey','-in',base/'ca.key','-pubout'): raise ValueError('CA key mismatch')
    if _run_openssl('x509','-in',base/'postgres.crt','-pubkey','-noout')!=_run_openssl('pkey','-in',base/'postgres.key','-pubout'): raise ValueError('postgres key mismatch')
    _run_openssl('verify','-CAfile',base/'ca.crt','-purpose','sslserver',base/'postgres.crt')
    extension=_run_openssl('x509','-in',base/'postgres.crt','-noout','-ext','subjectAltName').decode('ascii').splitlines()
    if len(extension)!=2 or extension[1].strip()!='DNS:localhost, DNS:postgres': raise ValueError('postgres SAN drift')
    fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def _network(token,expected,members,*,selected=SELECTED):
    _, network_name, project, _ = _settings(selected)
    item=origin21_products._objects(['docker','network','inspect',network_name]); labels=item.get('Labels') or {}
    if item.get('Name')!=network_name or item.get('Id')!=expected or item.get('Internal') is not True or labels.get(LABEL)!=token or labels.get('com.docker.compose.project')!=project or labels.get('com.docker.compose.network')!='default' or set((item.get('Containers') or {}).keys())!=set(members): raise ValueError('managed database network changed')


def _selected_volume(qualification,*,selected=SELECTED):
    _, _, _, volume = _settings(selected)
    if qualification is None: return volume
    if selected is not SELECTED: raise ValueError('qualification requires managed context')
    from deploy.local.origin21_managed_qualification import OwnedManagedQualification
    if type(qualification) is not OwnedManagedQualification: raise ValueError('qualification proof required')
    qualification.verify()
    return qualification.volume


def _volume(token,*,qualification=None,selected=SELECTED):
    volume=_selected_volume(qualification, selected=selected)
    item=origin21_products._objects(['docker','volume','inspect',volume]); labels=item.get('Labels') or {}
    if item.get('Name')!=volume or item.get('Driver')!='local' or item.get('Scope')!='local' or labels.get(LABEL)!=token or (item.get('Options') or {}) or (qualification is not None and labels.get('org.apicontour.managed-qualification-owner')!=qualification.token): raise ValueError('managed database volume changed')


def _db_inventory(token,expected):
    if not re.fullmatch('[0-9a-f]{32}',token) or type(expected) not in (list,tuple) or any(type(x) is not str or not re.fullmatch('[0-9a-f]{64}',x) for x in expected) or len(set(expected))!=len(expected): raise ValueError('invalid managed DB inventory')
    ids=origin21_products._command(['docker','ps','-aq','--no-trunc','--filter','label='+LABEL+'='+token],15).decode('ascii').split()
    if len(ids)!=len(expected) or set(ids)!=set(expected): raise ValueError('managed DB ownership inventory changed')


def _postgres(cid,image,network,token,*,running,qualification=None,selected=SELECTED):
    _, network_name, project, _ = _settings(selected)
    volume=_selected_volume(qualification, selected=selected)
    _db_inventory(token,[cid])
    item=origin21_products._objects(['docker','inspect',cid]); cfg=item.get('Config') or {}; host=item.get('HostConfig') or {}; state=item.get('State') or {}; labels=cfg.get('Labels') or {}; networks=(item.get('NetworkSettings') or {}).get('Networks') or {}; endpoint=networks.get(network_name) or {}; mounts=item.get('Mounts') or []
    if (item.get('Id')!=cid or item.get('Name')!='/'+project+'-postgres' or item.get('Image')!=image['id'] or cfg.get('Image')!=POSTGRES or labels.get(LABEL)!=token or labels.get('com.docker.compose.project')!=project or labels.get('com.docker.compose.service')!='postgres' or host.get('Init') is not True or host.get('Privileged') is not False or host.get('PortBindings') not in (None,{}) or host.get('PublishAllPorts') is not False or host.get('NetworkMode')!=network or set(networks)!={network_name} or 'postgres' not in (endpoint.get('Aliases') or []) or state.get('Running') is not running): raise ValueError('managed postgres changed')
    env=cfg.get('Env') or []; expected=dict(x.split('=',1) for x in image['env']); expected.update(PG_ENV)
    if (len(env)!=len(expected) or any(not isinstance(x,str) or '=' not in x for x in env) or dict(x.split('=',1) for x in env)!=expected or
        cfg.get('Entrypoint')!=image['entrypoint'] or cfg.get('Cmd')!=['sh','-c',PG_COMMAND] or cfg.get('WorkingDir')!=('' if image['workdir'] is None else image['workdir']) or
        host.get('Memory')!=512*1024*1024 or host.get('NanoCpus')!=1_000_000_000 or host.get('PidsLimit')!=128 or host.get('PidMode')=='host' or host.get('IpcMode')=='host' or host.get('UTSMode')=='host' or host.get('UsernsMode')=='host' or host.get('Devices') not in (None,[]) or host.get('DeviceRequests') not in (None,[]) or host.get('CapAdd') not in (None,[])):
        raise ValueError('managed postgres configuration changed')
    if len(mounts)!=1 or mounts[0].get('Type')!='volume' or mounts[0].get('Name')!=volume or mounts[0].get('Destination')!='/var/lib/postgresql/data' or mounts[0].get('RW') is not True: raise ValueError('managed postgres mount changed')
    if running:
        if state.get('Status')!='running' or endpoint.get('NetworkID')!=network or not isinstance(state.get('StartedAt'),str) or state['StartedAt'].startswith('0001-'): raise ValueError('managed postgres start changed')
    elif state.get('Status')!='created' or endpoint.get('NetworkID') not in ('',None): raise ValueError('managed postgres creation changed')
    return state


def verify_runtime_target(deployment,*,qualification=None,selected=SELECTED):
    """Recheck the persisted PostgreSQL generation before private SQL."""
    origin21_profile.require_context(selected)
    base, network_name, _, _ = _settings(selected)
    if selected is origin21_profile.HUMAN and qualification is not None: raise ValueError('unexpected qualification')
    if selected is SELECTED:
        from deploy.local.origin21_managed_qualification import require_matching
        require_matching(qualification)
    def record(name):
        raw=origin_credentials._file(base/name,4096); value=capture_renew.exact_json(raw)
        if type(value) is not dict or _bytes(value)!=raw: raise ValueError('managed target record invalid')
        return value
    intent=record('initializer.intent'); started=record('postgres.start.result')
    if (set(intent)!={'version','head','build_image','build_receipt_sha256','token','network','volume'} or intent['version']!=1 or intent['network']!=network_name or intent['volume']!=_context_call(selected,_selected_volume,qualification) or
        set(started)!={'version','id','started_at'} or started['version']!=1 or started['id']!=deployment.get('postgres_id') or
        not isinstance(started['started_at'],str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',started['started_at'])):
        raise ValueError('managed PostgreSQL generation invalid')
    if qualification is not None: qualification.require_build(intent['build_image'],intent['head'],intent['build_receipt_sha256'])
    image=origin21_products._image(POSTGRES)
    if image['id']!=deployment.get('postgres_image_id') or deployment.get('name')!=network_name: raise ValueError('managed PostgreSQL image changed')
    state=_context_call(selected,_postgres,started['id'],image,deployment['id'],intent['token'],running=True,qualification=qualification)
    if state['StartedAt']!=started['started_at']: raise ValueError('managed PostgreSQL generation changed')
    _context_call(selected,_volume,intent['token'],qualification=qualification)
    return started['started_at']


def _create_network(token,*,selected=SELECTED):
    base, network_name, project, _ = _settings(selected)
    _write(base/'network.intent',{'version':1,'name':network_name,'token':token})
    network=origin21_products._command(['docker','network','create','--internal','--label',LABEL+'='+token,'--label','com.docker.compose.project='+project,'--label','com.docker.compose.network=default',network_name]).decode('ascii')
    if not re.fullmatch('[0-9a-f]{64}',network): raise RuntimeError('network creation uncertain')
    _context_call(selected,_network,token,network,[]); _write(base/'network.result',{'version':1,'id':network})
    return network


def _start_postgres(cid,*,selected=SELECTED):
    base, _, _, _ = _settings(selected)
    _write(base/'postgres.start.intent',{'version':1,'id':cid})
    if origin21_products._command(['docker','start',cid]).decode('ascii')!=cid: raise RuntimeError('postgres start uncertain')


def _phase(base,name,runner,sql,check_source):
    if not re.fullmatch(r'[a-z0-9-]{1,40}',name): raise ValueError('invalid initializer phase')
    if not check_source(): raise ValueError('initializer source changed')
    _write(base/('phase-'+name+'.intent'),{'version':1,'phase':name,'sql_sha256':hashlib.sha256(sql.encode()).hexdigest()})
    runner.run((origin21_transport.GUARD+sql).encode(),'sql','postgres')
    if not check_source(): raise ValueError('initializer source changed')
    _write(base/('phase-'+name+'.done'),{'version':1,'phase':name})


def _base_logins(base,runner,check_source,*,selected=SELECTED):
    _settings(selected)
    # The stage-14 reference requires the same fixed baseline roles.
    # Only the closed human profile retains its fresh app login credential.
    app_password = None
    if selected is origin21_profile.HUMAN:
        from deploy.local import origin21_managed_human_secret
        app_password = origin21_managed_human_secret.create_fresh()
        if origin21_managed_human_secret.read_committed() != app_password: raise ValueError('app credential commitment changed')
    def login(role,groups,password=None): return 'CREATE ROLE '+role+" LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD '"+(secrets.token_hex(32) if password is None else password)+"'; GRANT "+','.join(groups)+' TO '+role+'; GRANT CONNECT ON DATABASE contour_local TO '+role+'; '
    _phase(base,'base-logins',runner,'BEGIN; '+login('contour_app',provision.GROUPS,app_password)+login('contour_local_ingress',['contour_ingestion'])+login('contour_local_worker',['contour_catalog_worker'])+'COMMIT;',check_source)

def initialize(*,image_id,head,build_receipt,build_receipt_sha256,qualification=None,selected=SELECTED):
    """Return a five-field managed runtime receipt only after checked success."""
    origin21_profile.require_context(selected)
    base, network_name, project, _ = _settings(selected)
    if selected is origin21_profile.HUMAN and qualification is not None: raise ValueError('unexpected qualification')
    if os.getuid()==0: raise RuntimeError('nonroot required')
    if selected is origin21_profile.HUMAN:
        from deploy.local import origin21_managed_human_preflight
        origin21_managed_human_preflight.check()
    os.umask(0o077); source=_context_call(selected,_source,head); _build(image_id,head,build_receipt,build_receipt_sha256)
    for stage in range(14,22): origin21_schema.require_reference(stage,'pre')
    origin21_schema.require_reference(14,'groups'); origin21_schema.require_reference(21,'enrolled')
    volume=_context_call(selected,_selected_volume,qualification)
    if qualification is None:
        if os.path.lexists(base): raise FileExistsError('managed state already exists')
        os.mkdir(base,0o700)
        parent=os.open(base.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(parent)
        finally: os.close(parent)
    else:
        qualification.require_build(image_id,head,build_receipt_sha256)
    token=secrets.token_hex(16)
    _write(base/'initializer.intent',{'version':1,'head':head,'build_image':image_id,'build_receipt_sha256':build_receipt_sha256,'token':token,'network':network_name,'volume':volume})
    _db_inventory(token,[])
    _fresh_ca(base)
    if selected is origin21_profile.HUMAN:
        from deploy.local import origin21_managed_human_identity
        origin21_managed_human_identity.initialize()
    secret=secrets.token_hex(32); origin_credentials._write(base/'postgres.password',secret.encode('ascii'))
    origin_credentials._write(base/'pg_hba.conf',b'local all all trust\nhostnossl all all all reject\nhostssl all all all scram-sha-256\n')
    if origin21_products._command(['docker','network','ls','--filter','name=^'+network_name+'$','--format','{{.Name}}']).split(): raise ValueError('managed network already exists')
    if origin21_products._command(['docker','volume','ls','--filter','name=^'+volume+'$','--format','{{.Name}}']).split(): raise ValueError('managed volume already exists')
    pg_info=origin21_products._image(POSTGRES); pg_image=pg_info['id']
    network=_context_call(selected,_create_network,token)
    _write(base/'volume.intent',{'version':1,'name':volume,'token':token})
    volume_args=['docker','volume','create','--label',LABEL+'='+token]
    if qualification is not None: volume_args+=['--label','org.apicontour.managed-qualification-owner='+qualification.token]
    if origin21_products._command(volume_args+[volume]).decode('ascii')!=volume: raise RuntimeError('volume creation uncertain')
    _context_call(selected,_volume,token,qualification=qualification); _write(base/'volume.result',{'version':1,'name':volume})
    _write(base/'postgres.intent',{'version':1,'image_id':pg_image,'network_id':network,'volume':volume})
    cid=origin21_products._command(['docker','create','--init','--pull=never','--name',project+'-postgres','--label',LABEL+'='+token,'--label','com.docker.compose.project='+project,'--label','com.docker.compose.service=postgres','--network',network,'--network-alias','postgres','--memory','512m','--cpus','1','--pids-limit','128','--mount','type=volume,src='+volume+',dst=/var/lib/postgresql/data','-e','PGDATA=/var/lib/postgresql/data/pgdata','-e','POSTGRES_DB=contour_local','-e','POSTGRES_PASSWORD_FILE=/tmp/initial-secret',POSTGRES,'sh','-c',PG_COMMAND]).decode('ascii')
    if not re.fullmatch('[0-9a-f]{64}',cid): raise RuntimeError('postgres creation uncertain')
    _context_call(selected,_postgres,cid,pg_info,network,token,running=False,qualification=qualification); _write(base/'postgres.created',{'version':1,'id':cid})
    for src,dst in (('ca.crt','/run/local-ca.crt'),('postgres.crt','/tmp/server.crt'),('postgres.key','/tmp/server.key'),('postgres.password','/tmp/initial-secret'),('pg_hba.conf','/tmp/pg_hba.conf')):
        origin21_products._command(['docker','cp',str(base/src),cid+':'+dst])
    _context_call(selected,_start_postgres,cid)
    deadline=time.monotonic()+60
    while True:
        try:
            check=('test "$(cat /proc/1/comm)" = docker-init && p=$(head -n 1 /var/lib/postgresql/data/pgdata/postmaster.pid) && '
                   'case "$p" in *[!0-9]*|\'\') exit 1;; esac && test "$p" -gt 1 && test "$(cat /proc/$p/comm)" = postgres && '
                   'exec psql -XqAt -v ON_ERROR_STOP=1 -U postgres -d contour_local -c "SELECT current_database()=\'contour_local\' AND current_setting(\'listen_addresses\')=\'*\' AND current_setting(\'ssl\')=\'on\';"')
            out=origin21_products._command(['docker','exec',cid,'sh','-c',check],5)
            if out==b't': break
        except (RuntimeError,TimeoutError): pass
        if time.monotonic()>=deadline: raise TimeoutError('postgres startup deadline')
        time.sleep(.2)
    state=_context_call(selected,_postgres,cid,pg_info,network,token,running=True,qualification=qualification); _context_call(selected,_network,token,network,[cid]); _context_call(selected,_volume,token,qualification=qualification)
    _write(base/'postgres.start.result',{'version':1,'id':cid,'started_at':state['StartedAt']})
    ca_sha=hashlib.sha256(capture_renew.read_file(base/'ca.crt',65536)).hexdigest()
    deployment={'name':network_name,'id':network,'owner_kind':'managed-human' if selected is origin21_profile.HUMAN else 'managed-local','owner_token':project,'postgres_id':cid,'postgres_image_id':pg_image,'ca_sha256':ca_sha}
    directory=base/'initializer-transport'; os.mkdir(directory,0o700)
    runner=origin21_sql_runner.for_deployment(directory,deployment,selected=selected,qualification=qualification)
    verify_target=runner.verify_target
    def checked_target(target):
        verify_target(target)
        current=_context_call(selected,_postgres,cid,pg_info,network,token,running=True,qualification=qualification)
        if current['StartedAt']!=state['StartedAt']: raise ValueError('postgres generation changed')
        _context_call(selected,_network,token,network,[cid]); _context_call(selected,_volume,token,qualification=qualification)
        if _context_call(selected,_source,head)!=source: raise ValueError('initializer source changed')
    runner.verify_target=checked_target
    check_source=lambda:_context_call(selected,_source,head)==source
    _phase(base,'bootstrap',runner,(ROOT/'db/bootstrap.sql').read_text(),check_source)
    for kind in provision.PROVISION: _phase(base,'provision-'+kind.replace('_','-'),runner,(ROOT/('db/provision_'+kind+'.sql')).read_text(),check_source)
    migrations=sorted((ROOT/'db/migrations').glob('*.sql'))
    if [int(path.name[:4]) for path in migrations]!=list(range(1,15)): raise ValueError('baseline migration drift')
    for path in migrations: _phase(base,'migration-'+path.name[:4],runner,path.read_text(),check_source)
    def query(sql): return runner.run((origin21_transport.GUARD+sql).encode(),'sql','postgres')
    t,p,s,e=map(provision.sql_quote,provision.IDS)
    _phase(base,'base-identities',runner,f"BEGIN; INSERT INTO contour.tenants VALUES ({t}); INSERT INTO contour.projects VALUES ({t},{p}); INSERT INTO contour.services VALUES ({t},{s},{p}); INSERT INTO contour.environments VALUES ({t},{e},{p}); COMMIT;",check_source)
    _base_logins(base,runner,check_source,selected=selected)
    origin21_schema.require_ready(list(range(1,15)),query,stage=14,phase='pre')
    if _context_call(selected,_source,head)!=source or _build(image_id,head,build_receipt,build_receipt_sha256)['image_id']!=image_id: raise ValueError('managed source or build changed')
    final=_context_call(selected,_postgres,cid,pg_info,network,token,running=True,qualification=qualification); _context_call(selected,_network,token,network,[cid]); _context_call(selected,_volume,token,qualification=qualification)
    if final['StartedAt']!=state['StartedAt']: raise ValueError('postgres generation changed')
    receipt={'version':1,'head':head,'image_id':image_id,'status':'passed','network':deployment}
    raw=_bytes(receipt); digest=hashlib.sha256(raw).hexdigest()
    _write(base/'initializer.done',{'version':1,'receipt_sha256':digest,'postgres_id':cid,'started_at':state['StartedAt']})
    origin_credentials._write(base/'runtime-receipt.json',raw)
    return base/'runtime-receipt.json',digest
