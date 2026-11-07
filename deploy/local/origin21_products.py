"""Closed initial creation/inspection of the two local origin21 product instances.

No Docker command executes on import. Creation is one-shot: ambiguity or an
existing ownership directory requires operator inspection, never auto-adoption,
restart, deletion or enrollment. Root supplies the resulting commitments to the
separate journaled enrollment API. This is not platform/hardware attestation.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import shutil
from deploy.local import capture_renew, origin21_credentials, origin21_evidence, origin21_profile, origin21_state, origin21_transport
from deploy.pilot import origin_credentials

ROOT=origin21_profile.ROOT
PROJECT='apicontour-origin21'
NETWORK=PROJECT+'_default'
OWNER=origin21_profile.STATE.parent/'origin21-products'
COMPOSE=['docker','compose','--project-name',PROJECT,'-f',str(ROOT/'deploy/local/origin21-compose.yaml')]
PRODUCTS=('replica1','replica2')
MODEL_LIMIT=65536


def _command(args,timeout=30,*,token=None,app_image=None,capture_network=None):
    # stderr is discarded and output/time are bounded by the private transport.
    env={'PATH':os.defpath,'HOME':os.path.expanduser('~'),
         'LOCAL_UID':str(os.getuid()),'LOCAL_GID':str(os.getgid())}
    if token is not None: env['ORIGIN21_OWNER_TOKEN']=token
    if app_image is not None: env['ORIGIN21_APP_IMAGE']=app_image
    if capture_network is not None: env['ORIGIN21_CAPTURE_NETWORK']=capture_network
    if not args or args[0]!='docker': raise ValueError('unsupported product command')
    binary=shutil.which('docker')
    if binary is None: raise RuntimeError('local Docker CLI unavailable')
    return origin21_transport._run([binary,*args[1:]],'',deadline=timeout,env=env).encode('utf-8')


def _objects(args):
    value=json.loads(_command(args))
    if not isinstance(value,list) or len(value)!=1 or not isinstance(value[0],dict): raise RuntimeError('invalid product inspection')
    return value[0]


def _build_receipt(image_id,head,path,digest):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',image_id) or not re.fullmatch(r'[0-9a-f]{40}',head) or not re.fullmatch(r'[0-9a-f]{64}',digest): raise ValueError('invalid app build identity')
    raw=capture_renew.read_file(Path(path),4096)
    if hashlib.sha256(raw).hexdigest()!=digest: raise ValueError('app build receipt digest mismatch')
    value=capture_renew.exact_json(raw)
    if type(value) is not dict or set(value)!={'version','head','image_id','status','network'} or value['version']!=1 or value['head']!=head or value['image_id']!=image_id or value['status']!='passed' or json.dumps(value,sort_keys=True,separators=(',',':')).encode()!=raw: raise ValueError('invalid app build receipt')
    network=value['network']
    if type(network) is not dict or set(network)!={'name','id','owner_kind','owner_token','postgres_id','postgres_image_id','ca_sha256'}: raise ValueError('invalid deployment network')
    if not all(isinstance(x,str) for x in network.values()) or not re.fullmatch('[0-9a-f]{64}',network['id']) or not re.fullmatch('[0-9a-f]{64}',network['postgres_id']) or not re.fullmatch('sha256:[0-9a-f]{64}',network['postgres_image_id']) or not re.fullmatch('[0-9a-f]{64}',network['ca_sha256']): raise ValueError('invalid deployment network')
    if network['owner_kind']=='local':
        if network['name']!='apicontour-local_default' or network['owner_token']!='apicontour-local': raise ValueError('invalid local network')
    elif network['owner_kind']=='fixture':
        if not re.fullmatch('[0-9a-f]{32}',network['owner_token']) or network['name']!='contour-origin21-qual-'+network['owner_token']: raise ValueError('invalid fixture network')
    else: raise ValueError('unsupported deployment network')
    current=origin21_transport._run(['git','rev-parse','HEAD'],'',deadline=15)
    dirty=origin21_transport._run(['git','status','--porcelain','--untracked-files=all'],'',deadline=15)
    if current!=head or dirty: raise ValueError('app source is not exact clean head')
    return network


def _network_digest(network):
    return hashlib.sha256(b'apicontour/origin21-deployment/1\n'+json.dumps(network,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def _image_id():
    item=_objects(['docker','image','inspect',origin21_evidence.IMAGE])
    value=item.get('Id')
    if not isinstance(value,str) or not re.fullmatch('sha256:[0-9a-f]{64}',value): raise RuntimeError('invalid product image')
    env=item.get('Config',{}).get('Env') or []
    if not isinstance(env,list) or any(not isinstance(x,str) or '=' not in x for x in env): raise RuntimeError('invalid image environment')
    return value,env,item.get('Config',{}).get('Cmd'),item.get('Config',{}).get('WorkingDir')


def _mounts(index):
    state=origin21_profile.STATE
    fixed={
        '/pilot/settings.js':ROOT/'deploy/pilot/settings.js', '/pilot/flows.json':ROOT/'deploy/pilot/flows.json',
        '/pilot/check_tls.js':ROOT/'deploy/pilot/check_tls.js', '/pilot/probe.js':ROOT/'deploy/pilot/probe.js',
        '/pilot/ca.crt':state.parent/'ca.crt',
    }
    for name in ('client.crt','client.key','server.crt','server.key'):
        fixed['/pilot/tls/'+name]=state/('replica'+str(index))/name
    return {target:os.path.realpath(path) for target,path in fixed.items()}


def validate(obj,index,cid,image_id,image_env,image_cmd,image_workdir,token,*,running):
    if type(index) is not int or index not in (1,2) or not re.fullmatch('[0-9a-f]{64}',cid): raise ValueError('invalid product identity')
    config=obj.get('Config') or {}; host=obj.get('HostConfig') or {}; labels=config.get('Labels') or {}; state=obj.get('State') or {}
    if (obj.get('Id')!=cid or obj.get('Name')!='/'+PROJECT+'-replica'+str(index)+'-1' or obj.get('Image')!=image_id or config.get('Image')!=origin21_evidence.IMAGE or
        labels.get('com.docker.compose.project')!=PROJECT or labels.get('com.docker.compose.service')!='replica'+str(index) or labels.get('org.apicontour.origin21.owner')!=token or
        config.get('User')!=str(os.getuid())+':'+str(os.getgid()) or state.get('Running') is not running or
        host.get('NetworkMode')!=NETWORK or host.get('ReadonlyRootfs') is not True or host.get('CapDrop')!=['ALL'] or
        set(host.get('SecurityOpt') or [])!={'no-new-privileges:true'} or host.get('Privileged') is not False or host.get('CapAdd') not in (None,[]) or host.get('PidMode')=='host' or host.get('IpcMode')=='host' or host.get('UTSMode')=='host' or host.get('UsernsMode')=='host' or host.get('Devices') not in (None,[]) or host.get('Memory')!=256*1024*1024 or
        host.get('NanoCpus')!=1_000_000_000 or host.get('PidsLimit')!=128 or (host.get('PortBindings') not in (None,{}))):
        raise RuntimeError('product configuration drift')
    if config.get('Entrypoint')!=['node','/usr/src/node-red/node_modules/node-red/red.js','--userDir','/data','--settings','/pilot/settings.js'] or config.get('Cmd')!=image_cmd or config.get('WorkingDir')!=image_workdir:
        raise RuntimeError('product entrypoint drift')
    env=config.get('Env') or []
    expected_env=dict(x.split('=',1) for x in image_env)
    expected_env.update(PILOT_TARGET='https://pilot-gateway:9443/pilot',PILOT_TLS_TEST='normal')
    if len(env)!=len(expected_env) or any('=' not in x for x in env) or dict(x.split('=',1) for x in env)!=expected_env: raise RuntimeError('product environment drift')
    tmpfs=host.get('Tmpfs') or {}
    expected_tmpfs={'/data','/tmp'}
    if set(tmpfs)!=expected_tmpfs or any(set(value.split(','))!={'rw','nosuid','nodev','noexec','size=16m','mode=1777'} for value in tmpfs.values()): raise RuntimeError('product tmpfs drift')
    mounts=obj.get('Mounts') or []; expected=_mounts(index)
    if len(mounts)!=len(expected): raise RuntimeError('product mount count drift')
    actual={m.get('Destination'):m for m in mounts}
    if len(actual)!=len(mounts): raise RuntimeError('product mounts ambiguous')
    for target,source in expected.items():
        item=actual.get(target) or {}
        if item.get('Type')!='bind' or item.get('RW') is not False or os.path.realpath(item.get('Source',''))!=source: raise RuntimeError('product mount drift')
    if running:
        networks=(obj.get('NetworkSettings') or {}).get('Networks') or {}
        if set(networks)!={NETWORK} or not re.fullmatch('[0-9a-f]{64}',networks[NETWORK].get('NetworkID','')): raise RuntimeError('product network drift')
        if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',state.get('StartedAt','')): raise RuntimeError('product generation unavailable')
    return state


def _network(expected_ids,token):
    network=_objects(['docker','network','inspect',NETWORK])
    labels=network.get('Labels') or {}; ident=network.get('Id','')
    if (network.get('Name')!=NETWORK or not re.fullmatch('[0-9a-f]{64}',ident) or network.get('Internal') is not True or
        labels.get('com.docker.compose.project')!=PROJECT or labels.get('com.docker.compose.network')!='default' or
        labels.get('org.apicontour.origin21.owner')!=token or set((network.get('Containers') or {}).keys())!=set(expected_ids)):
        raise RuntimeError('product network ownership drift')
    return ident


def _read_record(name):
    path=OWNER/name
    if stat.S_IMODE(os.lstat(path).st_mode)!=0o600: raise ValueError('unsafe product journal mode')
    raw=capture_renew.read_file(path,8192)
    value=capture_renew.exact_json(raw)
    if json.dumps(value,sort_keys=True,separators=(',',':')).encode()!=raw: raise ValueError('invalid product journal')
    return value


def _write_record(name,value):
    origin_credentials._write(OWNER/name,json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def _select_model(full,group):
    """Close a normalized Compose model over one fixed service group."""
    if group not in ('products','companions') or type(full) is not dict or set(full)!={'name','services','networks'} or full['name']!=PROJECT: raise ValueError('invalid compose model')
    services=full['services']; networks=full['networks']; selected=PRODUCTS if group=='products' else COMPANIONS
    if type(services) is not dict or set(services)!=set(PRODUCTS+COMPANIONS) or type(networks) is not dict or set(networks)!={'default','capture'}: raise ValueError('compose service scope drift')
    required_networks={'default'} if group=='products' else {'default','capture'}
    output={}; used_networks=set()
    for name in selected:
        original=services[name]
        if type(original) is not dict or any(key in original for key in ('build','links','external_links','extends','volumes_from','network_mode','pid','ipc')): raise ValueError('unsupported compose service reference')
        service=dict(original); bindings=service.get('networks')
        if type(bindings) is not dict or not bindings or not set(bindings).issubset(required_networks): raise ValueError('compose network scope drift')
        used_networks.update(bindings)
        dependencies=service.get('depends_on')
        if dependencies is not None:
            if type(dependencies) is not dict or not set(dependencies).issubset(services): raise ValueError('invalid compose dependencies')
            dependencies={key:value for key,value in dependencies.items() if key in selected}
            if dependencies: service['depends_on']=dependencies
            else: service.pop('depends_on',None)
        if type(service.get('volumes',[])) is not list: raise ValueError('invalid compose binds')
        for volume in service.get('volumes',[]):
            if type(volume) is not dict or volume.get('type')!='bind' or not isinstance(volume.get('source'),str) or not os.path.isabs(volume['source']): raise ValueError('invalid compose bind')
        output[name]=service
    if used_networks!=required_networks: raise ValueError('unreferenced compose network')
    return {'name':PROJECT,'services':output,'networks':{name:networks[name] for name in sorted(required_networks)}}


def _derive_model(group,token,app_image,capture_network):
    raw=_command(COMPOSE+['config','--format','json'],30,token=token,app_image=app_image,capture_network=capture_network)
    if len(raw)>MODEL_LIMIT: raise ValueError('compose model output bound')
    full=capture_renew.exact_json(raw)
    model=_select_model(full,group)
    default=full['networks']['default']; capture=full['networks']['capture']
    if (type(default) is not dict or default.get('name')!=NETWORK or default.get('internal') is not True or (default.get('labels') or {}).get('org.apicontour.origin21.owner')!=token or
        type(capture) is not dict or capture.get('name')!=capture_network or capture.get('external') is not True): raise ValueError('compose network identity drift')
    result=json.dumps(model,sort_keys=True,separators=(',',':')).encode()
    if not 1<=len(result)<=MODEL_LIMIT: raise ValueError('compose model bound')
    return result


def _verify_model(group,digest):
    if group not in ('products','companions') or not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest): raise ValueError('invalid compose model identity')
    raw=origin_credentials._file(OWNER/(group+'-model.json'),MODEL_LIMIT)
    if hashlib.sha256(raw).hexdigest()!=digest: raise ValueError('compose model changed')
    value=capture_renew.exact_json(raw)
    names=PRODUCTS if group=='products' else COMPANIONS; networks={'default'} if group=='products' else {'default','capture'}
    if type(value) is not dict or set(value)!={'name','services','networks'} or value['name']!=PROJECT or type(value['services']) is not dict or set(value['services'])!=set(names) or type(value['networks']) is not dict or set(value['networks'])!=networks or json.dumps(value,sort_keys=True,separators=(',',':')).encode()!=raw: raise ValueError('invalid stored compose model')
    used_networks=set()
    for service in value['services'].values():
        if type(service) is not dict or type(service.get('networks')) is not dict or not set(service['networks']).issubset(networks) or type(service.get('depends_on',{})) is not dict or not set(service.get('depends_on',{})).issubset(names): raise ValueError('stored compose model escapes group')
        used_networks.update(service['networks'])
    if used_networks!=networks: raise ValueError('stored compose network drift')
    return OWNER/(group+'-model.json')


def _identity_ready():
    profile=origin21_profile.PROFILE
    capture_renew.safe_dir(profile.state.parent); capture_renew.safe_dir(profile.state)
    journal=origin21_state._read(profile.state/'setup.json',origin21_state._identity(profile),origin21_state._source_identity())
    if journal['completed']!=1 or journal['pending'] is not None: raise ValueError('identities-only setup required')
    creds=origin21_credentials.Credentials(profile,profile.state.parent/'ca.crt',profile.state.parent/'ca.key')
    if creds.inspect()!=origin21_state.EXACT or creds.commitment()!=journal['credential_digest']: raise ValueError('credential bundle drift')


def start_products(*, app_image_id, build_head, build_receipt, build_receipt_sha256):
    """One-shot create/start of only the two fixed product services; never adopt."""
    _identity_ready()
    deployment=_build_receipt(app_image_id,build_head,build_receipt,build_receipt_sha256)
    _capture_network(deployment)
    if os.path.lexists(OWNER): raise ValueError('product ownership state already exists')
    existing=_command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+PROJECT]).split()
    if existing: raise ValueError('product project already exists')
    names=_command(['docker','network','ls','--filter','name=^'+NETWORK+'$','--format','{{.Name}}']).decode('ascii').splitlines()
    if NETWORK in names: raise ValueError('product network already exists')
    image_id,image_env,image_cmd,image_workdir=_image_id(); token=secrets.token_hex(32)
    os.mkdir(OWNER,0o700)
    fd=os.open(OWNER.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
    model=_derive_model('products',token,app_image_id,deployment['name'])
    origin_credentials._write(OWNER/'products-model.json',model)
    model_hash=hashlib.sha256(model).hexdigest()
    _write_record('intent.json',{'version':1,'project':PROJECT,'image':origin21_evidence.IMAGE,'image_id':image_id,'image_env':image_env,'image_cmd':image_cmd,'image_workdir':image_workdir,'token':token,'app_image_id':app_image_id,'build_head':build_head,'build_receipt_sha256':build_receipt_sha256,'deployment':deployment,'services':['replica1','replica2'],'model_sha256':model_hash})
    # Any create/start exception remains an explicit unresolved intent. No
    # broad removal, automatic recovery, or treating partial creation as success.
    model_path=_verify_model('products',model_hash)
    _command(['docker','compose','--project-name',PROJECT,'-f',str(model_path),'create','--no-build','--pull','never',*PRODUCTS],90,token=token,app_image=app_image_id,capture_network=deployment['name'])
    _verify_model('products',model_hash)
    ids=_command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+PROJECT]).decode('ascii').split()
    if len(ids)!=2 or len(set(ids))!=2: raise RuntimeError('product creation ambiguous')
    mapped={}
    for cid in ids:
        _verify_model('products',model_hash)
        obj=_objects(['docker','inspect',cid]); service=(obj.get('Config') or {}).get('Labels',{}).get('com.docker.compose.service')
        if service not in ('replica1','replica2') or service in mapped: raise RuntimeError('product identity ambiguous')
        index=int(service[-1]); validate(obj,index,cid,image_id,image_env,image_cmd,image_workdir,token,running=False); mapped[service]=cid
    for service in ('replica1','replica2'):
        _verify_model('products',model_hash)
        _command(['docker','start',mapped[service]],30)
    network_id=_network(mapped.values(),token)
    values=[]
    for index in (1,2):
        _verify_model('products',model_hash)
        cid=mapped['replica'+str(index)]; obj=_objects(['docker','inspect',cid]); state=validate(obj,index,cid,image_id,image_env,image_cmd,image_workdir,token,running=True)
        leaf=hashlib.sha256(origin_credentials._file(origin21_profile.PROFILE.origins[index-1].leaf_der)).hexdigest()
        values.append(origin21_evidence.descriptor({'container_id':cid,'image_id':image_id,'image_ref':origin21_evidence.IMAGE,
            'namespace':network_id,'service_label':'replica'+str(index),'leaf_sha256':leaf,'started_at':state['StartedAt'],
            'app_image_id':app_image_id,'build_head':build_head,'build_receipt_sha256':build_receipt_sha256,'deployment_sha256':_network_digest(deployment)},index,leaf))
    _write_record('products.json',{'version':1,'slots':values})
    commitments=tuple(origin21_evidence.digest(value) for value in values)
    _write_record('commitments.json',{'version':1,'sha256':[value.hex() for value in commitments]})
    return commitments


def inspect_slot(index):
    """Recheck the one recorded live generation; never restart or replace it."""
    if type(index) is not int or index not in (1,2): raise ValueError('unsupported product slot')
    capture_renew.safe_dir(OWNER)
    if stat.S_IMODE(os.lstat(OWNER).st_mode)!=0o700: raise ValueError('unsafe product ownership directory')
    intent=_read_record('intent.json'); record=_read_record('products.json')
    if set(intent)!={'version','project','image','image_id','image_env','image_cmd','image_workdir','token','app_image_id','build_head','build_receipt_sha256','deployment','services','model_sha256'} or intent['version']!=1 or intent['project']!=PROJECT or intent['image']!=origin21_evidence.IMAGE or intent['services']!=['replica1','replica2']:
        raise ValueError('product intent drift')
    _verify_model('products',intent['model_sha256'])
    _capture_network(intent['deployment'])
    if set(record)!={'version','slots'} or record['version']!=1 or not isinstance(record['slots'],list) or len(record['slots'])!=2: raise ValueError('product record drift')
    ids=[slot['container_id'] for slot in record['slots']]
    if os.path.lexists(OWNER/'companions-intent.json'):
        network_id=_companion_record(intent,ids)
    else:
        if os.path.lexists(OWNER/'companions.json'): raise ValueError('unexpected companion record')
        network_id=_network(ids,intent['token'])
        project_ids=_command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+PROJECT]).decode('ascii').split()
        if len(project_ids)!=2 or set(project_ids)!=set(ids): raise ValueError('project membership drift')
    _verify_model('products',intent['model_sha256'])
    if os.path.lexists(OWNER/'companions-intent.json'): _verify_model('companions',_read_record('companions-intent.json')['model_sha256'])
    item=record['slots'][index-1]; cid=item['container_id']; obj=_objects(['docker','inspect',cid]); state=validate(obj,index,cid,intent['image_id'],intent['image_env'],intent['image_cmd'],intent['image_workdir'],intent['token'],running=True)
    leaf=hashlib.sha256(origin_credentials._file(origin21_profile.PROFILE.origins[index-1].leaf_der)).hexdigest()
    current=origin21_evidence.descriptor({'container_id':cid,'image_id':intent['image_id'],'image_ref':origin21_evidence.IMAGE,
        'namespace':network_id,'service_label':'replica'+str(index),'leaf_sha256':leaf,'started_at':state['StartedAt'],
        'app_image_id':intent['app_image_id'],'build_head':intent['build_head'],'build_receipt_sha256':intent['build_receipt_sha256'],'deployment_sha256':_network_digest(intent['deployment'])},index,leaf)
    if current!=item: raise ValueError('product generation changed')
    return current

# Fixed companion set. App image ID must be supplied in a root-reviewed local
# build receipt; the Envoy and Node images are immutable digest references.
ENVOY='envoyproxy/envoy:v1.37.11@sha256:7765ad61185fca9c9a770c9e2cad640d085d708ae9c22f3741345e88331472a4'
COMPANIONS=('destination','origin21-capture-ingress','origin21-capture-worker','native-gateway','native-envoy')


def _image(ref):
    value=_objects(['docker','image','inspect',ref]); ident=value.get('Id',''); config=value.get('Config') or {}
    if not re.fullmatch('sha256:[0-9a-f]{64}',ident): raise ValueError('invalid companion image')
    env=config.get('Env') or []
    if not isinstance(env,list) or any(not isinstance(x,str) or '=' not in x for x in env): raise ValueError('invalid image environment')
    return {'id':ident,'env':env,'cmd':config.get('Cmd'),'entrypoint':config.get('Entrypoint'),'workdir':config.get('WorkingDir')}


def _companion_mounts(service):
    state=origin21_profile.STATE; root=state.parent
    if service=='destination': paths={
        '/pilot/destination.js':ROOT/'deploy/pilot/destination.js','/pilot/ca.crt':root/'ca.crt',
        '/pilot/tls/server.crt':state/'destination/server.crt','/pilot/tls/server.key':state/'destination/server.key'}
    elif service=='native-gateway': paths={'/run/native':state/'native/gateway'}
    elif service=='native-envoy': paths={'/run/forwarder':state/'native/forwarder'}
    elif service=='origin21-capture-worker': paths={
        '/run/capture/worker.json':state/'capture/runtime/worker.json',
        '/run/capture/worker.password':state/'capture/runtime/worker.password', '/run/capture/database-ca.crt':root/'ca.crt'}
    elif service=='origin21-capture-ingress':
        paths={'/run/capture/database-ca.crt':root/'ca.crt'}
        for name in ('ingress.json','ingress.password','server.crt.der','server.key.der','collector.crt.der','ca.der','policy.raw'):
            paths['/run/capture/'+name]=state/'capture/runtime'/name
    else: raise ValueError('unsupported companion')
    return {target:os.path.realpath(path) for target,path in paths.items()}


def _capture_network(deployment):
    name=deployment['name']; item=_objects(['docker','network','inspect',name]); labels=item.get('Labels') or {}
    if item.get('Name')!=name or item.get('Id')!=deployment['id']: raise RuntimeError('capture network drift')
    if deployment['owner_kind']=='local':
        if labels.get('com.docker.compose.project')!='apicontour-local' or labels.get('com.docker.compose.network')!='default': raise RuntimeError('local network ownership drift')
    elif deployment['owner_kind']=='fixture':
        if item.get('Internal') is not True or labels.get('org.apicontour.fixture-owner')!=deployment['owner_token']: raise RuntimeError('fixture network ownership drift')
    else: raise RuntimeError('unsupported deployment network')
    cid=deployment['postgres_id']
    if cid not in (item.get('Containers') or {}): raise RuntimeError('postgres network membership drift')
    pg=_objects(['docker','inspect',cid]); cfg=pg.get('Config') or {}; pglabels=cfg.get('Labels') or {}
    if pg.get('Id')!=cid or pg.get('Image')!=deployment['postgres_image_id'] or (pg.get('State') or {}).get('Running') is not True or (pg.get('HostConfig') or {}).get('Init') is not True or cfg.get('Image')!='postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4': raise RuntimeError('postgres identity drift')
    if deployment['owner_kind']=='local' and (pglabels.get('com.docker.compose.project')!='apicontour-local' or pglabels.get('com.docker.compose.service')!='postgres'): raise RuntimeError('postgres ownership drift')
    if deployment['owner_kind']=='fixture' and pglabels.get('org.apicontour.fixture-owner')!=deployment['owner_token']: raise RuntimeError('postgres ownership drift')
    network=((pg.get('NetworkSettings') or {}).get('Networks') or {}).get(name) or {}
    if network.get('NetworkID')!=deployment['id'] or 'postgres' not in (network.get('Aliases') or []): raise RuntimeError('postgres alias drift')
    ca=capture_renew.read_file(origin21_profile.STATE.parent/'ca.crt',65536)
    if hashlib.sha256(ca).hexdigest()!=deployment['ca_sha256']: raise RuntimeError('database CA drift')
    return deployment['id']


def _validate_companion(obj,service,cid,image,token,default_network,capture_network,capture_name,*,running):
    if service not in COMPANIONS or not re.fullmatch('[0-9a-f]{64}',cid): raise ValueError('invalid companion identity')
    config=obj.get('Config') or {}; host=obj.get('HostConfig') or {}; labels=config.get('Labels') or {}; state=obj.get('State') or {}
    ref=origin21_evidence.IMAGE if service=='destination' else ENVOY if service=='native-envoy' else image['id']
    memory=192*1024*1024 if service=='destination' else 256*1024*1024
    pids=64 if service=='destination' else 128
    if (obj.get('Id')!=cid or obj.get('Name')!='/'+PROJECT+'-'+service+'-1' or obj.get('Image')!=image['id'] or config.get('Image')!=ref or
        labels.get('com.docker.compose.project')!=PROJECT or labels.get('com.docker.compose.service')!=service or labels.get('org.apicontour.origin21.owner')!=token or
        config.get('User')!=str(os.getuid())+':'+str(os.getgid()) or state.get('Running') is not running or
        host.get('ReadonlyRootfs') is not True or host.get('Privileged') is not False or host.get('CapDrop')!=['ALL'] or host.get('CapAdd') not in (None,[]) or
        set(host.get('SecurityOpt') or [])!={'no-new-privileges:true'} or host.get('PidMode')=='host' or host.get('IpcMode')=='host' or host.get('UTSMode')=='host' or host.get('UsernsMode')=='host' or host.get('Devices') not in (None,[]) or
        host.get('Memory')!=memory or host.get('NanoCpus')!=1_000_000_000 or host.get('PidsLimit')!=pids or host.get('PortBindings') not in (None,{}) or host.get('Tmpfs') not in (None,{})):
        raise RuntimeError('companion configuration drift')
    entry={'destination':['node','/pilot/destination.js'],
           'origin21-capture-ingress':['/usr/local/bin/local_capture','ingress','/run/capture/ingress.json'],
           'origin21-capture-worker':['/usr/local/bin/local_capture','worker','/run/capture/worker.json'],
           'native-gateway':['/usr/local/bin/local_gateway','/run/native/gateway.json'],
           'native-envoy':image['entrypoint']}[service]
    cmd=['-c','/run/forwarder/envoy.json','--log-level','error'] if service=='native-envoy' else image['cmd']
    workdir='' if image['workdir'] is None else image['workdir']
    if type(workdir) is not str or config.get('Entrypoint')!=entry or config.get('Cmd')!=cmd or config.get('WorkingDir')!=workdir: raise RuntimeError('companion command drift')
    env=config.get('Env') or []; wanted=dict(x.split('=',1) for x in image['env'])
    if service=='destination': wanted['PILOT_DESTINATION_MODE']='normal'
    if len(env)!=len(wanted) or any('=' not in x for x in env) or dict(x.split('=',1) for x in env)!=wanted: raise RuntimeError('companion environment drift')
    mounts=obj.get('Mounts') or []; wanted_mounts=_companion_mounts(service); actual={m.get('Destination'):m for m in mounts}
    if len(mounts)!=len(wanted_mounts) or len(actual)!=len(mounts): raise RuntimeError('companion mount drift')
    for target,path in wanted_mounts.items():
        m=actual.get(target) or {}
        if m.get('Type')!='bind' or m.get('RW') is not False or os.path.realpath(m.get('Source',''))!=path: raise RuntimeError('companion mount drift')
    if running:
        networks=(obj.get('NetworkSettings') or {}).get('Networks') or {}
        expected=({capture_name:capture_network} if service in ('origin21-capture-ingress','origin21-capture-worker') else
                  {NETWORK:default_network,capture_name:capture_network} if service=='native-gateway' else {NETWORK:default_network})
        if set(networks)!=set(expected) or any(networks[name].get('NetworkID')!=ident for name,ident in expected.items()): raise RuntimeError('companion network drift')
        if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',state.get('StartedAt','')): raise RuntimeError('companion generation unavailable')
    return state


def _recorded_products(intent,record):
    _verify_model('products',intent['model_sha256'])
    if type(record) is not dict or set(record)!={'version','slots'} or record['version']!=1 or type(record['slots']) is not list or len(record['slots'])!=2: raise ValueError('product record drift')
    ids=[]
    for index,item in enumerate(record['slots'],1):
        _verify_model('products',intent['model_sha256'])
        if type(item) is not dict or not re.fullmatch('[0-9a-f]{64}',item.get('container_id','')): raise ValueError('product record drift')
        cid=item['container_id']; ids.append(cid)
        obj=_objects(['docker','inspect',cid]); state=validate(obj,index,cid,intent['image_id'],intent['image_env'],intent['image_cmd'],intent['image_workdir'],intent['token'],running=True)
        leaf=hashlib.sha256(origin_credentials._file(origin21_profile.PROFILE.origins[index-1].leaf_der)).hexdigest()
        current=origin21_evidence.descriptor({'container_id':cid,'image_id':intent['image_id'],'image_ref':origin21_evidence.IMAGE,
            'namespace':item.get('namespace',''),'service_label':'replica'+str(index),'leaf_sha256':leaf,'started_at':state['StartedAt'],
            'app_image_id':intent['app_image_id'],'build_head':intent['build_head'],'build_receipt_sha256':intent['build_receipt_sha256'],'deployment_sha256':_network_digest(intent['deployment'])},index,leaf)
        if current!=item: raise ValueError('product generation changed')
    if len(set(ids))!=2: raise ValueError('product identity collision')
    return ids


def _companion_record(intent,products):
    pending=_read_record('companions-intent.json'); record=_read_record('companions.json')
    if (type(pending) is not dict or set(pending)!={'version','token','image_id','build_head','build_receipt_sha256','capture_network','images','services','model_sha256'} or
        pending['version']!=1 or pending['token']!=intent['token'] or pending['image_id']!=intent['app_image_id'] or
        pending['build_head']!=intent['build_head'] or pending['build_receipt_sha256']!=intent['build_receipt_sha256'] or pending['services']!=list(COMPANIONS)):
        raise ValueError('companion intent drift')
    _verify_model('products',intent['model_sha256']); _verify_model('companions',pending['model_sha256'])
    if type(record) is not dict or set(record)!={'version','services'} or record['version']!=1 or type(record['services']) is not dict or set(record['services'])!=set(COMPANIONS): raise ValueError('companion record drift')
    current=origin21_transport._run(['git','rev-parse','HEAD'],'',deadline=15)
    dirty=origin21_transport._run(['git','status','--porcelain','--untracked-files=all'],'',deadline=15)
    if current!=intent['build_head'] or dirty: raise ValueError('app source changed')
    app=_image(intent['app_image_id']); node=_image(origin21_evidence.IMAGE); envoy=_image(ENVOY)
    expected_images={name:(node if name=='destination' else envoy if name=='native-envoy' else app) for name in COMPANIONS}
    if app['id']!=intent['app_image_id'] or node['id']!=intent['image_id'] or pending['images']!=expected_images: raise ValueError('companion image drift')
    capture=_capture_network(intent['deployment'])
    if capture!=pending['capture_network']: raise ValueError('capture network changed')
    slots=record['services']; network_members=products+[slots[x]['id'] for x in ('destination','native-gateway','native-envoy')]
    network=_network(network_members,intent['token'])
    for service in COMPANIONS:
        _verify_model('products',intent['model_sha256']); _verify_model('companions',pending['model_sha256'])
        entry=slots[service]
        if type(entry) is not dict or set(entry)!={'id','started_at'}: raise ValueError('companion record drift')
        image=pending['images'][service]
        obj=_objects(['docker','inspect',entry['id']]); state=_validate_companion(obj,service,entry['id'],image,intent['token'],network,capture,intent['deployment']['name'],running=True)
        if state['StartedAt']!=entry['started_at']: raise ValueError('companion generation changed')
    ids=_command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+PROJECT]).decode('ascii').split()
    if len(ids)!=7 or set(ids)!=set(products+[slots[x]['id'] for x in COMPANIONS]): raise ValueError('project membership drift')
    return network


def require_current_policy(psql,sensitive_execute,pending=None):
    from deploy.local import origin21_renewal, provision
    history=origin21_renewal.history(origin21_profile.BOUND,sensitive_execute,pending)
    if history is None: raise ValueError('observer policy unavailable')
    policy=history.head_policy; tenant=provision.sql_quote(provision.IDS[0]); collector=provision.sql_quote(origin21_profile.PROFILE.collector)
    issued=provision.sql_quote(policy['issued_at']); expires=provision.sql_quote(policy['expires_at']); revision=policy['revision']
    current=psql(f"SELECT (EXISTS (SELECT 1 FROM contour.collector_authorization WHERE tenant_id={tenant} AND collector_id={collector} AND enabled AND revoked_at IS NULL AND active_revision={revision}) AND pg_catalog.clock_timestamp()>={issued}::timestamptz AND pg_catalog.clock_timestamp()<{expires}::timestamptz)::text;")
    if current!='true': raise ValueError('observer policy not current')
    return revision


def start_companions(*,app_image_id,build_head,build_receipt,build_receipt_sha256,psql,sensitive_execute,authenticate):
    """One-shot fixed companion transition after complete operator enrollment.

    A partial or ambiguous transition is retained and refuses further starts.
    Product containers are never recreated, restarted or deleted here.
    """
    capture_renew.safe_dir(OWNER)
    if stat.S_IMODE(os.lstat(OWNER).st_mode)!=0o700: raise ValueError('unsafe product ownership directory')
    intent=_read_record('intent.json'); products=_read_record('products.json')
    if (intent.get('app_image_id'),intent.get('build_head'),intent.get('build_receipt_sha256'))!=(app_image_id,build_head,build_receipt_sha256): raise ValueError('app build identity changed')
    _verify_model('products',intent['model_sha256'])
    if not all(callable(x) for x in (psql,sensitive_execute,authenticate)) or psql is sensitive_execute: raise ValueError('trusted database callbacks required')
    deployment=_build_receipt(app_image_id,build_head,build_receipt,build_receipt_sha256)
    if deployment!=intent['deployment']: raise ValueError('deployment network changed')
    profile=origin21_profile.PROFILE
    journal=origin21_state._read(profile.state/'setup.json',origin21_state._identity(profile),origin21_state._source_identity())
    if journal['completed']!=len(origin21_state.PHASES) or journal['pending'] is not None: raise ValueError('complete enrollment required')
    product_ids=_recorded_products(intent,products)
    _network(product_ids,intent['token'])
    if os.path.lexists(OWNER/'companions-intent.json') or os.path.lexists(OWNER/'companions.json'): raise ValueError('companion state already exists')
    existing=_command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+PROJECT]).decode('ascii').split()
    if len(existing)!=2 or set(existing)!=set(product_ids): raise ValueError('project contains unplanned containers')
    expected=tuple(origin21_evidence.digest(slot) for slot in products['slots'])
    from deploy.local import origin21_setup
    origin21_setup.prepare(psql=psql,sensitive_execute=sensitive_execute,authenticate=authenticate,
        inspect_slot=inspect_slot,expected_evidence=expected,check_only=True)
    evidence=origin21_evidence.Evidence(profile,inspect_slot,expected)
    if evidence.inspect()!=origin21_state.EXACT or evidence.commitment()!=journal['evidence_digest']: raise ValueError('operator evidence drift')
    from deploy.local import origin21_renewal, origin21_schema
    allowed,pending=origin21_renewal.artifacts(origin21_profile.BOUND)
    if pending is not None: raise ValueError('renewal requires reconciliation')
    require_current_policy(psql,sensitive_execute,pending)
    credential=origin21_credentials.Credentials(profile,profile.state.parent/'ca.crt',profile.state.parent/'ca.key')
    credential.allow_observer_policy=True; credential.allow_operator_evidence=True; credential.allow_runtime_configs=True
    credential.allow_renewal_artifacts=frozenset(allowed)
    if credential.inspect()!=origin21_state.EXACT or credential.commitment()!=journal['credential_digest']: raise ValueError('credential commitment drift')
    versions=[int(x) for x in psql('SELECT version FROM contour.schema_migrations ORDER BY version;').splitlines()]
    origin21_schema.require_ready(versions,psql,stage=21,phase='enrolled')
    app=_image(app_image_id); node=_image(origin21_evidence.IMAGE); envoy=_image(ENVOY)
    if app['id']!=app_image_id or node['id']!=intent['image_id']: raise ValueError('companion image identity changed')
    images={name:(node if name=='destination' else envoy if name=='native-envoy' else app) for name in COMPANIONS}
    capture=_capture_network(intent['deployment'])
    model=_derive_model('companions',intent['token'],app_image_id,deployment['name'])
    origin_credentials._write(OWNER/'companions-model.json',model)
    model_hash=hashlib.sha256(model).hexdigest()
    _write_record('companions-intent.json',{'version':1,'token':intent['token'],'image_id':app_image_id,'build_head':build_head,
        'build_receipt_sha256':build_receipt_sha256,'capture_network':capture,'images':images,'services':list(COMPANIONS),'model_sha256':model_hash})
    _verify_model('products',intent['model_sha256']); model_path=_verify_model('companions',model_hash)
    _command(['docker','compose','--project-name',PROJECT,'-f',str(model_path),'create','--no-build','--pull','never',*COMPANIONS],90,token=intent['token'],app_image=app_image_id,capture_network=deployment['name'])
    _verify_model('products',intent['model_sha256']); _verify_model('companions',model_hash)
    ids=_command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+PROJECT]).decode('ascii').split()
    if len(ids)!=7 or not set(product_ids).issubset(ids) or len(set(ids))!=7: raise RuntimeError('companion creation ambiguous')
    mapped={}
    for cid in set(ids)-set(product_ids):
        _verify_model('products',intent['model_sha256']); _verify_model('companions',model_hash)
        obj=_objects(['docker','inspect',cid]); service=((obj.get('Config') or {}).get('Labels') or {}).get('com.docker.compose.service')
        if service not in COMPANIONS or service in mapped: raise RuntimeError('companion identity ambiguous')
        _validate_companion(obj,service,cid,images[service],intent['token'],'','',intent['deployment']['name'],running=False); mapped[service]=cid
    if set(mapped)!=set(COMPANIONS): raise RuntimeError('companion creation incomplete')
    for service in ('origin21-capture-ingress','origin21-capture-worker','destination','native-gateway','native-envoy'):
        _verify_model('products',intent['model_sha256']); _verify_model('companions',model_hash)
        _command(['docker','start',mapped[service]],30)
    members=product_ids+[mapped[x] for x in ('destination','native-gateway','native-envoy')]
    network=_network(members,intent['token'])
    if network!=products['slots'][0]['namespace'] or any(slot['namespace']!=network for slot in products['slots']): raise RuntimeError('product network changed')
    if _recorded_products(intent,products)!=product_ids: raise RuntimeError('product generation changed')
    states={}
    for service in COMPANIONS:
        _verify_model('products',intent['model_sha256']); _verify_model('companions',model_hash)
        obj=_objects(['docker','inspect',mapped[service]])
        state=_validate_companion(obj,service,mapped[service],images[service],intent['token'],network,capture,intent['deployment']['name'],running=True)
        states[service]={'id':mapped[service],'started_at':state['StartedAt']}
    _write_record('companions.json',{'version':1,'services':states})
    return {'companions_started':True,'pilot_ready':False}
