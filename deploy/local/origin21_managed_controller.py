"""Closed managed Origin21 topology checks for the owned edge bootstrap.

No commands execute on import. A complete managed operation also requires
owned companion/publisher creation and a one-time live Envoy binding.
"""
from deploy.gateway.managed_edge import NativeDirectoryPublisher,NativeReplicaPeer
from deploy.local import origin21_products as products,origin21_profile as profiles,origin21_state, capture_renew
from deploy.pilot import origin_credentials
import json
import os


def _topology_snapshot(peer,publisher,*,live_envoy=False,qualification=None):
    if type(peer) is not NativeReplicaPeer or type(publisher) is not NativeDirectoryPublisher: raise ValueError('managed native identities required')
    selected=profiles.MANAGED
    if qualification is not None: qualification.verify_owner(selected.owner)
    elif os.path.lexists(selected.owner/'qualification.intent'): raise ValueError('qualification proof required')
    intent=products._read_record('intent.json',selected=selected)
    recorded=products._read_record('products.json',selected=selected)
    pending=products._read_record('companions-intent.json',selected=selected)
    created=products._read_record('companions-created.json',selected=selected)
    if (type(intent) is not dict or intent.get('project')!=selected.project or
        type(pending) is not dict or set(pending)!={'version','token','image_id','build_head','build_receipt_sha256','capture_network','images','services','model_sha256'} or pending.get('version')!=1 or pending.get('token')!=intent.get('token') or
        (pending.get('image_id'),pending.get('build_head'),pending.get('build_receipt_sha256'))!=(intent.get('app_image_id'),intent.get('build_head'),intent.get('build_receipt_sha256')) or pending.get('services')!=list(products.COMPANIONS) or
        type(created) is not dict or set(created)!={'version','services'} or created['version']!=1 or
        type(created['services']) is not dict or set(created['services'])!=set(products.COMPANIONS)):
        raise ValueError('managed bootstrap records invalid')
    products._verify_model('products',intent['model_sha256'],selected=selected)
    products._verify_model('companions',pending['model_sha256'],selected=selected)
    source=origin21_state._source_identity(context=selected)
    state=origin21_state._read(selected.profile.state/'setup.json',origin21_state._identity(selected.profile),source)
    if state['completed']!=len(origin21_state.PHASES) or state['pending'] is not None: raise ValueError('managed enrollment incomplete')
    ids=products._recorded_products(intent,recorded,selected=selected)
    from deploy.local import origin21_managed_init
    if origin21_managed_init.SOURCE not in origin21_state.MANAGED_SOURCE_FILES: raise ValueError('managed DB source not pinned')
    db_raw=origin_credentials._file(origin21_managed_init.BASE/'initializer.intent',4096)
    db_intent=capture_renew.exact_json(db_raw)
    if (type(db_intent) is not dict or set(db_intent)!={'version','head','build_image','build_receipt_sha256','token','network','volume'} or db_intent.get('version')!=1 or json.dumps(db_intent,sort_keys=True,separators=(',',':')).encode()!=db_raw or
        (db_intent['head'],db_intent['build_image'])!=(intent['build_head'],intent['app_image_id']) or db_intent['network']!=intent['deployment']['name']): raise ValueError('managed DB ownership record changed')
    volume=origin21_managed_init._selected_volume(qualification)
    if db_intent['volume']!=volume: raise ValueError('managed DB volume identity changed')
    if qualification is not None: qualification.require_build(db_intent['build_image'],db_intent['head'],db_intent['build_receipt_sha256'])
    origin21_managed_init._db_inventory(db_intent['token'],[intent['deployment']['postgres_id']])
    start_raw=origin_credentials._file(origin21_managed_init.BASE/'postgres.start.result',4096); db_start=capture_renew.exact_json(start_raw)
    done_raw=origin_credentials._file(origin21_managed_init.BASE/'initializer.done',4096); db_done=capture_renew.exact_json(done_raw)
    if (type(db_start) is not dict or set(db_start)!={'version','id','started_at'} or db_start['version']!=1 or db_start['id']!=intent['deployment']['postgres_id'] or
        type(db_done) is not dict or set(db_done)!={'version','receipt_sha256','postgres_id','started_at'} or db_done['version']!=1 or
        db_done['postgres_id']!=db_start['id'] or db_done['started_at']!=db_start['started_at'] or db_done['receipt_sha256']!=intent['build_receipt_sha256'] or
        json.dumps(db_start,sort_keys=True,separators=(',',':')).encode()!=start_raw or json.dumps(db_done,sort_keys=True,separators=(',',':')).encode()!=done_raw): raise ValueError('managed DB generation record changed')
    pg_image=products._image(origin21_managed_init.POSTGRES)
    if pg_image['id']!=intent['deployment']['postgres_image_id']: raise ValueError('managed DB image changed')
    pg_state=origin21_managed_init._postgres(db_start['id'],pg_image,intent['deployment']['id'],db_intent['token'],running=True,qualification=qualification)
    if pg_state['StartedAt']!=db_start['started_at']: raise ValueError('managed DB generation changed')
    origin21_managed_init._volume(db_intent['token'],qualification=qualification)
    slots=recorded['slots']; services=created['services']; all_ids=list(ids)
    for service,item in services.items():
        if type(item) is not dict or set(item)!={'id','started_at'} or not isinstance(item['id'],str): raise ValueError('managed companion record invalid')
        all_ids.append(item['id'])
        if (service=='native-envoy') != (item['started_at'] is None): raise ValueError('managed companion start invalid')
    if len(set(all_ids))!=7 or publisher.cid in all_ids: raise ValueError('managed container identity collision')
    project_ids=products._command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+selected.project]).decode('ascii').split()
    if len(project_ids)!=7 or set(project_ids)!=set(all_ids): raise ValueError('managed project membership changed')
    edge_token=products._managed_edge_token(selected,intent['token'])
    edge_ids=products._command(['docker','ps','-aq','--no-trunc','--filter','label=org.apicontour.managed-edge-owner='+edge_token]).decode('ascii').split()
    if len(edge_ids)!=2 or set(edge_ids)!={services['native-envoy']['id'],publisher.cid}: raise ValueError('managed edge ownership membership changed')
    raw=origin_credentials._file(selected.edge/'publisher.json',32768); publisher_record=capture_renew.exact_json(raw)
    if json.dumps(publisher_record,sort_keys=True,separators=(',',':')).encode()!=raw or publisher_record!=publisher.identity(): raise ValueError('managed publisher record changed')
    if publisher.token!=edge_token or publisher.watched!=str(selected.edge/'watched'): raise ValueError('managed publisher identity changed')
    if peer.cid!=ids[0] or peer.image_id!=intent['image_id'] or peer.mounts!=products._mounts(1,selected=selected) or peer.envoy_cid!=services['native-envoy']['id'] or peer.envoy_mounts!=products._companion_mounts('native-envoy',selected=selected): raise ValueError('managed peer identity changed')
    business_members=ids+[services['destination']['id'],services['native-gateway']['id']]
    if live_envoy: business_members.append(services['native-envoy']['id'])
    business=products._network(business_members,intent['token'],selected=selected)
    capture=products._capture_network(intent['deployment'],selected=selected)
    if peer.network_id!=business or pending.get('capture_network')!=capture: raise ValueError('managed network identity changed')
    network=products._objects(['docker','network','inspect',intent['deployment']['name']])
    expected_capture={intent['deployment']['postgres_id'],services['native-gateway']['id'],services['origin21-capture-ingress']['id'],services['origin21-capture-worker']['id']}
    if set((network.get('Containers') or {}).keys())!=expected_capture or publisher.cid in expected_capture: raise ValueError('managed capture membership changed')
    images=pending.get('images')
    if type(images) is not dict or set(images)!=set(products.COMPANIONS): raise ValueError('managed images invalid')
    app=products._image(intent['app_image_id']); node=products._image(products.origin21_evidence.IMAGE); envoy=products._image(products.ENVOY)
    expected={name:(node if name=='destination' else envoy if name=='native-envoy' else app) for name in products.COMPANIONS}
    if app['id']!=intent['app_image_id'] or node['id']!=intent['image_id'] or images!=expected or peer.envoy_image_id!=envoy['id']: raise ValueError('managed image identity changed')
    envoy_started=None
    for service in products.COMPANIONS:
        item=services[service]; running=service!='native-envoy' or live_envoy
        obj=products._objects(['docker','inspect',item['id']])
        state=products._validate_companion(obj,service,item['id'],images[service],intent['token'],business,capture,intent['deployment']['name'],running=running,selected=selected,qualification=qualification)
        if service=='native-envoy' and live_envoy: envoy_started=state['StartedAt']
        elif running and state['StartedAt']!=item['started_at']: raise ValueError('managed companion generation changed')
    publisher.verify()
    if live_envoy: peer.verify_existing_after_start(slots[0]['started_at'],slots[0]['leaf_sha256'],envoy_started)
    else: peer.verify_existing_before_publication(slots[0]['started_at'],slots[0]['leaf_sha256'])
    return ({'version':1,'source':source,'peer':peer.identity(),'publisher':publisher.identity(),
            'products':slots,'companions':services,'business_network':business,'capture_network':capture,
            'postgres_id':intent['deployment']['postgres_id'],'postgres_started':db_start['started_at']},envoy_started)


def verify_before_publication(peer,publisher,*,qualification=None):
    """Return a stable exact pre-start snapshot; no SQL or product restart."""
    first=_topology_snapshot(peer,publisher,qualification=qualification); second=_topology_snapshot(peer,publisher,qualification=qualification)
    if first!=second: raise ValueError('managed prepublication topology changed')
    return first[0]


def verify_after_start(peer,publisher,record,*,qualification=None):
    first=_topology_snapshot(peer,publisher,live_envoy=True,qualification=qualification); second=_topology_snapshot(peer,publisher,live_envoy=True,qualification=qualification)
    if first!=second or first[0]!=record or not first[1]: raise ValueError('managed live topology changed')
    return {'replica_started':record['products'][0]['started_at'],'envoy_started':first[1]}


def start_envoy_once(owner):
    """Start only the prebound Envoy once, then bind and confirm its live TLS."""
    import hashlib
    from deploy.gateway.managed_edge import ManagedEdge,_regular
    if type(owner) is not ManagedEdge or type(owner.peer) is not NativeReplicaPeer or type(owner.publisher) is not NativeDirectoryPublisher: raise ValueError('managed edge owner required')
    data=owner._load()
    if data['current'] is not None or data['binding'] is not None or not data['pending'] or data['pending']['phase']!='staged': raise RuntimeError('managed start unavailable')
    raw=_regular(owner.state/'existing-origin.intent',32768); record=capture_renew.exact_json(raw)
    if json.dumps(record,sort_keys=True,separators=(',',':')).encode('ascii')!=raw or verify_before_publication(owner.peer,owner.publisher,qualification=owner.qualification)!=record: raise ValueError('managed pre-start topology changed')
    envoy=record['companions']['native-envoy']['id']
    launch=json.dumps({'version':1,'existing_sha256':hashlib.sha256(raw).hexdigest(),'envoy_cid':envoy},sort_keys=True,separators=(',',':')).encode('ascii')
    capability=owner._begin_existing_start(launch)
    if verify_before_publication(owner.peer,owner.publisher,qualification=owner.qualification)!=record: raise ValueError('managed pre-start topology changed')
    if products._command(['docker','start',envoy],30)!=envoy.encode('ascii'): raise RuntimeError('managed Envoy start uncertain')
    owner._bind_initial_existing_origin(capability)
    owner.reconcile()


def _verify_created_publisher(cid,edge_token,node,watched,*,stopped_at=None):
    """Inspect the exact inert publisher configuration before its first start."""
    import os
    import re
    from deploy.gateway.managed_edge import _PUBLISH_CLEAR,_PUBLISH_WARM,_publisher_env
    if not re.fullmatch('[0-9a-f]{64}',cid) or not re.fullmatch('[0-9a-f]{32}',edge_token): raise ValueError('publisher create identity invalid')
    obj=products._objects(['docker','inspect',cid]); cfg=obj.get('Config') or {}; host=obj.get('HostConfig') or {}; state=obj.get('State') or {}
    labels=cfg.get('Labels') or {}; mounts=obj.get('Mounts') or []; expected=_publisher_env(node['env']); expected.update({key:'' for key in _PUBLISH_CLEAR})
    if (obj.get('Id')!=cid or obj.get('Name')!='/'+profiles.MANAGED.project+'-edge-publisher' or obj.get('Image')!=node['id'] or cfg.get('Image')!=products.origin21_evidence.IMAGE or
        labels.get('org.apicontour.managed-edge-owner')!=edge_token or 'org.apicontour.origin21.owner' in labels or cfg.get('User')!=str(os.getuid())+':'+str(os.getgid()) or
        cfg.get('Entrypoint')!=['/usr/local/bin/node'] or cfg.get('Cmd')!=['-e',_PUBLISH_WARM] or _publisher_env(cfg.get('Env'))!=expected or
        state.get('Running') is not False or (stopped_at is None and (state.get('Status')!='created' or not str(state.get('StartedAt','')).startswith('0001-'))) or
        (stopped_at is not None and (state.get('Status')!='exited' or state.get('StartedAt')!=stopped_at or state.get('Pid')!=0 or state.get('Restarting') is not False or host.get('RestartPolicy',{}).get('Name') not in ('','no') or obj.get('ExecIDs') not in (None,[]))) or
        host.get('NetworkMode')!='none' or host.get('ReadonlyRootfs') is not True or host.get('Privileged') is not False or host.get('CapDrop')!=['ALL'] or host.get('CapAdd') not in (None,[]) or
        host.get('SecurityOpt') not in (['no-new-privileges'],['no-new-privileges:true']) or host.get('PidMode') not in ('',None) or host.get('IpcMode') not in ('','private',None) or host.get('UTSMode') not in ('',None) or host.get('UsernsMode') not in ('',None) or
        host.get('Devices') not in (None,[]) or host.get('DeviceRequests') not in (None,[]) or host.get('DeviceCgroupRules') not in (None,[]) or host.get('PortBindings') not in (None,{})):
        raise ValueError('publisher create identity changed')
    if type(mounts) is not list or len(mounts)!=1 or mounts[0].get('Type')!='bind' or mounts[0].get('Source')!=str(watched) or mounts[0].get('Destination')!='/watch' or mounts[0].get('RW') is not True: raise ValueError('publisher create mount changed')


def start_companions(*,app_image_id,build_head,build_receipt,build_receipt_sha256,transport,qualification=None):
    """Create the managed companions and publish the initial edge once.

    Every ambiguous create/start is retained for operator inspection; this
    entrypoint does not adopt or retry a partial topology.
    """
    import os
    import re
    import stat
    from deploy.gateway.managed_edge import ManagedEdge,_PUBLISH_CLEAR,_PUBLISH_WARM
    from deploy.local import origin21_credentials,origin21_evidence,origin21_renewal,origin21_schema,origin21_setup,origin21_transport
    selected=profiles.MANAGED
    if qualification is not None:
        from deploy.local.origin21_managed_qualification import OwnedManagedQualification
        if type(qualification) is not OwnedManagedQualification: raise ValueError('qualification proof required')
        qualification.verify()
    if type(transport) is not origin21_transport.ManagedTransport or transport.qualification is not qualification: raise ValueError('managed transport required')
    transport.verify()
    capture_renew.safe_dir(selected.owner)
    if stat.S_IMODE(os.lstat(selected.owner).st_mode)!=0o700: raise ValueError('managed owner unavailable')
    intent=products._read_record('intent.json',selected=selected); recorded=products._read_record('products.json',selected=selected)
    if (intent.get('app_image_id'),intent.get('build_head'),intent.get('build_receipt_sha256'))!=(app_image_id,build_head,build_receipt_sha256): raise ValueError('managed build changed')
    deployment=products._build_receipt(app_image_id,build_head,build_receipt,build_receipt_sha256,selected=selected)
    if deployment!=intent.get('deployment'): raise ValueError('managed deployment changed')
    products._verify_model('products',intent['model_sha256'],selected=selected)
    ids=products._recorded_products(intent,recorded,selected=selected)
    business=products._network(ids,intent['token'],selected=selected)
    if any(slot.get('namespace')!=business for slot in recorded['slots']): raise ValueError('managed product network changed')
    expected=tuple(products.origin21_evidence.digest(slot) for slot in recorded['slots'])
    origin21_setup.prepare(transport=transport,expected_evidence=expected,check_only=True,selected=selected)
    source=origin21_state._source_identity(context=selected)
    journal=origin21_state._read(selected.profile.state/'setup.json',origin21_state._identity(selected.profile),source)
    if journal['completed']!=len(origin21_state.PHASES) or journal['pending'] is not None: raise ValueError('managed enrollment incomplete')
    evidence=origin21_evidence.Evidence(selected.profile,lambda i:products.inspect_slot(i,selected=selected,**({'qualification':qualification} if qualification is not None else {})),expected)
    if evidence.inspect()!=origin21_state.EXACT or evidence.commitment()!=journal['evidence_digest']: raise ValueError('managed evidence changed')
    allowed,pending=origin21_renewal.artifacts(selected.bound)
    if pending is not None: raise ValueError('managed renewal unresolved')
    products.require_current_policy(transport.admin,transport.sensitive,selected=selected)
    credentials=origin21_credentials.Credentials(selected.profile,selected.profile.state.parent/'ca.crt',selected.profile.state.parent/'ca.key')
    credentials.allow_observer_policy=True; credentials.allow_operator_evidence=True; credentials.allow_runtime_configs=True; credentials.allow_renewal_artifacts=frozenset(allowed)
    if credentials.inspect()!=origin21_state.EXACT or credentials.commitment()!=journal['credential_digest']: raise ValueError('managed credentials changed')
    versions=[int(x) for x in transport.admin('SELECT version FROM contour.schema_migrations ORDER BY version;').splitlines()]
    origin21_schema.require_ready(versions,transport.admin,stage=21,phase='enrolled')
    if os.path.lexists(selected.owner/'companions-intent.json') or os.path.lexists(selected.owner/'companions.json'): raise ValueError('managed companions already attempted')
    existing=products._command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+selected.project]).decode('ascii').split()
    if len(existing)!=2 or set(existing)!=set(ids): raise ValueError('managed project membership changed')
    app=products._image(app_image_id); node=products._image(products.origin21_evidence.IMAGE); envoy=products._image(products.ENVOY)
    if app['id']!=app_image_id or node['id']!=intent['image_id']: raise ValueError('managed image changed')
    images={name:(node if name=='destination' else envoy if name=='native-envoy' else app) for name in products.COMPANIONS}
    capture=products._capture_network(deployment,selected=selected)
    if qualification is not None: qualification.verify_owner(selected.owner)
    model=products._derive_model('companions',intent['token'],app_image_id,deployment['name'],selected=selected,qualification=qualification)
    origin_credentials._write(selected.owner/'companions-model.json',model)
    import hashlib
    model_hash=hashlib.sha256(model).hexdigest()
    products._write_record('companions-intent.json',{'version':1,'token':intent['token'],'image_id':app_image_id,'build_head':build_head,'build_receipt_sha256':build_receipt_sha256,'capture_network':capture,'images':images,'services':list(products.COMPANIONS),'model_sha256':model_hash},selected=selected)
    model_path=products._verify_model('companions',model_hash,selected=selected)
    products._command(['docker','compose','--project-name',selected.project,'-f',str(model_path),'create','--no-build','--pull','never',*products.COMPANIONS],90,token=intent['token'],app_image=app_image_id,capture_network=deployment['name'])
    products._verify_model('products',intent['model_sha256'],selected=selected); products._verify_model('companions',model_hash,selected=selected)
    listed=products._command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+selected.project]).decode('ascii').split()
    if len(listed)!=7 or len(set(listed))!=7 or not set(ids).issubset(listed): raise RuntimeError('managed companion creation uncertain')
    mapped={}
    for cid in set(listed)-set(ids):
        obj=products._objects(['docker','inspect',cid]); service=((obj.get('Config') or {}).get('Labels') or {}).get('com.docker.compose.service')
        if service not in products.COMPANIONS or service in mapped: raise RuntimeError('managed companion identity uncertain')
        products._validate_companion(obj,service,cid,images[service],intent['token'],'','',deployment['name'],running=False,selected=selected,qualification=qualification)
        mapped[service]=cid
    if set(mapped)!=set(products.COMPANIONS): raise RuntimeError('managed companion creation incomplete')
    products._write_record('companions-created.intent',{'version':1,'services':mapped},selected=selected)
    services={}
    for service in ('origin21-capture-ingress','origin21-capture-worker','destination','native-gateway'):
        cid=mapped[service]
        products._write_record(service+'.start.intent',{'version':1,'id':cid},selected=selected)
        if products._command(['docker','start',cid],30)!=cid.encode('ascii'): raise RuntimeError('managed companion start uncertain')
        obj=products._objects(['docker','inspect',cid]); state=products._validate_companion(obj,service,cid,images[service],intent['token'],business,capture,deployment['name'],running=True,selected=selected,qualification=qualification)
        services[service]={'id':cid,'started_at':state['StartedAt']}
        products._write_record(service+'.start.result',services[service],selected=selected)
    services['native-envoy']={'id':mapped['native-envoy'],'started_at':None}
    products._write_record('companions-created.json',{'version':1,'services':services},selected=selected)
    edge_token=products._managed_edge_token(selected,intent['token'])
    origin_credentials._write(selected.edge/'publisher.intent',json.dumps({'version':1,'edge_token':edge_token,'image_id':node['id']},sort_keys=True,separators=(',',':')).encode())
    args=['docker','create','--pull=never','--name',selected.project+'-edge-publisher','--label','org.apicontour.managed-edge-owner='+edge_token,'--network','none','--user',str(os.getuid())+':'+str(os.getgid()),'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','32','--memory','128m']
    for key in _PUBLISH_CLEAR: args+=['--env',key+'=']
    args+=['--mount','type=bind,src='+str(selected.edge/'watched')+',dst=/watch','--entrypoint','/usr/local/bin/node',products.origin21_evidence.IMAGE,'-e',_PUBLISH_WARM]
    publisher_id=products._command(args,30).decode('ascii')
    if not re.fullmatch('[0-9a-f]{64}',publisher_id) or publisher_id in listed: raise RuntimeError('publisher create uncertain')
    origin_credentials._write(selected.edge/'publisher.created',json.dumps({'version':1,'id':publisher_id},sort_keys=True,separators=(',',':')).encode())
    _verify_created_publisher(publisher_id,edge_token,node,selected.edge/'watched')
    origin_credentials._write(selected.edge/'publisher.start.intent',json.dumps({'version':1,'id':publisher_id},sort_keys=True,separators=(',',':')).encode())
    if products._command(['docker','start',publisher_id],30)!=publisher_id.encode('ascii'): raise RuntimeError('publisher start uncertain')
    publisher_obj=products._objects(['docker','inspect',publisher_id]); publisher_start=(publisher_obj.get('State') or {}).get('StartedAt')
    publisher=NativeDirectoryPublisher(publisher_id,node['id'],publisher_start,selected.edge/'watched',edge_token,os.getuid(),os.getgid(),node['env'],**({'qualification':qualification} if qualification is not None else {}))
    publisher.verify()
    origin_credentials._write(selected.edge/'publisher.json',json.dumps(publisher.identity(),sort_keys=True,separators=(',',':')).encode())
    peer=NativeReplicaPeer(ids[0],intent['image_id'],business,products._mounts(1,selected=selected),mapped['native-envoy'],envoy['id'],products._companion_mounts('native-envoy',selected=selected))
    with ManagedEdge(selected.edge/'state',selected.edge/'published',selected.edge/'watched',selected.profile.state.parent/'ca.crt',selected.profile.state.parent/'ca.key',peer,publisher,qualification=qualification) as owner:
        owner.prepare_initial_existing_origin(); start_envoy_once(owner)
        binding=owner._load()['binding']; services['native-envoy']={'id':mapped['native-envoy'],'started_at':binding['envoy_started']}
    products._write_record('companions.json',{'version':1,'services':services},selected=selected)
    products._companion_record(intent,ids,selected=selected,**({'qualification':qualification} if qualification is not None else {}))
    return {'companions_started':True,'pilot_ready':False}


def open_edge(*,qualification=None):
    """Reopen only the already recorded managed edge; never rebind a generation."""
    import os
    from deploy.gateway.managed_edge import ManagedEdge
    selected=profiles.MANAGED
    intent=products._read_record('intent.json',selected=selected)
    recorded=products._read_record('products.json',selected=selected)
    created=products._read_record('companions-created.json',selected=selected)
    pending=products._read_record('companions-intent.json',selected=selected)
    if type(recorded) is not dict or type(recorded.get('slots')) is not list or len(recorded['slots'])!=2: raise ValueError('managed products unavailable')
    slots=recorded['slots']; services=created['services']; edge_token=products._managed_edge_token(selected,intent['token'])
    raw=origin_credentials._file(selected.edge/'publisher.json',32768); pub=capture_renew.exact_json(raw)
    if type(pub) is not dict or json.dumps(pub,sort_keys=True,separators=(',',':')).encode()!=raw: raise ValueError('managed publisher record invalid')
    node=products._image(products.origin21_evidence.IMAGE)
    publisher=NativeDirectoryPublisher(pub.get('cid'),node['id'],pub.get('started'),selected.edge/'watched',edge_token,os.getuid(),os.getgid(),node['env'],**({'qualification':qualification} if qualification is not None else {}))
    if publisher.identity()!=pub: raise ValueError('managed publisher record changed')
    peer=NativeReplicaPeer(slots[0]['container_id'],intent['image_id'],slots[0]['namespace'],products._mounts(1,selected=selected),services['native-envoy']['id'],pending['images']['native-envoy']['id'],products._companion_mounts('native-envoy',selected=selected))
    return ManagedEdge(selected.edge/'state',selected.edge/'published',selected.edge/'watched',selected.profile.state.parent/'ca.crt',selected.profile.state.parent/'ca.key',peer,publisher,qualification=qualification)


def verify_recorded_topology(*,qualification=None):
    """Enforce the persisted exact managed topology, including the publisher."""
    with open_edge(qualification=qualification) as owner:
        owner._managed_gate(owner._load())
