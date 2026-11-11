"""Exact final membership of the closed managed-human topology."""
import re

CONTAINERS = ('postgres', 'replica1', 'replica2', 'destination',
              'origin21-capture-ingress', 'origin21-capture-worker',
              'native-gateway', 'native-envoy', 'edge-publisher', 'app', 'mvp-keycloak')
_NETWORKS = {
    'business': ('replica1', 'replica2', 'destination', 'native-gateway', 'native-envoy'),
    'capture': ('postgres', 'origin21-capture-ingress', 'origin21-capture-worker', 'native-gateway', 'app'),
    'human': ('app', 'mvp-keycloak'),
}


def validate_membership(containers, networks):
    if (type(containers) is not dict or set(containers)!=set(CONTAINERS)
            or any(type(value) is not str or not re.fullmatch('[0-9a-f]{64}',value) for value in containers.values())
            or len(set(containers.values()))!=len(CONTAINERS)):
        raise ValueError('human container identity drift')
    if type(networks) is not dict or set(networks)!=set(_NETWORKS):
        raise ValueError('human network identity drift')
    for network, members in _NETWORKS.items():
        if type(networks[network]) is not set or networks[network]!={containers[name] for name in members}:
            raise ValueError('human network membership drift')


def validate_networks(containers, network_records, expected_ids, token, db_token):
    """Check IDs, ownership, labels and exact container membership for all three networks."""
    from deploy.local import origin21_profile
    selected=origin21_profile.HUMAN
    if (type(expected_ids) is not dict or set(expected_ids)!={'business','capture','human'} or
        any(type(v) is not str or not re.fullmatch('[0-9a-f]{64}',v) for v in expected_ids.values()) or
        len(set(expected_ids.values()))!=3 or type(token) is not str or not re.fullmatch('[0-9a-f]{64}',token) or
        type(db_token) is not str or not re.fullmatch('[0-9a-f]{32}',db_token)):
        raise ValueError('human network identity invalid')
    if type(network_records) is not dict or set(network_records)!=set(expected_ids): raise ValueError('human network inventory invalid')
    members={}
    for kind, name, project, network_label in (
        ('business',selected.network,selected.project,'default'),
        ('capture','apicontour-origin21-managed-human-db_default','apicontour-origin21-managed-human-db','default'),
        ('human',selected.project+'_human',selected.project,'human')):
        record=network_records[kind]
        if type(record) is not dict: raise ValueError('human network record invalid')
        labels=record.get('Labels') or {}
        if (record.get('Name')!=name or record.get('Id')!=expected_ids[kind] or record.get('Internal') is not True or
            labels.get('com.docker.compose.project')!=project or labels.get('com.docker.compose.network')!=network_label):
            raise ValueError('human network ownership drift')
        if kind in ('business','human') and labels.get('org.apicontour.origin21.owner')!=token:
            raise ValueError('human network owner drift')
        if kind=='capture' and labels.get('org.apicontour.managed-db-owner')!=db_token:
            raise ValueError('human database owner drift')
        entries=record.get('Containers')
        if type(entries) is not dict: raise ValueError('human network members invalid')
        members[kind]=set(entries)
    validate_membership(containers,members)


def validate_service(obj, service, cid, image, token, network_ids, started_at, *, running=True):
    """Check one running human container against its fixed configuration and generation."""
    import os
    from deploy.local import origin21_profile
    selected=origin21_profile.HUMAN
    if service not in ('app','mvp-keycloak') or type(cid) is not str or not re.fullmatch('[0-9a-f]{64}',cid):
        raise ValueError('human service identity invalid')
    if (type(image) is not dict or set(image)!={'id','env','cmd','entrypoint','workdir','user'} or
        not re.fullmatch('sha256:[0-9a-f]{64}',image['id']) or type(token) is not str or not re.fullmatch('[0-9a-f]{64}',token) or
        type(network_ids) is not dict or set(network_ids)!={'capture','human'} or
        any(type(v) is not str or not re.fullmatch('[0-9a-f]{64}',v) for v in network_ids.values()) or
        type(running) is not bool or (running and (not isinstance(started_at,str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',started_at))) or (not running and started_at is not None)):
        raise ValueError('human service evidence invalid')
    if type(obj) is not dict: raise ValueError('human service object invalid')
    config=obj.get('Config') or {}; host=obj.get('HostConfig') or {}; state=obj.get('State') or {}; labels=config.get('Labels') or {}
    keycloak=service=='mvp-keycloak'
    ref='quay.io/keycloak/keycloak@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244' if keycloak else image['id']
    user='1000:1000' if keycloak else str(os.getuid())+':'+str(os.getgid())
    memory=(1024 if keycloak else 512)*1024*1024; cpus=2_000_000_000 if keycloak else 1_000_000_000
    port='8443/tcp' if keycloak else '9443/tcp'; hostport='18444' if keycloak else '19443'
    binding={port:[{'HostIp':'127.0.0.1','HostPort':hostport}]}
    if (obj.get('Id')!=cid or obj.get('Name')!='/'+selected.project+'-'+service+'-1' or obj.get('Image')!=image['id'] or
        config.get('Image')!=ref or config.get('User')!=user or labels.get('com.docker.compose.project')!=selected.project or
        labels.get('com.docker.compose.service')!=service or labels.get('org.apicontour.origin21.owner')!=token or
        state.get('Running') is not running or (running and state.get('StartedAt')!=started_at) or
        (not running and (state.get('Status')!='created' or not str(state.get('StartedAt','')).startswith('0001-'))) or state.get('Restarting') is not False or
        host.get('Privileged') is not False or host.get('CapDrop')!=['ALL'] or host.get('CapAdd') not in (None,[]) or
        set(host.get('SecurityOpt') or [])!={'no-new-privileges:true'} or host.get('PidMode')=='host' or host.get('IpcMode')=='host' or
        host.get('UTSMode')=='host' or host.get('UsernsMode')=='host' or host.get('Devices') not in (None,[]) or
        host.get('DeviceRequests') not in (None,[]) or host.get('DeviceCgroupRules') not in (None,[]) or host.get('Memory')!=memory or host.get('NanoCpus')!=cpus or
        host.get('PidsLimit')!=(256 if keycloak else 128) or host.get('PortBindings')!=binding or host.get('PublishAllPorts') is not False or
        (host.get('RestartPolicy') or {}).get('Name') not in ('','no')):
        raise ValueError('human service configuration drift')
    if (host.get('ReadonlyRootfs') is not (not keycloak) or
        (not keycloak and (type(host.get('Tmpfs')) is not dict or set(host['Tmpfs'])!={'/tmp'} or
                          type(host['Tmpfs']['/tmp']) is not str or set(host['Tmpfs']['/tmp'].split(','))!={'rw','noexec','nosuid','size=16m'})) or
        (keycloak and host.get('Tmpfs') not in (None,{}))): raise ValueError('human service filesystem drift')
    command=['start','--db=dev-file','--hostname=https://idp.mvp.localhost:18444','--http-enabled=false',
             '--https-certificate-file=/run/local/idp.crt','--https-certificate-key-file=/run/local/idp.key','--import-realm'] if keycloak else image['cmd']
    if (config.get('Entrypoint')!=image['entrypoint'] or config.get('Cmd')!=command or
        config.get('WorkingDir')!=('' if image['workdir'] is None else image['workdir']) or config.get('Env')!=image['env']):
        raise ValueError('human service process drift')
    base=selected.profile.state.parent
    binds={'/run/config/platform.json':base/'container-platform.json','/run/config/business.json':base/'container-business.json',
           '/run/config/ca.crt':base/'ca.crt','/run/config/server.crt':base/'human/app.crt',
           '/run/config/server.key':base/'human/app.key','/run/config/jwks.json':base/'approved-jwks.json',
           '/run/config/database-password':base/'database-password'} if not keycloak else {
           '/run/local':base/'human/idp','/opt/keycloak/data/import':base/'human/realm'}
    mounts=obj.get('Mounts') or []; actual={item.get('Destination'):item for item in mounts}
    if type(mounts) is not list or len(actual)!=len(mounts) or len(mounts)!=len(binds)+(1 if keycloak else 0): raise ValueError('human mount count drift')
    for target,path in binds.items():
        mount=actual.get(target) or {}
        if mount.get('Type')!='bind' or mount.get('RW') is not False or os.path.realpath(mount.get('Source',''))!=os.path.realpath(path): raise ValueError('human bind drift')
    if keycloak:
        volume=actual.get('/opt/keycloak/data') or {}
        if volume.get('Type')!='volume' or volume.get('Name')!=selected.project+'_human-keycloak-data' or volume.get('RW') is not True: raise ValueError('human volume drift')
    network_settings=obj.get('NetworkSettings') or {}; networks=network_settings.get('Networks') or {}
    expected={selected.project+'_human':network_ids['human']}
    if not keycloak: expected['apicontour-origin21-managed-human-db_default']=network_ids['capture']
    if running and (set(networks)!=set(expected) or any(networks[name].get('NetworkID')!=ident for name,ident in expected.items()) or
        network_settings.get('Ports')!=binding or (keycloak and 'mvp-keycloak' not in (networks[selected.project+'_human'].get('Aliases') or []))):
        raise ValueError('human service network drift')
    if not running and (network_settings.get('Ports') not in (None,{}) or any((networks[name] or {}).get('NetworkID') not in (None,'') for name in networks)):
        raise ValueError('created human service already attached')


def _verify_intent(intent):
    import json
    from deploy.local import capture_renew, origin21_products as products, origin21_profile
    from deploy.pilot import origin_credentials
    selected=origin21_profile.HUMAN
    raw=origin_credentials._file(selected.owner/'human.intent',65536)
    value=capture_renew.exact_json(raw)
    if (type(value) is not dict or set(value)!={'version','token','models','images'} or value.get('version')!=1 or
        value.get('token')!=intent.get('token') or json.dumps(value,sort_keys=True,separators=(',',':')).encode()!=raw or
        type(value.get('models')) is not dict or set(value['models'])!={'identity','application'} or
        any(type(v) is not str or not re.fullmatch('[0-9a-f]{64}',v) for v in value['models'].values()) or
        type(value.get('images')) is not dict or set(value['images'])!={'app','mvp-keycloak'} or
        any(type(v) is not str or not re.fullmatch('sha256:[0-9a-f]{64}',v) for v in value['images'].values()) or
        value['images']['app']!=intent.get('app_image_id')):
        raise ValueError('human intent drift')
    for name,digest in value['models'].items(): products._verify_model(name,digest,selected=selected)
    return value


def verify_live(intent, recorded, companions, publisher_id, business_network, capture_network, db_token):
    """Reinspect the exact final human topology against the private recorded generations."""
    import json
    from deploy.local import capture_renew, origin21_products as products, origin21_profile
    from deploy.pilot import origin_credentials
    selected=origin21_profile.HUMAN
    origin21_profile.require_context(selected)
    transition=_verify_intent(intent)
    raw=origin_credentials._file(selected.owner/'human.json',65536)
    human=capture_renew.exact_json(raw)
    if (type(human) is not dict or set(human)!={'version','token','network_ids','services'} or human.get('version')!=1 or
        json.dumps(human,sort_keys=True,separators=(',',':')).encode()!=raw or human.get('token')!=intent.get('token')):
        raise ValueError('human topology record drift')
    network_ids=human['network_ids']; services=human['services']
    if (type(network_ids) is not dict or set(network_ids)!={'business','capture','human'} or
        network_ids['business']!=business_network or network_ids['capture']!=capture_network or
        type(services) is not dict or set(services)!={'app','mvp-keycloak'}):
        raise ValueError('human topology identity drift')
    if type(recorded) is not dict or type(recorded.get('slots')) is not list or len(recorded['slots'])!=2 or type(companions) is not dict:
        raise ValueError('human base topology invalid')
    ids={'postgres':intent['deployment']['postgres_id'],'replica1':recorded['slots'][0]['container_id'],
         'replica2':recorded['slots'][1]['container_id'],'edge-publisher':publisher_id}
    for name in products.COMPANIONS:
        ids[name]=companions[name]['id']
    refs={'app':intent['app_image_id'],
          'mvp-keycloak':'quay.io/keycloak/keycloak@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244'}
    for service in ('app','mvp-keycloak'):
        entry=services[service]
        if (type(entry) is not dict or set(entry)!={'id','started_at','image_id'} or type(entry.get('id')) is not str or
            not re.fullmatch('[0-9a-f]{64}',entry['id'])): raise ValueError('human service record invalid')
        image_obj=products._objects(['docker','image','inspect',refs[service]])
        config=image_obj.get('Config') or {}; image={'id':image_obj.get('Id'),'env':config.get('Env') or [],
            'cmd':config.get('Cmd'),'entrypoint':config.get('Entrypoint'),'workdir':config.get('WorkingDir'),'user':config.get('User')}
        if image['id']!=entry['image_id'] or image['id']!=transition['images'][service] or (service=='app' and image['id']!=intent['app_image_id']):
            raise ValueError('human image identity drift')
        obj=products._objects(['docker','inspect',entry['id']])
        validate_service(obj,service,entry['id'],image,intent['token'],{'capture':capture_network,'human':network_ids['human']},entry['started_at'])
        ids[service]=entry['id']
    for filename, expected in (
        ('human.identity.start.intent',{'version':1,'id':services['mvp-keycloak']['id']}),
        ('human.app.created',{'version':1,'id':services['app']['id'],'image_id':services['app']['image_id']}),
        ('human.app.start.intent',{'version':1,'id':services['app']['id']})):
        if origin_credentials._file(selected.owner/filename,65536)!=json.dumps(expected,sort_keys=True,separators=(',',':')).encode():
            raise ValueError('human service intent drift')
    prior_raw=origin_credentials._file(selected.owner/'human.identity',65536)
    prior=capture_renew.exact_json(prior_raw)
    if (type(prior) is not dict or set(prior)!={'version','token','network_id','service'} or prior.get('version')!=1 or
        json.dumps(prior,sort_keys=True,separators=(',',':')).encode()!=prior_raw or prior.get('token')!=intent['token'] or
        prior.get('network_id')!=network_ids['human'] or prior.get('service')!=services['mvp-keycloak']):
        raise ValueError('human identity generation drift')
    project_ids=products._command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+selected.project]).decode('ascii').split()
    expected_project={ids[name] for name in products.PRODUCTS+products.COMPANIONS+('app','mvp-keycloak')}
    if len(project_ids)!=len(expected_project) or set(project_ids)!=expected_project: raise ValueError('human project inventory drift')
    records={kind:products._objects(['docker','network','inspect',name]) for kind,name in (
        ('business',selected.network),('capture','apicontour-origin21-managed-human-db_default'),('human',selected.project+'_human'))}
    validate_networks(ids,records,network_ids,intent['token'],db_token)
    volume=products._objects(['docker','volume','inspect',selected.project+'_human-keycloak-data'])
    labels=volume.get('Labels') or {}
    if (volume.get('Name')!=selected.project+'_human-keycloak-data' or volume.get('Driver')!='local' or volume.get('Scope')!='local' or
        (volume.get('Options') or {}) or labels.get('org.apicontour.origin21.owner')!=intent['token'] or
        labels.get('com.docker.compose.project')!=selected.project or labels.get('com.docker.compose.volume')!='human-keycloak-data'):
        raise ValueError('human identity volume drift')
    return human


def verify_identity_stage(intent, recorded, companions, publisher_id, business_network, capture_network, db_token, *, removed_app=False):
    """Check the exact journaled 10-container bootstrap stage before app creation."""
    import json
    from deploy.local import capture_renew, origin21_products as products, origin21_profile
    from deploy.pilot import origin_credentials
    selected=origin21_profile.HUMAN
    origin21_profile.require_context(selected)
    transition=_verify_intent(intent)
    raw=origin_credentials._file(selected.owner/'human.identity',65536)
    identity=capture_renew.exact_json(raw)
    fields={'version','token','network_id','service'}
    if (type(identity) is not dict or set(identity)!=fields or identity.get('version')!=1 or identity.get('token')!=intent.get('token') or
        json.dumps(identity,sort_keys=True,separators=(',',':')).encode()!=raw or
        type(identity.get('network_id')) is not str or not re.fullmatch('[0-9a-f]{64}',identity['network_id'])):
        raise ValueError('human identity stage record invalid')
    entry=identity['service']
    if (type(entry) is not dict or set(entry)!={'id','started_at','image_id'} or type(entry.get('id')) is not str or
        not re.fullmatch('[0-9a-f]{64}',entry['id'])): raise ValueError('human identity service invalid')
    if origin_credentials._file(selected.owner/'human.identity.start.intent',65536)!=json.dumps({'version':1,'id':entry['id']},sort_keys=True,separators=(',',':')).encode():
        raise ValueError('human identity start intent drift')
    ref='quay.io/keycloak/keycloak@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244'
    image_obj=products._objects(['docker','image','inspect',ref]); config=image_obj.get('Config') or {}
    image={'id':image_obj.get('Id'),'env':config.get('Env') or [],'cmd':config.get('Cmd'),
           'entrypoint':config.get('Entrypoint'),'workdir':config.get('WorkingDir'),'user':config.get('User')}
    if image['id']!=entry['image_id'] or image['id']!=transition['images']['mvp-keycloak']: raise ValueError('human identity image drift')
    validate_service(products._objects(['docker','inspect',entry['id']]),'mvp-keycloak',entry['id'],image,intent['token'],
                     {'capture':capture_network,'human':identity['network_id']},entry['started_at'])
    if type(recorded) is not dict or type(recorded.get('slots')) is not list or len(recorded['slots'])!=2 or type(companions) is not dict:
        raise ValueError('human base topology invalid')
    ids={'postgres':intent['deployment']['postgres_id'],'replica1':recorded['slots'][0]['container_id'],
         'replica2':recorded['slots'][1]['container_id'],'edge-publisher':publisher_id,'mvp-keycloak':entry['id']}
    for name in products.COMPANIONS: ids[name]=companions[name]['id']
    if len(ids)!=10 or len(set(ids.values()))!=10 or any(type(v) is not str or not re.fullmatch('[0-9a-f]{64}',v) for v in ids.values()):
        raise ValueError('human identity stage collision')
    import os
    created_path=selected.owner/'human.app.created'
    created_app=None
    if os.path.lexists(created_path):
        created_raw=origin_credentials._file(created_path,65536); created_app=capture_renew.exact_json(created_raw)
        if (type(created_app) is not dict or set(created_app)!={'version','id','image_id'} or created_app.get('version')!=1 or
            json.dumps(created_app,sort_keys=True,separators=(',',':')).encode()!=created_raw or
            created_app.get('image_id')!=transition['images']['app'] or type(created_app.get('id')) is not str or
            not re.fullmatch('[0-9a-f]{64}',created_app['id']) or created_app.get('id') in ids.values()):
            raise ValueError('human app creation record invalid')
        app_obj=products._objects(['docker','image','inspect',intent['app_image_id']]); app_cfg=app_obj.get('Config') or {}
        app_image={'id':app_obj.get('Id'),'env':app_cfg.get('Env') or [],'cmd':app_cfg.get('Cmd'),
                   'entrypoint':app_cfg.get('Entrypoint'),'workdir':app_cfg.get('WorkingDir'),'user':app_cfg.get('User')}
        if app_image['id']!=created_app['image_id']: raise ValueError('human app image drift')
        if removed_app:
            import hashlib
            human_raw=origin_credentials._file(selected.owner/'human.json',65536); human=capture_renew.exact_json(human_raw)
            cleanup={'version':1,'token':intent['token'],'human_sha256':hashlib.sha256(human_raw).hexdigest()}
            if (type(human) is not dict or json.dumps(human,sort_keys=True,separators=(',',':')).encode()!=human_raw or
                human.get('token')!=intent['token'] or human.get('services',{}).get('app',{}).get('id')!=created_app['id'] or
                origin_credentials._file(selected.owner/'human.cleanup.intent',65536)!=json.dumps(cleanup,sort_keys=True,separators=(',',':')).encode()):
                raise ValueError('human cleanup intent drift')
            expected={'version':1,'id':created_app['id']}
            for filename in ('human.app.start.intent','human.cleanup-app.intent','human.cleanup-app.done'):
                if origin_credentials._file(selected.owner/filename,65536)!=json.dumps(expected,sort_keys=True,separators=(',',':')).encode(): raise ValueError('human app cleanup record drift')
            if products._command(['docker','ps','-aq','--no-trunc','--filter','id='+created_app['id']]).strip(): raise ValueError('human app remains')
        else:
            validate_service(products._objects(['docker','inspect',created_app['id']]),'app',created_app['id'],app_image,intent['token'],
                             {'capture':capture_network,'human':identity['network_id']},None,running=False)
    elif removed_app: raise ValueError('human app creation record missing')
    project_ids=products._command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+selected.project]).decode('ascii').split()
    expected_project={ids[name] for name in products.PRODUCTS+products.COMPANIONS+('mvp-keycloak',)}
    if created_app is not None and not removed_app: expected_project.add(created_app['id'])
    if len(project_ids)!=len(expected_project) or set(project_ids)!=expected_project: raise ValueError('human identity project inventory drift')
    names={'business':selected.network,'capture':'apicontour-origin21-managed-human-db_default','human':selected.project+'_human'}
    expected_ids={'business':business_network,'capture':capture_network,'human':identity['network_id']}
    expected_members={'business':('replica1','replica2','destination','native-gateway','native-envoy'),
                      'capture':('postgres','origin21-capture-ingress','origin21-capture-worker','native-gateway'),
                      'human':('mvp-keycloak',)}
    if len(set(expected_ids.values()))!=3: raise ValueError('human identity network collision')
    for kind,name in names.items():
        obj=products._objects(['docker','network','inspect',name]); labels=obj.get('Labels') or {}
        project='apicontour-origin21-managed-human-db' if kind=='capture' else selected.project
        network_label='human' if kind=='human' else 'default'
        if (obj.get('Name')!=name or obj.get('Id')!=expected_ids[kind] or obj.get('Internal') is not True or
            labels.get('com.docker.compose.project')!=project or labels.get('com.docker.compose.network')!=network_label or
            (kind=='capture' and labels.get('org.apicontour.managed-db-owner')!=db_token) or
            (kind!='capture' and labels.get('org.apicontour.origin21.owner')!=intent['token']) or
            set((obj.get('Containers') or {}).keys())!={ids[n] for n in expected_members[kind]}):
            raise ValueError('human identity network drift')
    volume=products._objects(['docker','volume','inspect',selected.project+'_human-keycloak-data']); labels=volume.get('Labels') or {}
    if (volume.get('Name')!=selected.project+'_human-keycloak-data' or volume.get('Driver')!='local' or volume.get('Scope')!='local' or
        (volume.get('Options') or {}) or labels.get('org.apicontour.origin21.owner')!=intent['token'] or
        labels.get('com.docker.compose.project')!=selected.project or labels.get('com.docker.compose.volume')!='human-keycloak-data'):
        raise ValueError('human identity volume drift')
    return identity


def verify_removed_stage(intent, recorded, companions, publisher_id, business_network, capture_network, db_token):
    """Verify the exact retained nine-container state after both human removals."""
    import hashlib
    import json
    from deploy.local import capture_renew, origin21_products as products, origin21_profile
    from deploy.pilot import origin_credentials
    selected=origin21_profile.HUMAN
    transition=_verify_intent(intent)
    raw=origin_credentials._file(selected.owner/'human.json',65536); human=capture_renew.exact_json(raw)
    if (type(human) is not dict or set(human)!={'version','token','network_ids','services'} or human.get('version')!=1 or
        human.get('token')!=intent['token'] or json.dumps(human,sort_keys=True,separators=(',',':')).encode()!=raw):
        raise ValueError('human removal source drift')
    cleanup={'version':1,'token':intent['token'],'human_sha256':hashlib.sha256(raw).hexdigest()}
    if origin_credentials._file(selected.owner/'human.cleanup.intent',65536)!=json.dumps(cleanup,sort_keys=True,separators=(',',':')).encode():
        raise ValueError('human cleanup intent drift')
    net=human['network_ids']; services=human['services']
    if (type(net) is not dict or set(net)!={'business','capture','human'} or net['business']!=business_network or net['capture']!=capture_network or
        any(type(v) is not str or not re.fullmatch('[0-9a-f]{64}',v) for v in net.values()) or len(set(net.values()))!=3 or
        type(services) is not dict or set(services)!={'app','mvp-keycloak'}): raise ValueError('human cleanup topology invalid')
    for name in ('app','mvp-keycloak'):
        item=services[name]
        if (type(item) is not dict or set(item)!={'id','started_at','image_id'} or type(item.get('id')) is not str or
            not re.fullmatch('[0-9a-f]{64}',item['id']) or item.get('image_id')!=transition['images'][name]): raise ValueError('human cleanup service invalid')
        done={'version':1,'id':item['id']}; phase='app' if name=='app' else 'identity'
        for suffix in ('intent','done'):
            if origin_credentials._file(selected.owner/('human.cleanup-'+phase+'.'+suffix),65536)!=json.dumps(done,sort_keys=True,separators=(',',':')).encode():
                raise ValueError('human cleanup phase drift')
        if products._command(['docker','ps','-aq','--no-trunc','--filter','id='+item['id']]).strip(): raise ValueError('human removed service remains')
    if services['app']['id']==services['mvp-keycloak']['id']: raise ValueError('human cleanup collision')
    ids={'postgres':intent['deployment']['postgres_id'],'replica1':recorded['slots'][0]['container_id'],
         'replica2':recorded['slots'][1]['container_id'],'edge-publisher':publisher_id}
    for name in products.COMPANIONS: ids[name]=companions[name]['id']
    if len(ids)!=9 or len(set(ids.values())|{services['app']['id'],services['mvp-keycloak']['id']})!=11: raise ValueError('human cleanup identity collision')
    project_ids=products._command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+selected.project]).decode('ascii').split()
    expected_project={ids[name] for name in products.PRODUCTS+products.COMPANIONS}
    if len(project_ids)!=7 or set(project_ids)!=expected_project: raise ValueError('human cleanup project drift')
    names={'business':selected.network,'capture':'apicontour-origin21-managed-human-db_default','human':selected.project+'_human'}
    members={'business':('replica1','replica2','destination','native-gateway','native-envoy'),
             'capture':('postgres','origin21-capture-ingress','origin21-capture-worker','native-gateway'),'human':()}
    for kind,name in names.items():
        obj=products._objects(['docker','network','inspect',name]); labels=obj.get('Labels') or {}
        project='apicontour-origin21-managed-human-db' if kind=='capture' else selected.project
        if (obj.get('Name')!=name or obj.get('Id')!=net[kind] or obj.get('Internal') is not True or
            labels.get('com.docker.compose.project')!=project or labels.get('com.docker.compose.network')!=('human' if kind=='human' else 'default') or
            (kind=='capture' and labels.get('org.apicontour.managed-db-owner')!=db_token) or
            (kind!='capture' and labels.get('org.apicontour.origin21.owner')!=intent['token']) or
            set((obj.get('Containers') or {}).keys())!={ids[n] for n in members[kind]}): raise ValueError('human cleanup network drift')
    volume=products._objects(['docker','volume','inspect',selected.project+'_human-keycloak-data']); labels=volume.get('Labels') or {}
    if (volume.get('Name')!=selected.project+'_human-keycloak-data' or volume.get('Driver')!='local' or volume.get('Scope')!='local' or
        (volume.get('Options') or {}) or labels.get('org.apicontour.origin21.owner')!=intent['token'] or
        labels.get('com.docker.compose.project')!=selected.project or labels.get('com.docker.compose.volume')!='human-keycloak-data'):
        raise ValueError('human cleanup volume drift')
    return human
