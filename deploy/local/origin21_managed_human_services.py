"""One-shot, journaled start of the fixed managed-human identity and app."""
import hashlib
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from deploy.local import (origin21_managed_controller as controller, origin21_managed_human_business as business,
    origin21_managed_human_preflight as preflight, origin21_managed_human_topology as topology,
    origin21_products as products, origin21_profile as profiles, origin21_ready, origin21_transport)
from deploy.pilot import origin_credentials


def _record(path, value):
    origin_credentials._write(path,json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def _image(ref):
    obj=products._objects(['docker','image','inspect',ref]); cfg=obj.get('Config') or {}
    image={'id':obj.get('Id'),'env':cfg.get('Env') or [],'cmd':cfg.get('Cmd'),
           'entrypoint':cfg.get('Entrypoint'),'workdir':cfg.get('WorkingDir'),'user':cfg.get('User')}
    if not isinstance(image['id'],str) or not re.fullmatch('sha256:[0-9a-f]{64}',image['id']): raise ValueError('human image unavailable')
    return image


def _transition(owner, baseline):
    first=controller._topology_snapshot(owner.peer,owner.publisher,live_envoy=True,_transition=controller._HUMAN_TRANSITION)
    second=controller._topology_snapshot(owner.peer,owner.publisher,live_envoy=True,_transition=controller._HUMAN_TRANSITION)
    if first!=second or first!=baseline: raise ValueError('human transition topology changed')


_STAGE_SEAL=object()


class _HumanStageProof:
    __slots__=('_owner','_baseline')
    def __init__(self, seal, owner, baseline):
        if seal is not _STAGE_SEAL or owner.closed or controller._context_for_publisher(owner.publisher) is not profiles.HUMAN:
            raise ValueError('human stage proof unavailable')
        self._owner,self._baseline=owner,baseline
    def verify(self):
        if self._owner.closed: raise ValueError('human stage proof closed')
        _transition(self._owner,self._baseline)


def _ready():
    selected=profiles.HUMAN
    context=ssl.create_default_context(cafile=str(selected.profile.state.parent/'ca.crt'))
    opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),urllib.request.ProxyHandler({}),check_no_redirect())
    until=time.monotonic()+60
    while True:
        try:
            with opener.open('https://mvp.localhost:19443/readyz',timeout=3) as response:
                if response.url=='https://mvp.localhost:19443/readyz' and response.status==200 and response.read(1025)==b'{"ready":true}': return
        except (urllib.error.URLError,TimeoutError,OSError): pass
        if time.monotonic()>=until: raise TimeoutError('human application readiness deadline')
        time.sleep(.5)


def check_no_redirect():
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,req,fp,code,msg,headers,newurl): return None
    return NoRedirect()


def start(expected, transport):
    """Require a verified capture first; never retry or adopt a partial start."""
    selected=profiles.HUMAN
    if type(transport) is not origin21_transport.ManagedTransport or transport._selected is not selected: raise ValueError('human managed transport required')
    profiles.require_context(selected)
    if type(expected) is not tuple or len(expected)!=2 or any(type(x) is not bytes or len(x)!=32 for x in expected): raise ValueError('fixed evidence required')
    preflight.check()
    transport.verify()
    capture=origin21_ready.check(expected,selected=selected,transport=transport)
    if capture!={'product_tls_and_catalog_verified':True,'ui_verified':False}: raise ValueError('capture not verified')
    controller.verify_recorded_topology(selected=selected)
    intent=products._read_record('intent.json',selected=selected)
    token=intent['token']; deployment=intent['deployment']
    if any(os.path.lexists(selected.owner/name) for name in ('human.intent','human.identity','human.json','identity-model.json','application-model.json')):
        raise ValueError('human transition already attempted')
    human_network=selected.project+'_human'; volume=selected.project+'_human-keycloak-data'
    if products._command(['docker','network','ls','--filter','name=^'+human_network+'$','--format','{{.Name}}']).split(): raise ValueError('human network already exists')
    if products._command(['docker','volume','ls','--filter','name=^'+volume+'$','--format','{{.Name}}']).split(): raise ValueError('human volume already exists')
    models={}
    for group in ('identity','application'):
        data=products._derive_model(group,token,intent['app_image_id'],deployment['name'],selected=selected)
        origin_credentials._write(selected.owner/(group+'-model.json'),data)
        models[group]=hashlib.sha256(data).hexdigest()
    keycloak_ref='quay.io/keycloak/keycloak@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244'
    images={'mvp-keycloak':_image(keycloak_ref),'app':_image(intent['app_image_id'])}
    if images['app']['id']!=intent['app_image_id']: raise ValueError('human app image drift')
    with controller.open_edge(selected=selected) as owner:
        baseline=controller._topology_snapshot(owner.peer,owner.publisher,live_envoy=True)
        if controller._topology_snapshot(owner.peer,owner.publisher,live_envoy=True)!=baseline: raise ValueError('managed baseline changed')
        _record(selected.owner/'human.intent',{'version':1,'token':token,'models':models,'images':{k:v['id'] for k,v in images.items()}})
        model=products._verify_model('identity',models['identity'],selected=selected)
        products._command(['docker','compose','--project-name',selected.project,'-f',str(model),'create','--no-build','--pull','never','mvp-keycloak'],90,token=token,app_image=intent['app_image_id'],capture_network=deployment['name'])
        network=products._objects(['docker','network','inspect',human_network]); network_id=network.get('Id')
        labels=network.get('Labels') or {}
        if (not isinstance(network_id,str) or not re.fullmatch('[0-9a-f]{64}',network_id) or network_id in (owner.peer.network_id,deployment['id']) or
            network.get('Name')!=human_network or network.get('Internal') is not True or (network.get('Containers') or {}) or
            labels.get('com.docker.compose.project')!=selected.project or labels.get('com.docker.compose.network')!='human' or labels.get('org.apicontour.origin21.owner')!=token):
            raise ValueError('human network creation uncertain')
        volume_obj=products._objects(['docker','volume','inspect',volume]); volume_labels=volume_obj.get('Labels') or {}
        if (volume_obj.get('Name')!=volume or volume_obj.get('Driver')!='local' or volume_obj.get('Scope')!='local' or (volume_obj.get('Options') or {}) or
            volume_labels.get('org.apicontour.origin21.owner')!=token or volume_labels.get('com.docker.compose.project')!=selected.project or
            volume_labels.get('com.docker.compose.volume')!='human-keycloak-data'):
            raise ValueError('human volume creation uncertain')
        ids=products._command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+selected.project,'--filter','label=com.docker.compose.service=mvp-keycloak']).decode('ascii').split()
        if len(ids)!=1 or not re.fullmatch('[0-9a-f]{64}',ids[0]): raise ValueError('human identity creation uncertain')
        cid=ids[0]; network_ids={'capture':deployment['id'],'human':network_id}
        base_ids={slot['container_id'] for slot in baseline[0]['products']} | {entry['id'] for entry in baseline[0]['companions'].values()}
        project_ids=products._command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+selected.project]).decode('ascii').split()
        if len(base_ids)!=7 or cid in base_ids or len(project_ids)!=8 or set(project_ids)!=base_ids|{cid}: raise ValueError('human identity inventory uncertain')
        topology.validate_service(products._objects(['docker','inspect',cid]),'mvp-keycloak',cid,images['mvp-keycloak'],token,network_ids,None,running=False)
        _record(selected.owner/'human.identity.start.intent',{'version':1,'id':cid})
        if products._command(['docker','start',cid],30)!=cid.encode('ascii'): raise RuntimeError('human identity start uncertain')
        obj=products._objects(['docker','inspect',cid]); started=(obj.get('State') or {}).get('StartedAt')
        topology.validate_service(obj,'mvp-keycloak',cid,images['mvp-keycloak'],token,network_ids,started)
        identity={'id':cid,'started_at':started,'image_id':images['mvp-keycloak']['id']}
        _record(selected.owner/'human.identity',{'version':1,'token':token,'network_id':network_id,'service':identity})
        _transition(owner,baseline)
        stage_transport=transport._bind_human_transition(_HumanStageProof(_STAGE_SEAL,owner,baseline))
        business.prepare(stage_transport)
        _transition(owner,baseline)
        model=products._verify_model('application',models['application'],selected=selected)
        products._command(['docker','compose','--project-name',selected.project,'-f',str(model),'create','--no-build','--pull','never','app'],90,token=token,app_image=intent['app_image_id'],capture_network=deployment['name'])
        ids=products._command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+selected.project,'--filter','label=com.docker.compose.service=app']).decode('ascii').split()
        if len(ids)!=1 or not re.fullmatch('[0-9a-f]{64}',ids[0]) or ids[0]==cid: raise ValueError('human app creation uncertain')
        app_id=ids[0]
        topology.validate_service(products._objects(['docker','inspect',app_id]),'app',app_id,images['app'],token,network_ids,None,running=False)
        _record(selected.owner/'human.app.created',{'version':1,'id':app_id,'image_id':images['app']['id']})
        _transition(owner,baseline)
        _record(selected.owner/'human.app.start.intent',{'version':1,'id':app_id})
        if products._command(['docker','start',app_id],30)!=app_id.encode('ascii'): raise RuntimeError('human app start uncertain')
        obj=products._objects(['docker','inspect',app_id]); app_start=(obj.get('State') or {}).get('StartedAt')
        topology.validate_service(obj,'app',app_id,images['app'],token,network_ids,app_start)
        app={'id':app_id,'started_at':app_start,'image_id':images['app']['id']}
        _record(selected.owner/'human.json',{'version':1,'token':token,'network_ids':{'business':owner.peer.network_id,'capture':deployment['id'],'human':network_id},'services':{'app':app,'mvp-keycloak':identity}})
        owner._managed_gate(owner._load())
        _ready()
        owner._managed_gate(owner._load())
    if origin21_ready.check(expected,selected=selected,transport=transport)!={'product_tls_and_catalog_verified':True,'ui_verified':False}: raise ValueError('capture readiness changed')
    return {'product_tls_and_catalog_verified':True,'app_tls_ready':True,'ui_verified':False}
