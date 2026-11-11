"""Explicit, fail-closed teardown of one complete managed-Origin topology.

Persistent PostgreSQL volume and all CA/signing material are retained. No
partial or ambiguous teardown is automatically resumed or adopted.
"""
import json
import os
from deploy.local import capture_renew,origin21_managed_controller as controller,origin21_managed_init as init,origin21_products as products,origin21_profile as profiles,origin21_state
from deploy.pilot import origin_credentials

SOURCE='deploy/local/origin21_managed_cleanup.py'


def _record(path):
    raw=origin_credentials._file(path,32768); value=capture_renew.exact_json(raw)
    if json.dumps(value,sort_keys=True,separators=(',',':')).encode()!=raw: raise ValueError('cleanup record invalid')
    return value


def _write(path,value): origin_credentials._write(path,json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def teardown(*,qualification=None):
    """Remove exact owned containers and networks, preserving database data."""
    return _teardown(qualification,False,None)


def dispose_after_lost_ack(proof,owner):
    """Qualification-only disposal after a verified lost publication ACK."""
    from deploy.local.origin21_managed_qualification import OwnedManagedQualification
    if type(proof) is not OwnedManagedQualification: raise ValueError('qualification proof required')
    from deploy.gateway.managed_edge import ManagedEdge
    if type(owner) is not ManagedEdge or owner.closed or owner.qualification is not proof or owner.uncertain is not True: raise ValueError('uncertain owned edge required')
    return _teardown(proof,True,owner)


def _human_cleanup_guard(selected, intent):
    if selected is not profiles.HUMAN: raise ValueError('human cleanup context required')
    import hashlib
    human_raw=origin_credentials._file(selected.owner/'human.json',65536); human=capture_renew.exact_json(human_raw)
    cleanup={'version':1,'token':intent['token'],'human_sha256':hashlib.sha256(human_raw).hexdigest()}
    if (_record(selected.owner/'human.cleanup.intent')!=cleanup or type(human) is not dict or
        json.dumps(human,sort_keys=True,separators=(',',':')).encode()!=human_raw or human.get('token')!=intent['token'] or
        type(human.get('services')) is not dict or set(human['services'])!={'app','mvp-keycloak'}): raise ValueError('human cleanup record invalid')
    network=human.get('network_ids',{}).get('human')
    import re
    if (type(network) is not str or not re.fullmatch('[0-9a-f]{64}',network) or
        any(_record(selected.owner/('human.cleanup-network.'+suffix))!={'version':1,'id':network} for suffix in ('intent','done'))): raise ValueError('human cleanup network record invalid')
    if products._command(['docker','network','ls','-q','--no-trunc','--filter','id='+network],15).strip(): raise ValueError('human cleanup network remains')
    for name,phase in (('app','app'),('mvp-keycloak','identity')):
        item=human['services'][name]
        if type(item) is not dict or type(item.get('id')) is not str or not re.fullmatch('[0-9a-f]{64}',item['id']): raise ValueError('human cleanup service invalid')
        if any(_record(selected.owner/('human.cleanup-'+phase+'.'+suffix))!={'version':1,'id':item['id']} for suffix in ('intent','done')) or products._command(['docker','ps','-aq','--no-trunc','--filter','id='+item['id']],15).strip(): raise ValueError('human cleanup service remains')
    volume=products._objects(['docker','volume','inspect',selected.project+'_human-keycloak-data']); labels=volume.get('Labels') or {}
    if (volume.get('Name')!=selected.project+'_human-keycloak-data' or volume.get('Driver')!='local' or volume.get('Scope')!='local' or
        (volume.get('Options') or {}) or labels.get('org.apicontour.origin21.owner')!=intent['token'] or
        labels.get('com.docker.compose.project')!=selected.project or labels.get('com.docker.compose.volume')!='human-keycloak-data'):
        raise ValueError('human cleanup volume drift')


def _teardown(qualification,lost_ack,held_owner,*,selected=profiles.MANAGED,human_cleanup=None):
    profiles.require_context(selected)
    if selected is profiles.HUMAN:
        if qualification is not None or lost_ack or held_owner is None or human_cleanup is not controller._HUMAN_CLEANUP: raise ValueError('human cleanup proof required')
    elif selected is not profiles.MANAGED or human_cleanup is not None: raise ValueError('unsupported cleanup context')
    base, network_name, project, volume_name = init._settings(selected)
    if qualification is not None:
        from deploy.local.origin21_managed_qualification import OwnedManagedQualification
        if type(qualification) is not OwnedManagedQualification: raise ValueError('qualification proof required')
        qualification.verify_owner(selected.owner)
    if SOURCE not in origin21_state._source_files(selected) or init.SOURCE not in origin21_state._source_files(selected): raise RuntimeError('cleanup source not pinned')
    initializer=_record(base/'initializer.intent'); done=_record(base/'initializer.done'); pg_start=_record(base/'postgres.start.result')
    if type(initializer) is not dict or set(initializer)!={'version','head','build_image','build_receipt_sha256','token','network','volume'} or initializer['version']!=1: raise ValueError('initializer intent invalid')
    source=init._context_call(selected,init._source,initializer['head'])
    if type(done) is not dict or set(done)!={'version','receipt_sha256','postgres_id','started_at'} or done['version']!=1: raise ValueError('initializer result invalid')
    receipt_raw=origin_credentials._file(base/'runtime-receipt.json',4096); receipt=capture_renew.exact_json(receipt_raw)
    import hashlib
    if json.dumps(receipt,sort_keys=True,separators=(',',':')).encode()!=receipt_raw or hashlib.sha256(receipt_raw).hexdigest()!=done['receipt_sha256'] or type(receipt) is not dict or set(receipt)!={'version','head','image_id','status','network'} or receipt['version']!=1 or receipt['head']!=initializer['head'] or receipt['image_id']!=initializer['build_image'] or receipt['status']!='passed': raise ValueError('runtime receipt changed')
    token=initializer.get('token'); pg_id=done.get('postgres_id'); started=done.get('started_at')
    if initializer.get('network')!=network_name or initializer.get('volume')!=init._context_call(selected,init._selected_volume,qualification) or pg_start!={'version':1,'id':pg_id,'started_at':started}: raise ValueError('initializer ownership changed')
    intent=products._read_record('intent.json',selected=selected); recorded=products._read_record('products.json',selected=selected)
    pending=products._read_record('companions-intent.json',selected=selected); complete=products._read_record('companions.json',selected=selected)
    deployment=intent['deployment']; slots=recorded['slots']; services=complete['services']; ids=[slot['container_id'] for slot in slots]
    if receipt['network']!=deployment or deployment['postgres_id']!=pg_id or deployment['name']!=network_name or len(ids)!=2 or set(services)!=set(products.COMPANIONS): raise ValueError('cleanup topology changed')
    images=pending['images']; all_ids=ids+[services[name]['id'] for name in products.COMPANIONS]
    if len(set(all_ids))!=7 or pg_id in all_ids: raise ValueError('cleanup identity collision')
    pg_image=products._image(init.POSTGRES)
    if pg_image['id']!=deployment['postgres_image_id']: raise ValueError('cleanup postgres image changed')
    from contextlib import nullcontext
    context=nullcontext(held_owner) if lost_ack or human_cleanup is not None else controller.open_edge(**({'qualification':qualification} if qualification is not None else {}))
    with context as owner:
        publisher=owner.publisher; edge_token=products._managed_edge_token(selected,intent['token'])
        if lost_ack:
            from deploy.gateway.managed_edge import _regular
            from deploy.local import origin21_managed_qualification_cleanup as qcleanup
            proof=qualification; proof.verify()
            topology=qcleanup._read(proof.folder/'topology.intent')
            original=qcleanup._read(proof.folder/'qualification.intent')
            original_sha=hashlib.sha256(json.dumps(original,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            expected_containers=ids+[services[name]['id'] for name in products.COMPANIONS]+[publisher.cid,pg_id]
            expected_networks=[slots[0]['namespace'],deployment['id']]
            if topology!={'version':1,'token':proof.token,'intent_sha256':original_sha,'containers':expected_containers,'networks':expected_networks} or len(set(expected_containers+expected_networks))!=11: raise ValueError('qualification topology changed')
            raw=_regular(owner.state/'publication.exec.intent',32768); publication=capture_renew.exact_json(raw)
            if type(publication) is not dict or set(publication)!={'publisher','document_sha256','nonce'} or publication['publisher']!=publisher.identity() or json.dumps(publication,sort_keys=True,separators=(',',':')).encode()!=raw: raise ValueError('publication intent changed')
            import re
            if not re.fullmatch('[0-9a-f]{32}',publication['nonce']) or not re.fullmatch('[0-9a-f]{64}',publication['document_sha256']): raise ValueError('publication intent invalid')
            marker=owner.watched/('.qualification-commit-'+publication['nonce'])
            if _regular(marker,128)!=(publication['document_sha256']+'\n').encode(): raise ValueError('publication commit marker changed')
            journal_raw=_regular(owner.state/'journal.json',4096); journal=capture_renew.exact_json(journal_raw)
            if type(journal) is not dict or journal.get('identity')!=owner.identity or journal.get('pending') is None: raise ValueError('publication journal changed')
            publisher_image=products._image(products.origin21_evidence.IMAGE)
            def unresolved():
                proof.verify_owner(selected.owner)
                if _regular(owner.state/'publication.exec.intent',32768)!=raw or _regular(marker,128)!=(publication['document_sha256']+'\n').encode() or _regular(owner.state/'journal.json',4096)!=journal_raw: raise ValueError('publication evidence changed')
            def stopped():
                unresolved()
                controller._verify_created_publisher(publisher.cid,publisher.token,publisher_image,selected.edge/'watched',stopped_at=publisher.started)
            stopped()
        elif human_cleanup is not None:
            if owner.closed or controller._context_for_publisher(publisher) is not selected: raise ValueError('human cleanup owner changed')
            _human_cleanup_guard(selected,intent)
            topology=None
        else:
            owner._managed_gate(owner._load())
            topology=qualification.bind_topology(owner.peer,publisher) if qualification is not None else None
        if publisher.cid in all_ids or publisher.cid==pg_id: raise ValueError('cleanup publisher collision')
        edge_record=owner.state/'existing-origin.intent'
        if not os.path.isfile(edge_record) or (not lost_ack and os.path.lexists(owner.state/'publication.exec.intent')): raise ValueError('cleanup edge intent unresolved')
        business=set(ids+[services[x]['id'] for x in ('destination','native-gateway','native-envoy')]); capture={pg_id,services['native-gateway']['id'],services['origin21-capture-ingress']['id'],services['origin21-capture-worker']['id']}
        remaining_products={i+1:slots[i] for i in range(2)}; remaining_services=dict(services); publisher_live=True
        def check_remaining():
            if human_cleanup is not None: _human_cleanup_guard(selected,intent)
            if lost_ack: unresolved()
            if init._context_call(selected,init._source,initializer['head'])!=source: raise ValueError('cleanup source changed')
            products._verify_model('products',intent['model_sha256'],selected=selected); products._verify_model('companions',pending['model_sha256'],selected=selected)
            products._network(business,intent['token'],selected=selected); init._context_call(selected,init._network,token,deployment['id'],capture); init._context_call(selected,init._volume,token,**({'qualification':qualification} if qualification is not None else {}))
            state=init._context_call(selected,init._postgres,pg_id,pg_image,deployment['id'],token,running=True,**({'qualification':qualification} if qualification is not None else {}))
            if state['StartedAt']!=started: raise ValueError('cleanup postgres generation changed')
            project=products._command(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+selected.project]).decode('ascii').split()
            expected={x['container_id'] for x in remaining_products.values()}|{x['id'] for x in remaining_services.values()}
            if len(project)!=len(expected) or set(project)!=expected: raise ValueError('cleanup project membership changed')
            edge_ids=products._command(['docker','ps','-aq','--no-trunc','--filter','label=org.apicontour.managed-edge-owner='+edge_token]).decode('ascii').split()
            expected_edge=({services['native-envoy']['id']} if 'native-envoy' in remaining_services else set())|({publisher.cid} if publisher_live else set())
            if len(edge_ids)!=len(expected_edge) or set(edge_ids)!=expected_edge: raise ValueError('cleanup edge membership changed')
            if publisher_live:
                if lost_ack: stopped()
                else: publisher.verify()
            for index,item in remaining_products.items():
                obj=products._objects(['docker','inspect',item['container_id']])
                state=products.validate(obj,index,item['container_id'],intent['image_id'],intent['image_env'],intent['image_cmd'],intent['image_workdir'],intent['token'],running=True,selected=selected)
                if state['StartedAt']!=item['started_at']: raise ValueError('cleanup product generation changed')
            for name,item in remaining_services.items():
                obj=products._objects(['docker','inspect',item['id']])
                state=products._validate_companion(obj,name,item['id'],images[name],intent['token'],slots[0]['namespace'],deployment['id'],deployment['name'],running=True,selected=selected,**({'qualification':qualification} if qualification is not None else {}))
                if state['StartedAt']!=item['started_at']: raise ValueError('cleanup companion generation changed')
        check_remaining()
        _write(selected.edge/'cleanup.intent',{'version':1,'postgres':pg_id,'publisher':publisher.cid,'products':ids,'services':services,'source':source})
        def remove(cid,name):
            check_remaining(); _write(selected.edge/('cleanup-'+name+'.intent'),{'version':1,'id':cid})
            if products._command(['docker','rm','-f',cid],30)!=cid.encode('ascii'): raise RuntimeError('cleanup removal uncertain')
            if products._command(['docker','ps','-aq','--no-trunc','--filter','id='+cid],15).strip(): raise RuntimeError('cleanup container remains')
            _write(selected.edge/('cleanup-'+name+'.done'),{'version':1,'id':cid})
        for name in ('native-envoy','native-gateway','destination','origin21-capture-worker','origin21-capture-ingress'):
            cid=remaining_services[name]['id']; remove(cid,name); remaining_services.pop(name)
            business.discard(cid); capture.discard(cid)
        for index in (2,1):
            cid=remaining_products[index]['container_id']; remove(cid,'replica'+str(index)); remaining_products.pop(index); business.discard(cid)
        remove(publisher.cid,'publisher'); publisher_live=False
        check_remaining()
        _write(selected.edge/'cleanup-business-network.intent',{'version':1,'id':slots[0]['namespace']})
        if products._command(['docker','network','rm',slots[0]['namespace']],30)!=slots[0]['namespace'].encode('ascii'): raise RuntimeError('business network removal uncertain')
        if products._command(['docker','network','ls','-q','--no-trunc','--filter','id='+slots[0]['namespace']],15).strip(): raise RuntimeError('business network remains')
        _write(selected.edge/'cleanup-business-network.done',{'version':1,'id':slots[0]['namespace']})
        # The last PG removal has its own complete identity proof; retain volume.
        if init._context_call(selected,init._source,initializer['head'])!=source: raise ValueError('cleanup source changed')
        init._context_call(selected,init._network,token,deployment['id'],[pg_id]); init._context_call(selected,init._volume,token,**({'qualification':qualification} if qualification is not None else {}))
        state=init._context_call(selected,init._postgres,pg_id,pg_image,deployment['id'],token,running=True,**({'qualification':qualification} if qualification is not None else {}))
        if state['StartedAt']!=started: raise ValueError('cleanup postgres generation changed')
        _write(selected.edge/'cleanup-postgres.intent',{'version':1,'id':pg_id})
        if products._command(['docker','rm','-f',pg_id],30)!=pg_id.encode('ascii'): raise RuntimeError('postgres removal uncertain')
        if products._command(['docker','ps','-aq','--no-trunc','--filter','id='+pg_id],15).strip(): raise RuntimeError('postgres remains')
        init._db_inventory(token,[])
        _write(selected.edge/'cleanup-postgres.done',{'version':1,'id':pg_id})
        if init._context_call(selected,init._source,initializer['head'])!=source: raise ValueError('cleanup source changed')
        init._context_call(selected,init._network,token,deployment['id'],[]); init._context_call(selected,init._volume,token,**({'qualification':qualification} if qualification is not None else {}))
        _write(selected.edge/'cleanup-capture-network.intent',{'version':1,'id':deployment['id']})
        if products._command(['docker','network','rm',deployment['id']],30)!=deployment['id'].encode('ascii'): raise RuntimeError('capture network removal uncertain')
        if products._command(['docker','network','ls','-q','--no-trunc','--filter','id='+deployment['id']],15).strip(): raise RuntimeError('capture network remains')
        _write(selected.edge/'cleanup-capture-network.done',{'version':1,'id':deployment['id']})
        _write(selected.edge/'cleanup.done',{'version':1,'volume_retained':True,'keys_retained':True})
        if qualification is not None:
            qualification.verify()
            _write(qualification.folder/'topology.cleaned',{'version':1,'token':qualification.token,'intent_sha256':topology['intent_sha256'],'containers_removed':topology['containers'],'networks_removed':topology['networks']})
