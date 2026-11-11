"""Explicit owned teardown of a complete managed-human topology.

Database, identity volume and private keys remain; partial outcomes are retained.
"""
import hashlib
import json
from deploy.local import (capture_renew, origin21_managed_cleanup as cleanup,
    origin21_managed_controller as controller, origin21_products as products, origin21_profile as profiles)
from deploy.pilot import origin_credentials


def _record(path,value):
    origin_credentials._write(path,json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def _check(owner,baseline):
    first=controller._topology_snapshot(owner.peer,owner.publisher,live_envoy=True,_cleanup=controller._HUMAN_CLEANUP)
    second=controller._topology_snapshot(owner.peer,owner.publisher,live_envoy=True,_cleanup=controller._HUMAN_CLEANUP)
    if first!=second or first!=baseline: raise ValueError('human cleanup topology changed')


def teardown():
    selected=profiles.HUMAN
    profiles.require_context(selected)
    with controller.open_edge(selected=selected) as owner:
        owner._managed_gate(owner._load())
        baseline=controller._topology_snapshot(owner.peer,owner.publisher,live_envoy=True)
        if controller._topology_snapshot(owner.peer,owner.publisher,live_envoy=True)!=baseline: raise ValueError('human cleanup baseline changed')
        raw=origin_credentials._file(selected.owner/'human.json',65536); human=capture_renew.exact_json(raw)
        if type(human) is not dict or json.dumps(human,sort_keys=True,separators=(',',':')).encode()!=raw: raise ValueError('human cleanup record invalid')
        record={'version':1,'token':human['token'],'human_sha256':hashlib.sha256(raw).hexdigest()}
        _record(selected.owner/'human.cleanup.intent',record)
        app=human['services']['app']['id']; identity=human['services']['mvp-keycloak']['id']
        _record(selected.owner/'human.cleanup-app.intent',{'version':1,'id':app})
        owner._managed_gate(owner._load())
        if products._command(['docker','rm','-f',app],30)!=app.encode('ascii'): raise RuntimeError('human app removal uncertain')
        if products._command(['docker','ps','-aq','--no-trunc','--filter','id='+app],15).strip(): raise RuntimeError('human app remains')
        _record(selected.owner/'human.cleanup-app.done',{'version':1,'id':app})
        _check(owner,baseline)
        _record(selected.owner/'human.cleanup-identity.intent',{'version':1,'id':identity})
        _check(owner,baseline)
        if products._command(['docker','rm','-f',identity],30)!=identity.encode('ascii'): raise RuntimeError('human identity removal uncertain')
        if products._command(['docker','ps','-aq','--no-trunc','--filter','id='+identity],15).strip(): raise RuntimeError('human identity remains')
        _record(selected.owner/'human.cleanup-identity.done',{'version':1,'id':identity})
        _check(owner,baseline)
        network=human['network_ids']['human']
        _record(selected.owner/'human.cleanup-network.intent',{'version':1,'id':network})
        _check(owner,baseline)
        if products._command(['docker','network','rm',network],30)!=network.encode('ascii'): raise RuntimeError('human network removal uncertain')
        if products._command(['docker','network','ls','-q','--no-trunc','--filter','id='+network],15).strip(): raise RuntimeError('human network remains')
        _record(selected.owner/'human.cleanup-network.done',{'version':1,'id':network})
        cleanup._teardown(None,False,owner,selected=selected,human_cleanup=controller._HUMAN_CLEANUP)
    return {'containers_removed':True,'networks_removed':True,'data_and_keys_retained':True}


if __name__=='__main__':
    import sys
    if len(sys.argv)!=1:
        print('Expected no arguments.',file=sys.stderr)
        raise SystemExit(2)
    try: print(teardown())
    except Exception:
        print('Managed human cleanup failed; remaining state retained.',file=sys.stderr)
        raise SystemExit(1) from None
