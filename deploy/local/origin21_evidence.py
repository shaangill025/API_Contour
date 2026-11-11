"""Exact operator-inspected local Docker identity binding for two fixed slots.

The inspector is a trusted operator adapter; this is not hardware attestation.
Its descriptors and expected commitments must be re-supplied at each restart.
"""
import hashlib
import datetime
import stat
import hmac
import json
import os
import re
from deploy.local import origin21_profile, origin21_state, capture_renew
from deploy.pilot import origin_credentials

IMAGE='docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963'
DOMAIN=b'apicontour/origin21-operator-docker/1\n'
FIELDS={'container_id','image_id','image_ref','namespace','service_label','leaf_sha256','started_at','app_image_id','build_head','build_receipt_sha256','deployment_sha256'}


def descriptor(value, index, leaf):
    if type(index) is not int or index not in (1,2) or type(value) is not dict or set(value)!=FIELDS: raise ValueError('invalid operator descriptor')
    if not all(isinstance(value[k],str) for k in FIELDS): raise ValueError('invalid operator descriptor')
    if (not re.fullmatch('[0-9a-f]{64}',value['container_id']) or
        not re.fullmatch('sha256:[0-9a-f]{64}',value['image_id']) or value['image_ref']!=IMAGE or
        not re.fullmatch('sha256:[0-9a-f]{64}',value['app_image_id']) or not re.fullmatch('[0-9a-f]{40}',value['build_head']) or not re.fullmatch('[0-9a-f]{64}',value['build_receipt_sha256']) or not re.fullmatch('[0-9a-f]{64}',value['deployment_sha256']) or
        not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',value['namespace']) or
        value['service_label']!='replica'+str(index) or
        not re.fullmatch('[0-9a-f]{64}',value['leaf_sha256']) or value['leaf_sha256']!=leaf or
        not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',value['started_at'])):
        raise ValueError('invalid operator descriptor')
    try: datetime.datetime.fromisoformat(value['started_at'].replace('Z','+00:00'))
    except ValueError: raise ValueError('invalid operator descriptor') from None
    return value


def _bytes(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def digest(value): return hashlib.sha256(DOMAIN+_bytes(value)).digest()


class Evidence:
    def __init__(self,profile,inspect_slot,expected):
        if (profile is not origin21_profile.PROFILE and profile is not origin21_profile.MANAGED_PROFILE and profile is not origin21_profile.HUMAN_PROFILE) or not callable(inspect_slot) or type(expected) is not tuple or len(expected)!=2 or any(type(x) is not bytes or len(x)!=32 for x in expected):
            raise ValueError('fixed operator evidence required')
        if profile is origin21_profile.HUMAN_PROFILE: origin21_profile.require_context(origin21_profile.HUMAN)
        self.profile,self.inspect_slot,self.expected=profile,inspect_slot,expected
        self.path=profile.state/'operator-evidence.json'
    def _current(self):
        values=[]
        for index,slot in enumerate(self.profile.origins,1):
            leaf=hashlib.sha256(origin_credentials._file(slot.leaf_der)).hexdigest()
            try: value=self.inspect_slot(index)
            except Exception: raise RuntimeError('operator inspection failed') from None
            value=descriptor(value,index,leaf)
            if not hmac.compare_digest(digest(value),self.expected[index-1]): raise ValueError('operator evidence changed')
            values.append(value)
        if values[0]['container_id']==values[1]['container_id'] or values[0]['leaf_sha256']==values[1]['leaf_sha256']: raise ValueError('operator identities collide')
        return {'version':1,'slots':values}
    def inspect(self):
        if not os.path.lexists(self.path): return origin21_state.ABSENT
        try:
            if stat.S_IMODE(os.lstat(self.path).st_mode)!=0o600: return origin21_state.DRIFT
            raw=capture_renew.read_file(self.path,8192)
            stored=capture_renew.exact_json(raw)
            if _bytes(stored)!=raw or stored!=self._current(): return origin21_state.DRIFT
            return origin21_state.EXACT
        except (ValueError,OSError,RuntimeError): return origin21_state.DRIFT
    def apply(self):
        if os.path.lexists(self.path): raise ValueError('operator evidence already exists')
        origin_credentials._write(self.path,_bytes(self._current()))
    def commitment(self):
        if self.inspect()!=origin21_state.EXACT: raise ValueError('operator evidence drift')
        return hashlib.sha256(capture_renew.read_file(self.path,8192)).hexdigest()
    def slot_digest(self,slot):
        if self.inspect()!=origin21_state.EXACT: raise ValueError('operator evidence drift')
        index=next((i for i,x in enumerate(self.profile.origins) if x is slot),None)
        if index is None: raise ValueError('unsupported origin slot')
        return self.expected[index].hex()
