"""Exact exclusive runtime configuration phase for the closed origin21 bundle."""
import json
import os
from deploy.local import capture_renew, origin21_profile, origin21_runtime, origin21_state
from deploy.pilot import origin_credentials


def expected():
    configs=origin21_runtime.configs()
    items={'capture/runtime/ingress.json':configs['capture']['ingress.json'],
           'capture/runtime/worker.json':configs['capture']['worker.json'],
           'native/gateway/gateway.json':configs['gateway'],
           'native/forwarder/envoy.json':configs['envoy']}
    return {name:(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode() for name,value in items.items()}


class Configs:
    def __init__(self, profile):
        if profile is not origin21_profile.PROFILE: raise ValueError('unsupported origin21 profile')
        self.root=profile.state
    def inspect(self):
        files=expected(); present=[os.path.lexists(self.root/name) for name in files]
        if not any(present): return origin21_state.ABSENT
        if not all(present): return origin21_state.DRIFT
        try:
            if all(capture_renew.read_file(self.root/name,65536)==value for name,value in files.items()): return origin21_state.EXACT
        except (OSError,ValueError): pass
        return origin21_state.DRIFT
    def apply(self):
        if self.inspect()!=origin21_state.ABSENT: raise ValueError('runtime config state unavailable')
        for name,value in expected().items(): origin_credentials._write(self.root/name,value)
