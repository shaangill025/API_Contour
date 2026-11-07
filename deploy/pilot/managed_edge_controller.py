"""Closed startup sequencing for one separately owned managed-edge fixture.

The caller must first create the exact labeled Envoy and replica containers.
This module neither creates nor removes containers and never reads product keys.
"""
import re
from deploy.gateway.managed_edge import ManagedEdge, NativeReplicaPeer, _command

LABEL='org.apicontour.managed-edge-owner'

class ManagedEdgeController:
    def __init__(self, state, published, watched, ca, ca_key, peer, owner_token):
        if type(peer) is not NativeReplicaPeer or not re.fullmatch(r'[0-9a-f]{32}',owner_token):
            raise ValueError('invalid owned controller')
        self.peer=peer; self.token=owner_token
        self.edge=ManagedEdge(state,published,watched,ca,ca_key,peer)
    def _owned(self,cid):
        value=_command(['docker','inspect','--format','{{ index .Config.Labels "'+LABEL+'" }}',cid])
        if value!=self.token.encode('ascii')+b'\n': raise ValueError('container ownership mismatch')
    def bootstrap(self):
        # Source/profile, created-state, mounts and image are checked by the peer
        # before SDS; immutable CIDs are started only after the pending write.
        for cid in (self.peer.envoy_cid,self.peer.cid): self._owned(cid)
        self.edge.prepare_initial()
        for cid in (self.peer.envoy_cid,self.peer.cid):
            self._owned(cid)
            if _command(['docker','start',cid]).strip()!=cid.encode('ascii'): raise RuntimeError('container start mismatch')
            self._owned(cid)
        self.edge.bind_initial_peer()
        self.edge.reconcile()
    def close(self): self.edge.close()
    def __enter__(self): return self
    def __exit__(self,*_): self.close()
