"""Bounded inclusive timings for one explicitly requested readiness diagnostic.

Metrics overlap and are not additive. No arguments, identities or results are
recorded, and this helper confers no readiness or qualification authority.
"""
from functools import wraps
import threading
import time

LABELS=('products_command','edge_command','transport_run','source_identity','managed_source',
        'owned_worktree','proof_verify','recorded_topology','peer_inspect','sql_run')
MAX_VALUE=999999999
MAX_CALLS=999999


class Profile:
    def __init__(self,proof,clock=time.monotonic_ns):
        from deploy.local.origin21_managed_qualification import OwnedManagedQualification
        if type(proof) is not OwnedManagedQualification or not callable(clock): raise ValueError('owned qualification required')
        self.proof=proof; self.clock=clock; self.lock=threading.Lock()
        self.counts={name:[0,0,0] for name in LABELS}; self.original=[]

    def _clock(self):
        try:
            value=self.clock()
            return value if type(value) is int and value>=0 else None
        except BaseException: return None

    def _wrap(self,name,original):
        @wraps(original)
        def wrapped(*args,**kwargs):
            start=self._clock()
            try: return original(*args,**kwargs)
            finally:
                end=self._clock()
                duration=end-start if start is not None and end is not None and end>=start else 0
                try:
                    with self.lock:
                        row=self.counts[name]
                        row[0]=min(MAX_CALLS,row[0]+1)
                        row[1]=min(MAX_VALUE*1000000,row[1]+duration)
                        row[2]=min(MAX_VALUE*1000000,max(row[2],duration))
                except BaseException: pass
        return wrapped

    def __enter__(self):
        from deploy.gateway import managed_edge
        from deploy.local import origin21_products,origin21_transport,origin21_state,origin21_managed_init,origin21_managed_qualification,origin21_managed_controller,origin21_sql_runner
        self.proof.verify()
        targets=((origin21_products,'_command'),(managed_edge,'_command'),(origin21_transport,'_run'),
                 (origin21_state,'_source_identity'),(origin21_managed_init,'_source'),
                 (origin21_managed_qualification,'_owned_worktree'),(origin21_managed_qualification.OwnedManagedQualification,'verify'),
                 (origin21_managed_controller,'verify_recorded_topology'),(managed_edge.NativeReplicaPeer,'_inspect'),
                 (origin21_sql_runner.Runner,'run'))
        try:
            for name,(owner,attribute) in zip(LABELS,targets,strict=True):
                original=getattr(owner,attribute); replacement=self._wrap(name,original)
                setattr(owner,attribute,replacement); self.original.append((owner,attribute,original,replacement))
        except BaseException as error:
            try: self._restore()
            except BaseException as cleanup: raise BaseExceptionGroup('profile and cleanup failures',[error,cleanup]) from None
            raise
        return self

    def _restore(self):
        changed=False
        for owner,attribute,original,replacement in reversed(self.original):
            try:
                if getattr(owner,attribute) is replacement: setattr(owner,attribute,original)
                else: changed=True
            except BaseException: changed=True
        self.original.clear()
        if changed: raise RuntimeError('profile hooks changed')

    def __exit__(self,kind,error,traceback):
        try: self._restore()
        except BaseException as cleanup:
            if error is not None: raise BaseExceptionGroup('profile and cleanup failures',[error,cleanup]) from None
            raise
        return False

    def lines(self):
        with self.lock:
            return ('managed-profile totals=inclusive-overlap-not-additive',) + tuple(
                'managed-profile name='+name+' calls='+str(self.counts[name][0])+
                ' inclusive_ms='+str(self.counts[name][1]//1000000)+' max_ms='+str(self.counts[name][2]//1000000) for name in LABELS)
