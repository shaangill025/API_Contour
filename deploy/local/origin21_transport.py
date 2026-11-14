"""Closed local operator SQL transport. Never print SQL or credentials.

No commands execute on import. Authentication uses loopback TLS and SCRAM,
not the local trust socket. Sensitive sessions disable statement/error logging
via startup options before any SQL is parsed and check those settings first.
"""
import os
import re
import selectors
import signal
import subprocess
import time
from deploy.local import origin21_profile

ROOT=origin21_profile.ROOT
COMPOSE=['docker','compose','-f',str(ROOT/'deploy/local/compose.yaml')]
OPTIONS=('-c log_statement=none -c log_min_duration_statement=-1 '
         '-c log_min_duration_sample=-1 -c log_min_error_statement=panic '
         '-c log_min_messages=panic -c log_duration=off '
         '-c log_statement_sample_rate=0 -c log_transaction_sample_rate=0')
GUARD="""DO $$ BEGIN IF current_setting('log_statement')<>'none'
 OR current_setting('log_min_duration_statement')<>'-1'
 OR current_setting('log_min_duration_sample')<>'-1'
 OR current_setting('log_min_error_statement')<>'panic'
 OR current_setting('log_min_messages')<>'panic'
 OR current_setting('log_duration')<>'off'
 OR current_setting('log_statement_sample_rate')::numeric<>0
 OR current_setting('log_transaction_sample_rate')::numeric<>0
 THEN RAISE EXCEPTION 'unsafe private session settings'; END IF; END $$;
"""
MAX=8*1024*1024


def _run(args, data, deadline=60, env=None):
    raw=data.encode('utf-8')
    if len(raw)>MAX: raise ValueError('operator input bound')
    process=subprocess.Popen(args,cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True,env=env)
    selector=selectors.DefaultSelector(); output=bytearray(); offset=0; end=time.monotonic()+deadline
    os.set_blocking(process.stdin.fileno(),False); os.set_blocking(process.stdout.fileno(),False)
    selector.register(process.stdin,selectors.EVENT_WRITE); selector.register(process.stdout,selectors.EVENT_READ)
    complete=False
    try:
        while selector.get_map():
            left=end-time.monotonic()
            if left<=0: raise TimeoutError('operator transport deadline')
            for key,_ in selector.select(left):
                if key.fileobj is process.stdin:
                    if offset==len(raw): selector.unregister(process.stdin); process.stdin.close(); continue
                    try: offset+=os.write(process.stdin.fileno(),raw[offset:offset+65536])
                    except BrokenPipeError: selector.unregister(process.stdin); process.stdin.close()
                else:
                    chunk=os.read(process.stdout.fileno(),min(65536,MAX+1-len(output)))
                    if not chunk: selector.unregister(process.stdout)
                    else:
                        output.extend(chunk)
                        if len(output)>MAX: raise RuntimeError('operator output bound')
        result=process.wait(timeout=max(.01,end-time.monotonic()))
        complete=True
        if result or offset!=len(raw): raise RuntimeError('operator database command failed')
        return bytes(output).decode('utf-8').strip()
    finally:
        selector.close()
        if not complete:
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
        try:
            if process.poll() is None: process.wait(timeout=5)
        finally:
            if not process.stdin.closed: process.stdin.close()
            process.stdout.close()


def admin(sql):
    if not isinstance(sql,str): raise ValueError('invalid SQL')
    from deploy.local import origin21_sql_runner
    return origin21_sql_runner.production().run((GUARD+sql).encode('utf-8'),'sql','postgres')


def sensitive(sql):
    if not isinstance(sql,str): raise ValueError('invalid SQL')
    from deploy.local import origin21_sql_runner
    return origin21_sql_runner.production().run((GUARD+sql).encode('utf-8'),'sql','postgres')


def authenticate(role,password):
    if role not in (origin21_profile.PROFILE.ingress_login,origin21_profile.PROFILE.worker_login): raise ValueError('unsupported role')
    if not isinstance(password,str) or not re.fullmatch('[A-Za-z0-9_-]{32,4096}',password): raise ValueError('invalid credential')
    from deploy.local import origin21_sql_runner
    return origin21_sql_runner.production().run(password.encode('ascii'),'auth',role)==role


_MANAGED_SEAL=object()


class ManagedTransport:
    """Context-bound local SQL transport; not an attestation against the host."""
    __slots__=('_runner','_deployment','_image','_head','_receipt','_digest','_sealed','_qualification','_selected','_human_transition')
    def __init__(self,seal,runner,deployment,image,head,receipt,digest,qualification=None,selected=origin21_profile.MANAGED,human_transition=None):
        if seal is not _MANAGED_SEAL or selected is not origin21_profile.MANAGED and selected is not origin21_profile.HUMAN: raise ValueError('managed transport factory required')
        object.__setattr__(self,'_selected',selected)
        if human_transition is not None and selected is not origin21_profile.HUMAN: raise ValueError('unexpected human transition')
        object.__setattr__(self,'_human_transition',human_transition)
        object.__setattr__(self,'_runner',runner); object.__setattr__(self,'_deployment',tuple(sorted(deployment.items())))
        object.__setattr__(self,'_image',image); object.__setattr__(self,'_head',head)
        object.__setattr__(self,'_receipt',receipt); object.__setattr__(self,'_digest',digest); object.__setattr__(self,'_qualification',qualification); object.__setattr__(self,'_sealed',True)
    def __setattr__(self,name,value): raise AttributeError('managed transport is immutable')
    @property
    def qualification(self): return self._qualification
    def verify(self):
        if self._selected is origin21_profile.MANAGED:
            from deploy.local.origin21_managed_qualification import require_matching
            require_matching(self._qualification)
        elif self._qualification is not None: raise ValueError('unexpected qualification')
        owner=self._selected.owner
        if self._qualification is not None: self._qualification.verify_owner(owner)
        elif os.path.lexists(owner/'qualification.intent'): raise ValueError('qualification proof required')
        from deploy.local import origin21_products
        deployment=origin21_products._build_receipt(self._image,self._head,self._receipt,self._digest,selected=self._selected)
        if tuple(sorted(deployment.items()))!=self._deployment: raise RuntimeError('managed deployment receipt changed')
        record=origin21_products._read_record('intent.json',selected=self._selected)
        if record.get('deployment')!=deployment or (record.get('app_image_id'),record.get('build_head'),record.get('build_receipt_sha256'))!=(self._image,self._head,self._digest): raise RuntimeError('managed owner record changed')
        if self._selected is origin21_profile.HUMAN:
            companions=os.path.lexists(owner/'companions.json')
            attempted=os.path.lexists(owner/'companions-intent.json') or os.path.lexists(owner/'companions-created.json')
            if attempted and not companions: raise ValueError('companion transition unresolved')
            pending=os.path.lexists(owner/'human.intent')
            complete=os.path.lexists(owner/'human.json')
            if (pending or complete) and not companions or (complete and not pending): raise ValueError('human topology record missing')
            if pending and not complete:
                from deploy.local.origin21_managed_human_services import _HumanStageProof
                if type(self._human_transition) is not _HumanStageProof: raise ValueError('human transition proof required')
                self._human_transition.verify()
            elif companions:
                from deploy.local import origin21_managed_controller
                origin21_managed_controller.verify_recorded_topology(selected=self._selected)
        self._runner.verify_target(self._runner.target)
    def admin(self,sql):
        if not isinstance(sql,str): raise ValueError('invalid SQL')
        self.verify(); return self._runner.run((GUARD+sql).encode('utf-8'),'sql','postgres')
    def sensitive(self,sql):
        if not isinstance(sql,str): raise ValueError('invalid SQL')
        self.verify(); return self._runner.run((GUARD+sql).encode('utf-8'),'sql','postgres')
    def authenticate(self,role,password):
        profile=self._selected.profile
        if role not in (profile.ingress_login,profile.worker_login) or not isinstance(password,str) or not re.fullmatch('[A-Za-z0-9_-]{32,4096}',password): raise ValueError('invalid credential')
        self.verify(); return self._runner.run(password.encode('ascii'),'auth',role)==role
    def _bind_human_transition(self, proof):
        from deploy.local.origin21_managed_human_services import _HumanStageProof
        if self._selected is not origin21_profile.HUMAN or type(proof) is not _HumanStageProof: raise ValueError('human transition proof required')
        proof.verify()
        return ManagedTransport(_MANAGED_SEAL,self._runner,dict(self._deployment),self._image,self._head,
                                self._receipt,self._digest,None,self._selected,proof)
    def authenticate_app(self, password):
        if self._selected is not origin21_profile.HUMAN or not isinstance(password,str) or not re.fullmatch('[0-9a-f]{64}',password): raise ValueError('human app credential required')
        self.verify(); return self._runner.run(password.encode('ascii'),'auth','contour_app')=='contour_app'


def managed_transport(*,image_id,head,receipt,digest,qualification=None,selected=origin21_profile.MANAGED):
    """Bind only the complete managed receipt and its verified private owner."""
    from deploy.local import capture_renew,origin21_products,origin21_sql_runner
    origin21_profile.require_context(selected)
    if selected is not origin21_profile.MANAGED and selected is not origin21_profile.HUMAN: raise ValueError('managed context required')
    if selected is origin21_profile.HUMAN and qualification is not None: raise ValueError('unexpected qualification')
    if selected is origin21_profile.MANAGED:
        from deploy.local.origin21_managed_qualification import require_matching
        require_matching(qualification)
    if qualification is not None:
        from deploy.local.origin21_managed_qualification import OwnedManagedQualification
        if type(qualification) is not OwnedManagedQualification: raise ValueError('qualification proof required')
        qualification.verify_owner(selected.owner)
    elif os.path.lexists(selected.owner/'qualification.intent'): raise ValueError('qualification proof required')
    deployment=origin21_products._build_receipt(image_id,head,receipt,digest,selected=selected)
    record=origin21_products._read_record('intent.json',selected=selected)
    if record.get('deployment')!=deployment or (record.get('app_image_id'),record.get('build_head'),record.get('build_receipt_sha256'))!=(image_id,head,digest): raise RuntimeError('managed owner record changed')
    origin21_products._capture_network(deployment,selected=selected)
    parent=selected.profile.state.parent; capture_renew.safe_dir(parent)
    directory=parent/'origin21-transport'
    try: os.mkdir(directory,0o700)
    except FileExistsError: pass
    else:
        fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    runner=origin21_sql_runner.for_deployment(directory,deployment,selected=selected,qualification=qualification)
    transport=ManagedTransport(_MANAGED_SEAL,runner,deployment,image_id,head,receipt,digest,qualification,selected)
    transport.verify()
    return transport
