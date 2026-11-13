#!/usr/bin/env python3
"""Real managed-Origin stream/capture qualification component.

This file never creates a listener. A full qualification also requires the
closed qualification-owned bootstrap and unknown-outcome disposal, neither of
which is emulated here. No synthetic capture authority or 503 path is used.
"""
import json
import contextlib
import contextvars
import hashlib
import os
from pathlib import Path
import re
import runpy
import secrets
import sys
import threading
import time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from deploy.local import docker_metadata,qualification_git,origin21_managed_controller as controller,origin21_products as products,origin21_profile as profiles,origin21_ready,origin21_state,origin21_transport

ROOT=profiles.ROOT
FIXTURE=ROOT/'tests/fixtures/managed-origin-qualification'
SOURCE='scripts/test-managed-origin-qualification.py'
M5_HELPER='scripts/test-managed-native-edge.py'
SHELL='exec 3<&0; /usr/local/bin/node -e "$1" fixture-client "$2" "$3" <&3 3<&- & p=$!; exec 3<&-; printf "PID %s\\n" "$p"; wait "$p"'

# Closed public diagnostics: never serialize exception messages or locals.
_PHASE='arguments'
_ALLOWED_FRAMES={
    'scripts/test-managed-origin-qualification.py', 'scripts/qualify-managed-origin.py',
    'deploy/local/origin21_managed_controller.py', 'deploy/local/origin21_managed_init.py',
    'deploy/local/origin21_managed_cli.py', 'deploy/local/origin21_managed_qualification.py',
    'deploy/local/origin21_managed_qualification_cleanup.py', 'deploy/local/origin21_managed_cleanup.py',
    'deploy/local/origin21_ready.py', 'deploy/local/origin21_products.py',
    'deploy/local/origin21_transport.py', 'deploy/local/origin21_sql_runner.py', 'deploy/local/docker_metadata.py', 'deploy/local/origin21_readiness_profile.py', 'deploy/local/qualification_git.py',
    'deploy/gateway/managed_edge.py', 'scripts/test-managed-native-edge.py',
    'scripts/qualify-origin21-onboarding.py',
}
_ALLOWED_TYPES={ValueError,RuntimeError,TimeoutError,AssertionError,PermissionError,FileNotFoundError,OSError,KeyError,IndexError,TypeError,AttributeError}
_RETAINED=[]
_STREAM_DEADLINE=180

_PROGRESS_PHASES=('initial-readiness', 'initialize', 'lost-ack', 'negative-cases', 'positive-streams', 'qualification-begin', 'source-check', 'stream-capture-baseline', 'stream-capture-wait', 'stream-client-start', 'stream-prefix', 'stream-readiness', 'stream-release', 'stream-setup', 'stream-transition', 'topology-up', 'transport', 'volume-disposal')

def _set_phase(phase):
    global _PHASE
    if phase not in _PROGRESS_PHASES: raise ValueError('invalid diagnostic phase')
    _PHASE=phase
    print('managed-progress phase='+phase,file=sys.stderr,flush=True)

class _OwnerGuard:
    def __init__(self,owner): self.owner=owner
    def __enter__(self): return self.owner
    def __exit__(self,kind,error,traceback):
        if not any(item[0] is self.owner for item in _RETAINED):
            try: self.owner.close()
            except BaseException as cleanup:
                if error is not None: raise BaseExceptionGroup('qualification and owner close failures',[error,cleanup]) from None
                raise


def failure_lines(error,phase):
    lines=[]
    def visit(exc,role,depth):
        if len(lines)>=16 or depth>=8: return
        if isinstance(exc,BaseExceptionGroup):
            for index,child in enumerate(exc.exceptions[:8]): visit(child,role if index==0 else 'cleanup',depth+1)
            return
        kind=type(exc).__name__ if type(exc) in _ALLOWED_TYPES else 'OtherError'
        locations=[]; tb=exc.__traceback__; count=0
        while tb is not None and count<128:
            filename=tb.tb_frame.f_code.co_filename
            for relative in _ALLOWED_FRAMES:
                if filename==str(ROOT/relative) and 0<tb.tb_lineno<10000000:
                    locations.append(relative+':'+str(tb.tb_lineno)); break
            tb=tb.tb_next; count+=1
        location=','.join(locations[-6:]) if locations else 'unavailable'
        lines.append('managed-failure phase='+phase+' role='+role+' type='+kind+' location='+location)
    visit(error,'primary',0)
    return lines


def _source_guard():
    required={SOURCE,M5_HELPER,'deploy/local/docker_metadata.py','deploy/local/qualification_git.py','deploy/local/origin21_readiness_profile.py','deploy/local/origin21_managed_qualification.py','deploy/local/origin21_managed_qualification_cleanup.py','deploy/local/origin21_managed_init.py','deploy/local/origin21_managed_cleanup.py','tests/fixtures/managed-origin-qualification/destination.js','tests/fixtures/managed-origin-qualification/client.js','tests/fixtures/managed-origin-qualification/control.js','tests/fixtures/managed-origin-qualification/publisher.js'}
    if not required.issubset(set(origin21_state.MANAGED_SOURCE_FILES)): raise RuntimeError('qualification source closure incomplete')
    return origin21_state._source_identity(context=profiles.MANAGED)


def _helper():
    before=_source_guard(); path=ROOT/M5_HELPER
    if any(p.is_symlink() for p in (path,*list(path.parents)[:2])) or not path.is_file(): raise ValueError('qualification helper unavailable')
    module=runpy.run_path(str(path))
    if _source_guard()!=before: raise ValueError('qualification source changed')
    return module


def _destination():
    record=products._read_record('companions.json',selected=profiles.MANAGED)
    cid=record['services']['destination']['id']; obj=products._objects(['docker','inspect',cid]); mounts=obj.get('Mounts') or []
    matches=[m for m in mounts if m.get('Destination')=='/pilot/destination.js']
    if len(matches)!=1 or matches[0].get('Type')!='bind' or matches[0].get('RW') is not False or matches[0].get('Source')!=str(FIXTURE/'destination.js'): raise ValueError('qualification destination not bound')
    return cid


def _control(destination,nonce,action):
    if not re.fullmatch('[0-9a-f]{64}',destination) or not re.fullmatch('[0-9a-f]{32}',nonce) or action not in ('status','release'): raise ValueError('invalid private control')
    script=(FIXTURE/'control.js').read_text()
    result=products._command(['docker','exec','--env','LD_PRELOAD=','--env','LD_LIBRARY_PATH=','--env','LD_AUDIT=','--env','NODE_OPTIONS=','--env','NODE_PATH=',destination,'/usr/bin/env','-i','/usr/local/bin/node','-e',script,'fixture-control',nonce,action],5)
    allowed=(b'PENDING',b'REQUEST_PREFIX',b'RESPONSE_PREFIX',b'DONE',b'ERROR',b'UNKNOWN') if action=='status' else (b'RELEASED',)
    if result not in allowed: raise RuntimeError('qualification control invalid')
    return result


def _wait_status(destination,nonce,expected,timeout=10):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        state=_control(destination,nonce,'status')
        if state==expected: return
        if state in (b'ERROR',b'DONE'): raise RuntimeError('qualification barrier failed')
        time.sleep(.02)
    raise TimeoutError('qualification barrier deadline')


def _commitments():
    record=products._read_record('commitments.json',selected=profiles.MANAGED)
    values=record.get('sha256') if type(record) is dict and set(record)=={'version','sha256'} and record['version']==1 else None
    if type(values) is not list or len(values)!=2 or any(type(x) is not str or not re.fullmatch('[0-9a-f]{64}',x) for x in values): raise ValueError('qualification commitments invalid')
    return tuple(bytes.fromhex(value) for value in values)


def _products(proof):
    return tuple(products.inspect_slot(i,selected=profiles.MANAGED,qualification=proof) for i in (1,2))


def _wait_capture(transport,before,descriptor,evidence,revision,index):
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        rows=origin21_ready.snapshot(transport.admin,selected=profiles.MANAGED)
        if origin21_ready.validate_fresh(rows,before,index,descriptor['leaf_sha256'],evidence,revision,selected=profiles.MANAGED): return
        time.sleep(.25)
    raise TimeoutError('qualification catalog deadline')


def _stream(mode,index,transition,destination,descriptor,helper,proof):
    global _PHASE
    _set_phase('stream-setup')
    if (mode,index,transition) not in (('request',1,'renew'),('response',2,'rollback'),('response',1,'renew'),('request',2,'rollback')): raise ValueError('unsupported qualification stream')
    owner=controller.open_edge(qualification=proof)
    try:
        return _stream_with_owner(mode,index,transition,destination,descriptor,helper,owner)
    finally:
        primary=sys.exc_info()[1]
        if not any(item[0] is owner for item in _RETAINED):
            try: owner.close()
            except BaseException as error:
                if primary is not None: raise BaseExceptionGroup('stream and owner close failures',[primary,error]) from None
                raise


def _stream_with_owner(mode,index,transition,destination,descriptor,helper,owner):
    global _PHASE
    nonce=secrets.token_hex(16); source=(FIXTURE/'client.js').read_text(); replica=descriptor['container_id']
    args=['docker','exec','-i','--env','LD_PRELOAD=','--env','LD_LIBRARY_PATH=','--env','LD_AUDIT=','--env','NODE_OPTIONS=','--env','NODE_PATH=',replica,'/usr/bin/env','-i','/bin/sh','-c',SHELL,'fixture',source,mode,nonce]
    for name in ('HeldStatusError','HeldStatus408','HeldStatus429','HeldStatus500','HeldStatus502','HeldStatus503','HeldStatus504','HeldStatusOther','HeldBodyLimitError','HeldPrefixError','HeldResponseError','HeldResponseAborted','HeldBodyMismatch','HeldRequestError','HeldTimeout','HeldControlError'):
        cls=helper.get(name)
        if isinstance(cls,type) and issubclass(cls,RuntimeError): _ALLOWED_TYPES.add(cls)
    ready=threading.Event(); prefix=threading.Event(); activated=threading.Event(); cancel=threading.Event(); done=threading.Event()
    result=[]; writer_errors=[]; state={'publish':False,'confirm':False}
    original_publish=owner._publish; original_confirm=owner._confirm
    diagnostic_enabled=os.environ.get('CONTOUR_MANAGED_READY_DIAGNOSTICS')=='1'
    diagnostic_start=time.monotonic(); diagnostic_count=[0]; diagnostic_lock=threading.Lock()
    def timing(name):
        if not diagnostic_enabled or name not in ('prefix','publish','confirm','activation','release'): return
        try:
            with diagnostic_lock:
                if diagnostic_count[0]>=5: return
                ms=min(999999999,max(0,int((time.monotonic()-diagnostic_start)*1000)))
                diagnostic_count[0]+=1
                print(f'managed-stream name={name} ms={ms} count={diagnostic_count[0]}',file=sys.stderr,flush=True)
        except BaseException: pass
    deadline=time.monotonic()+_STREAM_DEADLINE
    def remaining(): return max(0,deadline-time.monotonic())
    def publish(*args,**kwargs):
        if state['publish'] or state['confirm']: raise RuntimeError('duplicate publication')
        state['publish']=True; ready.set()
        if not prefix.wait(remaining()) or cancel.is_set() or not remaining(): raise TimeoutError('publication barrier cancelled')
        timing('publish')
        return original_publish(*args,**kwargs)
    def confirm(*args,**kwargs):
        if not state['publish'] or state['confirm'] or not prefix.is_set(): raise RuntimeError('confirmation out of order')
        state['confirm']=True
        value=original_confirm(*args,**kwargs)
        timing('confirm')
        activated.set()
        return value
    owner._publish=publish; owner._confirm=confirm
    def write():
        try:
            before=owner._load()['current_commitment']['cert_sha256']
            (owner.renew if transition=='renew' else owner.rollback)()
            after=owner._load()['current_commitment']['cert_sha256']
            if not activated.is_set() or before==after: raise RuntimeError('qualification fingerprint unchanged')
            result.append((before,after))
        except BaseException as error: writer_errors.append(error)
        finally: done.set()
    writer_context=contextvars.copy_context()
    writer=threading.Thread(target=lambda:writer_context.run(write),daemon=False)
    retained=(owner,writer); _RETAINED.append(retained)
    started=False
    monitor=None; pid=None; completed=False; primary=None; errors=[]
    try:
        writer.start(); started=True
        while not ready.wait(min(.05,remaining())):
            if done.is_set(): raise RuntimeError('writer ended before publication barrier')
            if not remaining(): raise TimeoutError('publication setup deadline')
        monitor=helper['Monitor'](args)
        client_deadline=min(deadline,time.monotonic()+15)
        _set_phase('stream-client-start')
        while time.monotonic()<client_deadline:
            lines=monitor.lines()
            if lines:
                match=re.fullmatch(rb'PID ([1-9][0-9]{0,9})',lines[0])
                if not match: raise RuntimeError('qualification remote identity unavailable')
                pid=match.group(1); break
            if monitor.proc.poll() is not None: raise RuntimeError('qualification client exited')
            time.sleep(.02)
        if pid is None: raise TimeoutError('qualification remote identity deadline')
        _set_phase('stream-prefix')
        if mode=='request': monitor.wait(b'CLIENT_WRITTEN',timeout=remaining()); _wait_status(destination,nonce,b'REQUEST_PREFIX',timeout=remaining())
        else: monitor.wait(b'RESPONSE_PREFIX',timeout=remaining()); _wait_status(destination,nonce,b'RESPONSE_PREFIX',timeout=remaining())
        _set_phase('stream-transition')
        timing('prefix'); prefix.set()
        while not activated.wait(min(.05,remaining())):
            monitor.lines()
            if monitor.proc.poll() is not None: raise RuntimeError('qualification client exited')
            if done.is_set(): raise RuntimeError('writer ended before activation')
            if not remaining(): raise TimeoutError('activation deadline')
        timing('activation')
        _set_phase('stream-release')
        timing('release')
        if mode=='request': monitor.send('RELEASE_REQUEST')
        else: _control(destination,nonce,'release')
        monitor.wait(b'PASS',timeout=remaining())
        monitor.finish([b'PID '+pid,b'CLIENT_WRITTEN' if mode=='request' else b'RESPONSE_PREFIX',b'PASS'])
        helper['remote_absent'](lambda a,**k:products._command(a,k.get('timeout',30)),replica,pid)
        if not remaining(): raise TimeoutError('qualification stream deadline')
        completed=True
    except BaseException as error:
        primary=error
    finally:
        cancel.set(); prefix.set()
        if monitor is not None:
            try: monitor.reap()
            except BaseException as error: errors.append(error)
        if monitor is not None and not completed:
            # Local Docker CLI exit alone is not proof that its in-container
            # child exited. Caller must retain the entire owned topology.
            errors.append(RuntimeError('qualification remote completion uncertain'))
        terminated=False
        if started:
            try:
                writer.join(remaining())
                terminated=not writer.is_alive()
            except BaseException as error: errors.append(error)
        if not terminated:
            errors.append(TimeoutError('qualification writer remains'))
        else:
            errors.extend(writer_errors)
            if not remaining(): errors.append(TimeoutError('qualification writer deadline'))
            try:
                owner._publish=original_publish; owner._confirm=original_confirm
                _RETAINED.remove(retained)
            except BaseException as error: errors.append(error)
        failures=([primary] if primary is not None else [])+errors
        if failures: raise BaseExceptionGroup('qualification stream and cleanup failures',failures) from None
    if len(result)!=1 or not completed: raise RuntimeError('qualification writer result missing')
    return result[0]



def _immutable_capture(transport,ids):
    """Read complete stored capture/proof rows for the fixed prior record IDs."""
    from deploy.local import provision
    if not isinstance(ids,set) or len(ids)>10000 or any(not isinstance(x,str) or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',x) for x in ids): raise ValueError('invalid prior record IDs')
    if not ids: return {}
    tenant=provision.sql_quote(provision.IDS[0]); collector=provision.sql_quote(profiles.MANAGED.profile.collector)
    ids_sql=','.join(provision.sql_quote(value)+'::uuid' for value in sorted(ids))
    raw=transport.admin(f"""SELECT coalesce(json_agg(json_build_array(m.record_id::text,to_jsonb(m),to_jsonb(b),to_jsonb(p),to_jsonb(q)) ORDER BY m.record_id),'[]'::json)::text
      FROM contour.ingestion_v2_metadata m JOIN contour.ingestion_batches b USING (tenant_id,collector_id,batch_id)
      JOIN contour.ingestion_payloads p USING (tenant_id,collector_id,batch_id)
      LEFT JOIN contour.origin_proofs q USING (tenant_id,collector_id,batch_id,record_id)
      WHERE m.tenant_id={tenant} AND m.collector_id={collector} AND m.record_id IN ({ids_sql});""")
    if not isinstance(raw,str) or len(raw.encode('utf-8'))>8*1024*1024: raise ValueError('capture evidence bound')
    rows=json.loads(raw)
    if not isinstance(rows,list) or len(rows)!=len(ids) or any(not isinstance(row,list) or len(row)!=5 or row[0] not in ids for row in rows): raise ValueError('capture evidence invalid')
    result={row[0]:row for row in rows}
    if set(result)!=ids: raise ValueError('capture evidence missing')
    return result


def _policy_cycle(transport,proof,expected,original,diagnostics=None):
    """Renew between completed streams and prove both old evidence and adoption."""
    from deploy.local import origin21_renewal, origin21_setup, provision
    selected=profiles.MANAGED
    proof.verify(); transport.verify()
    _,pending=origin21_renewal.artifacts(selected.bound)
    if pending is not None: raise ValueError('policy renewal already pending')
    history=origin21_renewal.history(selected.bound,transport.sensitive)
    if history is None or type(history.count) is not int or history.count<1 or type(history.head) is not bytes: raise ValueError('policy history invalid')
    revision=products.require_current_policy(transport.admin,transport.sensitive,selected=selected)
    if type(revision) is not int or history.count!=revision or history.head_policy.get('revision')!=revision: raise ValueError('policy head mismatch')
    prior=origin21_ready.snapshot(transport.admin,selected=selected)
    prior_by_id={row[0]:row for row in prior}
    if len(prior_by_id)!=len(prior): raise ValueError('duplicate prior evidence')
    prior_immutable=_immutable_capture(transport,set(prior_by_id))
    try:
        origin21_setup.prepare(transport=transport,expected_evidence=expected,renew=True,selected=selected)
        _,pending=origin21_renewal.artifacts(selected.bound)
        if pending is not None: raise ValueError('policy renewal outcome pending')
        renewed=origin21_renewal.history(selected.bound,transport.sensitive)
        current=products.require_current_policy(transport.admin,transport.sensitive,selected=selected)
        if renewed is None or renewed.count!=revision+1 or renewed.head_policy.get('revision')!=revision+1 or current!=revision+1 or renewed.initial!=history.initial or renewed.head==history.head: raise ValueError('policy renewal head mismatch')
        tenant=provision.sql_quote(provision.IDS[0]); collector=provision.sql_quote(selected.profile.collector)
        prior_head=transport.sensitive(f"SELECT EXISTS (SELECT 1 FROM contour.policy_revisions WHERE tenant_id={tenant} AND collector_id={collector} AND revision={revision} AND signed_envelope=decode('{history.head.hex()}','hex'))::text;")
        if prior_head!='true': raise ValueError('prior signed policy changed')
        before=origin21_ready.snapshot(transport.admin,selected=selected)
        before_ids={row[0] for row in before}
        if len(before_ids)!=len(before): raise ValueError('duplicate adoption baseline')
        # This is the existing post-case readiness check, not an extra or reused check.
        origin21_ready.check(expected,selected=selected,transport=transport,**({'_diagnostics':diagnostics} if diagnostics is not None else {}))
        after=origin21_ready.snapshot(transport.admin,selected=selected)
        after_by_id={row[0]:row for row in after}
        if len(after_by_id)!=len(after) or any(after_by_id.get(key)!=value for key,value in prior_by_id.items()) or _immutable_capture(transport,set(prior_by_id))!=prior_immutable: raise ValueError('prior capture evidence changed')
        fresh=[row for row in after if row[0] not in before_ids]
        leaves=[item['leaf_sha256'] for item in original]
        if len(set(leaves))!=2 or any(row[9] not in leaves for row in fresh): raise ValueError('adoption evidence scope')
        for index,leaf in enumerate(leaves,1):
            rows=[row for row in after if row[9]==leaf]
            if not origin21_ready.validate_fresh(rows,before_ids,index,leaf,expected[index-1],current,selected=selected): raise ValueError('policy adoption missing')
        if products.require_current_policy(transport.admin,transport.sensitive,selected=selected)!=current or transport.sensitive(f"SELECT EXISTS (SELECT 1 FROM contour.policy_revisions WHERE tenant_id={tenant} AND collector_id={collector} AND revision={revision} AND signed_envelope=decode('{history.head.hex()}','hex'))::text;")!='true': raise ValueError('policy changed after adoption')
        proof.verify(); transport.verify()
    except BaseException:
        # Unknown CAS or observation outcomes retain all qualification-owned state.
        if not any(item[0] is proof for item in _RETAINED): _RETAINED.append((proof,None))
        raise


def qualify_positive_streams(transport,proof):
    """Prove both held directions and real catalog observations on one graph.

    This component does not claim the full qualification: wrong-SAN and
    genuine unknown-exec disposal must also pass in the owning driver.
    """
    from deploy.local import origin21_managed_qualification
    if type(transport) is not origin21_transport.ManagedTransport or type(proof) is not origin21_managed_qualification.OwnedManagedQualification: raise ValueError('owned qualification required')
    proof.verify(); source=_source_guard(); helper=_helper(); transport.verify(); destination=_destination()
    original=_products(proof); expected=_commitments()
    diagnostics=(origin21_ready._QualificationDiagnostics(proof,lambda line:print(line,file=sys.stderr,flush=True))
                 if os.environ.get('CONTOUR_MANAGED_READY_DIAGNOSTICS')=='1' else None)
    global _PHASE
    _set_phase('initial-readiness')
    origin21_ready.check(expected,selected=profiles.MANAGED,transport=transport,**({'_diagnostics':diagnostics} if diagnostics is not None else {}))
    transitions=[]
    for case,(mode,index,transition) in enumerate((('request',1,'renew'),('response',2,'rollback'),('response',1,'renew'),('request',2,'rollback')),1):
        _set_phase('stream-capture-baseline')
        before={row[0] for row in origin21_ready.snapshot(transport.admin,selected=profiles.MANAGED)}
        revision=products.require_current_policy(transport.admin,transport.sensitive,selected=profiles.MANAGED)
        transitions.append(_stream(mode,index,transition,destination,original[index-1],helper,proof))
        _set_phase('stream-capture-wait')
        _wait_capture(transport,before,original[index-1],expected[index-1],revision,index)
        if _products(proof)!=original: raise ValueError('qualification product generation changed')
        _set_phase('stream-readiness')
        if case==2: _policy_cycle(transport,proof,expected,original,diagnostics)
        else: origin21_ready.check(expected,selected=profiles.MANAGED,transport=transport,**({'_diagnostics':diagnostics} if diagnostics is not None else {}))
        if _source_guard()!=source: raise ValueError('qualification source changed')
    for first,second in ((transitions[0],transitions[1]),(transitions[2],transitions[3])):
        if first[0]!=second[1] or first[1]!=second[0]: raise ValueError('qualification rollback fingerprint mismatch')
    return {'held_request':True,'held_response':True,'catalog_both_products':True}


def _wait_publication_intent(proof,*,setup_timeout=120,cancel=None):
    """Await same-process readiness after intent fsync and pre-exec checks."""
    deadline=time.monotonic()+setup_timeout
    while True:
        if cancel is not None and cancel.is_set(): raise RuntimeError('publication setup ended')
        if time.monotonic()>=deadline: raise TimeoutError('publication setup deadline')
        ready=proof.publication_exec_ready()
        if time.monotonic()>=deadline: raise TimeoutError('publication setup deadline')
        if ready is not None: return ready
        time.sleep(.01)


def qualify_lost_publication_ack(proof):
    """Prove remote commit followed by an unknown CLI outcome, never reconcile it."""
    import hashlib
    import threading
    from deploy.gateway.managed_edge import _regular
    from deploy.local.origin21_managed_qualification import OwnedManagedQualification
    if type(proof) is not OwnedManagedQualification: raise ValueError('owned qualification required')
    proof.verify(); source=_source_guard(); observed=[]; observer_errors=[]
    with _OwnerGuard(controller.open_edge(qualification=proof)) as owner:
        owner._managed_gate(owner._load())
        proof.bind_topology(owner.peer,owner.publisher)
        publisher=owner.publisher; publisher.verify(); publisher_identity=publisher.identity()
        cancel=threading.Event()
        def observe():
            try:
                path=owner.state/'publication.exec.intent'
                ready=_wait_publication_intent(proof,cancel=cancel)
                deadline=ready['started']+2
                if time.monotonic()>=deadline: raise TimeoutError('publication observation deadline')
                while time.monotonic()<deadline:
                    if path.exists():
                        raw=_regular(path,32768); item=json.loads(raw)
                        if json.dumps(item,sort_keys=True,separators=(',',':')).encode('ascii')!=raw or type(item) is not dict or set(item)!={'publisher','document_sha256','nonce'} or item!=ready['intent'] or item['publisher']!=publisher_identity or not re.fullmatch('[0-9a-f]{32}',item['nonce']) or not re.fullmatch('[0-9a-f]{64}',item['document_sha256']): raise ValueError('publication intent changed')
                        marker=owner.watched/('.qualification-commit-'+item['nonce'])
                        if marker.exists():
                            if _regular(marker,128)!=(item['document_sha256']+'\n').encode('ascii'): raise ValueError('publication marker changed')
                            publisher.verify()
                            inspected=products._objects(['docker','inspect',publisher.cid]); exec_ids=inspected.get('ExecIDs')
                            if type(exec_ids) is not list or len(exec_ids)!=1 or not re.fullmatch('[0-9a-f]{64}',exec_ids[0]): raise ValueError('publication exec identity unavailable')
                            running=products._objects(['docker','inspect','--type','exec',exec_ids[0]])
                            process=running.get('ProcessConfig') or {}
                            args=['-i','NODE_OPTIONS=','NODE_PATH=','/usr/local/bin/node','-e',proof.publisher_source().decode('utf-8'),'fixture-publisher',item['document_sha256'],item['nonce']]
                            if running.get('ContainerID')!=publisher.cid or running.get('Running') is not True or process.get('entrypoint')!='/usr/bin/env' or process.get('arguments')!=args: raise ValueError('publication exec identity changed')
                            if _regular(path,32768)!=raw or _source_guard()!=source: raise ValueError('publication identity changed')
                            if time.monotonic()>=deadline: raise TimeoutError('publication observation deadline')
                            observed.append((item['nonce'],item['document_sha256']))
                            return
                    time.sleep(.01)
                raise TimeoutError('publication marker deadline')
            except BaseException as error: observer_errors.append(error)
        proof.arm_ack_loss(); watcher_context=contextvars.copy_context(); watcher=threading.Thread(target=lambda:watcher_context.run(observe),daemon=False)
        retained=(owner,watcher); _RETAINED.append(retained); started=False
        failures=[]
        try:
            watcher.start(); started=True
            try: owner.renew()
            except TimeoutError: pass
            else: raise AssertionError('unknown publication unexpectedly acknowledged')
        except BaseException as error: failures.append(error)
        try:
            if proof.publication_exec_ready() is None: cancel.set()
        except BaseException as error: failures.append(error)
        terminated=False
        if started:
            try:
                watcher.join(45)
                terminated=not watcher.is_alive()
            except BaseException as error: failures.append(error)
        if terminated:
            _RETAINED.remove(retained); failures.extend(observer_errors)
        else: failures.append(RuntimeError('publication observer remains'))
        if len(observed)!=1 and not observer_errors: failures.append(RuntimeError('remote publication commit unproven'))
        if len(failures)==1: raise failures[0]
        if failures: raise BaseExceptionGroup('publication and observer failures',failures)
        from deploy.local import capture_renew
        journal_raw=_regular(owner.state/'journal.json',4096); journal=capture_renew.exact_json(journal_raw)
        if not (owner.state/'publication.exec.intent').is_file() or type(journal) is not dict or journal.get('identity')!=owner.identity or journal.get('pending') is None: raise ValueError('unknown publication not retained')
        state=products._objects(['docker','inspect',publisher.cid]).get('State') or {}
        if state.get('Running') is not False or state.get('Pid')!=0 or state.get('Restarting') is not False or state.get('StartedAt')!=publisher.started: raise ValueError('publisher stop unproven')
        if _source_guard()!=source: raise ValueError('qualification source changed')
        from deploy.local import origin21_managed_cleanup
        origin21_managed_cleanup.dispose_after_lost_ack(proof,owner)
    return {'remote_commit_before_lost_ack':True,'publisher_stopped':True,'publication_intent_retained':True,'owned_topology_removed':True}


def _pause_and_reconcile(owner,proof=None):
    envoy=owner.peer.envoy_cid; paused=False; pause_error=None
    before=owner._load()
    owner._managed_gate(before)
    original_obj=products._objects(['docker','inspect',envoy])
    fixed_keys=('Id','Image','Config','HostConfig','Mounts')
    if (type(original_obj) is not dict or original_obj.get('Id')!=envoy or original_obj.get('Image')!=owner.peer.envoy_image_id
        or type(original_obj.get('Config')) is not dict or type(original_obj.get('HostConfig')) is not dict or type(original_obj.get('Mounts')) is not list
        or (original_obj.get('State') or {}).get('StartedAt')!=before['binding']['envoy_started']): raise ValueError('Envoy identity unavailable')
    fixed={key:original_obj[key] for key in fixed_keys}
    previous=proof.publication_ack() if proof is not None else None
    original_confirm=owner._confirm
    def confirm(*args,**kwargs):
        nonlocal paused,pause_error
        if paused: raise RuntimeError('duplicate confirmation')
        paused=True
        try:
            if products._command(['docker','pause',envoy],15)!=envoy.encode(): raise RuntimeError('Envoy pause uncertain')
            obj=products._objects(['docker','inspect',envoy]); state=obj.get('State') or {}
            if state.get('Running') is not True or state.get('Paused') is not True or state.get('StartedAt')!=before['binding']['envoy_started']: raise ValueError('paused Envoy generation changed')
        except BaseException as error:
            pause_error=error
            raise
        return original_confirm(*args,**kwargs)
    owner._confirm=confirm
    try:
        try: owner.renew()
        except (ValueError,RuntimeError,OSError,TimeoutError): pass
        else: raise AssertionError('unconfirmed publication accepted')
        if pause_error is not None: raise pause_error
        pending=owner._load()['pending']
        if type(pending) is not dict or pending.get('phase')!='staged': raise ValueError('staged publication missing')
        if not paused or proof is None: raise ValueError('qualification publication proof required')
        receipt=proof.publication_ack(); expected=hashlib.sha256(owner._document(pending['candidate'],pending['commitment'])).hexdigest()
        if (type(receipt) is not dict or set(receipt)!={'sequence','publisher','document_sha256','nonce'} or type(receipt['sequence']) is not int or receipt['sequence']!=(1 if previous is None else previous['sequence']+1) or receipt['publisher']!=owner.publisher.identity() or receipt['document_sha256']!=expected or not re.fullmatch('[0-9a-f]{32}',receipt['nonce'])): raise ValueError('publication ACK missing')
        obj=products._objects(['docker','inspect',envoy]); state=obj.get('State') or {}
        if state.get('Running') is not True or state.get('Paused') is not True or state.get('StartedAt')!=before['binding']['envoy_started']: raise ValueError('paused Envoy generation changed')
    finally:
        owner._confirm=original_confirm
        primary=sys.exc_info()[1]
        try:
            if paused:
                current=products._objects(['docker','inspect',envoy])
                state=current.get('State') if type(current) is dict else None
                if (type(current) is not dict or any(current.get(key)!=value for key,value in fixed.items())
                    or type(state) is not dict or state.get('StartedAt')!=before['binding']['envoy_started']
                    or state.get('Running') is not True or type(state.get('Paused')) is not bool):
                    raise RuntimeError('Envoy cleanup identity uncertain')
                if state['Paused'] and products._command(['docker','unpause',envoy],15)!=envoy.encode(): raise RuntimeError('Envoy unpause uncertain')
        except BaseException as cleanup:
            if primary is not None: raise BaseExceptionGroup('qualification and unpause failures',[primary,cleanup]) from None
            raise
    owner._managed_gate(before)
    for operation in (owner.renew,owner.rollback):
        try: operation()
        except RuntimeError: pass
        else: raise AssertionError('pending publication did not block')
    owner.reconcile()


def qualify_wrong_name_and_pending(proof):
    """Exercise a wrong-SAN candidate and a known publisher ACK without confirmation."""
    import tempfile
    import uuid
    from deploy.gateway import certificates
    from deploy.local.origin21_managed_qualification import OwnedManagedQualification
    if type(proof) is not OwnedManagedQualification: raise ValueError('owned qualification required')
    proof.verify(); source=_source_guard()
    with controller.open_edge(qualification=proof) as owner:
        owner._managed_gate(owner._load()); before=owner._load()
        with tempfile.TemporaryDirectory(prefix='wrong-name-',dir=proof.folder) as directory:
            folder=Path(directory); key=folder/'key'; csr=folder/'csr'; cert=folder/'cert'; ext=folder/'ext'
            ext.write_text('basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\nsubjectAltName=DNS:wrong.invalid\nextendedKeyUsage=serverAuth\n')
            certificates._run('req','-newkey','rsa:2048','-nodes','-keyout',key,'-out',csr,'-subj','/CN=wrong.invalid')
            certificates._run('x509','-req','-in',csr,'-CA',owner.ca,'-CAkey',owner.certs.ca_key,'-set_serial',str(int.from_bytes(os.urandom(20),'big')),'-out',cert,'-days','1','-extfile',ext)
            certificates._run('verify','-x509_strict','-purpose','sslserver','-verify_hostname','wrong.invalid','-CAfile',owner.ca,cert)
            if certificates._run('x509','-in',cert,'-pubkey','-noout')!=certificates._run('pkey','-in',key,'-pubout'): raise ValueError('wrong-name fixture key mismatch')
            version='v-'+uuid.uuid4().hex; target=owner.published/version; target.mkdir(mode=0o700)
            try:
                for src,name in ((cert,'cert.pem'),(key,'key.pem')):
                    fd=os.open(target/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    with os.fdopen(fd,'wb') as out: out.write(src.read_bytes()); out.flush(); os.fsync(out.fileno())
                try: owner.certs.validate_native_edge(version)
                except ValueError: pass
                else: raise AssertionError('wrong SAN accepted')
                if owner._load()!=before: raise ValueError('wrong SAN changed journal')
            finally:
                for name in ('cert.pem','key.pem'):
                    path=target/name
                    if path.exists(): path.unlink()
                target.rmdir()
        _pause_and_reconcile(owner,proof)
        if owner._load()['pending'] is not None or _source_guard()!=source: raise ValueError('pending publication not reconciled')
    return {'wrong_san_rejected':True,'pending_confirmation_reconciled':True}


def main(argv):
    """Run using an exact clean worktree and its already verified build receipt."""
    from deploy.local import origin21_managed_qualification as qualification,origin21_managed_init as init,origin21_managed_cli as cli,origin21_managed_qualification_cleanup as disposal
    global _PHASE
    if len(argv)<4: raise ValueError('build evidence required')
    flags=argv[4:]
    if len(flags)!=len(set(flags)) or any(flag not in ('--fresh-metadata','--profile-readiness','--fresh-source') for flag in flags): raise ValueError('invalid qualification flags')
    fresh_metadata='--fresh-metadata' in flags; profile_readiness='--profile-readiness' in flags; fresh_source='--fresh-source' in flags
    image,head,receipt,digest=argv[:4]
    _set_phase('source-check')
    source=_source_guard()
    _set_phase('qualification-begin')
    proof=qualification.begin(image_id=image,head=head,build_receipt=receipt,build_receipt_sha256=digest)
    try:
        with contextlib.ExitStack() as stack:
            if fresh_source: stack.enter_context(qualification_git.qualification_scope(proof))
            if fresh_metadata: stack.enter_context(docker_metadata.qualification_scope(proof))
            _set_phase('initialize')
            path,runtime_digest=init.initialize(image_id=image,head=head,build_receipt=receipt,build_receipt_sha256=digest,qualification=proof)
            _set_phase('topology-up')
            cli.main(['up',image,head,str(path),runtime_digest],qualification=proof)
            _set_phase('transport')
            transport=origin21_transport.managed_transport(image_id=image,head=head,receipt=str(path),digest=runtime_digest,qualification=proof)
            if profile_readiness:
                from deploy.local import origin21_readiness_profile,origin21_managed_cleanup
                _set_phase('initial-readiness')
                with origin21_readiness_profile.Profile(proof) as profile:
                    readiness=origin21_ready.check(_commitments(),selected=profiles.MANAGED,transport=transport)
                if readiness!={'product_tls_and_catalog_verified':True,'ui_verified':False}: raise ValueError('readiness diagnostic result')
                for line in profile.lines(): print(line,flush=True)
                _set_phase('volume-disposal')
                origin21_managed_cleanup.teardown(qualification=proof)
                disposal.dispose_synthetic_volume(proof)
                if _source_guard()!=source: raise ValueError('qualification source changed')
                return {'scope':'single-full-readiness-diagnostic','component':True}
            _set_phase('positive-streams')
            positive=qualify_positive_streams(transport,proof)
            _set_phase('negative-cases')
            negative=qualify_wrong_name_and_pending(proof)
            _set_phase('lost-ack')
            unknown=qualify_lost_publication_ack(proof)
            _set_phase('volume-disposal')
            disposal.dispose_synthetic_volume(proof)
            if _source_guard()!=source: raise ValueError('qualification source changed')
            return {'positive':positive,'negative':negative,'unknown':unknown,'cleanup':True}
    finally:
        primary=sys.exc_info()[1]
        if _RETAINED: _RETAINED.append((proof,None))
        else:
            try: proof.close()
            except BaseException as error:
                if primary is not None: raise BaseExceptionGroup('qualification and proof close failures',[primary,error]) from None
                raise


if __name__=='__main__':
    try:
        result=main(sys.argv[1:])
        if result.get('scope')=='single-full-readiness-diagnostic': print('managed-component scope=single-full-readiness-diagnostic result=pass')
        else: print('managed Origin qualification passed')
    except BaseException as error:
        for line in failure_lines(error,_PHASE): print(line,file=sys.stderr,flush=True)
        print('managed Origin qualification failed; owned state retained',file=sys.stderr)
        raise SystemExit(1) from None
