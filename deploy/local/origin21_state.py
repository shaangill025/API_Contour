"""Isolated v21 setup journal foundation; no production operation is wired.

All phases remain blocked by the absent reference comparator. A future caller
must supply closed, trusted operations with strict independent inspection; the
journal is not database authority or a readiness attestation.
"""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from deploy.local import capture_renew, origin21_profile, origin21_schema

ABSENT, EXACT, DRIFT = 'ABSENT', 'EXACT', 'DRIFT'
PHASES = ('credentials', 'groups', 'migration_15', 'migration_16', 'migration_17',
          'migration_18', 'migration_19', 'migration_20', 'migration_21',
          'logins', 'observer', 'operator_evidence',
          'origin_1_target', 'origin_1_lifecycle', 'origin_1_credential', 'origin_1_grant',
          'origin_2_target', 'origin_2_lifecycle', 'origin_2_credential', 'origin_2_grant',
          'runtime_configs')
SOURCE_FILES = ('deploy/local/docker_metadata.py','deploy/local/origin21_profile.py', 'deploy/local/origin21_schema.py',
                'deploy/local/origin21_state.py', 'deploy/local/origin21_runtime.py', 'deploy/local/origin21_setup.py', 'deploy/local/origin21_configs.py', 'deploy/local/origin21_transport.py',
                'deploy/local/origin21_provision.py', 'deploy/local/origin21_sql_runner.py', 'deploy/local/origin21_products.py', 'deploy/local/origin21_cli.py', 'deploy/local/origin21_ready.py', 'deploy/local/origin21-compose.yaml', 'deploy/local/origin21-postgres-init.yaml', 'deploy/local/up.py',
                'deploy/pilot/settings.js', 'deploy/pilot/flows.json', 'deploy/pilot/destination.js', 'deploy/pilot/probe.js', 'deploy/pilot/check_tls.js',
                'deploy/local/origin21_credentials.py', 'deploy/local/origin21_logins.py', 'deploy/local/origin21_evidence.py',
                'deploy/local/origin21_enrollment.py', 'deploy/local/origin21_renewal.py',
                'deploy/local/origin21_lease.py',
                'deploy/pilot/origin_enrollment.py', 'deploy/pilot/origin_renewal.py',
                'deploy/pilot/origin_credentials.py', 'deploy/pilot/origin_setup_state.py',
                'deploy/local/capture_renew.py', 'deploy/local/capture_provision.py',
                'deploy/local/capture_profiles.py', 'deploy/gateway/config.py',
                'deploy/local/provision.py', 'deploy/pilot/native_envoy.py',
                'deploy/pilot/native_gateway_config.py',
                *(f'deploy/local/origin21_reference_{v}_pre.json' for v in range(14,22)),
                'deploy/local/origin21_reference_14_groups.json',
                'deploy/local/origin21_reference_21_enrolled.json',
                'db/provision_v2_ingress.sql', 'db/provision_origin_ingress.sql',
                'db/opt-in-migrations/0015_origin_lifecycle.sql',
                'db/opt-in-migrations/0016_v2_unattributed.sql',
                'db/opt-in-migrations/0017_origin_proofs.sql',
                'db/opt-in-migrations/0018_causal_runtime_registry.sql',
                'db/opt-in-migrations/0019_causal_sessions.sql',
                'db/opt-in-migrations/0020_causal_inbox.sql',
                'db/opt-in-migrations/0021_origin_admission.sql')
MANAGED_SOURCE_FILES = SOURCE_FILES + ('deploy/local/origin21_readiness_profile.py','tests/fixtures/docker-metadata/test_metadata.py','deploy/gateway/managed_edge.py','deploy/gateway/certificates.py',
    'deploy/pilot/native_edge_probe.js','deploy/pilot/managed_edge_controller.py',
    'deploy/pilot/flows-wrong-name.json','deploy/pilot/flows-wrong-ca.json',
    'deploy/local/origin21-managed-compose.yaml','deploy/local/origin21_managed_controller.py',
    'deploy/local/origin21_managed_cli.py','deploy/local/origin21_managed_init.py',
    'deploy/local/origin21_managed_bootstrap.py','deploy/local/origin21_managed_cleanup.py',
    'deploy/local/origin21_managed_qualification.py','deploy/local/origin21_managed_qualification_cleanup.py',
    'scripts/test-managed-origin-qualification.py','scripts/qualify-managed-origin.py',
    'scripts/qualify-origin21-onboarding.py','scripts/test-managed-native-edge.py',
    'tests/fixtures/managed-origin/test_controller.py','tests/fixtures/managed-origin/test_cli.py',
    'tests/fixtures/managed-origin/test_initializer.py','tests/fixtures/managed-origin/test_bootstrap.py',
    'tests/fixtures/managed-origin/test_cleanup.py','tests/fixtures/managed-origin/test_qualification_cleanup.py',
    'tests/fixtures/managed-origin-qualification/client.js','tests/fixtures/managed-origin-qualification/control.js',
    'tests/fixtures/managed-origin-qualification/destination.js','tests/fixtures/managed-origin-qualification/publisher.js',
    'tests/fixtures/managed-origin-qualification/test_driver.py','tests/fixtures/managed-origin-qualification/test_fixture.py',
    'tests/fixtures/managed-origin-qualification/test_proof.py','tests/fixtures/managed-origin-qualification/test_wrapper.py',
    'tests/fixtures/managed-origin-qualification/test_readiness_profile.py')
HUMAN_SOURCE_FILES = MANAGED_SOURCE_FILES + (
    'deploy/local/origin21-managed-human-compose.yaml',
    'deploy/local/check_oidc.py',
    'deploy/local/origin21_managed_human_preflight.py',
    'deploy/local/origin21_managed_human_secret.py',
    'deploy/local/origin21_managed_human_identity.py',
    'deploy/local/origin21_managed_human_business.py',
    'deploy/local/origin21_managed_human_topology.py',
    'deploy/local/origin21_managed_human_services.py',
    'deploy/local/origin21_managed_human_cli.py',
    'deploy/local/origin21_managed_human_cleanup.py',
    'tests/fixtures/managed-human/test_profile.py',
    'tests/fixtures/managed-human/test_preflight.py',
    'tests/fixtures/managed-human/test_app_secret.py',
    'tests/fixtures/managed-human/test_source.py',
    'tests/fixtures/managed-human/test_initializer.py',
    'tests/fixtures/managed-human/test_oidc_profile.py',
    'tests/fixtures/managed-human/test_realm.py',
    'tests/fixtures/managed-human/test_business.py',
    'tests/fixtures/managed-human/test_model.py',
    'tests/fixtures/managed-human/test_membership.py',
    'tests/fixtures/managed-human/test_sql_role.py',
    'tests/fixtures/managed-human/test_topology.py',
    'tests/fixtures/managed-human/test_services.py',
    'tests/fixtures/managed-human/test_cli.py',
    'tests/fixtures/managed-human/test_cleanup.py',
    'tests/fixtures/managed-human/test_transport_gate.py',
    'tests/fixtures/managed-human/legacy-membership.json',
)
MAX_JOURNAL = 4096
_ACTIVE_SETUP_LOCKS = {}


def _encode(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def _identity(profile):
    value=profile._asdict()
    value['state']=str(profile.state)
    value['capture']=str(profile.capture)
    value['origins']=[dict(slot._asdict(),leaf_der=str(slot.leaf_der)) for slot in profile.origins]
    return hashlib.sha256(_encode(value)).hexdigest()


def _source_files(context):
    if context is origin21_profile.STATIC: return SOURCE_FILES
    if context is origin21_profile.MANAGED: return MANAGED_SOURCE_FILES
    if context is origin21_profile.HUMAN: return HUMAN_SOURCE_FILES
    raise ValueError('unsupported origin21 context')


def _source_snapshot(context=origin21_profile.STATIC):
    files=_source_files(context)
    if context is origin21_profile.STATIC: return {name:(origin21_profile.ROOT/name).read_bytes() for name in files}
    result={}
    for name in files:
        path=origin21_profile.ROOT/name
        if not path.is_file() or any(part.is_symlink() for part in (path,*list(path.parents)[:len(Path(name).parts)-1])): raise ValueError('managed source unavailable')
        result[name]=path.read_bytes()
    return result


def _source_identity(snapshot=None, context=origin21_profile.STATIC):
    files=_source_files(context)
    snapshot=_source_snapshot(context) if snapshot is None else snapshot
    if set(snapshot)!=set(files): raise ValueError('source closure mismatch')
    digest=hashlib.sha256()
    for name in files:
        digest.update(name.encode()+b'\0'+hashlib.sha256(snapshot[name]).digest())
    return digest.hexdigest()


def _read(path, identity, source):
    if stat.S_IMODE(os.lstat(path).st_mode)!=0o600: raise ValueError('unsafe journal mode')
    raw=capture_renew.read_file(path,MAX_JOURNAL)
    value=capture_renew.exact_json(raw)
    if not isinstance(value,dict) or set(value)!={'version','descriptor','source','completed','pending','credential_digest','evidence_digest'} or _encode(value)!=raw:
        raise ValueError('invalid journal')
    n=value['completed']
    if type(value['version']) is not int or value['version']!=1 or value['descriptor']!=identity or value['source']!=source or type(n) is not int or not 0<=n<=len(PHASES):
        raise ValueError('journal identity or order mismatch')
    credential=value['credential_digest']
    if n > PHASES.index('credentials'):
        if not isinstance(credential,str) or len(credential)!=64 or any(c not in '0123456789abcdef' for c in credential): raise ValueError('credential commitment mismatch')
    elif credential is not None: raise ValueError('unexpected credential commitment')
    evidence=value['evidence_digest']
    if n > PHASES.index('operator_evidence'):
        if not isinstance(evidence,str) or len(evidence)!=64 or any(c not in '0123456789abcdef' for c in evidence): raise ValueError('evidence commitment mismatch')
    elif evidence is not None: raise ValueError('unexpected evidence commitment')
    if value['pending'] is not None and (n==len(PHASES) or value['pending']!=PHASES[n]): raise ValueError('journal pending mismatch')
    return value


def _initial(path, state):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:
        out.write(_encode(state)); out.flush(); os.fsync(out.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def _status(operation):
    result=operation.inspect()
    if type(result) is not str or result not in (ABSENT,EXACT,DRIFT): raise ValueError('invalid phase state')
    return result


def run(profile, operations, *, snapshot=None, set_context=None, after_complete=None, require_complete=False, identities_only=False, completed_check_only=False):
    """Reconcile only a complete fixed phase set after an approved reference.

    Partial initial writes and drift fail closed; an unplanned exact state is
    never adopted. A completed phase is rechecked before any new mutation.
    """
    selected=origin21_profile.context_for_profile(profile)
    origin21_profile.require_context(selected)
    if type(completed_check_only) is not bool or (completed_check_only and (not require_complete or identities_only)) or type(identities_only) is not bool or type(require_complete) is not bool or (identities_only and require_complete): raise ValueError('invalid setup mode')
    phases=PHASES[:1] if identities_only else PHASES
    if type(operations) is not dict or set(operations)!=set(phases): raise ValueError('invalid operations')
    for stage in range(14,22): origin21_schema.require_reference(stage,'pre')
    origin21_schema.require_reference(14,'groups')
    origin21_schema.require_reference(21,'enrolled')
    capture_renew.safe_dir(profile.state.parent)
    if identities_only:
        try:
            os.mkdir(profile.state,0o700)
        except FileExistsError: pass
        else:
            parent=os.open(profile.state.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try: os.fsync(parent)
            finally: os.close(parent)
    capture_renew.safe_dir(profile.state)
    if stat.S_IMODE(os.lstat(profile.state).st_mode)!=0o700: raise ValueError('unsafe state directory')
    lock=profile.state/'setup.lock'
    fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    capability=None
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1: raise ValueError('unsafe lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        capability=object(); _ACTIVE_SETUP_LOCKS[capability]=(fd,profile,lock)
        source=_source_identity(snapshot,selected)
        if _source_identity(context=selected)!=source: raise ValueError('source snapshot drift')
        return _reconcile(profile.state/'setup.json',_identity(profile),source,operations,set_context=set_context,after_complete=after_complete,require_complete=require_complete,phases=phases,selected=selected,completed_check_only=completed_check_only,_lock_capability=capability)
    finally:
        if capability is not None: _ACTIVE_SETUP_LOCKS.pop(capability,None)
        os.close(fd)


@contextlib.contextmanager
def _completed_evidence_scope(path,identity,source,state,operations,selected,enabled,lock_capability):
    if not enabled:
        yield None
        return
    from deploy.local import origin21_enrollment, origin21_evidence
    lock=_ACTIVE_SETUP_LOCKS.get(lock_capability)
    if lock is None or lock[1] is not selected.profile or lock[2]!=path.parent/'setup.lock': raise ValueError('setup lock unavailable')
    lock_fd=lock[0]
    def lock_current():
        held=os.fstat(lock_fd); current=os.lstat(lock[2])
        return (_ACTIVE_SETUP_LOCKS.get(lock_capability)==lock and
                stat.S_ISREG(held.st_mode) and held.st_uid==os.getuid() and
                stat.S_IMODE(held.st_mode)==0o600 and held.st_nlink==1 and
                stat.S_ISREG(current.st_mode) and (held.st_dev,held.st_ino)==(current.st_dev,current.st_ino))
    if not lock_current(): raise ValueError('setup lock unavailable')
    if state['completed']!=len(PHASES) or state['pending'] is not None: raise ValueError('committed setup required')
    evidence=operations['operator_evidence']
    if type(evidence) is not origin21_evidence.Evidence or evidence.profile is not selected.profile: raise ValueError('invalid evidence scope')
    def fresh():
        if evidence.inspect()!=EXACT: raise ValueError('operator evidence drift')
        return hashlib.sha256(capture_renew.read_file(evidence.path,8192)).hexdigest()
    sealed_journal=_encode(state)
    before=fresh()
    if before!=state['evidence_digest']: raise ValueError('evidence commitment drift')
    expected=tuple(evidence.expected)
    sealed_inspector=evidence.inspect_slot; sealed_path=evidence.path; sealed_slots=tuple(selected.bound.origins)
    if len(expected)!=2 or any(type(x) is not bytes or len(x)!=32 for x in expected): raise ValueError('invalid evidence scope')
    active=[True]
    class CheckedEvidence:
        def inspect(self):
            if not active[0]: raise ValueError('evidence scope closed')
            return EXACT
        def commitment(self):
            if not active[0]: raise ValueError('evidence scope closed')
            return before
    checked=dict(operations); checked['operator_evidence']=CheckedEvidence()
    try:
        for number,slot in enumerate(selected.bound.origins,1):
            for kind in ('lifecycle','credential','grant'):
                name=f'origin_{number}_{kind}'; op=operations[name]
                if type(op) is not origin21_enrollment.Fact or op.profile is not selected.bound or op.slot is not slot or op.kind!=kind or getattr(op.evidence,'__self__',None) is not evidence or getattr(op.evidence,'__func__',None) is not origin21_evidence.Evidence.slot_digest: raise ValueError('invalid evidence fact scope')
                used=[False]
                def digest_for(actual, *, wanted=slot, value=expected[number-1].hex(), once=used):
                    if not active[0] or once[0] or actual is not wanted: raise ValueError('invalid evidence scope use')
                    once[0]=True
                    return value
                checked[name]=origin21_enrollment.Fact(op.profile,op.psql,op.slot,op.kind,digest_for)
        yield checked
    finally:
        active[0]=False
        primary=sys.exc_info()[1]; errors=[]
        for check in (lambda: _encode(state)==sealed_journal and _encode(_read(path,identity,source))==sealed_journal, lambda: _source_identity(context=selected)==source, lambda: evidence.profile is selected.profile and evidence.inspect_slot is sealed_inspector and evidence.path==sealed_path and evidence.expected==expected and all(a is b for a,b in zip(selected.bound.origins,sealed_slots,strict=True)) and _ACTIVE_SETUP_LOCKS.get(lock_capability)==lock, lambda: fresh()==before, lock_current):
            try:
                if not check(): raise ValueError('completed evidence scope drift')
            except BaseException as error: errors.append(error)
        if errors:
            if primary is not None: raise BaseExceptionGroup('evidence scope and final verification failed',[primary,*errors]) from None
            if len(errors)==1: raise errors[0]
            raise BaseExceptionGroup('evidence scope final verification failed',errors)


def _reconcile(path, identity, source, operations, *, set_context=None, after_complete=None, require_complete=False, phases=PHASES, selected=origin21_profile.STATIC, completed_check_only=False, _lock_capability=None):
    origin21_profile.require_context(selected)
    def source_now():
        return _source_identity() if selected is origin21_profile.STATIC else _source_identity(context=selected)
    if os.path.lexists(path): state=_read(path,identity,source)
    else:
        if require_complete: raise ValueError('committed setup required')
        state=dict(version=1,descriptor=identity,source=source,completed=0,pending=None,credential_digest=None,evidence_digest=None)
        _initial(path,state)
    if state['completed']>len(phases) or (state['pending'] is not None and state['pending'] not in phases): raise ValueError('setup prefix cannot inspect later phases')
    if require_complete and (state['completed']!=len(PHASES) or state['pending'] is not None): raise ValueError('committed setup required')
    with _completed_evidence_scope(path,identity,source,state,operations,selected,completed_check_only,_lock_capability) as checked:
        checked_ops=checked if checked is not None else operations
        if set_context is not None:
            if checked is not None: set_context(state,checked_evidence=True)
            else: set_context(state)
        for phase in PHASES[:state['completed']]:
            if _status(checked_ops[phase])!=EXACT: raise ValueError('completed phase drift')
            if phase=='credentials' and checked_ops[phase].commitment()!=state['credential_digest']: raise ValueError('credential commitment drift')
            if phase=='operator_evidence' and checked_ops[phase].commitment()!=state['evidence_digest']: raise ValueError('evidence commitment drift')
    while state['completed']<len(phases):
        phase=phases[state['completed']]; op=operations[phase]
        if state['pending'] is None:
            if _status(op)!=ABSENT: raise ValueError('unplanned setup state')
            state['pending']=phase; capture_renew.replace_durable(path,_encode(state))
        status=_status(op)
        if status==DRIFT: raise ValueError('pending phase drift')
        if status==ABSENT:
            if source_now()!=source: raise ValueError('source changed')
            op.apply()
            if source_now()!=source or _status(op)!=EXACT: raise ValueError('phase postcondition failed')
        if source_now()!=source: raise ValueError('source changed')
        if phase in ('credentials','operator_evidence'):
            commitment=op.commitment()
            if not isinstance(commitment,str) or len(commitment)!=64 or any(c not in '0123456789abcdef' for c in commitment): raise ValueError('credential commitment invalid')
            state['credential_digest' if phase=='credentials' else 'evidence_digest']=commitment
        state['completed']+=1; state['pending']=None
        capture_renew.replace_durable(path,_encode(state))
    if after_complete is not None: return after_complete(lambda: source_now()==source)
