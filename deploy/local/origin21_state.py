"""Isolated v21 setup journal foundation; no production operation is wired.

All phases remain blocked by the absent reference comparator. A future caller
must supply closed, trusted operations with strict independent inspection; the
journal is not database authority or a readiness attestation.
"""
import fcntl
import hashlib
import json
import os
import stat

from deploy.local import capture_renew, origin21_profile, origin21_schema

ABSENT, EXACT, DRIFT = 'ABSENT', 'EXACT', 'DRIFT'
PHASES = ('credentials', 'groups', 'migration_15', 'migration_16', 'migration_17',
          'migration_18', 'migration_19', 'migration_20', 'migration_21',
          'logins', 'observer', 'operator_evidence',
          'origin_1_target', 'origin_1_lifecycle', 'origin_1_credential', 'origin_1_grant',
          'origin_2_target', 'origin_2_lifecycle', 'origin_2_credential', 'origin_2_grant',
          'runtime_configs')
SOURCE_FILES = ('deploy/local/origin21_profile.py', 'deploy/local/origin21_schema.py',
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
MAX_JOURNAL = 4096


def _encode(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def _identity(profile):
    value=profile._asdict()
    value['state']=str(profile.state)
    value['capture']=str(profile.capture)
    value['origins']=[dict(slot._asdict(),leaf_der=str(slot.leaf_der)) for slot in profile.origins]
    return hashlib.sha256(_encode(value)).hexdigest()


def _source_snapshot():
    return {name:(origin21_profile.ROOT/name).read_bytes() for name in SOURCE_FILES}


def _source_identity(snapshot=None):
    snapshot=_source_snapshot() if snapshot is None else snapshot
    digest=hashlib.sha256()
    for name in SOURCE_FILES:
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


def run(profile, operations, *, snapshot=None, set_context=None, after_complete=None, require_complete=False, identities_only=False):
    """Reconcile only a complete fixed phase set after an approved reference.

    Partial initial writes and drift fail closed; an unplanned exact state is
    never adopted. A completed phase is rechecked before any new mutation.
    """
    if profile is not origin21_profile.PROFILE: raise ValueError('unsupported profile')
    if type(identities_only) is not bool or type(require_complete) is not bool or (identities_only and require_complete): raise ValueError('invalid setup mode')
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
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1: raise ValueError('unsafe lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        source=_source_identity(snapshot)
        if _source_identity()!=source: raise ValueError('source snapshot drift')
        return _reconcile(profile.state/'setup.json',_identity(profile),source,operations,set_context=set_context,after_complete=after_complete,require_complete=require_complete,phases=phases)
    finally:
        os.close(fd)


def _reconcile(path, identity, source, operations, *, set_context=None, after_complete=None, require_complete=False, phases=PHASES):
    if os.path.lexists(path): state=_read(path,identity,source)
    else:
        if require_complete: raise ValueError('committed setup required')
        state=dict(version=1,descriptor=identity,source=source,completed=0,pending=None,credential_digest=None,evidence_digest=None)
        _initial(path,state)
    if state['completed']>len(phases) or (state['pending'] is not None and state['pending'] not in phases): raise ValueError('setup prefix cannot inspect later phases')
    if require_complete and (state['completed']!=len(PHASES) or state['pending'] is not None): raise ValueError('committed setup required')
    if set_context is not None: set_context(state)
    for phase in PHASES[:state['completed']]:
        if _status(operations[phase])!=EXACT: raise ValueError('completed phase drift')
        if phase=='credentials' and operations[phase].commitment()!=state['credential_digest']: raise ValueError('credential commitment drift')
        if phase=='operator_evidence' and operations[phase].commitment()!=state['evidence_digest']: raise ValueError('evidence commitment drift')
    while state['completed']<len(phases):
        phase=phases[state['completed']]; op=operations[phase]
        if state['pending'] is None:
            if _status(op)!=ABSENT: raise ValueError('unplanned setup state')
            state['pending']=phase; capture_renew.replace_durable(path,_encode(state))
        status=_status(op)
        if status==DRIFT: raise ValueError('pending phase drift')
        if status==ABSENT:
            if _source_identity()!=source: raise ValueError('source changed')
            op.apply()
            if _source_identity()!=source or _status(op)!=EXACT: raise ValueError('phase postcondition failed')
        if _source_identity()!=source: raise ValueError('source changed')
        if phase in ('credentials','operator_evidence'):
            commitment=op.commitment()
            if not isinstance(commitment,str) or len(commitment)!=64 or any(c not in '0123456789abcdef' for c in commitment): raise ValueError('credential commitment invalid')
            state['credential_digest' if phase=='credentials' else 'evidence_digest']=commitment
        state['completed']+=1; state['pending']=None
        capture_renew.replace_durable(path,_encode(state))
    if after_complete is not None: return after_complete(lambda: _source_identity()==source)
