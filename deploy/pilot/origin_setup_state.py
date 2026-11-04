"""Journal protocol for a future closed local origin setup; no setup is exposed.

Phase operations are supplied by the eventual orchestrator. Inspectors must be
read-only and return only ABSENT, EXACT, or DRIFT for their complete postcondition.
This module alone does not provision or validate a database.
"""
import fcntl
import hashlib
import json
import os
import stat

from deploy.local import capture_profiles, capture_renew

ABSENT, EXACT, DRIFT = 'ABSENT', 'EXACT', 'DRIFT'
PHASES = ('groups', 'migration_15', 'migration_16', 'migration_17', 'credentials', 'logins', 'observer',
          'origin_1_target', 'origin_1_lifecycle', 'origin_1_credential', 'origin_1_grant',
          'origin_2_target', 'origin_2_lifecycle', 'origin_2_credential', 'origin_2_grant', 'runtime_configs')
SCHEMA_PHASES = PHASES[:4]
CREDENTIAL_PHASES = PHASES[:5]
LOGIN_PHASES = PHASES[:6]
ENROLLMENT_PHASES = PHASES[:15]
SOURCE_FILES = ('deploy/pilot/origin_renewal.py', 'deploy/pilot/origin_enrollment.py', 'deploy/pilot/origin_logins.py', 'deploy/pilot/origin_credentials.py', 'deploy/pilot/origin_setup.py', 'deploy/pilot/origin_setup_state.py',
                'deploy/pilot/origin_schema.py', 'deploy/pilot/origin_catalog_capture.py',
                'deploy/pilot/origin_reference_catalog.json',
                'deploy/pilot/origin_reference_catalog_15.json', 'deploy/pilot/origin_reference_catalog_16.json',
                'deploy/local/capture_profiles.py',
                'deploy/local/capture_renew.py', 'deploy/local/provision.py',
                'db/provision_v2_ingress.sql', 'db/provision_origin_ingress.sql',
                'db/opt-in-migrations/0015_origin_lifecycle.sql',
                'db/opt-in-migrations/0016_v2_unattributed.sql',
                'db/opt-in-migrations/0017_origin_proofs.sql')
MAX_JOURNAL = 4096


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _identity(profile):
    capture = profile.capture
    descriptor = {
        'name': capture.name, 'state': str(profile.state), 'capture': str(capture.capture),
        'collector': capture.collector, 'source': capture.source, 'deployment': capture.deployment,
        'instance': capture.instance, 'nonce': capture.nonce,
        'approved_names': capture.approved_names, 'approved_route_segments': capture.approved_route_segments,
        'ingress_login': profile.ingress_login, 'worker_login': profile.worker_login,
        'ingress_group': profile.ingress_group, 'worker_group': profile.worker_group,
        'origins': [dict(deployment=o.deployment, instance=o.instance, lifecycle=o.lifecycle,
                         credential=o.credential, grant=o.grant, leaf_der=str(o.leaf_der)) for o in profile.origins],
    }
    return _digest(json.dumps(descriptor, sort_keys=True, separators=(',', ':')).encode())


def _source_snapshot():
    return {name: (capture_profiles.ROOT / name).read_bytes() for name in SOURCE_FILES}


def _source_identity(snapshot=None):
    snapshot = _source_snapshot() if snapshot is None else snapshot
    digest = hashlib.sha256()
    for name in SOURCE_FILES:
        digest.update(name.encode() + b'\0' + hashlib.sha256(snapshot[name]).digest())
    return digest.hexdigest()


def _encode(state):
    return json.dumps(state, sort_keys=True, separators=(',', ':')).encode()


def _read(path, identity, source):
    info = os.lstat(path)
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError('unsafe setup journal mode')
    raw = capture_renew.read_file(path, MAX_JOURNAL)
    state = capture_renew.exact_json(raw)
    if not isinstance(state, dict) or set(state) != {'version', 'descriptor', 'source', 'completed', 'pending', 'credential_digest'} or _encode(state) != raw:
        raise ValueError('invalid setup journal')
    count = state['completed']
    if type(state['version']) is not int or state['version'] != 1 or state['descriptor'] != identity or state['source'] != source or type(count) is not int or not 0 <= count <= len(PHASES):
        raise ValueError('setup journal identity or order mismatch')
    digest = state['credential_digest']
    if (count >= len(CREDENTIAL_PHASES)) != (isinstance(digest,str) and len(digest)==64 and all(c in '0123456789abcdef' for c in digest)):
        raise ValueError('setup credential commitment mismatch')
    if count < len(CREDENTIAL_PHASES) and digest is not None: raise ValueError('unexpected credential commitment')
    if state['pending'] is not None and (count == len(PHASES) or state['pending'] != PHASES[count]):
        raise ValueError('setup journal phase mismatch')
    return state


def _status(operation):
    result = operation.inspect()
    if result not in (ABSENT, EXACT, DRIFT) or type(result) is not str:
        raise ValueError('unknown setup postcondition')
    return result


def _initial(path, state):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(_encode(state)); output.flush(); os.fsync(output.fileno())
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(directory)
        finally: os.close(directory)
    except BaseException:
        # A partial initial journal remains an explicit refusal on restart.
        raise


def run(profile, operations, *, after_pending=None, bind_sources=None, through_credentials=False, through_logins=False, through_enrollment=False, set_context=None, after_complete=None, require_enrolled=False):
    """Reconcile fixed ordered phases; operation failures retain the journal.

    A phase with no pending intent must be absent; an existing exact state is
    not adopted. Completed phases are rechecked before any later mutation.
    """
    if profile is not capture_profiles.ORIGIN_PILOT:
        raise ValueError('unsupported origin profile')
    if type(through_credentials) is not bool or type(through_logins) is not bool or type(through_enrollment) is not bool or (through_logins and not through_credentials) or (through_enrollment and not through_logins): raise ValueError('invalid setup prefix')
    phases = ENROLLMENT_PHASES if through_enrollment else LOGIN_PHASES if through_logins else CREDENTIAL_PHASES if through_credentials else SCHEMA_PHASES
    if type(operations) is not dict or set(operations) != set(phases):
        raise ValueError('invalid setup operations')
    capture_renew.safe_dir(profile.state.parent)
    capture_renew.safe_dir(profile.state)
    if stat.S_IMODE(os.lstat(profile.state).st_mode) != 0o700:
        raise ValueError('unsafe setup directory mode')
    lock_path = profile.state / 'setup.lock'
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise ValueError('unsafe setup lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = profile.state / 'setup.json'
        snapshot = _source_snapshot()
        identity, source = _identity(profile), _source_identity(snapshot)
        if bind_sources is not None: bind_sources(snapshot)
        if os.path.lexists(path):
            state = _read(path, identity, source)
        else:
            if require_enrolled: raise ValueError('committed origin setup required')
            state = dict(version=1, descriptor=identity, source=source, completed=0, pending=None, credential_digest=None)
            _initial(path, state)
        if require_enrolled and (state['completed'] != len(ENROLLMENT_PHASES) or state['pending'] is not None):
            raise ValueError('committed origin setup required')
        if state['completed'] > len(phases):
            raise ValueError('setup prefix cannot inspect later phases')
        if set_context is not None: set_context(state)
        for phase in PHASES[:state['completed']]:
            if _status(operations[phase]) != EXACT:
                raise ValueError('completed setup phase drift')
            if phase == 'credentials' and operations[phase].commitment() != state['credential_digest']:
                raise ValueError('credential commitment drift')
        while state['completed'] < len(phases):
            phase = PHASES[state['completed']]
            operation = operations[phase]
            if state['pending'] is None:
                if _status(operation) != ABSENT:
                    raise ValueError('unplanned setup state')
                state['pending'] = phase
                capture_renew.replace_durable(path, _encode(state))
                if after_pending is not None: after_pending(phase)
            status = _status(operation)
            if status == DRIFT:
                raise ValueError('pending setup phase drift')
            if status == ABSENT:
                if _source_identity() != source: raise ValueError('setup sources changed')
                operation.apply()
                if _source_identity() != source: raise ValueError('setup sources changed after operation')
                if _status(operation) != EXACT:
                    raise ValueError('setup postcondition not exact')
            if _source_identity() != source: raise ValueError('setup sources changed before completion')
            if phase == 'credentials': state['credential_digest'] = operation.commitment()
            state['completed'] += 1
            state['pending'] = None
            capture_renew.replace_durable(path, _encode(state))
        if after_complete is not None: return after_complete(lambda: _source_identity()==source)
    finally:
        os.close(fd)
