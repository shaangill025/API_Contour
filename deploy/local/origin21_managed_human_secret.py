"""Fresh app credential commitment for the closed managed-human initializer."""
import hashlib
import json
import os
import secrets
import stat

from deploy.local import origin21_profile
from deploy.pilot import origin_credentials


def _base():
    return origin21_profile.HUMAN.profile.state.parent


def create_fresh():
    """Durably create the password and its intent; never adopt partial state."""
    origin21_profile.require_context(origin21_profile.HUMAN)
    base = _base()
    info = os.lstat(base)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('unsafe managed human state')
    password_path, intent_path = base/'database-password', base/'app-credential.intent'
    if os.path.lexists(password_path) or os.path.lexists(intent_path):
        raise FileExistsError('managed human app credential exists')
    password = secrets.token_hex(32)
    raw = password.encode('ascii')
    origin_credentials._write(password_path, raw)
    if origin_credentials._file(password_path, 128) != raw:
        raise ValueError('managed human app credential changed')
    intent = {'version': 1, 'sha256': hashlib.sha256(raw).hexdigest()}
    origin_credentials._write(intent_path, json.dumps(intent, sort_keys=True, separators=(',', ':')).encode('ascii'))
    return password


def read_committed():
    """Read only a matching private credential and its canonical commitment."""
    origin21_profile.require_context(origin21_profile.HUMAN)
    base = _base()
    raw = origin_credentials._file(base/'database-password', 128)
    if len(raw) != 64 or any(byte not in b'0123456789abcdef' for byte in raw):
        raise ValueError('invalid managed human app credential')
    expected = json.dumps({'version': 1, 'sha256': hashlib.sha256(raw).hexdigest()},
                          sort_keys=True, separators=(',', ':')).encode('ascii')
    if origin_credentials._file(base/'app-credential.intent', 256) != expected:
        raise ValueError('managed human app credential commitment changed')
    return raw.decode('ascii')
