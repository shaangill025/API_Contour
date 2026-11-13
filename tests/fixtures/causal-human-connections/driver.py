"""Fixed SQL31 continuation for the existing disposable SQL29 fixture.

The supervisor must run the existing SQL29 fixture first, then run each value
returned by scenario_sql() in order in that same psql backend with autocommit and
ON_ERROR_STOP. This module never opens a connection or accepts arbitrary SQL.
Synthetic issuer assertions do not establish TLS or signature possession.
"""
from pathlib import Path
import os
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[3]
FILES = (
    'db/opt-in-migrations/0032_human_causal_reader.sql',
    'db/tests/human_causal_connections.sql',
    'tests/fixtures/causal-human-connections/cases.sql',
)


def _source(name, tracked=False):
    if name not in FILES:
        raise ValueError('unsupported fixture source')
    path = ROOT / name
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('fixture source symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= 2_000_000:
            raise ValueError('fixture source invalid')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(2_000_001)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('fixture source changed')
        if tracked:
            result = subprocess.run(['git', 'show', 'HEAD:' + name], cwd=ROOT, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=True)
            if result.stderr or result.stdout != raw:
                raise ValueError('tracked fixture source changed')
        return raw.decode('utf-8', 'strict')
    finally:
        os.close(fd)


def scenario_sql():
    values = tuple(_source(name, tracked=True) for i, name in enumerate(FILES))
    if any(not migration.rstrip().endswith('COMMIT;') for migration in values[:1]):
        raise ValueError('migration incomplete')
    return values
