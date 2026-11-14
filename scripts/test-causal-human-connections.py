#!/usr/bin/env python3
"""Explicit synthetic SQL31 continuation of the supervised SQL29 fixture."""
import os
from pathlib import Path
import runpy
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]


def continuation_sql():
    """Build the fixed suffix for the same psql request as the SQL29 fixture."""
    values = _fixed_driver['scenario_sql']()
    if type(values) is not tuple or len(values) != 3 or any(type(v) is not str or not v for v in values):
        raise ValueError('invalid human causal continuation')
    ledger = "DO $$ BEGIN IF (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,32)) THEN RAISE EXCEPTION 'human causal ledger mismatch'; END IF; END $$;"
    return '\n'.join((values[0], ledger, *values[1:]))


def write_receipt(directory):
    path = Path(directory) / 'causal-human-connections.done'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(b'causal-human-connections-complete\n')
        out.flush()
        os.fsync(out.fileno())


def require_receipt(directory):
    path = Path(directory) / 'causal-human-connections.done'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        expected = b'causal-human-connections-complete\n'
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != len(expected):
            raise ValueError('edge fixture receipt')
        if os.read(fd, 128) != expected or os.read(fd, 1):
            raise ValueError('edge fixture receipt')
    finally:
        os.close(fd)


def main():
    if len(sys.argv) != 1:
        raise ValueError('no arguments')
    sys.argv = [str(ROOT / 'scripts/test-postgres-tls.py'), '--causal-human-connections']
    runpy.run_path(str(ROOT / 'scripts/test-postgres-tls.py'), run_name='__main__')


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        try:
            loader = runpy.run_path(str(ROOT / 'scripts/test-postgres-tls.py'))['checked_receiver_loader']
            for line in loader()['failure_lines'](error):
                print(line, file=sys.stderr)
        except Exception:
            pass
        print('FAIL: causal human synthetic fixture', file=sys.stderr)
        raise SystemExit(1) from None
