#!/usr/bin/env python3
"""Disposable SQL28 fixture; no deployment, peer, TLS or race qualification."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    'seed': 'db/tests/causal_runtime_registry_pre.sql',
    'm26': 'db/opt-in-migrations/0026_causal_evidence_enrollment.sql',
    'm27': 'db/opt-in-migrations/0027_causal_observer_inbox.sql',
    'm28': 'db/opt-in-migrations/0028_causal_receiver_enrollment.sql',
    'fixture': 'db/tests/causal_receiver_enrollment.sql',
}


def require_applicable(raw):
    # Deliberately fail before capture creates an output directory or service.
    # Never remove, rewrite or execute a bypass of the reviewed migration guard.
    if not isinstance(raw, bytes) or len(raw) > 2_000_000:
        raise ValueError('migration unavailable')
    text = raw.decode('utf-8', 'strict')
    if 'receiver enrollment candidate incomplete; do not apply' in text or text.rstrip().endswith('ROLLBACK;'):
        raise ValueError('receiver migration deliberately inactive')
    if not text.rstrip().endswith('COMMIT;'):
        raise ValueError('receiver migration not applicable')


def load_existing():
    path = ROOT / 'scripts/test-causal-evidence-enrollment.py'
    if not path.is_file() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('qualified helper unavailable')
    raw = path.read_bytes()
    saved = subprocess.run(['git', 'show', 'HEAD:scripts/test-causal-evidence-enrollment.py'], cwd=ROOT,
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=15, check=True)
    if saved.stderr or len(raw) > 2_000_000 or saved.stdout != raw:
        raise ValueError('qualified helper changed')
    spec = importlib.util.spec_from_file_location('receiver_evidence_helper', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if path.read_bytes() != raw:
        raise ValueError('qualified helper changed')
    return module


class Hooks:
    def __init__(self, existing, schema):
        self.base = existing.QualificationHooks('schema25', schema)
        self.files = None
        self.complete = False

    def preflight(self, sources):
        self.base.preflight(sources)
        required = ['scripts/test-causal-receiver-enrollment.py',
                    'tests/fixtures/causal-receiver-enrollment/test_driver.py', *FILES.values()]
        if any(name not in sources for name in required):
            raise ValueError('receiver source missing')
        self.files = {}
        for key, name in FILES.items():
            path = ROOT / name
            if not path.is_file() or any(p.is_symlink() for p in (path, *path.parents)):
                raise ValueError('receiver source unavailable')
            raw = path.read_bytes()
            if len(raw) > 2_000_000 or hashlib.sha256(raw).hexdigest() != sources[name]:
                raise ValueError('receiver source changed')
            self.files[key] = raw
        require_applicable(self.files['m28'])

    def after_stage17(self, execute):
        self.base.after_stage17(execute)
        execute(self.files['seed'].decode('utf-8', 'strict'))

    def after_forward(self, stage, execute):
        self.base.after_forward(stage, execute)
        if stage == 25:
            if self.complete or self.files is None:
                raise ValueError('receiver stage order')
            for name in ('m26', 'm27'):
                execute(self.files[name].decode('utf-8', 'strict'))
            # Migration and fixture use unaltered reviewed source bytes.
            execute(self.files['m28'].decode('utf-8', 'strict') + '\n' +
                    self.files['fixture'].decode('utf-8', 'strict'))
            expected = '{' + ','.join(str(x) for x in range(1, 29)) + '}'
            if execute('SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;') != expected:
                raise RuntimeError('receiver ledger mismatch')
            self.complete = True

    def receipt(self):
        if not self.complete:
            raise RuntimeError('receiver qualification incomplete')
        return {'mode': 'receiver28', 'schema_stage': 28, 'scope': 'synthetic-sql-only',
                'authenticated_transport': False, 'public_enrollment_races_verified': False}


def main(argv):
    if len(argv) != 1:
        raise ValueError('expected private output')
    path = Path(argv[0])
    if not path.is_absolute() or '..' in path.parts or any(p.is_symlink() for p in (path, *path.parents)) or path.exists():
        raise ValueError('invalid output')
    require_applicable((ROOT / FILES['m28']).read_bytes())
    sys.dont_write_bytecode = True
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    existing = load_existing()
    capture = existing.load_capture()
    from deploy.local import origin25_schema
    hooks = Hooks(existing, origin25_schema)
    capture['main']([str(path)], _hooks=hooks)
    if not hooks.complete:
        raise RuntimeError('receiver qualification incomplete')
    print('PASS: receiver28 synthetic SQL; public enrollment races unverified', flush=True)


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception:
        print('Receiver SQL qualification failed; private state retained if created.', file=sys.stderr, flush=True)
        raise SystemExit(1) from None
