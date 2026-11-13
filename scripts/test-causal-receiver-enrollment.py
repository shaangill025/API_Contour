#!/usr/bin/env python3
"""Disposable SQL28 fixture; no deployment, peer or TLS qualification."""
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
    'races': 'scripts/receiver_enrollment_races.py',
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
    diagnostic_context = 'receiver-v1'
    def __init__(self, existing, schema):
        self.base = existing.QualificationHooks('schema25', schema)
        self.existing = existing
        self.race_results = ()
        self.race_module = None
        self.files = None
        self.complete = False

    def preflight(self, sources):
        self.base.preflight(sources)
        required = ['scripts/test-causal-receiver-enrollment.py',
                    'tests/fixtures/causal-receiver-enrollment/test_driver.py',
                    'tests/fixtures/causal-receiver-enrollment/test_races.py', *FILES.values()]
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
        namespace={'__name__':'receiver_enrollment_races','__file__':str(ROOT / FILES['races'])}
        exec(compile(self.files['races'],namespace['__file__'],'exec'),namespace)
        if (ROOT / FILES['races']).read_bytes()!=self.files['races']: raise ValueError('race source changed')
        self.race_module=namespace

    def after_stage17(self, execute):
        self.base.after_stage17(execute)
        execute(self.files['seed'].decode('utf-8', 'strict'))

    def before_forward(self, stage):
        if stage == 25: print('receiver-stage=base25',file=sys.stderr,flush=True)

    def after_forward(self, stage, execute):
        self.base.after_forward(stage, execute)
        if stage == 25:
            if self.complete or self.files is None:
                raise ValueError('receiver stage order')
            for name in ('m26', 'm27'):
                print('receiver-stage='+name,file=sys.stderr,flush=True)
                execute(self.files[name].decode('utf-8', 'strict'))
            # Migration and fixture use unaltered reviewed source bytes.
            print('receiver-stage=m28',file=sys.stderr,flush=True)
            execute(self.files['m28'].decode('utf-8', 'strict'))
            print('receiver-stage=fixture',file=sys.stderr,flush=True)
            execute(self.files['fixture'].decode('utf-8', 'strict'))
            expected = '{' + ','.join(str(x) for x in range(1, 29)) + '}'
            if execute('SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;') != expected:
                raise RuntimeError('receiver ledger mismatch')
            if self.race_module is None: raise RuntimeError('receiver race source unavailable')
            print('receiver-stage=races',file=sys.stderr,flush=True)
            self.race_results=self.race_module['run_races'](execute,self.existing)
            if self.race_results!=self.race_module['RESULTS']: raise RuntimeError('receiver races incomplete')
            self.complete = True

    def receipt(self):
        if not self.complete:
            raise RuntimeError('receiver qualification incomplete')
        return {'mode': 'receiver28', 'schema_stage': 28, 'scope': 'synthetic-sql-only',
                'authenticated_transport': False, 'public_enrollment_races_verified': list(self.race_results)}


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
    print('PASS: receiver28 synthetic SQL and public enrollment races', flush=True)


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception:
        print('Receiver SQL qualification failed; private state retained if created.', file=sys.stderr, flush=True)
        raise SystemExit(1) from None
