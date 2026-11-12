#!/usr/bin/env python3
"""Closed disposable schema25/gateway26 SQL fixture; no mTLS or issuer claim."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
LEDGER='SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;'
FILES={'seed':'db/tests/causal_runtime_registry_pre.sql',
       'migration':'db/opt-in-migrations/0026_causal_evidence_enrollment.sql',
       'fixture':'db/tests/causal_evidence_enrollment.sql'}


def origin_inventory_sql():
    from deploy.local import origin21_schema
    return origin21_schema.inventory_sql()


def guard_probe(migration):
    """Re-execute the exact migration guard in a fresh psql, assert SQLSTATE 42501."""
    text=migration.decode('utf-8')
    head='DO $$ BEGIN\n'; end='\nEND $$;'
    if text.count(head)!=1 or head not in text or end not in text: raise ValueError('migration guard shape')
    body=text.split(head,1)[1].split(end,1)[0]
    if "ERRCODE='42501'" not in body or 'generate_series(1,25)' not in body: raise ValueError('migration guard identity')
    return ("DO $origin25_retry$ BEGIN BEGIN\n"+body+"\nRAISE EXCEPTION 'guard accepted reapplication' USING ERRCODE='P0001';\n"
            "EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $origin25_retry$;\nSELECT '42501';")


class QualificationHooks:
    def __init__(self,mode,schema,files=None):
        if mode not in ('schema25','gateway26'): raise ValueError('unsupported qualification mode')
        self.mode,self.schema,self.files=mode,schema,files
        self.seeded=False;self.next_stage=22;self.complete=False
    def preflight(self,sources):
        required=['scripts/test-causal-evidence-enrollment.py','deploy/local/origin25_schema.py',
                  *['deploy/local/origin25_reference_%d_enrolled.json'%n for n in (22,23,24,25)]]
        if self.mode=='gateway26': required+=list(FILES.values())
        if any(name not in sources for name in required): raise ValueError('qualification source missing')
        if self.mode=='gateway26':
            self.files={}
            for key,name in FILES.items():
                path=ROOT/name
                if not path.is_file() or any(part.is_symlink() for part in (path,*path.parents)): raise ValueError('qualification source unavailable')
                raw=path.read_bytes()
                if hashlib.sha256(raw).hexdigest()!=sources[name]: raise ValueError('qualification source changed')
                self.files[key]=raw
    def after_stage17(self,execute):
        if self.seeded: raise ValueError('duplicate qualification seed')
        self.seeded=True
        if self.mode=='gateway26': execute(self.files['seed'].decode('utf-8'))
    def after_forward(self,stage,execute):
        if not self.seeded or stage!=self.next_stage: raise ValueError('qualification stage order')
        if stage in (22,23,24): self.schema._require_migration_stage(execute,stage)
        elif stage==25:
            self.schema.require_ready(execute)
            from deploy.local import origin21_schema
            try: origin21_schema.require_ledger(list(range(1,26)))
            except ValueError: pass
            else: raise RuntimeError('legacy 21 accepted stage 25')
            if self.mode=='gateway26': self._gateway(execute)
            self.complete=True
        else: raise ValueError('invalid qualification stage')
        self.next_stage+=1
    def receipt(self):
        if not self.complete: raise RuntimeError('qualification incomplete')
        return {'mode':self.mode,'schema_stage':25 if self.mode=='schema25' else 26,
                'scope':'synthetic-sql-only','authenticated_transport':False}
    def _gateway(self,execute):
        migration=self.files['migration'];fixture=self.files['fixture']
        # One execute is one fresh psql session: temp fixture state cannot leak
        # into a separate backend and ON_ERROR_STOP remains enabled.
        execute(migration.decode('utf-8')+'\n'+fixture.decode('utf-8'))
        if execute(LEDGER)!='{'+','.join(map(str,range(1,27)))+'}': raise RuntimeError('stage 26 ledger mismatch')
        before=execute(origin_inventory_sql())
        if type(before) is not str or len(before.encode('utf-8'))>8*1024*1024: raise RuntimeError('stage 26 metadata invalid')
        inventory=json.loads(before)
        if (type(inventory) is not dict or set(inventory)!={'version','server_major','items'} or
            type(inventory['version']) is not int or inventory['version']!=1 or
            type(inventory['server_major']) is not int or inventory['server_major']!=16 or
            type(inventory['items']) is not list or not inventory['items']): raise RuntimeError('stage 26 metadata invalid')
        if execute(guard_probe(migration))!='42501': raise RuntimeError('stage 26 reapply guard accepted')
        if execute(LEDGER)!='{'+','.join(map(str,range(1,27)))+'}' or execute(origin_inventory_sql())!=before:
            raise RuntimeError('stage 26 metadata changed after guard')


def load_capture():
    path=ROOT/'scripts/capture-origin25-reference.py'
    if not path.is_file() or any(part.is_symlink() for part in (path,*path.parents)): raise ValueError('capture source unavailable')
    status=subprocess.run(['git','status','--porcelain','--untracked-files=all'],cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=True)
    if status.stdout or status.stderr: raise ValueError('clean reviewed source required')
    result=subprocess.run(['git','show','HEAD:scripts/capture-origin25-reference.py'],cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=True)
    raw=path.read_bytes()
    if result.stderr or len(raw)>2_000_000 or raw!=result.stdout: raise ValueError('capture source changed')
    namespace={'__file__':str(path),'__name__':'causal_evidence_capture'}
    exec(compile(raw,str(path),'exec'),namespace)
    if path.read_bytes()!=raw: raise ValueError('capture source changed')
    return namespace


def main(argv):
    if len(argv)!=2 or argv[0] not in ('schema25','gateway26'): raise ValueError('expected closed mode and private output')
    path=Path(argv[1])
    if not path.is_absolute() or '..' in path.parts or any(part.is_symlink() for part in (path,*path.parents)): raise ValueError('invalid output')
    if path.exists(): raise ValueError('output already exists')
    sys.dont_write_bytecode=True
    if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
    capture=load_capture()
    from deploy.local import origin25_schema
    hooks=QualificationHooks(argv[0],origin25_schema)
    capture['main']([str(path)],_hooks=hooks)
    if not hooks.complete: raise RuntimeError('qualification incomplete')
    print('PASS: '+argv[0]+' synthetic SQL qualification; no mTLS claim',flush=True)


def failure_location(error):
    allowed={'test-causal-evidence-enrollment.py','capture-origin25-reference.py',
             'origin25_schema.py','fixture_psql_transport.py'}
    frames=[]; trace=error.__traceback__
    while trace is not None:
        name=Path(trace.tb_frame.f_code.co_filename).name
        if name in allowed: frames.append(name+':'+str(trace.tb_lineno))
        trace=trace.tb_next
    return ','.join(frames[-6:]) or 'unavailable'


if __name__=='__main__':
    try: main(sys.argv[1:])
    except Exception as error:
        print('qualification-location='+failure_location(error),file=sys.stderr,flush=True)
        print('Causal evidence qualification failed; private state retained.',file=sys.stderr,flush=True)
        raise SystemExit(1) from None
