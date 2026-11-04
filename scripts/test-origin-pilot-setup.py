#!/usr/bin/env python3
"""Qualify the synthetic internal origin setup on a fresh private PostgreSQL.

This does not qualify runtime capture, platform attestation, or causal tracing.
"""
import hashlib
import os
import re
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
SUPPORT = ROOT/'tests/fixtures/origin-setup'
IMAGE = 'postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4'


def command(args, data=None, timeout=60):
    result = subprocess.run(args,input=data,text=True,capture_output=True,timeout=timeout)
    if result.returncode: raise RuntimeError('owned setup qualification command failed')
    return result.stdout.strip()


def ensure_image():
    result = subprocess.run(['docker','image','inspect',IMAGE],capture_output=True,timeout=30)
    if result.returncode:
        diagnostic=result.stderr.decode('utf-8','replace').lower()
        if 'no such image' not in diagnostic and 'image not found' not in diagnostic:
            raise RuntimeError('owned fixture image inspection failed')
        command(['docker','pull',IMAGE],timeout=1800)
        command(['docker','image','inspect',IMAGE],timeout=30)


def source_snapshot():
    files=[ROOT/'deploy/local/provision.py',ROOT/'deploy/local/capture_profiles.py',ROOT/'deploy/local/capture_renew.py',ROOT/'deploy/local/capture_provision.py',
           ROOT/'db/bootstrap.sql',Path(__file__),
           *ROOT.joinpath('db').glob('provision_*.sql'),*ROOT.joinpath('db/migrations').glob('*.sql'),
           *ROOT.joinpath('db/opt-in-migrations').glob('*.sql'),*ROOT.joinpath('deploy/pilot').glob('origin_*.py'),
           *ROOT.joinpath('deploy/pilot').glob('origin_reference*.json'),*SUPPORT.glob('*.py')]
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def find_owned(name, owner):
    """Find only the uniquely labeled fixture, including after a run timeout."""
    result=subprocess.run(['docker','inspect','--format',
        '{{.Id}} {{index .Config.Labels "apicontour.fixture"}}',name],
        text=True,capture_output=True,timeout=15)
    if result.returncode: return None
    fields=result.stdout.strip().split()
    if len(fields)!=2 or fields[1]!=owner or not re.fullmatch(r'[0-9a-f]{64}',fields[0]):
        return None
    return fields[0]


def synthetic_profile(directory, base):
    """Rebase every profile-owned path into the caller's temporary state."""
    capture=base.capture._replace(capture=directory/'capture')
    origins=tuple(slot._replace(leaf_der=directory/('replica'+str(index))/'client.crt.der')
                  for index,slot in enumerate(base.origins,1))
    return base._replace(state=directory,capture=capture,origins=origins)


def main():
    if len(sys.argv)!=1: raise ValueError('this qualification accepts no arguments')
    os.umask(0o077)
    before=source_snapshot()
    ensure_image()
    owner = uuid.uuid4().hex
    name = 'apicontour-origin-setup-'+owner
    container_id = None
    audit = None
    cleanup_ok = False
    ca_cleanup = False
    concurrency = None
    try:
        container_id=command(['docker','run','-d','--name',name,'--label','apicontour.fixture='+owner,
            '--pull','never','--network','none','--memory','512m','--cpus','1','--pids-limit','128',
            '--tmpfs','/var/lib/postgresql/data:rw,nosuid,noexec,size=256m',
            '-e','POSTGRES_DB=contour_local','-e','POSTGRES_PASSWORD=isolated-fixture-only',
            '-e','POSTGRES_HOST_AUTH_METHOD=reject','-e','POSTGRES_INITDB_ARGS=--auth-local=trust --auth-host=reject',IMAGE,
            '-c','listen_addresses=','-c','unix_socket_directories=/var/run/postgresql',
            '-c','log_statement=all','-c','log_min_duration_statement=0','-c','log_min_error_statement=error'],timeout=90)
        if not re.fullmatch(r'[0-9a-f]{64}',container_id):
            container_id=None
            raise RuntimeError('owned container identity unavailable')
        if find_owned(name,owner)!=container_id:
            raise RuntimeError('owned container identity unavailable')
        for _ in range(120):
            ready=subprocess.run(['docker','exec',container_id,'sh','-c',
                'test "$(cat /proc/1/comm)" = postgres && pg_isready -h /var/run/postgresql -U postgres -d contour_local'],
                capture_output=True,timeout=5)
            if ready.returncode==0: break
            time.sleep(.5)
        else: raise RuntimeError('owned PostgreSQL not ready')
        sys.path.insert(0,str(ROOT))
        from deploy.local import capture_profiles, provision
        def raw_sql(query):
            return command(['docker','exec','-i',container_id,'psql','-X','-qAt','-v','ON_ERROR_STOP=1',
                '-h','/var/run/postgresql','-U','postgres','-d','contour_local'],query)
        def sql(query):
            nonlocal concurrency
            if concurrency is None and 'INSERT INTO contour.collectors' in query and query.rstrip().endswith('ROLLBACK;'):
                concurrency=runpy.run_path(str(SUPPORT/'concurrency.py'))['probe'](container_id,raw_sql,query)
                return ''
            return raw_sql(query)
        sql((ROOT/'db/bootstrap.sql').read_text())
        for item in provision.PROVISION: sql((ROOT/('db/provision_'+item+'.sql')).read_text())
        for migration in provision.MIGRATIONS: sql(migration.read_text())
        if sql('SELECT version FROM contour.schema_migrations ORDER BY version;')!='\n'.join(map(str,range(1,15))):
            raise RuntimeError('default ledger mismatch')
        tenant,project,service,environment=map(provision.sql_quote,provision.IDS)
        sql(f'BEGIN; INSERT INTO contour.tenants VALUES ({tenant}); INSERT INTO contour.projects VALUES ({tenant},{project}); INSERT INTO contour.services VALUES ({tenant},{service},{project}); INSERT INTO contour.environments VALUES ({tenant},{environment},{project}); COMMIT;')
        sensitive,authenticate,wrong_database,audit=runpy.run_path(str(SUPPORT/'login_transport.py'))['configure'](container_id,sql)
        schema_checked=False
        def sensitive_with_schema_check(query):
            nonlocal schema_checked
            if not schema_checked:
                runpy.run_path(str(ROOT/'deploy/pilot/origin_schema_fixture.py'))['run_cases'](raw_sql)
                schema_checked=True
            return sensitive(query)
        fixture=runpy.run_path(str(ROOT/'deploy/pilot/origin_setup_fixture.py'))['run_cases']
        scratch=None
        try:
            with tempfile.TemporaryDirectory(prefix='apicontour-origin-setup-ca-') as directory:
                scratch=Path(directory); cert=scratch/'ca.crt'; key=scratch/'ca.key'
                wrong_cert=scratch/'wrong-ca.crt'; wrong_key=scratch/'wrong-ca.key'
                command(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-sha256',
                    '-keyout',str(key),'-out',str(cert),'-days','2','-subj','/CN=APIContour-owned-setup-fixture',
                    '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'])
                command(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-sha256',
                    '-keyout',str(wrong_key),'-out',str(wrong_cert),'-days','2','-subj','/CN=APIContour-owned-wrong-ca',
                    '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'])
                credential_root=scratch/'credential-profile'; credential_root.mkdir(mode=0o700)
                profile=synthetic_profile(credential_root,capture_profiles.ORIGIN_PILOT)
                credential_fixture=runpy.run_path(str(ROOT/'deploy/pilot/origin_credentials_fixture.py'))['run_cases']
                if credential_fixture(profile,cert,key,wrong_ca_cert=wrong_cert)!='synthetic origin credential fixture passed':
                    raise RuntimeError('credential negative matrix incomplete')
                if fixture(sql,cert,key,sensitive_execute=sensitive_with_schema_check,authenticate=authenticate,
                           wrong_database_execute=wrong_database,enrollment=True,renewal=True)!='origin schema preparation fault fixture passed':
                    raise RuntimeError('combined PostgreSQL setup matrix incomplete')
        finally:
            ca_cleanup=scratch is not None and not os.path.lexists(scratch)
        if not ca_cleanup: raise RuntimeError('owned CA cleanup failed')
        if not schema_checked: raise RuntimeError('schema negative matrix did not execute')
        if not concurrency or not all(value is True for value in concurrency.values()):
            raise RuntimeError('owned observer concurrency checks incomplete')
        result=audit(); audit=None
        if not all(result[key] for key in ('logging_positive_control','private_session_absent','sensitive_values_absent')):
            raise RuntimeError('private-session audit failed')
    finally:
        audit_failed=False
        if audit is not None:
            try: audit()
            except Exception: audit_failed=True
        owned=find_owned(name,owner)
        if owned is not None and (container_id is None or owned==container_id):
            container_id=owned
            removal=subprocess.run(['docker','rm','-f',container_id],capture_output=True,timeout=30)
            remaining=subprocess.run(['docker','ps','-aq','--no-trunc','--filter','id='+container_id],capture_output=True,timeout=15)
            cleanup_ok=removal.returncode==0 and remaining.returncode==0 and not remaining.stdout.strip() and find_owned(name,owner) is None
        elif container_id is None:
            # No confirmed owned container existed. A failed `docker run` still
            # propagates; never remove an unowned name collision.
            cleanup_ok=True
        if not cleanup_ok or audit_failed: raise RuntimeError('owned fixture cleanup or logging audit failed')
    if source_snapshot()!=before: raise RuntimeError('qualification source changed during execution')
    print('Synthetic internal origin setup and committed renewal qualification passed; runtime capture and platform attestation are not qualified.')


if __name__=='__main__':
    try: main()
    except Exception:
        print('Synthetic internal origin setup qualification failed; see local prerequisites and fixture status.',file=sys.stderr)
        raise SystemExit(1)
