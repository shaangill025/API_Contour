"""Provision a local database without resetting existing data or credentials."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-mvp'
COMPOSE = ['docker', 'compose', '-f', str(ROOT / 'deploy/local/compose.yaml')]
ISSUER = 'https://localhost:8444/realms/apicontour-local'
IDS = ['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002',
       '00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000004']
ACTORS = ['00000000-0000-4000-8000-000000000101', '00000000-0000-4000-8000-000000000102']
GROUPS = ['contour_human_lookup', 'contour_declared_reader', 'contour_declared_writer',
          'contour_comparison_reader', 'contour_comparison_writer', 'contour_review_reader',
          'contour_review_writer', 'contour_approval_reader', 'contour_approval_writer',
          'contour_catalog_reader']
PROVISION = ['authority', 'catalog', 'declared', 'approval', 'comparison', 'review', 'human']
MIGRATIONS = sorted((ROOT / 'db/migrations').glob('*.sql'))

def sql_quote(value):
    if '\x00' in value: raise ValueError('invalid SQL value')
    return "'" + value.replace("'", "''") + "'"

def psql(sql):
    result = subprocess.run(COMPOSE + ['exec', '-T', '-u', 'postgres', 'postgres', 'psql', '-X', '-qAt',
                                      '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'contour_local'],
                            input=sql, text=True, capture_output=True, timeout=60)
    if result.returncode: raise RuntimeError('database provisioning failed; state retained')
    return result.stdout.strip()

def private_file(path):
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise RuntimeError('required private configuration is missing or accessible to other users')
    return path.read_text()

def main():
    os.umask(0o077)
    subjects = json.loads(private_file(STATE / 'subjects.json'))
    if set(subjects) != {'owner', 'viewer'} or any(not isinstance(v,str) or not 1 <= len(v) <= 255 or any(ord(c)<32 or ord(c)>126 for c in v) for v in subjects.values()) or subjects['owner'] == subjects['viewer']:
        raise RuntimeError('verified subjects are invalid')
    password = private_file(STATE / 'database-password')
    private_file(STATE / 'postgres/admin-password')
    if private_file(STATE / 'postgres/pgpass') != 'localhost:5432:contour_local:contour_app:' + password + '\n':
        raise RuntimeError('database credential files disagree')
    role_count = int(psql("SELECT count(*) FROM pg_roles WHERE rolname IN ('contour_owner','contour_runtime');"))
    has_schema = psql("SELECT (to_regclass('contour.schema_migrations') IS NOT NULL)::text;") == 'true'
    if role_count == 0 and not has_schema:
        psql((ROOT / 'db/bootstrap.sql').read_text())
        for name in PROVISION: psql((ROOT / ('db/provision_' + name + '.sql')).read_text())
    elif role_count != 2:
        raise RuntimeError('partial bootstrap; manual inspection required')
    # All provision scripts must have completed; never repair an unknown partial bootstrap.
    required = ['contour_owner', 'contour_runtime']
    # The authority roles differ from the business roles; inspect all names created by each script.
    for name in PROVISION:
        import re
        required.extend(re.findall(r'CREATE ROLE\s+(\w+)', (ROOT / ('db/provision_' + name + '.sql')).read_text(), re.I))
    required = sorted(set(required))
    present = psql('SELECT rolname FROM pg_roles WHERE rolname IN (' + ','.join(map(sql_quote, required)) + ') ORDER BY rolname;').splitlines()
    if present != required: raise RuntimeError('incomplete provision roles; manual inspection required')
    versions = [int(path.name[:4]) for path in MIGRATIONS]
    if versions != list(range(1,len(versions)+1)): raise RuntimeError('unexpected migration files')
    installed = [] if not has_schema else [int(v) for v in psql('SELECT version FROM contour.schema_migrations ORDER BY version;').splitlines()]
    if installed != versions[:len(installed)]: raise RuntimeError('unexpected migration ledger')
    for path in MIGRATIONS[len(installed):]: psql(path.read_text())
    if [int(v) for v in psql('SELECT version FROM contour.schema_migrations ORDER BY version;').splitlines()] != versions:
        raise RuntimeError('migration ledger did not reach expected version')
    exists = psql("SELECT count(*) FROM pg_roles WHERE rolname='contour_app';") == '1'
    if not exists:
        psql('BEGIN; CREATE ROLE contour_app LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD ' + sql_quote(password) + '; GRANT ' + ','.join(GROUPS) + ' TO contour_app; GRANT CONNECT ON DATABASE contour_local TO contour_app; COMMIT;')
    actual_groups = psql("SELECT p.rolname FROM pg_auth_members m JOIN pg_roles p ON p.oid=m.roleid JOIN pg_roles a ON a.oid=m.member WHERE a.rolname='contour_app' ORDER BY p.rolname;").splitlines()
    if actual_groups != sorted(GROUPS) or psql("SELECT (rolcanlogin AND rolinherit AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND rolconfig IS NULL)::text FROM pg_roles WHERE rolname='contour_app';") != 'true':
        raise RuntimeError('runtime login privilege drift')
    # Check the full membership graph, not just the app login's direct grants.
    # MEMBER deliberately includes membership through non-inheriting edges as well:
    # a login must not be able to SET ROLE into an unexpected privileged group.
    effective_groups = psql("SELECT r.rolname FROM pg_roles r WHERE r.rolname <> 'contour_app' AND pg_has_role('contour_app', r.oid, 'MEMBER') ORDER BY r.rolname;").splitlines()
    if effective_groups != sorted(GROUPS):
        raise RuntimeError('runtime effective role membership drift')
    unsafe_groups = psql("SELECT rolname FROM pg_roles WHERE rolname IN (" + ','.join(map(sql_quote, GROUPS)) + ") AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR NOT rolinherit OR rolconfig IS NOT NULL) ORDER BY rolname;")
    if unsafe_groups:
        raise RuntimeError('runtime group attributes drift')
    probe = subprocess.run(COMPOSE + ['exec','-T','-e','PGPASSFILE=/run/config/pgpass','-e','PGSSLMODE=verify-full',
                            '-e','PGSSLROOTCERT=/run/local-ca.crt','postgres','psql','-X','-qAt','-h','localhost','-U','contour_app','-d','contour_local','-c','SELECT current_user;'], capture_output=True, text=True, timeout=15)
    if probe.returncode or probe.stdout.strip() != 'contour_app': raise RuntimeError('runtime TLS login failed; credentials or certificate changed')
    tenant, project, service, environment = map(sql_quote, IDS)
    actor_count = int(psql('SELECT count(*) FROM contour.human_actors WHERE actor_id IN (' + ','.join(map(sql_quote, ACTORS)) + ');'))
    if actor_count not in (0, 2): raise RuntimeError('partial human identity provisioning')
    statements = [f"INSERT INTO contour.tenants VALUES ({tenant}) ON CONFLICT DO NOTHING;",
                  f"INSERT INTO contour.projects VALUES ({tenant},{project}) ON CONFLICT DO NOTHING;",
                  f"INSERT INTO contour.services VALUES ({tenant},{service},{project}) ON CONFLICT DO NOTHING;",
                  f"INSERT INTO contour.environments VALUES ({tenant},{environment},{project}) ON CONFLICT DO NOTHING;",
                  f"INSERT INTO contour.service_import_defaults VALUES ({tenant},{project},{service},{environment}) ON CONFLICT DO NOTHING;",
                  'SET LOCAL ROLE contour_human_provisioner;']
    for name, actor, role in zip(['owner','viewer'], ACTORS, ['service_owner','viewer']):
        actor, subject, issuer, role = map(sql_quote, [actor,subjects[name],ISSUER,role])
        inserts = [f"INSERT INTO contour.human_actors VALUES ({actor},true) ON CONFLICT DO NOTHING;",
          f"INSERT INTO contour.human_identities VALUES ({issuer},{subject},{actor},true) ON CONFLICT DO NOTHING;",
          f"INSERT INTO contour.human_tenant_memberships VALUES ({tenant},{actor},true) ON CONFLICT DO NOTHING;",
          f"INSERT INTO contour.human_project_memberships VALUES ({tenant},{project},{actor},true) ON CONFLICT DO NOTHING;",
          f"INSERT INTO contour.human_service_roles VALUES ({tenant},{project},{service},{actor},{role},true) ON CONFLICT DO NOTHING;"]
        if actor_count == 0: statements += inserts
        statements += [f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM contour.human_actors a JOIN contour.human_identities i USING(actor_id) JOIN contour.human_tenant_memberships t USING(actor_id) JOIN contour.human_project_memberships p USING(tenant_id,actor_id) JOIN contour.human_service_roles r USING(tenant_id,project_id,actor_id) WHERE a.actor_id={actor} AND a.enabled AND i.issuer={issuer} AND i.subject={subject} AND i.enabled AND t.tenant_id={tenant} AND t.enabled AND p.project_id={project} AND p.enabled AND r.service_id={service} AND r.role={role} AND r.enabled) OR (SELECT count(*) FROM contour.human_identities WHERE actor_id={actor}) <> 1 OR (SELECT count(*) FROM contour.human_service_roles WHERE actor_id={actor}) <> 1 THEN RAISE EXCEPTION 'identity drift'; END IF; END $$;"]
    # Reset role to inspect the fixed default, including a pre-existing conflicting default.
    statements += ['RESET ROLE;', f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM contour.service_import_defaults WHERE tenant_id={tenant} AND project_id={project} AND service_id={service} AND environment_id={environment}) THEN RAISE EXCEPTION 'default drift'; END IF; END $$;"]
    psql('BEGIN; ' + '\n'.join(statements) + ' COMMIT;')
    business = dict(database_host='localhost', database_port=5544, database_name='contour_local', database_user='contour_app',
                    database_password_file=str(STATE / 'database-password'), database_ca_file=str(STATE / 'ca.crt'),
                    tenant_id=IDS[0], project_id=IDS[1], service_id=IDS[2], environment_id=IDS[3],
                    routes=[['/source','/orders']], approved_names=['id','name','status'], approved_media=['application/json','text/plain'])
    path = STATE / 'business.json'
    if path.exists() and json.loads(private_file(path)) != business: raise RuntimeError('business configuration drift')
    if not path.exists(): path.write_text(json.dumps(business, indent=2) + '\n')
    print('Local database provisioned and TLS runtime login verified.')

if __name__ == '__main__':
    try: main()
    except Exception:
        print('Local database setup failed; existing data and credentials retained. Inspect local configuration and provisioning state.', file=sys.stderr)
        raise SystemExit(1)
