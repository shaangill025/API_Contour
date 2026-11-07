"""Read-only origin21 business-start preflight; never provision or reset data."""
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from deploy.local import origin21_schema, provision


def main():
    # A missing or unreviewed reference fails before credentials or SQL access.
    origin21_schema.require_reference(21,'enrolled')
    versions=[int(v) for v in provision.psql('SELECT version FROM contour.schema_migrations ORDER BY version;').splitlines()]
    origin21_schema.require_ready(versions,provision.psql,stage=21,phase='enrolled')
    state=provision.STATE
    subjects=json.loads(provision.private_file(state/'subjects.json'))
    if set(subjects)!={'owner','viewer'} or any(not isinstance(v,str) or not 1<=len(v)<=255 or any(ord(c)<32 or ord(c)>126 for c in v) for v in subjects.values()) or subjects['owner']==subjects['viewer']:
        raise RuntimeError('verified subjects invalid')
    password=provision.private_file(state/'database-password')
    provision.private_file(state/'postgres/admin-password')
    if provision.private_file(state/'postgres/pgpass')!='localhost:5432:contour_local:contour_app:'+password+'\n': raise RuntimeError('database credentials disagree')
    groups=provision.psql("SELECT p.rolname FROM pg_auth_members m JOIN pg_roles p ON p.oid=m.roleid JOIN pg_roles a ON a.oid=m.member WHERE a.rolname='contour_app' ORDER BY p.rolname;").splitlines()
    effective=provision.psql("SELECT r.rolname FROM pg_roles r WHERE r.rolname <> 'contour_app' AND pg_has_role('contour_app',r.oid,'MEMBER') ORDER BY r.rolname;").splitlines()
    if groups!=sorted(provision.GROUPS) or effective!=sorted(provision.GROUPS): raise RuntimeError('business role drift')
    probe=subprocess.run(provision.COMPOSE+['exec','-T','-e','PGPASSFILE=/run/config/pgpass','-e','PGSSLMODE=verify-full',
        '-e','PGSSLROOTCERT=/run/local-ca.crt','postgres','psql','-X','-qAt','-h','localhost','-U','contour_app','-d','contour_local','-c','SELECT current_user;'],capture_output=True,text=True,timeout=15)
    if probe.returncode or probe.stdout.strip()!='contour_app': raise RuntimeError('business TLS login failed')
    tenant,project,service,environment=map(provision.sql_quote,provision.IDS)
    for name,actor,role in zip(('owner','viewer'),provision.ACTORS,('service_owner','viewer')):
        actor,subject,issuer,role=map(provision.sql_quote,(actor,subjects[name],provision.ISSUER,role))
        sql=f"""SELECT (EXISTS (SELECT 1 FROM contour.human_actors a JOIN contour.human_identities i USING(actor_id)
          JOIN contour.human_tenant_memberships t USING(actor_id) JOIN contour.human_project_memberships p USING(tenant_id,actor_id)
          JOIN contour.human_service_roles r USING(tenant_id,project_id,actor_id)
          WHERE a.actor_id={actor} AND a.enabled AND i.issuer={issuer} AND i.subject={subject} AND i.enabled
          AND t.tenant_id={tenant} AND t.enabled AND p.project_id={project} AND p.enabled
          AND r.service_id={service} AND r.role={role} AND r.enabled)
          AND (SELECT count(*) FROM contour.human_identities WHERE actor_id={actor})=1
          AND (SELECT count(*) FROM contour.human_service_roles WHERE actor_id={actor})=1
          AND EXISTS (SELECT 1 FROM contour.service_import_defaults WHERE tenant_id={tenant} AND project_id={project} AND service_id={service} AND environment_id={environment}))::text;"""
        if provision.psql(sql)!='true': raise RuntimeError('business identity or scope drift')
    expected=dict(database_host='localhost',database_port=5544,database_name='contour_local',database_user='contour_app',
        database_password_file=str(state/'database-password'),database_ca_file=str(state/'ca.crt'),
        tenant_id=provision.IDS[0],project_id=provision.IDS[1],service_id=provision.IDS[2],environment_id=provision.IDS[3],
        routes=[['/source','/orders']],approved_names=['id','name','status'],approved_media=['application/json','text/plain'])
    if json.loads(provision.private_file(state/'business.json'))!=expected: raise RuntimeError('business configuration drift')
    print('Origin21 business preflight passed; existing state retained.')


if __name__=='__main__':
    try: main()
    except Exception:
        print('Origin21 business preflight failed; existing state retained.',file=sys.stderr)
        raise SystemExit(1)
