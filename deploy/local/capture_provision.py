"""Provision the opt-in local capture profile, retaining all existing state."""
import importlib.util
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-mvp'
CAPTURE = STATE / 'capture'
spec = importlib.util.spec_from_file_location('local_provision', ROOT / 'deploy/local/provision.py')
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
TENANT, PROJECT, SERVICE, ENVIRONMENT = base.IDS
COLLECTOR = '00000000-0000-4000-8000-000000000201'
SOURCE = '00000000-0000-4000-8000-000000000202'
DEPLOYMENT = '00000000-0000-4000-8000-000000000203'
INSTANCE = '00000000-0000-4000-8000-000000000204'
NONCE = '00000000-0000-4000-8000-000000000205'


def main():
    os.umask(0o077)
    runtime = CAPTURE / 'runtime'; private = CAPTURE / 'private'
    for name in ['server.crt.der','server.key.der','collector.crt.der','ca.der','policy.raw','ingress.password','worker.password']:
        if not (runtime/name).is_file(): raise RuntimeError('capture credentials incomplete')
    envelope = (private/'policy.json').read_bytes()
    if not 1 <= len(envelope) <= 1048576: raise RuntimeError('policy invalid')
    roles = [('contour_local_ingress','contour_ingestion'),('contour_local_worker','contour_catalog_worker')]
    quote = base.sql_quote
    for role, group in roles:
        password = base.private_file(runtime / ('ingress.password' if role.endswith('ingress') else 'worker.password'))
        if base.psql('SELECT count(*) FROM pg_roles WHERE rolname='+quote(role)) == '0':
            base.psql('BEGIN; CREATE ROLE '+role+' LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD '+quote(password)+'; GRANT '+group+' TO '+role+'; GRANT CONNECT ON DATABASE contour_local TO '+role+'; COMMIT;')
        membership = base.psql("SELECT r.rolname FROM pg_roles r WHERE r.rolname <> "+quote(role)+" AND pg_has_role("+quote(role)+",r.oid,'MEMBER') ORDER BY r.rolname;").splitlines()
        safe = base.psql("SELECT (rolcanlogin AND rolinherit AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND rolconfig IS NULL)::text FROM pg_roles WHERE rolname="+quote(role))
        if membership != [group] and not (group == 'contour_ingestion' and membership == ['contour_ingestion','contour_runtime']):
            raise RuntimeError('capture role membership drift')
        if safe != 'true': raise RuntimeError('capture role attributes drift')
    t,p,s,e,c,src,d,i,n = map(quote,[TENANT,PROJECT,SERVICE,ENVIRONMENT,COLLECTOR,SOURCE,DEPLOYMENT,INSTANCE,NONCE])
    existing = base.psql('SELECT count(*) FROM contour.collectors WHERE tenant_id='+t+' AND collector_id='+c)
    if existing == '0':
        statements = [f"SELECT set_config('apicontour.tenant_id',{t},true);", 'SET LOCAL ROLE contour_admin;',
            f"INSERT INTO contour.deployments VALUES ({t},{d},{p},{s},{e});",
            f"SELECT contour.lock_collector({t},{c});", f"INSERT INTO contour.collectors VALUES ({t},{c});",
            f"INSERT INTO contour.workload_assignments VALUES ({t},{c},{p},{s},{e},{d});",
            f"INSERT INTO contour.workload_instances VALUES ({t},{p},{s},{e},{d},{i});",
            f"SELECT contour.register_instance_source({t},{src},{c},{p},{s},{e},{d},{n},{i});",
            f"INSERT INTO contour.source_authorization VALUES ({t},{src},{c},'gateway',ARRAY['http_json_v1']);",
            f"INSERT INTO contour.policy_revisions VALUES ({t},{c},1,decode('{envelope.hex()}','hex'));",
            f"UPDATE contour.collector_authorization SET active_revision=1,enabled=true WHERE tenant_id={t} AND collector_id={c};"]
        base.psql('BEGIN; '+'\n'.join(statements)+' COMMIT;')
    elif existing != '1': raise RuntimeError('capture identity drift')
    # Refuse partial or changed enrollment rather than implicitly repairing it.
    valid = base.psql(f"SELECT EXISTS (SELECT 1 FROM contour.collector_authorization a JOIN contour.policy_revisions r USING(tenant_id,collector_id) JOIN contour.source_authorization sa USING(tenant_id,collector_id) JOIN contour.source_instance_bindings b USING(tenant_id,source_id,collector_id) WHERE a.tenant_id={t} AND a.collector_id={c} AND a.enabled AND a.revoked_at IS NULL AND a.active_revision=1 AND r.revision=1 AND r.signed_envelope=decode('{envelope.hex()}','hex') AND sa.source_id={src} AND sa.technique='gateway' AND sa.parser_profiles=ARRAY['http_json_v1'] AND b.project_id={p} AND b.service_id={s} AND b.environment_id={e} AND b.deployment_id={d} AND b.instance_id={i})::text;")
    if valid != 'true': raise RuntimeError('capture enrollment drift')
    common = dict(database_host='postgres',database_port=5432,database_name='contour_local',ca_file='/run/capture/database-ca.crt',tenant=TENANT,collector=COLLECTOR)
    configs = {
        'ingress.json': dict(common,database_user='contour_local_ingress',password_file='/run/capture/ingress.password',server_certificate_der='/run/capture/server.crt.der',server_key_der='/run/capture/server.key.der',client_ca_der='/run/capture/ca.der',collector_certificate_der='/run/capture/collector.crt.der',policy_key_file='/run/capture/policy.raw',listen='0.0.0.0:9445'),
        'worker.json': dict(common,database_user='contour_local_worker',password_file='/run/capture/worker.password')}
    for name, config in configs.items():
        path=runtime/name
        if path.exists() and json.loads(path.read_text()) != config: raise RuntimeError('capture config drift')
        if not path.exists(): path.write_text(json.dumps(config,indent=2)+'\n')
    print('Synthetic capture roles and instance-bound enrollment verified.')

if __name__ == '__main__': main()
