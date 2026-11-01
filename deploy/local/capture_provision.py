"""Provision the opt-in local capture profile, retaining all existing state."""
import base64
import datetime
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile

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
sys.path.insert(0, str(Path(__file__).resolve().parent))
import capture_profiles


def runtime_configs(collector):
    common = dict(database_host='postgres',database_port=5432,database_name='contour_local',ca_file='/run/capture/database-ca.crt',tenant=TENANT,collector=collector)
    return {
        'ingress.json': dict(common,database_user='contour_local_ingress',password_file='/run/capture/ingress.password',server_certificate_der='/run/capture/server.crt.der',server_key_der='/run/capture/server.key.der',client_ca_der='/run/capture/ca.der',collector_certificate_der='/run/capture/collector.crt.der',policy_key_file='/run/capture/policy.raw',listen='0.0.0.0:9445'),
        'worker.json': dict(common,database_user='contour_local_worker',password_file='/run/capture/worker.password')}


def verify_pilot_policy(profile, private, runtime, envelope):
    # Import lazily to avoid the renewal module's existing provisioning import.
    import capture_renew
    scratch = tempfile.gettempdir()
    key = capture_renew.read_file(private/'policy.key', 16384)
    public = capture_renew.crypt('public', key, b'', profile=profile, scratch=scratch)
    if len(public) != 44 or public[-32:] != capture_renew.read_file(runtime/'policy.raw', 32):
        raise RuntimeError('pilot policy signer drift')
    return capture_renew.checked_envelope(envelope, public, profile, scratch)


def main(profile=None):
    os.umask(0o077)
    profile = profile or capture_profiles.DEFAULT
    if profile not in (capture_profiles.DEFAULT, capture_profiles.PILOT): raise ValueError('unknown capture profile')
    capture = CAPTURE if profile.name == 'default' else profile.capture
    COLLECTOR, SOURCE, DEPLOYMENT, INSTANCE, NONCE = profile.collector, profile.source, profile.deployment, profile.instance, profile.nonce
    runtime = capture / 'runtime'; private = capture / 'private'
    for name in ['server.crt.der','server.key.der','collector.crt.der','ca.der','policy.raw','ingress.password','worker.password']:
        if not (runtime/name).is_file(): raise RuntimeError('capture credentials incomplete')
    if os.path.lexists(private/'renew.pending'): raise RuntimeError('policy renewal requires reconciliation')
    if profile.name == 'pilot':
        import capture_renew
        envelope = capture_renew.read_file(private/'policy.json', 16384)
    else:
        envelope = (private/'policy.json').read_bytes()
    if not 1 <= len(envelope) <= 1048576: raise RuntimeError('policy invalid')
    if profile.name == 'pilot':
        policy = verify_pilot_policy(profile, private, runtime, envelope)
    else:
        encoded = json.loads(envelope)['payload_base64url']
        policy = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
    if profile.name == 'pilot':
        expires = datetime.datetime.fromisoformat(policy['expires_at'].replace('Z', '+00:00'))
        if expires.tzinfo is None or datetime.datetime.now(datetime.timezone.utc) >= expires:
            raise RuntimeError('pilot policy expired; run capture_renew.py --profile pilot')
    revision = policy['revision']
    if type(revision) is not int or not 1 <= revision <= 18446744073709551615: raise RuntimeError('policy revision invalid')
    roles = [('contour_local_ingress','contour_ingestion'),('contour_local_worker','contour_catalog_worker')]
    quote = base.sql_quote
    # A login can SET ROLE into inherited groups. Reject unsafe attributes or a
    # missing group before creating logins or touching collector enrollment.
    groups = ['contour_ingestion', 'contour_runtime', 'contour_catalog_worker']
    safe_groups = base.psql("SELECT count(*) FROM pg_roles WHERE rolname IN (" +
        ','.join(map(quote,groups)) + ") AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls " +
        "AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND rolinherit AND rolconfig IS NULL;")
    if safe_groups != str(len(groups)): raise RuntimeError('capture group attributes drift')
    for role, group in roles:
        password = base.private_file(runtime / ('ingress.password' if role.endswith('ingress') else 'worker.password'))
        if profile.name == 'pilot' and password != base.private_file(STATE / 'capture' / 'runtime' / ('ingress.password' if role.endswith('ingress') else 'worker.password')):
            raise RuntimeError('restricted role credential drift')
        if base.psql('SELECT count(*) FROM pg_roles WHERE rolname='+quote(role)) == '0':
            if profile.name == 'pilot': raise RuntimeError('restricted role unavailable')
            base.psql('BEGIN; CREATE ROLE '+role+' LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD '+quote(password)+'; GRANT '+group+' TO '+role+'; GRANT CONNECT ON DATABASE contour_local TO '+role+'; COMMIT;')
        membership = base.psql("SELECT r.rolname FROM pg_roles r WHERE r.rolname <> "+quote(role)+" AND pg_has_role("+quote(role)+",r.oid,'MEMBER') ORDER BY r.rolname;").splitlines()
        safe = base.psql("SELECT (rolcanlogin AND rolinherit AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND rolconfig IS NULL)::text FROM pg_roles WHERE rolname="+quote(role))
        if membership != [group] and not (group == 'contour_ingestion' and membership == ['contour_ingestion','contour_runtime']):
            raise RuntimeError('capture role membership drift')
        if safe != 'true': raise RuntimeError('capture role attributes drift')
    t,p,s,e,c,src,d,i,n = map(quote,[TENANT,PROJECT,SERVICE,ENVIRONMENT,COLLECTOR,SOURCE,DEPLOYMENT,INSTANCE,NONCE])
    existing = base.psql('SELECT count(*) FROM contour.collectors WHERE tenant_id='+t+' AND collector_id='+c)
    if existing == '0':
        if revision != 1: raise RuntimeError('initial policy revision invalid')
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
    valid = base.psql(f"SELECT EXISTS (SELECT 1 FROM contour.collector_authorization a JOIN contour.policy_revisions r USING(tenant_id,collector_id) JOIN contour.source_authorization sa USING(tenant_id,collector_id) JOIN contour.source_instance_bindings b USING(tenant_id,source_id,collector_id) WHERE a.tenant_id={t} AND a.collector_id={c} AND a.enabled AND a.revoked_at IS NULL AND a.active_revision={revision} AND r.revision={revision} AND r.signed_envelope=decode('{envelope.hex()}','hex') AND sa.source_id={src} AND sa.technique='gateway' AND sa.parser_profiles=ARRAY['http_json_v1'] AND b.project_id={p} AND b.service_id={s} AND b.environment_id={e} AND b.deployment_id={d} AND b.instance_id={i})::text;")
    if valid != 'true': raise RuntimeError('capture enrollment drift')
    # Existing valid rows are insufficient if the fixed collector also has
    # additional authority. Check only this tenant/collector; do not repair it.
    exact = base.psql(f"SELECT ("
        f"(SELECT count(*) FROM contour.sources WHERE tenant_id={t} AND collector_id={c})=1 AND "
        f"(SELECT count(*) FROM contour.sources WHERE tenant_id={t} AND collector_id={c} AND source_id={src} AND project_id={p} AND service_id={s} AND environment_id={e} AND deployment_id={d} AND source_nonce={n} AND binding_mode='instance')=1 AND "
        f"(SELECT count(*) FROM contour.source_authorization WHERE tenant_id={t} AND collector_id={c})=1 AND "
        f"(SELECT count(*) FROM contour.source_instance_bindings WHERE tenant_id={t} AND collector_id={c})=1 AND "
        f"(SELECT count(*) FROM contour.workload_assignments WHERE tenant_id={t} AND collector_id={c})=1 AND "
        f"(SELECT count(*) FROM contour.workload_assignments WHERE tenant_id={t} AND collector_id={c} AND project_id={p} AND service_id={s} AND environment_id={e} AND deployment_id={d})=1"
        f")::text;")
    if exact != 'true': raise RuntimeError('capture enrollment drift')
    for name, config in runtime_configs(COLLECTOR).items():
        path=runtime/name
        if path.exists() and json.loads(path.read_text()) != config: raise RuntimeError('capture config drift')
        if not path.exists(): path.write_text(json.dumps(config,indent=2)+'\n')
    print('Synthetic capture roles and instance-bound enrollment verified.')

if __name__ == '__main__': main(capture_profiles.arguments(sys.argv[1:]))
