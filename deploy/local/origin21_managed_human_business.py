"""Fixed human authorization setup on the owned, enrolled capture database."""
import json
import os
from deploy.local import (check_oidc, origin21_managed_human_secret, origin21_profile,
                          origin21_schema, origin21_transport, provision)
from deploy.pilot import origin_credentials


def _persist(path, value):
    encoded = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if os.path.lexists(path):
        if origin_credentials._file(path, 65536) != encoded: raise ValueError('human runtime config drift')
    else:
        origin_credentials._write(path, encoded)


def prepare(transport):
    if type(transport) is not origin21_transport.ManagedTransport or transport._selected is not origin21_profile.HUMAN:
        raise ValueError('human managed transport required')
    origin21_profile.require_context(origin21_profile.HUMAN)
    transport.verify()
    origin21_schema.require_reference(21, 'enrolled')
    versions=[int(v) for v in transport.admin('SELECT version FROM contour.schema_migrations ORDER BY version;').splitlines()]
    origin21_schema.require_ready(versions, transport.admin, stage=21, phase='enrolled')
    check_oidc.main(selected=origin21_profile.HUMAN)
    base=origin21_profile.HUMAN.profile.state.parent
    subjects=json.loads(origin_credentials._file(base/'subjects.json',16384))
    password=origin21_managed_human_secret.read_committed()
    psql=transport.admin
    groups=psql("SELECT p.rolname FROM pg_auth_members m JOIN pg_roles p ON p.oid=m.roleid JOIN pg_roles a ON a.oid=m.member WHERE a.rolname='contour_app' ORDER BY p.rolname;").splitlines()
    effective=psql("SELECT r.rolname FROM pg_roles r WHERE r.rolname <> 'contour_app' AND pg_has_role('contour_app',r.oid,'MEMBER') ORDER BY r.rolname;").splitlines()
    attrs=psql("SELECT (rolcanlogin AND rolinherit AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND rolconfig IS NULL)::text FROM pg_roles WHERE rolname='contour_app';")
    unsafe=psql("SELECT rolname FROM pg_roles WHERE rolname IN ("+','.join(map(provision.sql_quote, provision.GROUPS))+") AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR NOT rolinherit OR rolconfig IS NOT NULL) ORDER BY rolname;")
    if groups!=sorted(provision.GROUPS) or effective!=sorted(provision.GROUPS) or attrs!='true' or unsafe:
        raise ValueError('human app role drift')
    if not transport.authenticate_app(password): raise ValueError('human app TLS authentication failed')
    count=int(psql('SELECT count(*) FROM contour.human_actors WHERE actor_id IN ('+','.join(map(provision.sql_quote,provision.ACTORS))+');'))
    if count != 0: raise ValueError('human membership state already exists')
    psql(provision._human_statements(subjects,count,selected=origin21_profile.HUMAN))
    issuer='https://idp.mvp.localhost:18444/realms/apicontour-mvp'
    platform=dict(transport='managed_docker',issuer=issuer,authorization_endpoint=issuer+'/protocol/openid-connect/auth',
        token_endpoint=issuer+'/protocol/openid-connect/token',client_id='apicontour-mvp',callback='https://mvp.localhost:19443/auth/callback',
        tls_certificate='/run/config/server.crt',tls_private_key='/run/config/server.key',provider_ca='/run/config/ca.crt',jwks='/run/config/jwks.json')
    app=dict(database_host='postgres',database_port=5432,database_name='contour_local',database_user='contour_app',
        database_password_file='/run/config/database-password',database_ca_file='/run/config/ca.crt',
        tenant_id=provision.IDS[0],project_id=provision.IDS[1],service_id=provision.IDS[2],environment_id=provision.IDS[3],
        routes=[['/source','/orders']],approved_names=['id','name','status'],approved_media=['application/json','text/plain'])
    _persist(base/'container-platform.json',platform)
    _persist(base/'container-business.json',app)
    return {'identity_verified':True,'business_provisioned':True,'capture_verified':False,'ui_verified':False}
