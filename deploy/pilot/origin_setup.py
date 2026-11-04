"""Internal journaled schema preparation for the closed local origin pilot.

This does not prepare credentials, enroll origins, start services, or qualify a
pilot. SQL is restricted to the fixed local database provisioning connection.
"""
from deploy.local import capture_profiles, provision
from deploy.pilot import origin_catalog_capture, origin_credentials, origin_enrollment, origin_logins, origin_schema, origin_setup_state as state

ROOT = capture_profiles.ROOT
GROUPS = ('contour_v2_ingress', 'contour_origin_ingress')
MIGRATIONS = {
    15: ROOT/'db/opt-in-migrations/0015_origin_lifecycle.sql',
    16: ROOT/'db/opt-in-migrations/0016_v2_unattributed.sql',
    17: ROOT/'db/opt-in-migrations/0017_origin_proofs.sql',
}
LOCK = 'SELECT pg_catalog.pg_advisory_xact_lock(1330792272, 1);'


def _ledger(psql):
    raw = psql('SELECT version FROM contour.schema_migrations ORDER BY version;')
    try: versions = [int(item) for item in raw.splitlines()]
    except (ValueError, AttributeError): raise RuntimeError('invalid schema ledger') from None
    if versions not in [list(range(1, n + 1)) for n in (14, 15, 16, 17)]:
        raise RuntimeError('unexpected schema ledger')
    return len(versions)


def _groups(psql, expected_origin_login=False):
    allowed = ("r.rolname='contour_origin_ingress' AND member.rolname='contour_local_origin_ingress' AND NOT m.admin_option AND m.inherit_option AND m.set_option"
               if expected_origin_login else 'FALSE')
    result = psql("""SELECT CASE WHEN count(*)=0 THEN 'ABSENT'
      WHEN count(*)=2 AND bool_and(NOT rolcanlogin AND rolinherit AND NOT rolsuper AND NOT rolbypassrls
        AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND rolconfig IS NULL)
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.member
          WHERE r.rolname IN ('contour_v2_ingress','contour_origin_ingress'))
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid
          JOIN pg_catalog.pg_roles member ON member.oid=m.member
          WHERE r.rolname IN ('contour_v2_ingress','contour_origin_ingress') AND NOT ("""+allowed+""")) THEN 'EXACT'
      ELSE 'DRIFT' END FROM pg_catalog.pg_roles WHERE rolname IN ('contour_v2_ingress','contour_origin_ingress');""")
    if result not in (state.ABSENT, state.EXACT, state.DRIFT): raise RuntimeError('invalid group inspection')
    return result


def _stage_objects(psql, version):
    # Verify presence, owner, FORCE RLS and key guarding interfaces. Full 17
    # readiness has the stronger catalog checks shared with ordinary startup.
    if version == 15:
        names = ('origin_lifecycles','origin_credentials','origin_observer_grants','origin_terminal_events')
        fn = 'enroll_origin(uuid,uuid,uuid,uuid,uuid,uuid,uuid,text,bytea)'
    elif version == 16:
        names = ('ingestion_v2_metadata',)
        fn = None
    else:
        names = ('origin_proofs','origin_pending_batch','origin_tenant_state','catalog_origin_heads')
        fn = 'begin_origin_ingress(uuid,uuid)'
    expected = ','.join("('"+name+"')" for name in names)
    function = "true" if fn is None else "pg_catalog.to_regprocedure('contour."+fn+"') IS NOT NULL"
    sql = f"""WITH expected(name) AS (VALUES {expected}), objects AS (
      SELECT e.name,c.oid,c.relrowsecurity,c.relforcerowsecurity,r.rolname FROM expected e
      LEFT JOIN pg_catalog.pg_class c ON c.oid=pg_catalog.to_regclass('contour.'||e.name)
      LEFT JOIN pg_catalog.pg_roles r ON r.oid=c.relowner)
    SELECT CASE WHEN count(oid)=0 AND NOT ({function}) THEN 'ABSENT'
      WHEN count(oid)={len(names)} AND bool_and(relrowsecurity AND relforcerowsecurity AND rolname='contour_owner')
        AND ({function}) THEN 'EXACT' ELSE 'DRIFT' END FROM objects;"""
    # 16 has no separate representative function; its only representative is
    # the table. This expression keeps the absent test symmetric.
    if fn is None: sql = sql.replace('count(oid)=0 AND NOT (true)', 'count(oid)=0')
    result = psql(sql)
    if result not in (state.ABSENT,state.EXACT,state.DRIFT): raise RuntimeError('invalid schema inspection')
    return result


def _partial_guards(psql, version, ledger):
    if ledger not in (15,16) or ledger < version: return False
    if version == 15:
        selected = [t for t in origin_schema.TRIGGERS if t[0] in
                    ('origin_lifecycles','origin_credentials','origin_observer_grants','origin_terminal_events')
                    and t[1] != 'origin_z_fact_epoch']
        signatures = [name for name in origin_schema.FUNCTIONS if name.startswith(
            ('enroll_origin(', 'enroll_origin_credential(', 'grant_origin_observer(', 'end_origin('))]
        funcs = ','.join("('"+name+"')" for name in signatures)
        extra = f"""AND NOT EXISTS (SELECT 1 FROM (VALUES {funcs}) e(sig)
          LEFT JOIN pg_catalog.pg_proc p ON p.oid=pg_catalog.to_regprocedure('contour.'||e.sig)
          WHERE p.oid IS NULL OR NOT pg_catalog.has_function_privilege('contour_admin',p.oid,'EXECUTE')
          OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
            WHERE a.grantee=0 AND a.privilege_type='EXECUTE'))"""
    else:
        selected = [t for t in origin_schema.TRIGGERS if t[0]=='ingestion_v2_metadata'
                    and t[1] in ('immutable_v2_metadata','no_truncate_v2_metadata')]
        extra = """AND NOT EXISTS (SELECT 1 FROM (VALUES
          ('ingestion_batches','ingestion_v1_only'),('ingestion_payloads','payload_v1_only')) e(tab,name)
          WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p
            JOIN pg_catalog.pg_roles r ON r.rolname='contour_ingestion'
            WHERE p.polrelid=pg_catalog.to_regclass('contour.'||e.tab) AND p.polname=e.name
              AND NOT p.polpermissive AND p.polcmd='a' AND p.polroles=ARRAY[r.oid] AND p.polwithcheck IS NOT NULL))"""
    rows = ','.join("('"+tab+"','"+name+"','"+fn+"',"+str(kind)+")" for tab,name,fn,_,kind in selected)
    catalog_matches = origin_catalog_capture.reference_matches_sql(ledger)
    query = f"""SELECT (({catalog_matches}) AND NOT EXISTS (SELECT 1 FROM (VALUES {rows}) e(tab,name,fn,kind)
      WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
        JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE t.tgrelid=pg_catalog.to_regclass('contour.'||e.tab) AND t.tgname=e.name
          AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype=e.kind
          AND n.nspname='contour' AND p.proname=e.fn)) {extra})::text;"""
    return psql(query) == 'true'


def _absent_sql(versions):
    representatives = {
        15: (('origin_lifecycles','origin_credentials','origin_observer_grants','origin_terminal_events'),
             'enroll_origin(uuid,uuid,uuid,uuid,uuid,uuid,uuid,text,bytea)'),
        16: (('ingestion_v2_metadata',), None),
        17: (('origin_proofs','origin_pending_batch','origin_tenant_state','catalog_origin_heads'),
             'begin_origin_ingress(uuid,uuid)'),
    }
    predicates = []
    for version in versions:
        tables, function = representatives[version]
        predicates.extend("pg_catalog.to_regclass('contour."+table+"') IS NULL" for table in tables)
        if function:
            predicates.append("pg_catalog.to_regprocedure('contour."+function+"') IS NULL")
    return ' AND '.join(predicates) or 'true'


class Groups:
    def __init__(self, psql, context=None): self.psql, self.context = psql, context if context is not None else {'login':False}
    def inspect(self):
        try: ledger = _ledger(self.psql)
        except RuntimeError: return state.DRIFT
        status = _groups(self.psql, self.context['login'])
        if status == state.ABSENT and ledger == 14 and all(_stage_objects(self.psql, n) == state.ABSENT for n in (15,16,17)):
            return state.ABSENT
        if status == state.EXACT: return state.EXACT
        return state.DRIFT
    def apply(self):
        self.psql("""BEGIN; """ + LOCK + """
          DO $$ BEGIN IF pg_catalog.current_database()<>'contour_local' THEN RAISE EXCEPTION 'wrong local database'; END IF;
          IF (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,14))
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname IN ('contour_v2_ingress','contour_origin_ingress'))
          OR NOT (""" + _absent_sql((15,16,17)) + """)
          THEN RAISE EXCEPTION 'origin setup state changed'; END IF; END $$;
          CREATE ROLE contour_v2_ingress NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
          CREATE ROLE contour_origin_ingress NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
          COMMIT;""")


class Migration:
    def __init__(self, psql, version, context=None): self.psql, self.version, self.source, self.context = psql, version, None, context if context is not None else {'login':False}
    def inspect(self):
        try: ledger = _ledger(self.psql)
        except RuntimeError: return state.DRIFT
        if _groups(self.psql, self.context['login']) != state.EXACT: return state.DRIFT
        objects = _stage_objects(self.psql, self.version)
        if ledger == self.version - 1 and objects == state.ABSENT:
            # Later-stage artifacts cannot be silently adopted either.
            if all(_stage_objects(self.psql, n) == state.ABSENT for n in range(self.version+1,18)):
                return state.ABSENT
            return state.DRIFT
        if ledger >= self.version and objects == state.EXACT:
            if ledger < 17 and not _partial_guards(self.psql, self.version, ledger): return state.DRIFT
            if ledger == 17:
                try: origin_schema.require_ready(self.psql, expected_origin_login=self.context['login'])
                except RuntimeError: return state.DRIFT
            return state.EXACT
        return state.DRIFT
    def apply(self):
        if self.source is None: raise RuntimeError('migration source not bound')
        text = self.source.decode('utf-8')
        if not text.lstrip().startswith('--') or '\nBEGIN;\n' not in text:
            raise RuntimeError('unexpected migration source')
        previous = self.version - 1
        guard = LOCK + f""" DO $$ BEGIN IF pg_catalog.current_database()<>'contour_local' THEN RAISE EXCEPTION 'wrong local database'; END IF; IF (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
          IS DISTINCT FROM ARRAY(SELECT generate_series(1,{previous})) OR NOT ({_absent_sql(range(self.version,18))}) THEN RAISE EXCEPTION 'origin setup ledger changed'; END IF; END $$;\n"""
        self.psql(text.replace('\nBEGIN;\n', '\nBEGIN;\n'+guard, 1))


def _prepare(profile, psql, credential=None, login=None, enrollment=False):
    if profile is not capture_profiles.ORIGIN_PILOT: raise ValueError('unsupported origin profile')
    if psql('SELECT pg_catalog.current_database()::text;') != 'contour_local': raise RuntimeError('wrong local database')
    context={'login':False}
    operations = {'groups': Groups(psql,context), **{'migration_'+str(v): Migration(psql,v,context) for v in (15,16,17)}}
    if credential is not None: operations['credentials'] = credential
    if login is not None: operations['logins'] = login
    observer = origin_enrollment.Observer(profile,psql) if enrollment else None
    if observer is not None:
        operations['observer'] = observer
        for number,slot in enumerate(profile.origins,1):
            operations[f'origin_{number}_target'] = origin_enrollment.Target(profile,psql,slot)
            for kind in ('lifecycle','credential','grant'):
                operations[f'origin_{number}_{kind}'] = origin_enrollment.Fact(profile,psql,slot,kind)
    def bind_sources(snapshot):
        for version in (15,16,17):
            operations['migration_'+str(version)].source = snapshot[str(MIGRATIONS[version].relative_to(ROOT))]
    def set_context(current):
        if current['completed'] >= 7 or current['pending']=='observer':
            if observer is None or credential is None: raise ValueError('observer context unavailable')
            if observer.policy() is not None: credential.allow_observer_policy=True
        if current['completed'] >= len(state.LOGIN_PHASES) or current['pending']=='logins':
            if login is None or credential is None or credential.inspect()!=state.EXACT or credential.commitment()!=current['credential_digest']:
                raise ValueError('login context credential drift')
            status=login.inspect()
            if status==state.EXACT: context['login']=True
            elif status!=state.ABSENT or current['completed'] >= len(state.LOGIN_PHASES):
                raise ValueError('login context drift')
    state.run(profile, operations, bind_sources=bind_sources, through_credentials=credential is not None,
              through_logins=login is not None, through_enrollment=enrollment, set_context=set_context)


def prepare_schema(profile=capture_profiles.ORIGIN_PILOT, *, psql=provision.psql):
    """Journal explicitly requested schema preparation; never reports pilot ready."""
    _prepare(profile, psql)
    return {'schema_ready': True, 'pilot_ready': False}


def prepare_credentials(profile, ca_cert, ca_key, *, psql=provision.psql):
    """Prepare the closed identity bundle; no policy, login or pilot runtime."""
    _prepare(profile, psql, origin_credentials.Credentials(profile,ca_cert,ca_key))
    return {'schema_ready': True, 'credentials_ready': True, 'pilot_ready': False}


def prepare_logins(profile, ca_cert, ca_key, *, psql=provision.psql, sensitive_execute, authenticate):
    """Prepare fixed logins with caller-verified password authentication."""
    credential=origin_credentials.Credentials(profile,ca_cert,ca_key)
    login=origin_logins.Logins(profile,psql,sensitive_execute,authenticate)
    _prepare(profile,psql,credential,login)
    return {'schema_ready':True,'credentials_ready':True,'logins_ready':True,'pilot_ready':False}


def prepare_enrollment(profile, ca_cert, ca_key, *, psql=provision.psql, sensitive_execute, authenticate):
    """Prepare synthetic registry only; never report a runtime pilot ready."""
    credential=origin_credentials.Credentials(profile,ca_cert,ca_key)
    login=origin_logins.Logins(profile,psql,sensitive_execute,authenticate)
    _prepare(profile,psql,credential,login,enrollment=True)
    import datetime
    policy=origin_enrollment.Observer(profile,psql).policy()
    if policy is None: raise ValueError('initial observer policy unavailable')
    issued=datetime.datetime.fromisoformat(policy[1]['issued_at'].replace('Z','+00:00'))
    expires=datetime.datetime.fromisoformat(policy[1]['expires_at'].replace('Z','+00:00'))
    now=datetime.datetime.now(datetime.timezone.utc)
    return {'schema_ready':True,'credentials_ready':True,'logins_ready':True,'enrollment_prepared':True,
            'policy_current':issued<=now<expires,'pilot_ready':False}
