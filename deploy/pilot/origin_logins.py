"""Fixed restricted logins for the internal origin setup journal.

Authentication is delegated to a trusted callback. The separate mandatory
sensitive executor must establish a dedicated database session with statement
and error-statement logging disabled before parsing verifier-bearing SQL. Neither
the verifier nor SQL may be logged or passed as a process argument.
"""
import base64
import hashlib
import hmac
import secrets

from deploy.local import capture_profiles, provision
from deploy.pilot import origin_credentials, origin_setup_state as state

LOCK = 'SELECT pg_catalog.pg_advisory_xact_lock(1330792272, 1);'
ROLES = (('contour_local_origin_ingress','contour_origin_ingress','ingress'),
         ('contour_local_origin_worker','contour_catalog_worker','worker'))


def scram_verifier(password, salt):
    """Derive PostgreSQL SCRAM-SHA-256 verifier; both input and output are sensitive."""
    if not isinstance(password,str) or not password.isascii() or not password or not isinstance(salt,bytes) or len(salt)!=16:
        raise ValueError('invalid SCRAM input')
    salted=hashlib.pbkdf2_hmac('sha256',password.encode('ascii'),salt,4096)
    client=hmac.new(salted,b'Client Key',hashlib.sha256).digest()
    stored=hashlib.sha256(client).digest()
    server=hmac.new(salted,b'Server Key',hashlib.sha256).digest()
    enc=lambda value: base64.b64encode(value).decode('ascii')
    return 'SCRAM-SHA-256$4096:'+enc(salt)+'$'+enc(stored)+':'+enc(server)


class Logins:
    def __init__(self, profile, psql, sensitive_execute, authenticate):
        if profile is not capture_profiles.ORIGIN_PILOT or not callable(authenticate) or not callable(sensitive_execute) or sensitive_execute is psql:
            raise ValueError('closed profile and authentication callback required')
        self.profile, self.psql, self.sensitive_execute, self.authenticate = profile, psql, sensitive_execute, authenticate

    def _password(self, name):
        raw=origin_credentials._file(self.profile.state/('capture/runtime/'+name+'.password'),4096)
        try: password=raw.decode('ascii')
        except UnicodeDecodeError: raise ValueError('invalid credential') from None
        if not password or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in password):
            raise ValueError('invalid credential')
        return password

    def inspect(self):
        result=self.psql("""WITH wanted(login, grp) AS (VALUES
          ('contour_local_origin_ingress','contour_origin_ingress'),
          ('contour_local_origin_worker','contour_catalog_worker')),
        roles AS (SELECT w.*,r.oid,r.rolcanlogin,r.rolinherit,r.rolsuper,r.rolbypassrls,
          r.rolcreaterole,r.rolcreatedb,r.rolreplication,r.rolconfig,r.rolconnlimit,r.rolvaliduntil
          FROM wanted w LEFT JOIN pg_catalog.pg_roles r ON r.rolname=w.login)
        SELECT CASE WHEN count(oid)=0 THEN 'ABSENT'
        WHEN count(oid)=2 AND bool_and(rolcanlogin AND rolinherit AND NOT rolsuper AND NOT rolbypassrls
          AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND rolconfig IS NULL
          AND rolconnlimit=-1 AND rolvaliduntil IS NULL)
        AND NOT EXISTS (SELECT 1 FROM roles r WHERE
          (SELECT count(*) FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid)<>1
          OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles g ON g.oid=m.roleid
            WHERE m.member=r.oid AND g.rolname=r.grp AND NOT m.admin_option AND m.inherit_option AND m.set_option)
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.roleid=r.oid)
          OR (SELECT array_agg(g.rolname::text ORDER BY g.rolname::text) FROM pg_catalog.pg_roles g
              WHERE g.oid<>r.oid AND pg_catalog.pg_has_role(r.oid,g.oid,'MEMBER'))<>ARRAY[r.grp::text]
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting d WHERE d.setrole=r.oid)
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_shdepend d WHERE d.refclassid='pg_catalog.pg_authid'::pg_catalog.regclass
              AND d.refobjid=r.oid AND NOT
              (d.deptype='a' AND d.classid='pg_catalog.pg_database'::pg_catalog.regclass
                AND d.objid=(SELECT oid FROM pg_catalog.pg_database WHERE datname='contour_local')))
          OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database d,
              LATERAL pg_catalog.aclexplode(coalesce(d.datacl,pg_catalog.acldefault('d',d.datdba))) a
              WHERE d.datname='contour_local' AND a.grantee=r.oid AND a.privilege_type='CONNECT' AND NOT a.is_grantable)
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_database d,
              LATERAL pg_catalog.aclexplode(coalesce(d.datacl,pg_catalog.acldefault('d',d.datdba))) a
              WHERE a.grantee=r.oid AND (d.datname<>'contour_local' OR a.privilege_type<>'CONNECT' OR a.is_grantable))
        ) THEN 'EXACT' ELSE 'DRIFT' END FROM roles;""")
        if result not in (state.ABSENT,state.EXACT,state.DRIFT): raise RuntimeError('login inspection failed')
        if result!=state.EXACT: return result
        for role,_,name in ROLES:
            # The callback is trusted to perform a real password-authenticated
            # connection; its only accepted result is the literal boolean True.
            try: authenticated = self.authenticate(role,self._password(name))
            except Exception: raise RuntimeError('login authentication check failed') from None
            if authenticated is not True: return state.DRIFT
        return state.EXACT

    def apply(self):
        quote=provision.sql_quote
        ingress=self._password('ingress'); worker=self._password('worker')
        if ingress==worker: raise ValueError('independent credentials required')
        ingress_verifier=scram_verifier(ingress,secrets.token_bytes(16))
        worker_verifier=scram_verifier(worker,secrets.token_bytes(16))
        sql="""BEGIN; """+LOCK+"""
          DO $$ BEGIN IF pg_catalog.current_database()<>'contour_local' THEN RAISE EXCEPTION 'wrong local database'; END IF;
          IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname IN
             ('contour_local_origin_ingress','contour_local_origin_worker')) THEN
             RAISE EXCEPTION 'origin login state changed'; END IF;
             IF (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname IN ('contour_origin_ingress','contour_catalog_worker')
               AND NOT rolcanlogin AND rolinherit AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole
               AND NOT rolcreatedb AND NOT rolreplication AND rolconfig IS NULL)<>2
               OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid
                 WHERE r.rolname='contour_origin_ingress')
               OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.member
                 WHERE r.rolname IN ('contour_origin_ingress','contour_catalog_worker'))
             THEN RAISE EXCEPTION 'origin login group drift'; END IF; END $$;
          CREATE ROLE contour_local_origin_ingress LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD """+quote(ingress_verifier)+""";
          CREATE ROLE contour_local_origin_worker LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD """+quote(worker_verifier)+""";
          GRANT contour_origin_ingress TO contour_local_origin_ingress WITH ADMIN FALSE, INHERIT TRUE, SET TRUE;
          GRANT contour_catalog_worker TO contour_local_origin_worker WITH ADMIN FALSE, INHERIT TRUE, SET TRUE;
          GRANT CONNECT ON DATABASE contour_local TO contour_local_origin_ingress,contour_local_origin_worker;
          COMMIT;"""
        try: self.sensitive_execute(sql)
        except Exception: raise RuntimeError('login provisioning failed; state retained') from None
