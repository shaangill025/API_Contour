"""Disposable fixture provisioning for the opt-in full 1..21 profile."""
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[1]


def apply_base(execute):
    session = runpy.run_path(str(ROOT / 'scripts/test-postgres-causal-sessions.py'))
    execute((ROOT / 'db/bootstrap.sql').read_text())
    for name in session['PROVISIONS']:
        execute((ROOT / ('db/provision_' + name + '.sql')).read_text())
    for name in session['MIGRATIONS']:
        execute((ROOT / ('db/migrations/' + name + '.sql')).read_text())


SIGNATURE = "contour.resolve_origin_record_checked(uuid,uuid,contour.ingestion_v2_metadata,jsonb)"
CATALOG_QUERY = ("SELECT concat_ws('|',p.oid::text,p.proowner::text,p.prosecdef::text,"
                 "p.provolatile::text,coalesce(p.proconfig::text,''),coalesce(p.proacl::text,'')) "
                 "FROM pg_catalog.pg_proc p WHERE p.oid='" + SIGNATURE + "'::regprocedure;")

BOUNDARY_QUERY = ("SELECT (p.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='contour_owner') "
                  "AND NOT p.prosecdef AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog'] "
                  "AND NOT has_function_privilege('contour_origin_ingress',p.oid,'EXECUTE') "
                  "AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')) "
                  "FROM pg_catalog.pg_proc p WHERE p.oid='" + SIGNATURE + "'::regprocedure;")

VERIFIER_QUERY = ("SELECT md5(pg_catalog.pg_get_functiondef(p.oid)) || '|' || p.proowner::text || '|' || coalesce(p.proacl::text,'') "
                  "FROM pg_catalog.pg_proc p WHERE p.oid='contour.verify_origin_proof(uuid,uuid)'::regprocedure;")


def apply_through_20(execute):
    session = runpy.run_path(str(ROOT / 'scripts/test-postgres-causal-sessions.py'))
    inbox = runpy.run_path(str(ROOT / 'scripts/test-postgres-causal-inbox.py'))
    for name in (*session['OPT_INS'], inbox['OPT_INS'][-1]):
        execute((ROOT / ('db/opt-in-migrations/' + name + '.sql')).read_text())


def apply_21(execute):
    before=execute(CATALOG_QUERY)
    verifier=execute(VERIFIER_QUERY)
    if not before or not verifier or execute(BOUNDARY_QUERY) != 't': raise RuntimeError('origin resolver catalog unavailable')
    execute((ROOT / 'db/opt-in-migrations/0021_origin_admission.sql').read_text())
    if execute(CATALOG_QUERY) != before or execute(VERIFIER_QUERY) != verifier or execute(BOUNDARY_QUERY) != 't': raise RuntimeError('origin resolver catalog changed')
    if execute('SELECT array_agg(version ORDER BY version)::text FROM contour.schema_migrations;') != '{' + ','.join(map(str, range(1, 22))) + '}':
        raise RuntimeError('origin admission migration ledger mismatch')


def apply_opt_ins(execute):
    apply_through_20(execute)
    apply_21(execute)
