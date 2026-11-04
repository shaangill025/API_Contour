"""Read-only schema metadata query for an explicitly selected reference DB.

The caller must provide the database connection. This module does not connect,
choose a database, store a baseline, inspect row data, or assert readiness.
"""
import json
from pathlib import Path
from deploy.pilot import origin_schema

# Fixed migration-affected scope, including old tables whose policies or grants
# are changed by opt-in migrations. Do not infer scope from a live database.
TABLES = origin_schema.TABLES + (
    'ingestion_batches', 'ingestion_payloads', 'sources', 'workload_assignments',
    'policy_revisions', 'collector_authorization', 'source_authorization',
    'workload_instances', 'observation_windows',
)
SHARED_FUNCTIONS = ('tenant_context()', 'collector_lock_key(uuid,uuid)',
    'guard_collector(uuid,uuid)', 'lock_collector(uuid,uuid)')
FUNCTIONS = tuple(origin_schema.FUNCTIONS) + SHARED_FUNCTIONS
EARLY_TABLES = ('origin_lifecycles','origin_credentials','origin_observer_grants','origin_terminal_events',
    'ingestion_batches','ingestion_payloads','sources','workload_assignments','policy_revisions',
    'collector_authorization','source_authorization','workload_instances','observation_windows')
EARLY_FUNCTIONS = tuple(name for name in FUNCTIONS if name.split('(')[0] in {
    'origin_lock_held','origin_collector_lock_held','begin_origin_operation','lock_origin_credential',
    'lock_origin_collector','require_origin_locks','origin_server_time','origin_history_highwater',
    'guard_origin_insert','enroll_origin','enroll_origin_credential','grant_origin_observer','end_origin'}) + SHARED_FUNCTIONS


def _scope(version):
    if type(version) is not int or version not in (15, 16, 17): raise ValueError('unsupported schema version')
    if version == 17: return TABLES, FUNCTIONS
    return EARLY_TABLES + (('ingestion_v2_metadata',) if version == 16 else ()), EARLY_FUNCTIONS


def _q(value): return "'" + value.replace("'", "''") + "'"


def capture_sql(version=17):
    selected_tables, selected_functions = _scope(version)
    tables = ','.join('('+_q(name)+')' for name in selected_tables)
    functions = ','.join('('+_q(name)+')' for name in selected_functions)
    return f"""WITH expected_tables(name) AS (VALUES {tables}),
    expected_functions(signature) AS (VALUES {functions}),
    tables AS (
      SELECT e.name,c.oid,c.relowner,c.relacl,c.relrowsecurity,c.relforcerowsecurity,
             o.rolname AS owner
      FROM expected_tables e LEFT JOIN pg_catalog.pg_class c ON c.oid=pg_catalog.to_regclass('contour.'||e.name)
      LEFT JOIN pg_catalog.pg_roles o ON o.oid=c.relowner
    ), functions AS (
      SELECT e.signature,p.oid,p.proowner,p.proacl,p.prosecdef,p.proconfig,o.rolname AS owner
      FROM expected_functions e LEFT JOIN pg_catalog.pg_proc p ON p.oid=pg_catalog.to_regprocedure('contour.'||e.signature)
      LEFT JOIN pg_catalog.pg_roles o ON o.oid=p.proowner
    )
    SELECT pg_catalog.jsonb_build_object(
      'schema', (SELECT pg_catalog.jsonb_build_object('present',true,'owner',owner.rolname,
        'acl',coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
          'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE r.rolname END,'grantor',g.rolname,
          'privilege',a.privilege_type,'grantable',a.is_grantable)
          ORDER BY CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE r.rolname END,a.privilege_type,g.rolname)
          FROM pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
          LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantor),'[]'::jsonb))
        FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles owner ON owner.oid=n.nspowner
        WHERE n.nspname='contour'),
      'tables', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'name',name,'present',oid IS NOT NULL,'owner',owner,'rls',relrowsecurity,'force_rls',relforcerowsecurity)
        ORDER BY name) FROM tables),'[]'::jsonb),
      'policies', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'table',t.name,'name',p.polname,'command',p.polcmd,'permissive',p.polpermissive,
        'roles',coalesce((SELECT pg_catalog.jsonb_agg(CASE WHEN role_oid=0 THEN 'PUBLIC' ELSE r.rolname END
            ORDER BY CASE WHEN role_oid=0 THEN 'PUBLIC' ELSE r.rolname END)
          FROM pg_catalog.unnest(p.polroles) AS roles(role_oid) LEFT JOIN pg_catalog.pg_roles r ON r.oid=role_oid),'[]'::jsonb),
        'using',pg_catalog.pg_get_expr(p.polqual,p.polrelid),
        'check',pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid)) ORDER BY t.name,p.polname)
        FROM tables t JOIN pg_catalog.pg_policy p ON p.polrelid=t.oid),'[]'::jsonb),
      'table_acl', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'table',t.name,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE r.rolname END,
        'grantor',g.rolname,'privilege',a.privilege_type,'grantable',a.is_grantable)
        ORDER BY t.name,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE r.rolname END,a.privilege_type,g.rolname)
        FROM tables t CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(t.relacl,pg_catalog.acldefault('r',t.relowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantor
        WHERE a.grantee<>t.relowner),'[]'::jsonb),
      'column_acl', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'table',t.name,'column',col.attname,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE r.rolname END,
        'grantor',g.rolname,'privilege',a.privilege_type,'grantable',a.is_grantable)
        ORDER BY t.name,col.attname,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE r.rolname END,a.privilege_type,g.rolname)
        FROM tables t JOIN pg_catalog.pg_attribute col ON col.attrelid=t.oid AND col.attnum>0 AND NOT col.attisdropped
        CROSS JOIN LATERAL pg_catalog.aclexplode(col.attacl) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantor
        WHERE a.grantee<>t.relowner),'[]'::jsonb),
      'functions', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'signature',f.signature,'present',f.oid IS NOT NULL,'owner',f.owner,
        'security_definer',f.prosecdef,'config',f.proconfig,
        'acl',coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
          'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE r.rolname END,'grantor',g.rolname,
          'privilege',a.privilege_type,'grantable',a.is_grantable)
          ORDER BY CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE r.rolname END,a.privilege_type,g.rolname)
          FROM pg_catalog.aclexplode(coalesce(f.proacl,pg_catalog.acldefault('f',f.proowner))) a
          LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantor),'[]'::jsonb))
        ORDER BY f.signature) FROM functions f),'[]'::jsonb)
    )::text;"""


def reference_matches_sql(version):
    """Compare live metadata with the fixed reviewed reference, never adopt it."""
    _scope(version)
    name = 'origin_reference_catalog.json' if version == 17 else 'origin_reference_catalog_' + str(version) + '.json'
    expected = json.loads(Path(__file__).with_name(name).read_text())
    encoded = _q(json.dumps(expected, sort_keys=True, separators=(',', ':')))
    query = capture_sql(version).rstrip().removesuffix(';')
    return '(' + query + ')::jsonb = ' + encoded + '::jsonb'


def capture(execute, version=17):
    """Return parsed reference metadata from the caller's explicitly chosen DB."""
    selected_tables, selected_functions = _scope(version)
    result = json.loads(execute(capture_sql(version)))
    if not isinstance(result, dict) or set(result) != {'schema','tables','policies','table_acl','column_acl','functions'}:
        raise ValueError('invalid reference catalog result')
    if not isinstance(result['schema'],dict) or result['schema'].get('present') is not True or not isinstance(result['schema'].get('acl'),list):
        raise ValueError('invalid reference catalog result')
    if any(not isinstance(result[key], list) for key in ('tables','policies','table_acl','column_acl','functions')):
        raise ValueError('invalid reference catalog result')
    if len(result['tables']) != len(selected_tables) or len(result['functions']) != len(selected_functions):
        raise ValueError('incomplete reference catalog result')
    if any(item.get('present') is not True for item in result['tables'] + result['functions']):
        raise ValueError('missing reference catalog object')
    return result
