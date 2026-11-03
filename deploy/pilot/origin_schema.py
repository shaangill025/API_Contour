"""Read-only readiness checks for an already installed opt-in origin schema.

This checks catalog interfaces and guards under a trusted database owner; it is
not an attestation of SQL function bodies or a replacement for migrations.
"""
TABLES = ('origin_lifecycles', 'origin_credentials', 'origin_observer_grants',
          'origin_terminal_events', 'origin_tenant_state', 'origin_ingress_context',
          'origin_proofs', 'origin_logical_usage', 'origin_batch_proof_completion',
          'origin_pending_batch', 'catalog_origin_projection', 'catalog_origin_heads',
          'ingestion_v2_metadata')
PRIVATE = ('origin_tenant_state', 'origin_ingress_context', 'origin_proofs',
           'origin_logical_usage', 'origin_batch_proof_completion', 'origin_pending_batch',
           'catalog_origin_heads')
TRIGGERS = [(table, trigger, function, deferred, kind) for table in
    ('origin_lifecycles', 'origin_credentials', 'origin_observer_grants', 'origin_terminal_events')
    for trigger, function, deferred, kind in (
        ('origin_immutable', 'immutable_row', False, 27), ('origin_no_truncate', 'immutable_row', False, 34),
        ('origin_insert_guard', 'guard_origin_insert', False, 7), ('origin_z_fact_epoch', 'assign_origin_fact_epoch', False, 7))]
TRIGGERS += [
    ('ingestion_v2_metadata', 'immutable_v2_metadata', 'immutable_row', False, 27),
    ('ingestion_v2_metadata', 'no_truncate_v2_metadata', 'immutable_row', False, 34),
    ('ingestion_v2_metadata', 'enqueue_origin_pending_batch', 'enqueue_origin_pending_batch', False, 5),
    ('ingestion_payloads', 'mark_origin_payload_provenance', 'mark_origin_payload_provenance', False, 7),
    ('origin_ingress_context', 'cleanup_origin_ingress_context', 'cleanup_origin_ingress_context', True, 5),
    ('origin_pending_batch', 'check_origin_pending_batch', 'check_origin_pending_batch', True, 5),
    ('origin_proofs', 'origin_proof_immutable', 'immutable_row', False, 27),
    ('origin_proofs', 'origin_proof_no_truncate', 'immutable_row', False, 34),
    ('origin_batch_proof_completion', 'origin_batch_completion_immutable', 'immutable_row', False, 27),
    ('origin_batch_proof_completion', 'origin_batch_completion_no_truncate', 'immutable_row', False, 34),
    ('catalog_origin_projection', 'catalog_origin_immutable', 'immutable_row', False, 27),
    ('catalog_origin_projection', 'catalog_origin_no_truncate', 'immutable_row', False, 34)]
# Signatures and exact non-owner EXECUTE grantees for the externally callable
# origin interfaces and private trigger helpers used by the checks above.
FUNCTIONS = {
    'enroll_origin(uuid,uuid,uuid,uuid,uuid,uuid,uuid,text,bytea)': ('contour_admin',),
    'enroll_origin_credential(uuid,uuid,uuid,bytea)': ('contour_admin',),
    'grant_origin_observer(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid)': ('contour_admin',),
    'end_origin(uuid,text,uuid)': ('contour_admin',),
    'begin_origin_ingress(uuid,uuid)': ('contour_origin_ingress',),
    'require_origin_ingress(uuid,uuid)': ('contour_origin_ingress',),
    'resolve_origin_record(uuid,uuid,uuid,uuid,bytea)': ('contour_origin_ingress',),
    'verify_origin_proof(uuid,uuid)': ('contour_catalog_worker','contour_origin_ingress'),
    'verify_origin_batch_proofs(uuid,uuid,uuid,bytea)': ('contour_catalog_worker','contour_origin_ingress'),
    'write_origin_batch_proofs(uuid,uuid,uuid,bytea)': ('contour_origin_ingress',),
    'origin_insert_authorized(uuid,uuid)': ('contour_origin_ingress',),
    'catalog_origin_mapping(uuid,uuid,uuid,bytea)': ('contour_catalog_worker',),
    'catalog_origin_absent(uuid,uuid,uuid)': ('contour_catalog_worker',),
    'catalog_origin_requires_canonical(uuid,uuid,uuid)': ('contour_catalog_worker',),
    'origin_retry_requires_canonical(uuid,uuid,uuid)': ('contour_origin_ingress',),
    'project_catalog_origins(uuid,uuid,uuid,bytea)': ('contour_catalog_worker',),
    'human_origin_candidates(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,integer)': ('contour_catalog_reader',),
    'human_origin_operation(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid)': ('contour_catalog_reader',),
    'mark_origin_payload_provenance()': (), 'enqueue_origin_pending_batch()': (),
    'check_origin_pending_batch()': (), 'cleanup_origin_ingress_context()': (),
    'guard_origin_insert()': (), 'assign_origin_fact_epoch()': (),
    'origin_lock_held(integer,integer)': (), 'origin_collector_lock_held(uuid,uuid)': (),
    'begin_origin_operation(uuid)': (), 'lock_origin_credential(bytea)': (),
    'lock_origin_collector(uuid,uuid)': (), 'require_origin_locks(uuid,uuid,bytea)': (),
    'origin_server_time()': (), 'origin_lifecycle_highwater(uuid,uuid)': (),
    'origin_history_highwater(uuid,uuid)': (), 'ensure_origin_tenant_state(uuid)': (),
    'parse_origin_batch(uuid,uuid,uuid,bytea)': (),
    'resolve_origin_record_checked(uuid,uuid,contour.ingestion_v2_metadata,jsonb)': (),
    'encode_origin_proof(contour.origin_proofs)': (),
    'verify_origin_proof_parsed(uuid,contour.origin_proofs,contour.ingestion_batches,contour.ingestion_v2_metadata,jsonb)': (),
    'origin_proof_set_digest(uuid,uuid,uuid)': (),
    'verify_origin_batch_parsed(uuid,uuid,uuid,contour.ingestion_batches,jsonb)': (),
}


DEFINER = {'enroll_origin','enroll_origin_credential','grant_origin_observer','end_origin',
    'cleanup_origin_ingress_context','begin_origin_ingress','require_origin_ingress',
    'resolve_origin_record','verify_origin_proof','verify_origin_batch_proofs',
    'write_origin_batch_proofs','origin_insert_authorized','mark_origin_payload_provenance',
    'enqueue_origin_pending_batch','check_origin_pending_batch','catalog_origin_mapping',
    'catalog_origin_absent','catalog_origin_requires_canonical','origin_retry_requires_canonical',
    'project_catalog_origins','human_origin_candidates','human_origin_operation'}
TABLE_GRANTS = [(table,'contour_admin','SELECT') for table in
    ('origin_lifecycles','origin_credentials','origin_observer_grants','origin_terminal_events')]
TABLE_GRANTS += [('catalog_origin_projection','contour_catalog_worker','SELECT'),
    ('ingestion_v2_metadata','contour_v2_ingress','SELECT'),
    ('ingestion_v2_metadata','contour_v2_ingress','INSERT'),
    ('ingestion_v2_metadata','contour_origin_ingress','SELECT'),
    ('ingestion_v2_metadata','contour_origin_ingress','INSERT'),
    ('ingestion_v2_metadata','contour_catalog_worker','SELECT')]


def _q(value): return "'" + value.replace("'", "''") + "'"
def _values(rows): return ','.join('(' + ','.join(_q(x) for x in row) + ')' for row in rows)


def readiness_sql(*, expected_origin_login=False):
    if type(expected_origin_login) is not bool:
        raise ValueError('invalid origin login context')
    # Only the fixed future profile login may be allowed, and only when the
    # caller has independently established its committed journal phase.
    allowed = ("target.rolname='contour_origin_ingress' AND member.rolname='contour_local_origin_ingress' AND NOT m.admin_option AND m.inherit_option AND m.set_option"
               if expected_origin_login else 'FALSE')
    login_check = """EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname='contour_local_origin_ingress'
        AND r.rolcanlogin AND r.rolinherit AND NOT r.rolsuper AND NOT r.rolbypassrls
        AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND r.rolconfig IS NULL)
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid WHERE r.rolname='contour_local_origin_ingress')
      AND (SELECT array_agg(p.rolname::text ORDER BY p.rolname::text) FROM pg_catalog.pg_roles p
        WHERE p.rolname<>'contour_local_origin_ingress'
          AND pg_catalog.pg_has_role('contour_local_origin_ingress',p.oid,'MEMBER')) = ARRAY['contour_origin_ingress']""" if expected_origin_login else 'true'
    tables = _values((name,) for name in TABLES)
    private = _values((name,) for name in PRIVATE)
    triggers = _values((t,n,f,'true' if d else 'false',str(k)) for t,n,f,d,k in TRIGGERS)
    funcs = _values((name, ','.join(sorted(roles)), 'true' if name.split('(')[0] in DEFINER else 'false') for name,roles in FUNCTIONS.items())
    grants = _values(TABLE_GRANTS)
    # The reference is an explicitly reviewed, fresh PG16 schema-only capture;
    # compare complete policy and ACL inventories, never adopt live state.
    from deploy.pilot import origin_catalog_capture
    catalog_matches = origin_catalog_capture.reference_matches_sql(17)
    return f"""WITH expected_tables(name) AS (VALUES {tables}),
    private_tables(name) AS (VALUES {private}),
    expected_triggers(tab, name, fn, deferred, kind) AS (VALUES {triggers}),
    expected_functions(signature, grantees, definer) AS (VALUES {funcs}),
    expected_grants(tab, role, privilege) AS (VALUES {grants})
SELECT (
  ({catalog_matches})
  AND (SELECT count(*)=2 FROM pg_catalog.pg_roles WHERE rolname IN ('contour_v2_ingress','contour_origin_ingress')
    AND NOT rolcanlogin AND rolinherit AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole
    AND NOT rolcreatedb AND NOT rolreplication AND rolconfig IS NULL)
  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.member
    WHERE r.rolname IN ('contour_v2_ingress','contour_origin_ingress'))
  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles target ON target.oid=m.roleid JOIN pg_catalog.pg_roles member ON member.oid=m.member
    WHERE target.rolname IN ('contour_v2_ingress','contour_origin_ingress')
      AND NOT ({allowed}))
  AND ({login_check})
  AND NOT EXISTS (SELECT 1 FROM expected_tables e LEFT JOIN pg_catalog.pg_class c ON c.oid=pg_catalog.to_regclass('contour.'||e.name)
    LEFT JOIN pg_catalog.pg_roles o ON o.oid=c.relowner
    WHERE c.oid IS NULL OR c.relkind<>'r' OR o.rolname<>'contour_owner' OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
  AND NOT EXISTS (SELECT 1 FROM (
    (SELECT e.name tab,coalesce(r.rolname,'PUBLIC') role,a.privilege_type privilege
      FROM expected_tables e JOIN pg_catalog.pg_class c ON c.oid=pg_catalog.to_regclass('contour.'||e.name)
      CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
      LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE a.grantee<>c.relowner
      EXCEPT SELECT tab,role,privilege FROM expected_grants)
    UNION ALL
    (SELECT tab,role,privilege FROM expected_grants EXCEPT
      SELECT e.name,coalesce(r.rolname,'PUBLIC'),a.privilege_type
      FROM expected_tables e JOIN pg_catalog.pg_class c ON c.oid=pg_catalog.to_regclass('contour.'||e.name)
      CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
      LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE a.grantee<>c.relowner)) drift)
  AND NOT EXISTS (SELECT 1 FROM expected_tables e JOIN pg_catalog.pg_class c ON c.oid=pg_catalog.to_regclass('contour.'||e.name)
    CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
    WHERE a.grantee<>c.relowner AND a.is_grantable)
  AND NOT EXISTS (SELECT 1 FROM expected_tables e JOIN pg_catalog.pg_class c ON c.oid=pg_catalog.to_regclass('contour.'||e.name)
    JOIN pg_catalog.pg_attribute col ON col.attrelid=c.oid AND col.attnum>0 AND NOT col.attisdropped
    CROSS JOIN LATERAL pg_catalog.aclexplode(col.attacl) a
    WHERE a.grantee<>c.relowner)
  AND NOT EXISTS (SELECT 1 FROM expected_triggers e WHERE NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
    JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    WHERE t.tgrelid=pg_catalog.to_regclass('contour.'||e.tab) AND t.tgname=e.name AND t.tgenabled='O'
      AND NOT t.tgisinternal AND t.tgtype=e.kind::smallint AND n.nspname='contour' AND p.proname=e.fn
      AND t.tgdeferrable=e.deferred::boolean AND t.tginitdeferred=e.deferred::boolean))
  AND NOT EXISTS (SELECT 1 FROM (VALUES
    ('ingestion_batches','ingestion_v1_only','contour_ingestion'),
    ('ingestion_payloads','payload_v1_only','contour_ingestion'),
    ('ingestion_v2_metadata','v2_metadata_unattributed_only','contour_v2_ingress')) AS e(tab,policy,role)
    WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_roles r ON r.rolname=e.role
      WHERE p.polrelid=pg_catalog.to_regclass('contour.'||e.tab) AND p.polname=e.policy
      AND NOT p.polpermissive AND p.polcmd='a' AND p.polroles=ARRAY[r.oid] AND p.polwithcheck IS NOT NULL))
  AND EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=pg_catalog.to_regclass('contour.ingestion_payloads')
    AND a.attname='origin_writer_provenance' AND a.atttypid='pg_catalog.bool'::pg_catalog.regtype AND a.attnotnull AND NOT a.attisdropped)
  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname IN
    ('contour_ingestion','contour_v2_ingress','contour_origin_ingress')
    AND pg_catalog.has_column_privilege(r.oid,pg_catalog.to_regclass('contour.ingestion_payloads'),'origin_writer_provenance','INSERT'))
  AND NOT EXISTS (SELECT 1 FROM expected_functions e LEFT JOIN pg_catalog.pg_proc p ON p.oid=pg_catalog.to_regprocedure('contour.'||e.signature)
    LEFT JOIN pg_catalog.pg_roles o ON o.oid=p.proowner WHERE p.oid IS NULL OR o.rolname<>'contour_owner' OR p.prosecdef<>e.definer::boolean
    OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog']
    OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
      WHERE a.grantee<>p.proowner AND a.is_grantable)
    OR coalesce((SELECT string_agg(CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE r.rolname END, ',' ORDER BY CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE r.rolname END)
      FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
      LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
      WHERE a.privilege_type='EXECUTE' AND a.grantee<>p.proowner), '') <> e.grantees)
)::text;"""


def require_ready(psql, *, expected_origin_login=False):
    if psql(readiness_sql(expected_origin_login=expected_origin_login)) != 'true':
        raise RuntimeError('opt-in origin schema readiness drift')
