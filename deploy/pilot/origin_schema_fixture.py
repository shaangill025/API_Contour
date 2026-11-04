"""Owned PostgreSQL fixture hook; caller supplies a disposable admin SQL executor.

Requires a disposable database already at exact ledger 1..17 with both opt-in
roles. No containers, connections, state creation, or credentials are managed here.
Each negative mutation is transactional and rolled back on the same connection.
"""
from unittest import mock
from deploy.local import provision
from deploy.pilot import origin_schema


def run_cases(execute):
    ledger = execute('SELECT version FROM contour.schema_migrations ORDER BY version;')
    if [int(v) for v in ledger.splitlines()] != list(range(1, 18)):
        raise AssertionError('fixture requires exact complete origin ledger')
    # NULL ACL is a valid absence of column grants; the zero-dimensional
    # empty ARRAY[] must never be passed to aclexplode on PostgreSQL.
    if execute('SELECT count(*) FROM pg_catalog.aclexplode(NULL::pg_catalog.aclitem[]);') != '0':
        raise AssertionError('unexpected NULL column ACL behavior')
    if execute('SELECT (pg_catalog.array_ndims(ARRAY[]::pg_catalog.aclitem[]) IS NULL)::text;') != 'true':
        raise AssertionError('unexpected empty ACL array dimensions')
    check = origin_schema.readiness_sql()
    if execute(check) != 'true':
        raise AssertionError('complete origin readiness rejected')
    negatives = {
        'guard': 'ALTER TABLE contour.ingestion_payloads DISABLE TRIGGER mark_origin_payload_provenance;',
        'wrong trigger event': 'DROP TRIGGER mark_origin_payload_provenance ON contour.ingestion_payloads; CREATE TRIGGER mark_origin_payload_provenance AFTER INSERT ON contour.ingestion_payloads FOR EACH ROW EXECUTE FUNCTION contour.mark_origin_payload_provenance();',
        'column': 'ALTER TABLE contour.ingestion_payloads ALTER COLUMN origin_writer_provenance DROP NOT NULL;',
        'role membership': 'GRANT contour_ingestion TO contour_v2_ingress;',
        'incoming membership': 'GRANT contour_origin_ingress TO contour_runtime;',
        'transitive membership': 'CREATE ROLE origin_fixture_middle NOLOGIN; GRANT contour_origin_ingress TO origin_fixture_middle; GRANT origin_fixture_middle TO contour_runtime;',
        'grant option': 'GRANT SELECT ON contour.origin_lifecycles TO contour_admin WITH GRANT OPTION;',
        'unexpected table grant': 'GRANT SELECT ON contour.origin_proofs TO contour_runtime;',
        'unexpected column grant': 'GRANT SELECT (lifecycle_id) ON contour.origin_lifecycles TO contour_runtime;',
        'unexpected policy': 'CREATE POLICY unexpected_read ON contour.origin_proofs TO contour_runtime USING (true); GRANT SELECT ON contour.origin_proofs TO contour_runtime;',
        'restrictive predicate': 'DROP POLICY ingestion_v1_only ON contour.ingestion_batches; CREATE POLICY ingestion_v1_only ON contour.ingestion_batches AS RESTRICTIVE FOR INSERT TO contour_ingestion WITH CHECK (true);',
        'required shared function grant': 'REVOKE EXECUTE ON FUNCTION contour.guard_collector(uuid,uuid) FROM contour_origin_ingress;',
        'unexpected shared function grant': 'GRANT EXECUTE ON FUNCTION contour.guard_collector(uuid,uuid) TO contour_catalog_reader;',
        'unexpected schema privilege': 'GRANT CREATE ON SCHEMA contour TO contour_runtime;',
        'function security': 'ALTER FUNCTION contour.begin_origin_ingress(uuid,uuid) SECURITY INVOKER;',
        'function search path': 'ALTER FUNCTION contour.begin_origin_ingress(uuid,uuid) RESET search_path;',
        'column grant': 'GRANT INSERT (origin_writer_provenance) ON contour.ingestion_payloads TO contour_origin_ingress;',
        'public function': 'GRANT EXECUTE ON FUNCTION contour.begin_origin_ingress(uuid,uuid) TO PUBLIC;',
    }
    for name, mutation in negatives.items():
        if execute('BEGIN; ' + mutation + check + ' ROLLBACK;') != 'false':
            raise AssertionError(name + ' drift was accepted')
    # The one future login exception is deliberately opt-in and requires the
    # complete PG16 membership edge, including no delegation rights.
    future = origin_schema.readiness_sql(expected_origin_login=True)
    prefix = 'BEGIN; CREATE ROLE contour_local_origin_ingress LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; '
    for label, grant, expected in (
        ('baseline', 'GRANT contour_origin_ingress TO contour_local_origin_ingress;', 'true'),
        ('admin option', 'GRANT contour_origin_ingress TO contour_local_origin_ingress WITH ADMIN TRUE;', 'false'),
        ('inherit option', 'GRANT contour_origin_ingress TO contour_local_origin_ingress WITH INHERIT FALSE;', 'false'),
        ('set option', 'GRANT contour_origin_ingress TO contour_local_origin_ingress WITH SET FALSE;', 'false'),
    ):
        if execute(prefix + grant + future + ' ROLLBACK;') != expected:
            raise AssertionError('future login '+label+' membership mismatch')
    if execute(check) != 'true':
        raise AssertionError('fixture mutation did not roll back')
    # Read a transactional ledger-14 view; dispatch must only recheck it and
    # never apply an opt-in migration. The transaction itself is rolled back.
    ledger14 = execute('BEGIN; DELETE FROM contour.schema_migrations WHERE version>14; SELECT version FROM contour.schema_migrations ORDER BY version; ROLLBACK;')
    if [int(v) for v in ledger14.splitlines()] != list(range(1, 15)):
        raise AssertionError('fixture ledger-14 view mismatch')
    with mock.patch.object(provision, 'psql', return_value=ledger14) as psql:
        provision.apply_migrations(list(range(1, 15)), list(range(1, 15)))
        if psql.call_count != 1 or not psql.call_args.args[0].startswith('SELECT version'):
            raise AssertionError('default ledger performed unexpected SQL')
    # The dispatcher must reject every incomplete or extra ledger before it
    # issues a query, including a partially applied opt-in migration sequence.
    for installed in (list(range(1, 16)), list(range(1, 17)), list(range(1, 19))):
        with mock.patch.object(provision, 'psql') as psql:
            try: provision.apply_migrations(installed, list(range(1, 15)))
            except RuntimeError: pass
            else: raise AssertionError('partial ledger accepted')
            if psql.called: raise AssertionError('partial ledger performed SQL')
    return 'origin schema readiness fixture passed'
