-- Assertions execute as actual restricted logins, never SET ROLE from postgres.
\connect contour_fixture contour_declared_writer_test
SELECT fixture.assert(session_user='contour_declared_writer_test','real declared writer login');
DO $$ DECLARE role_name text; relation text; BEGIN
    FOREACH role_name IN ARRAY ARRAY['contour_declared_writer','contour_declared_reader'] LOOP
        PERFORM fixture.assert(NOT EXISTS (SELECT 1 FROM pg_auth_members
            WHERE member=role_name::regrole),'declared group inherits nothing');
        PERFORM fixture.assert(NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=role_name
            AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR rolcanlogin)),
            'restricted declared nonlogin group');
        PERFORM fixture.assert(has_table_privilege(role_name,'contour.declared_versions','SELECT')
            AND NOT has_table_privilege(role_name,'contour.declared_versions','UPDATE,DELETE,TRUNCATE'),
            'declared read and immutable permissions');
        PERFORM fixture.assert(has_column_privilege(role_name,'contour.declared_versions','declared_wire','INSERT')
            =(role_name='contour_declared_writer')
            AND NOT has_column_privilege(role_name,'contour.declared_versions','created_at','INSERT'),
            'writer columns exclude server timestamp');
        PERFORM fixture.assert(has_table_privilege(role_name,'contour.operations','SELECT')
            AND has_table_privilege(role_name,'contour.operations','INSERT')=(role_name='contour_declared_writer')
            AND NOT has_table_privilege(role_name,'contour.operations','UPDATE,DELETE,TRUNCATE'),
            'narrow operation privileges');
        FOREACH relation IN ARRAY ARRAY['ingestion_batches','ingestion_payloads','variants',
            'observation_windows','catalog_processed_batches','collectors','policy_revisions','sources'] LOOP
            PERFORM fixture.assert(NOT has_table_privilege(role_name,'contour.'||relation,
                'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'),'no unrelated rights');
        END LOOP;
    END LOOP;
    PERFORM fixture.assert(EXISTS(SELECT 1 FROM pg_class WHERE oid='contour.declared_versions'::regclass
        AND relowner='contour_owner'::regrole AND relrowsecurity AND relforcerowsecurity),'forced owner RLS');
    FOREACH role_name IN ARRAY ARRAY['contour_runtime','contour_admin','contour_ingestion',
        'contour_catalog_worker','contour_catalog_reader'] LOOP
        PERFORM fixture.assert(NOT has_table_privilege(role_name,'contour.declared_versions',
            'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'),'no existing role permission expansion');
    END LOOP;
    FOREACH relation IN ARRAY ARRAY['operations','declared_versions'] LOOP
        PERFORM fixture.expect_state('UPDATE contour.'||relation||' SET tenant_id=tenant_id','42501');
        PERFORM fixture.expect_state('DELETE FROM contour.'||relation,'42501');
        PERFORM fixture.expect_state('TRUNCATE contour.'||relation,'42501');
    END LOOP;
END $$;
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.declared_versions)
    AND NOT EXISTS(SELECT 1 FROM contour.operations),'absent context hides rows');
SELECT fixture.expect_state($q$INSERT INTO contour.declared_versions
    (tenant_id,operation_id,project_id,service_id,environment_id,codec_version,declared_wire)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000001',1,decode('00','hex'))$q$,'42501');
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
-- This operation has never had a variant, source or observation.
INSERT INTO contour.operations (tenant_id,operation_id,operation_hash,identity_version,canonical_key,
    project_id,service_id,environment_id) VALUES (contour.tenant_context(),
    '00000000-0000-0000-0000-000000000051',decode(repeat('51',32),'hex'),1,
    convert_to('["declared-only"]','UTF8'),'00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
INSERT INTO contour.declared_versions (tenant_id,version_id,operation_id,project_id,service_id,
    environment_id,codec_version,declared_wire) VALUES (contour.tenant_context(),
    '00000000-0000-0000-0000-000000000051','00000000-0000-0000-0000-000000000051',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',1,decode('0009c3a9f09f9880','hex'));
SELECT fixture.assert((SELECT encode(declared_wire,'hex')='0009c3a9f09f9880'
    AND created_at BETWEEN transaction_timestamp() AND clock_timestamp()
    FROM contour.declared_versions),'exact NUL control Unicode bytes and server time');
-- SQL stores opaque bytes; these fixtures intentionally are not checked graph documents.
DO $$ DECLARE wire bytea; row contour.declared_versions; scope_column text; BEGIN
    SELECT * INTO row FROM contour.declared_versions;
    FOREACH wire IN ARRAY ARRAY[decode('00','hex'),decode(repeat('ab',1048576),'hex')] LOOP
        INSERT INTO contour.declared_versions (tenant_id,operation_id,project_id,service_id,
            environment_id,codec_version,declared_wire) VALUES (row.tenant_id,row.operation_id,
            row.project_id,row.service_id,row.environment_id,1,wire);
        PERFORM fixture.assert(EXISTS(SELECT 1 FROM contour.declared_versions WHERE declared_wire=wire),
            'inclusive byte limits round trip');
    END LOOP;
    FOREACH wire IN ARRAY ARRAY[decode('','hex'),decode(repeat('ab',1048577),'hex')] LOOP
        BEGIN
            INSERT INTO contour.declared_versions (tenant_id,operation_id,project_id,service_id,
                environment_id,codec_version,declared_wire) VALUES (row.tenant_id,row.operation_id,
                row.project_id,row.service_id,row.environment_id,1,wire);
            RAISE EXCEPTION 'invalid byte bound accepted';
        EXCEPTION WHEN check_violation THEN NULL; END;
    END LOOP;
    -- Each other workload identifier is independently valid, but does not belong to this operation.
    FOREACH scope_column IN ARRAY ARRAY['project_id','service_id','environment_id','operation_id'] LOOP
        PERFORM fixture.expect_state(format('INSERT INTO contour.declared_versions
            (tenant_id,operation_id,project_id,service_id,environment_id,codec_version,declared_wire)
            SELECT tenant_id,%s,%s,%s,%s,codec_version,declared_wire
            FROM contour.declared_versions WHERE version_id=%L',
            CASE WHEN scope_column='operation_id' THEN quote_literal('00000000-0000-0000-0000-000000000002')||'::uuid' ELSE 'operation_id' END,
            CASE WHEN scope_column='project_id' THEN quote_literal('00000000-0000-0000-0000-000000000002')||'::uuid' ELSE 'project_id' END,
            CASE WHEN scope_column='service_id' THEN quote_literal('00000000-0000-0000-0000-000000000002')||'::uuid' ELSE 'service_id' END,
            CASE WHEN scope_column='environment_id' THEN quote_literal('00000000-0000-0000-0000-000000000002')||'::uuid' ELSE 'environment_id' END,
            row.version_id),'23503');
    END LOOP;
    PERFORM fixture.expect_state($q$INSERT INTO contour.declared_versions
        (tenant_id,operation_id,project_id,service_id,environment_id,codec_version,declared_wire)
        SELECT tenant_id,operation_id,project_id,service_id,environment_id,2,declared_wire
        FROM contour.declared_versions$q$,'23514');
    PERFORM fixture.expect_state($q$INSERT INTO contour.declared_versions
        (tenant_id,version_id,operation_id,project_id,service_id,environment_id,codec_version,declared_wire)
        SELECT tenant_id,version_id,operation_id,project_id,service_id,environment_id,codec_version,declared_wire
        FROM contour.declared_versions$q$,'23505');
    PERFORM fixture.expect_state($q$INSERT INTO contour.declared_versions
        (tenant_id,operation_id,project_id,service_id,environment_id,codec_version,declared_wire,created_at)
        SELECT tenant_id,operation_id,project_id,service_id,environment_id,codec_version,declared_wire,now()
        FROM contour.declared_versions$q$,'42501');
    PERFORM fixture.expect_state($q$INSERT INTO contour.declared_versions
        (tenant_id,operation_id,project_id,service_id,environment_id,codec_version,declared_wire)
        SELECT 'bbbbbbbb-0000-0000-0000-000000000000',operation_id,project_id,service_id,
            environment_id,codec_version,declared_wire FROM contour.declared_versions$q$,'42501');
    PERFORM fixture.expect_state($q$INSERT INTO contour.operations
        SELECT 'bbbbbbbb-0000-0000-0000-000000000000',operation_id,operation_hash,identity_version,
            canonical_key,project_id,service_id,environment_id FROM contour.operations$q$,'42501');
END $$;
COMMIT;
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.declared_versions),'commit clears tenant context');
-- Both rows disappear when the caller rolls back their common transaction.
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
INSERT INTO contour.operations SELECT tenant_id,'00000000-0000-0000-0000-000000000052',
    decode(repeat('52',32),'hex'),identity_version,canonical_key,project_id,service_id,environment_id
    FROM contour.operations WHERE operation_id='00000000-0000-0000-0000-000000000051';
INSERT INTO contour.declared_versions (tenant_id,version_id,operation_id,project_id,service_id,
    environment_id,codec_version,declared_wire)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000052','00000000-0000-0000-0000-000000000052',
        project_id,service_id,environment_id,codec_version,declared_wire FROM contour.declared_versions
    WHERE version_id='00000000-0000-0000-0000-000000000051';
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.operations WHERE operation_id='00000000-0000-0000-0000-000000000052')
    AND NOT EXISTS(SELECT 1 FROM contour.declared_versions WHERE version_id='00000000-0000-0000-0000-000000000052'),
    'operation and version rollback together');
ROLLBACK;
-- A failed version insert rolls back the newly created operation in its savepoint.
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
DO $$ BEGIN
    BEGIN
        INSERT INTO contour.operations SELECT tenant_id,'00000000-0000-0000-0000-000000000053',
            decode(repeat('53',32),'hex'),identity_version,canonical_key,project_id,service_id,environment_id
            FROM contour.operations WHERE operation_id='00000000-0000-0000-0000-000000000051';
        INSERT INTO contour.declared_versions (tenant_id,operation_id,project_id,service_id,
            environment_id,codec_version,declared_wire)
            SELECT tenant_id,'00000000-0000-0000-0000-000000000053',project_id,service_id,
                environment_id,codec_version,decode('','hex') FROM contour.declared_versions
            WHERE version_id='00000000-0000-0000-0000-000000000051';
        RAISE EXCEPTION 'invalid version accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;
    PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM contour.operations
        WHERE operation_id='00000000-0000-0000-0000-000000000053'), 'failed version rolls back new operation');
END $$;
COMMIT;
-- A different trusted tenant can reuse the same internal UUIDs without collision.
BEGIN;
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.declared_versions)
    AND NOT EXISTS(SELECT 1 FROM contour.operations),'writer wrong tenant hides existing data');
INSERT INTO contour.operations (tenant_id,operation_id,operation_hash,identity_version,canonical_key,
    project_id,service_id,environment_id) VALUES (contour.tenant_context(),
    '00000000-0000-0000-0000-000000000051',decode(repeat('51',32),'hex'),1,
    convert_to('["declared-only"]','UTF8'),'00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
INSERT INTO contour.declared_versions (tenant_id,version_id,operation_id,project_id,service_id,
    environment_id,codec_version,declared_wire) VALUES (contour.tenant_context(),
    '00000000-0000-0000-0000-000000000051','00000000-0000-0000-0000-000000000051',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',1,decode('bb','hex'));
SELECT fixture.assert((SELECT count(*)=1 AND bool_and(declared_wire=decode('bb','hex'))
    FROM contour.declared_versions),'tenant-local UUID reuse');
ROLLBACK;
\connect contour_fixture contour_declared_reader_test
SELECT fixture.assert(session_user='contour_declared_reader_test','real declared reader login');
SELECT fixture.expect_state('INSERT INTO contour.operations DEFAULT VALUES','42501');
SELECT fixture.expect_state('INSERT INTO contour.declared_versions DEFAULT VALUES','42501');
SELECT fixture.expect_state('UPDATE contour.declared_versions SET declared_wire=declared_wire','42501');
SELECT fixture.expect_state('DELETE FROM contour.declared_versions','42501');
SELECT fixture.expect_state('TRUNCATE contour.declared_versions','42501');
SELECT fixture.expect_state('SELECT * FROM contour.ingestion_payloads','42501');
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.declared_versions),'reader absent context hides versions');
BEGIN;
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.declared_versions)
    AND NOT EXISTS(SELECT 1 FROM contour.operations),'reader wrong tenant hides all rows');
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT count(*) FROM contour.declared_versions)=3,'reader sees all immutable versions');
SELECT fixture.assert((SELECT count(*) FROM contour.declared_versions d JOIN contour.operations o
    USING(tenant_id,operation_id,project_id,service_id,environment_id))=3,'reader scoped operation join');
ROLLBACK;
