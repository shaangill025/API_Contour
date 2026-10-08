-- Real login with no runtime/authority membership.
\connect contour_fixture contour_catalog_worker_test
SELECT fixture.assert(session_user='contour_catalog_worker_test','real catalog worker login');
DO $$ DECLARE role_name text; relation text; BEGIN
    FOREACH role_name IN ARRAY ARRAY['contour_catalog_worker','contour_catalog_reader'] LOOP
        PERFORM fixture.assert(NOT EXISTS (SELECT 1 FROM pg_auth_members
            WHERE member=role_name::regrole),'catalog role inherits nothing');
        PERFORM fixture.assert(NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=role_name
            AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR rolcanlogin)),
            'restricted nonlogin role');
        FOREACH relation IN ARRAY ARRAY['operations','variants','observation_windows','catalog_processed_batches'] LOOP
            PERFORM fixture.assert(EXISTS(SELECT 1 FROM pg_class WHERE oid=('contour.'||relation)::regclass
                AND relowner='contour_owner'::regrole AND relrowsecurity AND relforcerowsecurity),'forced owner RLS');
            PERFORM fixture.assert(has_table_privilege(role_name,'contour.'||relation,'SELECT')=(role_name='contour_catalog_worker' OR relation<>'catalog_processed_batches')
                AND has_table_privilege(role_name,'contour.'||relation,'INSERT')=(role_name='contour_catalog_worker')
                AND NOT has_table_privilege(role_name,'contour.'||relation,'UPDATE,DELETE,TRUNCATE'), 'catalog grants');
        END LOOP;
        PERFORM fixture.assert(NOT has_table_privilege(role_name,'contour.collectors','SELECT,INSERT,UPDATE')
            AND NOT has_table_privilege(role_name,'contour.policy_revisions','SELECT,INSERT'), 'no identity or policy grants');
    END LOOP;
    FOREACH relation IN ARRAY ARRAY['operations','variants','observation_windows','catalog_processed_batches'] LOOP
        PERFORM fixture.expect_state('UPDATE contour.'||relation||' SET tenant_id=tenant_id','42501');
        PERFORM fixture.expect_state('DELETE FROM contour.'||relation,'42501');
        PERFORM fixture.expect_state('TRUNCATE contour.'||relation,'42501');
    END LOOP;
END $$;
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.operations)
    AND NOT EXISTS(SELECT 1 FROM contour.ingestion_payloads),'no context hides catalog and inbox');
SELECT fixture.expect_state('INSERT INTO contour.ingestion_payloads DEFAULT VALUES','42501');
SELECT fixture.expect_state('UPDATE contour.ingestion_batches SET batch_id=batch_id','42501');
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT count(*) FROM contour.ingestion_payloads)=2,'scoped accepted inbox read');
INSERT INTO contour.operations VALUES (contour.tenant_context(),'00000000-0000-0000-0000-000000000001',decode(repeat('11',32),'hex'),1,
    convert_to('["operation\u0000"]','UTF8'),'00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
INSERT INTO contour.variants VALUES (contour.tenant_context(),'00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',1,'http_json_v1',1,
    decode(repeat('22',32),'hex'),decode(repeat('00',65536),'hex'),decode('0009c3a9','hex'));
INSERT INTO contour.catalog_processed_batches VALUES (contour.tenant_context(),
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',1,DEFAULT);
INSERT INTO contour.observation_windows VALUES (contour.tenant_context(),
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
    1000000000,1,1000000,'structure','partial',ARRAY['sampled','limit','clock_skew'],true,599,
    '2026-10-08T01:02:03.123456789Z','2026-10-08T01:02:03.987654321Z',
    '2026-10-08T01:02:04.000000001Z','2026-10-08T01:12:04.000000001Z',
    convert_to('["x-approved"]','UTF8'),convert_to('[]','UTF8'),convert_to('["a\u0000b"]','UTF8'));
SELECT fixture.assert((SELECT octet_length(canonical_structure)=65536 AND encode(structure_wire,'hex')='0009c3a9'
    FROM contour.variants),'large and NUL structure bytes exact');
SELECT fixture.assert((SELECT observation_count=1000000000 AND sample_denominator=1000000
    AND first_seen='2026-10-08T01:02:03.123456789Z' AND last_seen='2026-10-08T01:02:03.987654321Z'
    AND convert_from(query_parameter_names,'UTF8')='["a\u0000b"]' FROM contour.observation_windows),
    'exact per-record count sampling timestamps approved names');
-- Copying a row with a separately valid but different deployment must fail.
DO $$ DECLARE row contour.observation_windows; op contour.operations; BEGIN
    SELECT * INTO row FROM contour.observation_windows;
    row.record_id := '00000000-0000-0000-0000-000000000099';
    row.deployment_id := '00000000-0000-0000-0000-000000000002';
    BEGIN INSERT INTO contour.observation_windows SELECT row.*;
        RAISE EXCEPTION 'mixed source workload accepted';
    EXCEPTION WHEN foreign_key_violation THEN NULL; END;
    row.deployment_id := '00000000-0000-0000-0000-000000000001';
    -- A revision belonging to collector 1 cannot be borrowed by collector 2.
    BEGIN
        INSERT INTO contour.variants SELECT tenant_id,'00000000-0000-0000-0000-000000000099',
            operation_id,'00000000-0000-0000-0000-000000000002',policy_revision,
            parser_profile,canonicalization_version,structure_hash,canonical_structure,structure_wire
            FROM contour.variants;
        RAISE EXCEPTION 'cross collector policy revision accepted';
    EXCEPTION WHEN foreign_key_violation THEN NULL; END;
    INSERT INTO contour.variants SELECT tenant_id,'00000000-0000-0000-0000-000000000003',
        operation_id,'00000000-0000-0000-0000-000000000002',3,
        parser_profile,canonicalization_version,structure_hash,canonical_structure,structure_wire
        FROM contour.variants;
    row.variant_id := '00000000-0000-0000-0000-000000000003';
    BEGIN INSERT INTO contour.observation_windows SELECT row.*;
        RAISE EXCEPTION 'cross collector variant accepted';
    EXCEPTION WHEN foreign_key_violation THEN NULL; END;
    row.variant_id := '00000000-0000-0000-0000-000000000001';
    -- Both operation and source workloads exist, but the evidence mixes them.
    INSERT INTO contour.operations SELECT tenant_id,'00000000-0000-0000-0000-000000000002',
        decode(repeat('44',32),'hex'),identity_version,canonical_key,
        '00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002',
        '00000000-0000-0000-0000-000000000002' FROM contour.operations;
    INSERT INTO contour.variants SELECT tenant_id,'00000000-0000-0000-0000-000000000002',
        '00000000-0000-0000-0000-000000000002',collector_id,policy_revision,
        parser_profile,canonicalization_version,structure_hash,canonical_structure,structure_wire
        FROM contour.variants WHERE variant_id='00000000-0000-0000-0000-000000000001';
    row.operation_id := '00000000-0000-0000-0000-000000000002';
    row.variant_id := '00000000-0000-0000-0000-000000000002';
    BEGIN INSERT INTO contour.observation_windows SELECT row.*;
        RAISE EXCEPTION 'mixed operation workload accepted';
    EXCEPTION WHEN foreign_key_violation THEN NULL; END;
    row.operation_id := '00000000-0000-0000-0000-000000000001';
    row.variant_id := '00000000-0000-0000-0000-000000000001';
    row.sample_denominator := 0;
    BEGIN INSERT INTO contour.observation_windows SELECT row.*;
        RAISE EXCEPTION 'invalid sampling accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;
    SELECT * INTO op FROM contour.operations WHERE operation_id='00000000-0000-0000-0000-000000000001';
    op.tenant_id := 'bbbbbbbb-0000-0000-0000-000000000000';
    BEGIN INSERT INTO contour.operations SELECT op.*;
        RAISE EXCEPTION 'cross tenant insert accepted';
    EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
COMMIT;
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.observation_windows),'commit clears catalog context');
-- One transaction owns its claim and every derived row; rollback leaves none.
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
INSERT INTO contour.catalog_processed_batches VALUES (contour.tenant_context(),
    '00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001',1,DEFAULT);
INSERT INTO contour.operations SELECT tenant_id,'00000000-0000-0000-0000-000000000099',decode(repeat('33',32),'hex'),identity_version,
    canonical_key,project_id,service_id,environment_id FROM contour.operations
    WHERE operation_id='00000000-0000-0000-0000-000000000001';
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT count(*) FROM contour.operations)=2
    AND (SELECT count(*) FROM contour.catalog_processed_batches)=1,'derived row and claim rollback together');
ROLLBACK;
\connect contour_fixture contour_catalog_reader_test
SELECT fixture.expect_state('SELECT * FROM contour.ingestion_payloads','42501');
SELECT fixture.expect_state('SELECT * FROM contour.catalog_processed_batches','42501');
SELECT fixture.expect_state('INSERT INTO contour.operations DEFAULT VALUES','42501');
SELECT fixture.expect_state('DELETE FROM contour.observation_windows','42501');
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.operations)
    AND NOT EXISTS(SELECT 1 FROM contour.variants) AND NOT EXISTS(SELECT 1 FROM contour.observation_windows),
    'reader no context hides all catalog tables');
BEGIN;
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.operations o JOIN contour.variants v
    USING(tenant_id,operation_id) JOIN contour.observation_windows w USING(tenant_id,variant_id,operation_id)),
    'reader cross tenant joins hidden');
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.operations)
    AND NOT EXISTS(SELECT 1 FROM contour.variants) AND NOT EXISTS(SELECT 1 FROM contour.observation_windows),
    'reader cross tenant hides all catalog tables');
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT count(*) FROM contour.observation_windows)=1,'reader scoped evidence');
ROLLBACK;
