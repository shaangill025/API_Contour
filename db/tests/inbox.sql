-- Actual restricted LOGIN: durable inbox storage, not application admission.
\connect contour_fixture contour_ingest_test
SELECT fixture.assert(session_user='contour_ingest_test','real ingestion login');
SELECT fixture.assert(to_regclass('contour.ingestion_batches') IS NOT NULL,
    'durable inbox header exists');
DO $$ DECLARE relation text; role_name text; BEGIN
    FOREACH relation IN ARRAY ARRAY['ingestion_batches','ingestion_payloads'] LOOP
        PERFORM fixture.assert(EXISTS(SELECT 1 FROM pg_class c
            WHERE c.oid=('contour.'||relation)::regclass AND c.relowner='contour_owner'::regrole
            AND c.relrowsecurity AND c.relforcerowsecurity),'owner and forced RLS');
        PERFORM fixture.assert(has_table_privilege(current_user,'contour.'||relation,'SELECT')
            AND has_table_privilege(current_user,'contour.'||relation,'INSERT')
            AND NOT has_table_privilege(current_user,'contour.'||relation,'UPDATE')
            AND NOT has_table_privilege(current_user,'contour.'||relation,'DELETE')
            AND NOT has_table_privilege(current_user,'contour.'||relation,'TRUNCATE'),'append-only ingestion grants');
        FOREACH role_name IN ARRAY ARRAY['contour_runtime','contour_admin'] LOOP
            PERFORM fixture.assert(NOT has_table_privilege(role_name,'contour.'||relation,'SELECT')
                AND NOT has_table_privilege(role_name,'contour.'||relation,'INSERT'),'no shared role inbox access');
        END LOOP;
        PERFORM fixture.expect_state('UPDATE contour.'||relation||' SET batch_id=batch_id','42501');
        PERFORM fixture.expect_state('DELETE FROM contour.'||relation,'42501');
        PERFORM fixture.expect_state('TRUNCATE contour.'||relation,'42501');
    END LOOP;
END $$;
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.ingestion_batches)
    AND NOT EXISTS(SELECT 1 FROM contour.ingestion_payloads),'no context denies inbox');
SELECT fixture.expect_state($q$INSERT INTO contour.ingestion_batches
    (tenant_id,collector_id,batch_id,request_digest,digest_version,record_count)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',decode(repeat('01',32),'hex'),1,1)$q$,'42501');
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.lock_collector('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
-- Scope checks, collector FK and all checked header bounds.
DO $$ DECLARE command text; base text; BEGIN
    base := $q$INSERT INTO contour.ingestion_batches
        (tenant_id,collector_id,batch_id,request_digest,digest_version,record_count) VALUES
        ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000099',decode(repeat('01',32),'hex'),1,1)$q$;
    PERFORM fixture.expect_state(replace(base,'aaaaaaaa-','bbbbbbbb-'),'42501');
    PERFORM fixture.expect_state(replace(base,'000000000001','000000000088'),'23503');
    PERFORM fixture.expect_state(replace(base,$s$repeat('01',32)$s$,$s$repeat('01',31)$s$),'23514');
    PERFORM fixture.expect_state(replace(base,$s$repeat('01',32)$s$,$s$repeat('01',33)$s$),'23514');
    PERFORM fixture.expect_state(replace(base,$s$,1,1)$s$,$s$,2,1)$s$),'23514');
    PERFORM fixture.expect_state(replace(base,$s$,1,1)$s$,$s$,1,0)$s$),'23514');
    PERFORM fixture.expect_state(replace(base,$s$,1,1)$s$,$s$,1,501)$s$),'23514');
END $$;
INSERT INTO contour.ingestion_batches
    (tenant_id,collector_id,batch_id,request_digest,digest_version,record_count)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',decode(repeat('01',32),'hex'),1,1),
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000001',decode(repeat('02',32),'hex'),1,500);
SELECT fixture.assert((SELECT count(*) FROM contour.ingestion_batches WHERE receipt_id IS NOT NULL
    AND accepted_at BETWEEN transaction_timestamp() AND clock_timestamp())=2,'server receipt and time defaults');
SELECT fixture.assert((SELECT count(DISTINCT receipt_id) FROM contour.ingestion_batches)=2,'distinct server receipts');
SELECT fixture.expect_state($q$INSERT INTO contour.ingestion_batches
    SELECT * FROM contour.ingestion_batches WHERE collector_id='00000000-0000-0000-0000-000000000001'$q$,'23505');
DO $$ DECLARE base text; BEGIN
    base := $q$INSERT INTO contour.ingestion_payloads VALUES
        ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000001',1,decode('00','hex'))$q$;
    PERFORM fixture.expect_state(replace(base,'aaaaaaaa-','bbbbbbbb-'),'42501');
    PERFORM fixture.expect_state(replace(base,'000000000001', '000000000077'),'23503');
    PERFORM fixture.expect_state(replace(base,$s$,1,decode$s$,$s$,2,decode$s$),'23514');
    PERFORM fixture.expect_state(replace(base,$s$decode('00','hex')$s$,$s$decode('','hex')$s$),'23514');
    PERFORM fixture.expect_state(replace(base,$s$decode('00','hex')$s$,$s$decode(repeat('00',1048577),'hex')$s$),'23514');
END $$;
INSERT INTO contour.ingestion_payloads VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',1,decode('0001090a0dc3a9f09f9880','hex')),
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000001',1,decode(repeat('00',1048576),'hex'));
SELECT fixture.assert((SELECT encode(checked_batch,'hex') FROM contour.ingestion_payloads
    WHERE collector_id='00000000-0000-0000-0000-000000000001')='0001090a0dc3a9f09f9880',
    'NUL control Unicode bytea exact roundtrip');
SELECT fixture.expect_state($q$SELECT '{"name":"\u0000"}'::jsonb$q$,'22P05');
SELECT fixture.expect_state($q$INSERT INTO contour.ingestion_payloads
    SELECT * FROM contour.ingestion_payloads WHERE collector_id='00000000-0000-0000-0000-000000000001'$q$,'23505');
-- A failed payload rolls back its header in the same subtransaction.
DO $$ BEGIN
    BEGIN
        INSERT INTO contour.ingestion_batches
            (tenant_id,collector_id,batch_id,request_digest,digest_version,record_count)
            VALUES (contour.tenant_context(),'00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000099',decode(repeat('03',32),'hex'),1,1);
        INSERT INTO contour.ingestion_payloads VALUES
            (contour.tenant_context(),'00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000099',1,decode('','hex'));
        RAISE EXCEPTION 'payload failure missing';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
    PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM contour.ingestion_batches
        WHERE batch_id='00000000-0000-0000-0000-000000000099'),'failed pair header absent');
    PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM contour.ingestion_payloads
        WHERE batch_id='00000000-0000-0000-0000-000000000099'),'failed pair payload absent');
END $$;
COMMIT;
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.ingestion_batches),'commit clears local context');
BEGIN;
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.ingestion_batches b
    JOIN contour.ingestion_payloads p USING (tenant_id,collector_id,batch_id)),'cross tenant join hides pairs');
SELECT contour.lock_collector('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
-- Tenant A's same collector/batch header cannot satisfy tenant B's payload FK.
SELECT fixture.expect_state($q$INSERT INTO contour.ingestion_payloads VALUES
    ('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',1,decode('04','hex'))$q$,'23503');
INSERT INTO contour.ingestion_batches
    (tenant_id,collector_id,batch_id,request_digest,digest_version,record_count)
    VALUES (contour.tenant_context(),'00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',decode(repeat('04',32),'hex'),1,1);
INSERT INTO contour.ingestion_payloads VALUES
    (contour.tenant_context(),'00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',1,decode('04','hex'));
SELECT fixture.assert((SELECT count(*) FROM contour.ingestion_batches b
    JOIN contour.ingestion_payloads p USING (tenant_id,collector_id,batch_id))=1,'tenant reuse independent');
ROLLBACK;
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.expect_state($q$INSERT INTO contour.ingestion_batches SELECT * FROM contour.ingestion_batches$q$,'25001');
ROLLBACK;
\connect contour_fixture contour_test
SELECT fixture.expect_state('SELECT * FROM contour.ingestion_payloads','42501');
SELECT fixture.expect_state('INSERT INTO contour.ingestion_batches DEFAULT VALUES','42501');
\connect contour_fixture contour_admin_test
SELECT fixture.expect_state('SELECT * FROM contour.ingestion_payloads','42501');
SELECT fixture.expect_state('INSERT INTO contour.ingestion_batches DEFAULT VALUES','42501');
