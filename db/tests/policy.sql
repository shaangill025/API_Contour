BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.expect_state('UPDATE contour.sources SET source_nonce = source_nonce', '42501');
ROLLBACK;
\connect contour_fixture contour_admin_test
SELECT fixture.assert(session_user = 'contour_admin_test', 'real admin login');
SELECT fixture.assert(NOT pg_has_role(current_user,'contour_owner','MEMBER'), 'admin no owner');
SELECT fixture.assert(pg_has_role(current_user,'contour_runtime','MEMBER'), 'admin read inheritance');
SELECT fixture.assert(NOT (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreaterole
    OR rolcreatedb OR rolreplication),'restricted non-login groups') FROM pg_roles
    WHERE rolname IN ('contour_admin','contour_ingestion');
DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['tenants','projects','services','environments','deployments',
        'collectors','workload_assignments','sources','policy_revisions','collector_authorization','source_authorization'] LOOP
        PERFORM fixture.assert(NOT has_table_privilege(current_user,'contour.'||relation,'DELETE')
            AND NOT has_table_privilege(current_user,'contour.'||relation,'TRUNCATE'), 'no destructive grant');
        PERFORM fixture.assert(EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='contour' AND c.relname=relation
            AND c.relrowsecurity AND c.relforcerowsecurity AND r.rolname='contour_owner'), 'forced RLS owner');
    END LOOP;
END $$;
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.collector_authorization),'no context denies');
SELECT fixture.expect_state($q$SELECT contour.lock_collector('aaaaaaaa-0000-0000-0000-000000000000',
    '00000000-0000-0000-0000-000000000001')$q$,'42501');
SELECT fixture.expect_state('SET ROLE contour_owner','42501');
SELECT fixture.expect_state('UPDATE contour.sources SET source_nonce=source_nonce','42501');
SELECT fixture.expect_state('DELETE FROM contour.policy_revisions','42501');
SELECT fixture.expect_state($q$INSERT INTO contour.policy_revisions VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',1,'inert')$q$,'42501');
SELECT fixture.expect_state('UPDATE contour.policy_revisions SET revision=revision','42501');
SELECT fixture.assert(NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='contour' AND p.prosecdef),'no definer functions');
SELECT fixture.assert(NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='contour' AND NOT coalesce(p.proconfig @> ARRAY['search_path=pg_catalog'],false)),
    'fixed function search paths');
SELECT fixture.assert(NOT EXISTS (SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
    WHERE p.oid='contour.lock_collector(uuid,uuid)'::regprocedure AND a.grantee=0),
    'public cannot lock');

BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.lock_collector('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.assert((SELECT count(*) FROM contour.collector_authorization)=2,'tenant backfill visible');
SELECT fixture.expect_state($q$INSERT INTO contour.policy_revisions VALUES
    ('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',1,'x')$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.policy_revisions VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',1.5,'x')$q$,'23514');
SELECT fixture.expect_state($q$INSERT INTO contour.policy_revisions VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',18446744073709551616,'x')$q$,'23514');
SELECT fixture.expect_state($q$INSERT INTO contour.policy_revisions VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',0,'x')$q$,'23514');
SELECT fixture.expect_state($q$INSERT INTO contour.policy_revisions VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',1,'\x')$q$,'23514');
SELECT fixture.expect_state($q$INSERT INTO contour.policy_revisions VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',1,decode(repeat('00',1048577),'hex'))$q$,'23514');
INSERT INTO contour.policy_revisions VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',1,'inert-signed-envelope'),
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',2,'inert-signed-envelope-2'),
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',18446744073709551615,decode(repeat('00',1048576),'hex'));
SELECT fixture.expect_state($q$INSERT INTO contour.policy_revisions VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',1,'different')$q$,'23505');
SELECT fixture.expect_state('UPDATE contour.collector_authorization SET enabled=true','23514');
UPDATE contour.collector_authorization SET active_revision=1,enabled=true
    WHERE collector_id='00000000-0000-0000-0000-000000000001';
UPDATE contour.collector_authorization SET active_revision=2
    WHERE collector_id='00000000-0000-0000-0000-000000000001';
UPDATE contour.collector_authorization SET active_revision=2,enabled=false
    WHERE collector_id='00000000-0000-0000-0000-000000000001';
UPDATE contour.collector_authorization SET enabled=true
    WHERE collector_id='00000000-0000-0000-0000-000000000001';
SELECT fixture.expect_state($q$UPDATE contour.collector_authorization SET active_revision=1
    WHERE collector_id='00000000-0000-0000-0000-000000000001'$q$,'23514');
SELECT fixture.expect_state($q$UPDATE contour.collector_authorization SET active_revision=NULL
    WHERE collector_id='00000000-0000-0000-0000-000000000001'$q$,'23514');
SELECT fixture.expect_state($q$UPDATE contour.collector_authorization SET active_revision=3
    WHERE collector_id='00000000-0000-0000-0000-000000000001'$q$,'23503');
SELECT fixture.expect_state($q$UPDATE contour.collector_authorization SET collector_id=collector_id$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.source_authorization VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',
     '00000000-0000-0000-0000-000000000002','runtime',ARRAY['p'])$q$,'23503');
INSERT INTO contour.source_authorization VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',
     '00000000-0000-0000-0000-000000000001','runtime',ARRAY['http_json_v1']);
DO $$ DECLARE profiles text[]; BEGIN
    FOREACH profiles SLICE 1 IN ARRAY ARRAY[ARRAY['p','p'],ARRAY['p',NULL],ARRAY['1bad','x']] LOOP
        PERFORM fixture.expect_state(format('UPDATE contour.source_authorization SET parser_profiles=%L::text[]',profiles),'23514');
    END LOOP;
    PERFORM fixture.expect_state('UPDATE contour.source_authorization SET parser_profiles=ARRAY[]::text[]','23514');
    PERFORM fixture.expect_state($q$UPDATE contour.source_authorization SET parser_profiles=ARRAY[['p']]$q$,'23514');
END $$;
SELECT fixture.expect_state('UPDATE contour.source_authorization SET parser_profiles=NULL','23502');
SELECT fixture.expect_state($q$UPDATE contour.source_authorization SET technique='other'$q$,'23514');
UPDATE contour.source_authorization SET parser_profiles=ARRAY(SELECT 'p'||n FROM generate_series(1,128)n);
SELECT fixture.expect_state($q$UPDATE contour.source_authorization SET parser_profiles=
    ARRAY(SELECT 'p'||n FROM generate_series(1,129)n)$q$,'23514');
UPDATE contour.source_authorization SET parser_profiles=ARRAY['http_json_v1'];
COMMIT;

BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.lock_collector('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
UPDATE contour.collector_authorization SET revoked_at=clock_timestamp(),enabled=false
    WHERE collector_id='00000000-0000-0000-0000-000000000001';
SELECT fixture.expect_state($q$UPDATE contour.collector_authorization SET revoked_at=NULL
    WHERE collector_id='00000000-0000-0000-0000-000000000001'$q$,'23514');
SELECT fixture.expect_state($q$UPDATE contour.collector_authorization SET enabled=true
    WHERE collector_id='00000000-0000-0000-0000-000000000001'$q$,'23514');
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT enabled AND revoked_at IS NULL FROM contour.collector_authorization
    WHERE collector_id='00000000-0000-0000-0000-000000000001'),'rollback restores authorization');
SELECT contour.lock_collector('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000003');
INSERT INTO contour.collectors VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000003');
SELECT fixture.assert(EXISTS(SELECT 1 FROM contour.collector_authorization
    WHERE collector_id='00000000-0000-0000-0000-000000000003' AND NOT enabled AND active_revision IS NULL),'new collector disabled');
SELECT fixture.assert((SELECT count(*) FROM contour.source_authorization)=1,'no fabricated profiles');
COMMIT;

BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.lock_collector('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000002');
UPDATE contour.collector_authorization SET revoked_at=clock_timestamp()
    WHERE collector_id='00000000-0000-0000-0000-000000000002';
COMMIT;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.lock_collector('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000002');
SELECT fixture.expect_state($q$UPDATE contour.collector_authorization SET revoked_at=NULL
    WHERE collector_id='00000000-0000-0000-0000-000000000002'$q$,'23514');
SELECT fixture.expect_state($q$UPDATE contour.collector_authorization SET revoked_at=clock_timestamp()
    WHERE collector_id='00000000-0000-0000-0000-000000000002'$q$,'23514');
SELECT fixture.assert(EXISTS(SELECT 1 FROM contour.collector_authorization WHERE
    collector_id='00000000-0000-0000-0000-000000000002' AND revoked_at IS NOT NULL AND NOT enabled),'persisted terminal revocation');
COMMIT;

\connect contour_fixture contour_ingest_test
SELECT fixture.assert(session_user='contour_ingest_test','real ingestion login');
SELECT fixture.assert(NOT pg_has_role(current_user,'contour_admin','MEMBER')
    AND NOT pg_has_role(current_user,'contour_owner','MEMBER'),'ingestion separate');
DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['tenants','projects','services','environments','deployments',
        'collectors','workload_assignments','sources','policy_revisions','collector_authorization','source_authorization'] LOOP
        PERFORM fixture.assert(has_table_privilege(current_user,'contour.'||relation,'SELECT')
            AND NOT has_table_privilege(current_user,'contour.'||relation,'INSERT')
            AND NOT has_any_column_privilege(current_user,'contour.'||relation,'UPDATE')
            AND NOT has_table_privilege(current_user,'contour.'||relation,'DELETE'),'read only ingestion');
    END LOOP;
END $$;
BEGIN;
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT count(*) FROM contour.collector_authorization)=2,'tenant B isolation');
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.policy_revisions),'tenant A policies hidden');
ROLLBACK;
