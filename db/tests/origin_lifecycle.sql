-- Synthetic opt-in registry fixture, run as restricted contour_admin_test.
SELECT fixture.assert(session_user='contour_admin_test','origin fixture admin login');
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.origin_lifecycles),'no tenant context');
DO $$ DECLARE relation text; role_name text; BEGIN
  FOREACH relation IN ARRAY ARRAY['origin_lifecycles','origin_credentials','origin_observer_grants','origin_terminal_events'] LOOP
    PERFORM fixture.assert(EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='contour' AND c.relname=relation AND c.relrowsecurity AND c.relforcerowsecurity),'origin forced RLS');
    PERFORM fixture.assert(has_table_privilege('contour_admin','contour.'||relation,'SELECT')
      AND NOT has_table_privilege('contour_admin','contour.'||relation,'INSERT')
      AND NOT has_table_privilege('contour_admin','contour.'||relation,'UPDATE')
      AND NOT has_table_privilege('contour_admin','contour.'||relation,'DELETE')
      AND NOT has_table_privilege('contour_admin','contour.'||relation,'TRUNCATE'),'admin read only');
    FOREACH role_name IN ARRAY ARRAY['contour_runtime','contour_ingestion','contour_catalog_worker',
      'contour_catalog_reader','contour_declared_writer','contour_declared_reader',
      'contour_approval_writer','contour_approval_reader','contour_comparison_writer',
      'contour_comparison_reader','contour_review_writer','contour_review_reader',
      'contour_human_provisioner','contour_human_lookup'] LOOP
      PERFORM fixture.assert(NOT has_table_privilege(role_name,'contour.'||relation,'SELECT')
        AND NOT has_table_privilege(role_name,'contour.'||relation,'INSERT'),'no unrelated origin access');
    END LOOP;
  END LOOP;
  PERFORM fixture.assert(NOT has_function_privilege('contour_ingestion',
    'contour.enroll_origin(uuid,uuid,uuid,uuid,uuid,uuid,uuid,text,bytea)','EXECUTE'),'no ingestion enrollment');
  PERFORM fixture.assert(NOT has_function_privilege('contour_admin',
    'contour.begin_origin_operation(uuid)','EXECUTE'),'private gate helper');
  PERFORM fixture.assert(NOT has_function_privilege('contour_admin',
    'contour.origin_server_time()','EXECUTE') AND NOT has_function_privilege('contour_admin',
    'contour.origin_history_highwater(uuid,uuid)','EXECUTE'),'private clock and history helpers');
END $$;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',false);
SELECT fixture.expect_state($q$SELECT contour.enroll_origin('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000599','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000101','untrusted',decode(repeat('aa',32),'hex'))$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.enroll_origin('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000599','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000101','trusted_platform_v1',decode('aa','hex'))$q$,'23514');
-- Two additional source-independent origin instances for lifecycle and concurrency tests.
INSERT INTO contour.workload_instances VALUES
 ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000110'),
 ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000111'),
 ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000112');
SELECT contour.enroll_origin('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000501',
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000101','trusted_platform_v1',decode(repeat('aa',32),'hex'));
-- Ensure a reproducible gap for the fixture-only backwards-clock test.
SELECT pg_sleep(0.02);
SELECT contour.enroll_origin('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000503',
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000110','trusted_platform_v1',decode(repeat('ab',32),'hex'));
SELECT contour.enroll_origin('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000504',
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000111','trusted_platform_v1',decode(repeat('ac',32),'hex'));
SELECT contour.enroll_origin('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000505',
 '00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000112','trusted_platform_v1',decode(repeat('ad',32),'hex'));
SELECT contour.grant_origin_observer('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000525','00000000-0000-0000-0000-000000000505','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
SELECT fixture.assert((SELECT l.service_id<>g.service_id FROM contour.origin_lifecycles l JOIN contour.origin_observer_grants g USING(tenant_id,lifecycle_id)
 WHERE l.lifecycle_id='00000000-0000-0000-0000-000000000505' AND g.grant_id='00000000-0000-0000-0000-000000000525'),'origin and destination scopes are independent');
SELECT pg_sleep(0.02);
SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','grant_revoked','00000000-0000-0000-0000-000000000525');
SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000511','00000000-0000-0000-0000-000000000501',decode(repeat('11',32),'hex'));
SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000512','00000000-0000-0000-0000-000000000501',decode(repeat('22',32),'hex'));
SELECT fixture.assert((SELECT count(*)=2 FROM contour.origin_credentials WHERE lifecycle_id='00000000-0000-0000-0000-000000000501'),'same lifecycle rotation');
SELECT fixture.expect_state($q$SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000519','00000000-0000-0000-0000-000000000501',NULL)$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000519','00000000-0000-0000-0000-000000000501',decode('11','hex'))$q$,'23514');
SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','credential_revoked','00000000-0000-0000-0000-000000000511');
SELECT fixture.expect_state($q$SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000513','00000000-0000-0000-0000-000000000501',decode(repeat('11',32),'hex'))$q$,'23505');
DO $$ DECLARE message text; detail text; BEGIN
  BEGIN
    PERFORM contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000513','00000000-0000-0000-0000-000000000501',decode(repeat('11',32),'hex'));
    RAISE EXCEPTION 'expected duplicate rejection';
  EXCEPTION WHEN unique_violation THEN
    GET STACKED DIAGNOSTICS message=MESSAGE_TEXT, detail=PG_EXCEPTION_DETAIL;
    PERFORM fixture.assert(message='credential unavailable' AND coalesce(detail,'') NOT LIKE '%'||repeat('11',32)||'%', 'duplicate credential error is opaque');
  END;
END $$;
SELECT fixture.expect_state($q$SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','credential_revoked','00000000-0000-0000-0000-000000000511')$q$,'23505');
SELECT contour.grant_origin_observer('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000521','00000000-0000-0000-0000-000000000501','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
SELECT fixture.expect_state($q$SELECT contour.grant_origin_observer('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000522','00000000-0000-0000-0000-000000000501','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001')$q$,'23505');
SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','grant_revoked','00000000-0000-0000-0000-000000000521');
SELECT fixture.expect_state($q$SELECT contour.grant_origin_observer('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000521','00000000-0000-0000-0000-000000000501','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001')$q$,'23505');
SELECT contour.grant_origin_observer('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000522','00000000-0000-0000-0000-000000000501','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
SELECT pg_sleep(0.02);
SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000516','00000000-0000-0000-0000-000000000501',decode(repeat('33',32),'hex'));
SELECT fixture.assert((SELECT count(*)=2 FROM contour.origin_observer_grants WHERE lifecycle_id='00000000-0000-0000-0000-000000000501'),'regrant retains history');
SELECT fixture.assert((SELECT new_grant.granted_at >= revoked.event_at FROM contour.origin_observer_grants new_grant
 JOIN contour.origin_terminal_events revoked ON revoked.tenant_id=new_grant.tenant_id
 WHERE new_grant.grant_id='00000000-0000-0000-0000-000000000522'
 AND revoked.grant_id='00000000-0000-0000-0000-000000000521' AND revoked.event_kind='grant_revoked'),'regrant time follows revocation');
SELECT fixture.expect_state($q$SELECT contour.grant_origin_observer('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000523','00000000-0000-0000-0000-000000000501','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001')$q$,'23514');
SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','lifecycle_closed','00000000-0000-0000-0000-000000000504');
SELECT fixture.expect_state($q$SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000514','00000000-0000-0000-0000-000000000504',decode(repeat('44',32),'hex'))$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.grant_origin_observer('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000524','00000000-0000-0000-0000-000000000504','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001')$q$,'23514');
SELECT fixture.expect_state($q$INSERT INTO contour.origin_lifecycles DEFAULT VALUES$q$,'42501');
SELECT fixture.expect_state($q$UPDATE contour.origin_credentials SET leaf_sha256=leaf_sha256$q$,'42501');
SELECT fixture.expect_state($q$TRUNCATE contour.origin_terminal_events$q$,'42501');
SELECT fixture.expect_state($q$SELECT contour.enroll_origin_credential('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000515','00000000-0000-0000-0000-000000000501',decode(repeat('55',32),'hex'))$q$,'42501');
SELECT set_config('apicontour.origin_gate','forged',false);
SELECT fixture.expect_state($q$INSERT INTO contour.origin_credentials DEFAULT VALUES$q$,'42501');
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',false);
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.origin_lifecycles),'origin tenant isolation');
SELECT contour.enroll_origin('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000502',
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000107','trusted_platform_v1',decode(repeat('bb',32),'hex'));
SELECT fixture.expect_state($q$SELECT contour.enroll_origin_credential('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000515','00000000-0000-0000-0000-000000000502',decode(repeat('11',32),'hex'))$q$,'23505');
SELECT fixture.assert((SELECT count(*)=1 FROM contour.origin_lifecycles),'tenant B sees only B');
