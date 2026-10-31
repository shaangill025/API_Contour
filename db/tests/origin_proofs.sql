-- Run as a real login inheriting only contour_origin_ingress.
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.expect_state($q$SELECT * FROM contour.origin_ingress_context$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.origin_ingress_context VALUES (txid_current(),pg_backend_pid(),'aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',clock_timestamp())$q$,'42501');
SELECT fixture.expect_state($q$SELECT contour.require_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001')$q$,'42501');
SELECT fixture.expect_state($q$SELECT contour.begin_origin_ingress('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001')$q$,'42501');
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT contour.require_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.expect_state($q$SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001')$q$,'40001');
SELECT fixture.expect_state($q$SELECT contour.require_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000002')$q$,'42501');
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
SELECT fixture.expect_state($q$SELECT contour.require_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001')$q$,'42501');
COMMIT;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
ROLLBACK;
-- Public advisory lock functions and caller-controlled settings cannot forge the row.
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT set_config('apicontour.origin_ingress','true',true);
CREATE TEMP TABLE origin_ingress_context (transaction_id bigint, backend_pid integer, tenant_id uuid, collector_id uuid);
INSERT INTO origin_ingress_context VALUES (txid_current(),pg_backend_pid(),'aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT pg_advisory_xact_lock(1330792270,hashtext('aaaaaaaa-0000-0000-0000-000000000000'));
-- Collector key is computed by a test-only helper provisioned by the harness.
SELECT pg_advisory_xact_lock(fixture.origin_collector_key('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001'));
SELECT fixture.expect_state($q$SELECT contour.require_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001')$q$,'42501');
SELECT fixture.expect_state($q$SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001')$q$,'40001');
ROLLBACK;
SELECT pg_advisory_lock(123,456);
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.expect_state($q$SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001')$q$,'40001');
ROLLBACK;
SELECT pg_advisory_unlock(123,456);

-- Forcing deferred cleanup early removes authority even while Q and C remain held.
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SET CONSTRAINTS contour.cleanup_origin_ingress_context IMMEDIATE;
SELECT fixture.expect_state($q$SELECT contour.require_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001')$q$,'42501');
SELECT fixture.expect_state($q$SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001')$q$,'40001');
COMMIT;
