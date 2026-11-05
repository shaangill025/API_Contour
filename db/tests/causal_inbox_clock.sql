-- Run after causal_inbox_basic.sql in the same psql connection, after corruption.
-- Advance to a new short-lived session and hold the insert past its expiry.
CREATE FUNCTION pg_temp.short_claim() RETURNS contour.causal_session_claim LANGUAGE sql AS $$
 SELECT ROW((c).tenant_id,(c).runtime_id,(c).collector_id,(c).source_id,(c).project_id,(c).service_id,(c).environment_id,(c).deployment_id,(c).instance_id,(c).lifecycle_id,(c).export_leaf,(c).profile_name,(c).profile_hash,
 'fe000000-0000-4000-8000-000000000002'::uuid,(c).grant_revision,(c).grant_digest,(c).grant_issued,(c).grant_expires,(c).policy_revision,(c).policy_envelope,(c).policy_issued,(c).policy_expires,5000000,(c).max_batch_events,(c).max_batch_bytes,(c).queue_bytes,(c).queue_ttl_seconds)::contour.causal_session_claim FROM (SELECT pg_temp.inbox_claim() c) x $$;
CREATE FUNCTION pg_temp.delayed_inbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(6); RETURN NEW; END $$;
SET ROLE contour_causal_issuer;
SELECT * FROM contour.issue_causal_session(pg_temp.short_claim());
RESET ROLE;
-- The formerly current epoch is superseded immediately by issuance of epoch 2.
SET ROLE contour_causal_inbox_writer;
DO $$ DECLARE msg text; denied boolean:=false; BEGIN
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',1,repeat('1',32),repeat('a',32))); EXCEPTION WHEN check_violation THEN GET STACKED DIAGNOSTICS msg=MESSAGE_TEXT; denied:=(msg='session unavailable'); END;
 IF NOT denied THEN RAISE EXCEPTION 'superseded session was not rejected'; END IF;
END $$;
RESET ROLE;
-- Baseline proves the new session and normal admission work before delay.
SET ROLE contour_causal_inbox_writer;
SELECT * FROM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',2,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),convert_to(replace(convert_from(pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000012',12,repeat('c',32),repeat('e',32)),'UTF8'),'"session_epoch":1','"session_epoch":2'),'UTF8'));
RESET ROLE;
CREATE TEMP TABLE inbox_clock_usage AS SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
GRANT SELECT ON inbox_clock_usage TO contour_owner;
CREATE TRIGGER inbox_test_delay BEFORE INSERT ON contour.causal_inbox_batches FOR EACH ROW EXECUTE FUNCTION pg_temp.delayed_inbox();
SET ROLE contour_causal_inbox_writer;
DO $$ DECLARE p bytea; message text; rejected boolean:=false; BEGIN
 p:=convert_to(replace(convert_from(pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000004',4,repeat('4',32),repeat('d',32)),'UTF8'),'"session_epoch":1','"session_epoch":2'),'UTF8');
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',2,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),p); EXCEPTION WHEN check_violation THEN GET STACKED DIAGNOSTICS message=MESSAGE_TEXT; rejected:=(message='session unavailable at final lease check'); END;
 IF NOT rejected THEN RAISE EXCEPTION 'final lease diagnostic missing'; END IF;
END $$;
-- The same session must now fail the initial lease check as expired.
DO $$ DECLARE msg text; denied boolean:=false; BEGIN
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',2,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),convert_to(replace(convert_from(pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000012',12,repeat('c',32),repeat('e',32)),'UTF8'),'"session_epoch":1','"session_epoch":2'),'UTF8')); EXCEPTION WHEN check_violation THEN GET STACKED DIAGNOSTICS msg=MESSAGE_TEXT; denied:=(msg='session unavailable'); END;
 IF NOT denied THEN RAISE EXCEPTION 'expired session was not rejected'; END IF;
END $$;
RESET ROLE;
DROP TRIGGER inbox_test_delay ON contour.causal_inbox_batches;
SET ROLE contour_owner;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM contour.causal_inbox_batches WHERE batch_id='aa000000-0000-4000-8000-000000000004') OR EXISTS(SELECT 1 FROM contour.causal_inbox_events WHERE batch_id='aa000000-0000-4000-8000-000000000004') OR (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='f0000000-0000-4000-8000-000000000001') IS DISTINCT FROM (SELECT used_bytes FROM inbox_clock_usage) THEN RAISE EXCEPTION 'expired final check leaked rows'; END IF; END $$;
RESET ROLE;
