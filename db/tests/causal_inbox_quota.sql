-- Run after basic, before corruption, in the same psql connection. The near-cap
-- seed is synthetic; this is not evidence of the real origin-proof write path.
CREATE TEMP TABLE inbox_saved_usage AS SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
UPDATE contour.origin_logical_usage SET used_bytes=1073741824 WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
SET ROLE contour_causal_inbox_writer;
DO $$ DECLARE r record; name text; BEGIN
 SELECT * INTO r FROM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',1,repeat('1',32),repeat('a',32)));
 IF NOT r.duplicate THEN RAISE EXCEPTION 'quota blocked exact retry'; END IF;
END $$;
DO $$ DECLARE rejected boolean:=false; constraint_name text; BEGIN
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000011',11,repeat('b',32),repeat('f',32)));
 EXCEPTION WHEN program_limit_exceeded THEN GET STACKED DIAGNOSTICS constraint_name=CONSTRAINT_NAME; rejected:=(constraint_name='origin_logical_quota_exhausted'); END;
 IF NOT rejected THEN RAISE EXCEPTION 'quota exhaustion was not structured'; END IF;
END $$;
RESET ROLE;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM contour.causal_inbox_batches WHERE batch_id='aa000000-0000-4000-8000-000000000011') OR EXISTS(SELECT 1 FROM contour.causal_inbox_events WHERE batch_id='aa000000-0000-4000-8000-000000000011') OR (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='f0000000-0000-4000-8000-000000000001')<>1073741824 THEN RAISE EXCEPTION 'quota rejection leaked facts or charge'; END IF; END $$;
UPDATE contour.origin_logical_usage SET used_bytes=(SELECT used_bytes FROM inbox_saved_usage) WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
