-- Disposable test only: run after causal_inbox_basic.sql and after installing
-- only the reviewed private helper into this test transaction. Not a migration.
SELECT set_config('apicontour.tenant_id','f0000000-0000-4000-8000-000000000001',false);
CREATE FUNCTION pg_temp.check_committed_batch(expected boolean) RETURNS void LANGUAGE plpgsql AS $$
DECLARE ok boolean:=false;
BEGIN
 BEGIN
  PERFORM contour.causal_committed_batch_valid('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,'aa000000-0000-4000-8000-000000000001');
  ok:=true;
 EXCEPTION WHEN check_violation THEN NULL;
 END;
 IF ok IS DISTINCT FROM expected THEN RAISE EXCEPTION 'committed batch integrity mismatch'; END IF;
END $$;
DO $$ BEGIN
 IF has_function_privilege('contour_causal_inbox_writer','contour.causal_committed_batch_valid(uuid,uuid,numeric,uuid)','EXECUTE')
 OR has_function_privilege('contour_runtime','contour.causal_committed_batch_valid(uuid,uuid,numeric,uuid)','EXECUTE')
 THEN RAISE EXCEPTION 'private helper executable'; END IF;
END $$;
SELECT pg_temp.check_committed_batch(true);
BEGIN;
ALTER TABLE contour.causal_inbox_batches DISABLE TRIGGER causal_inbox_batch_immutable;
ALTER TABLE contour.causal_inbox_events DISABLE TRIGGER causal_inbox_event_immutable;
SAVEPOINT original;
UPDATE contour.causal_inbox_batches SET receipt_id=gen_random_uuid() WHERE batch_id='aa000000-0000-4000-8000-000000000001';
SELECT pg_temp.check_committed_batch(false);
ROLLBACK TO original;
UPDATE contour.causal_inbox_batches SET batch_digest=decode(repeat('00',32),'hex') WHERE batch_id='aa000000-0000-4000-8000-000000000001';
SELECT pg_temp.check_committed_batch(false);
ROLLBACK TO original;
UPDATE contour.causal_inbox_batches SET event_count=2 WHERE batch_id='aa000000-0000-4000-8000-000000000001';
SELECT pg_temp.check_committed_batch(false);
ROLLBACK TO original;
UPDATE contour.causal_inbox_events SET event_digest=decode(repeat('00',32),'hex') WHERE batch_id='aa000000-0000-4000-8000-000000000001';
SELECT pg_temp.check_committed_batch(false);
ROLLBACK TO original;
DELETE FROM contour.causal_inbox_events WHERE batch_id='aa000000-0000-4000-8000-000000000001';
SELECT pg_temp.check_committed_batch(false);
ROLLBACK TO original;
INSERT INTO contour.causal_inbox_events SELECT tenant_id,runtime_id,session_epoch,batch_id,seq+1,repeat('f',32),kind,root,activity,parent,attempt,marker_digest,first_missing_seq,last_missing_seq,reason,event_digest FROM contour.causal_inbox_events WHERE batch_id='aa000000-0000-4000-8000-000000000001';
SELECT pg_temp.check_committed_batch(false);
ROLLBACK TO original;
UPDATE contour.causal_inbox_batches SET canonical_batch=convert_to('invalid','UTF8') WHERE batch_id='aa000000-0000-4000-8000-000000000001';
SELECT pg_temp.check_committed_batch(false);
ROLLBACK TO original;
SELECT pg_temp.check_committed_batch(true);
ROLLBACK;
DO $$ BEGIN
 BEGIN
  PERFORM contour.causal_committed_batch_valid('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,'aa000000-0000-4000-8000-000000000099');
  RAISE EXCEPTION 'missing batch accepted';
 EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
