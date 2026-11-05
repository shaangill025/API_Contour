-- Run after causal_inbox_basic.sql in the same psql connection.
-- This superuser-only corruption simulates damaged persisted state.
RESET ROLE;
ALTER TABLE contour.causal_inbox_events DISABLE TRIGGER causal_inbox_event_immutable;
UPDATE contour.causal_inbox_events SET event_digest=decode(repeat('00',32),'hex') WHERE batch_id='aa000000-0000-4000-8000-000000000001';
ALTER TABLE contour.causal_inbox_events ENABLE TRIGGER causal_inbox_event_immutable;
SET ROLE contour_causal_inbox_writer;
DO $$ BEGIN
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',1,repeat('1',32),repeat('a',32))); RAISE EXCEPTION 'damaged exact retry accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',2,repeat('2',32),repeat('b',32))); RAISE EXCEPTION 'damaged conflicting retry accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
-- Restore index, then corrupt only the receipt while leaving it non-null.
ALTER TABLE contour.causal_inbox_events DISABLE TRIGGER causal_inbox_event_immutable;
UPDATE contour.causal_inbox_events e SET event_digest=x.event_digest FROM contour.causal_inbox_batches b CROSS JOIN LATERAL contour.causal_decoded_events(contour.causal_parse(b.canonical_batch)) x WHERE e.batch_id=b.batch_id AND e.seq=x.seq AND b.batch_id='aa000000-0000-4000-8000-000000000001';
ALTER TABLE contour.causal_inbox_events ENABLE TRIGGER causal_inbox_event_immutable;
ALTER TABLE contour.causal_inbox_batches DISABLE TRIGGER causal_inbox_batch_immutable;
UPDATE contour.causal_inbox_batches SET receipt_id=pg_catalog.gen_random_uuid() WHERE batch_id='aa000000-0000-4000-8000-000000000001';
ALTER TABLE contour.causal_inbox_batches ENABLE TRIGGER causal_inbox_batch_immutable;
SET ROLE contour_causal_inbox_writer;
DO $$ BEGIN
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',1,repeat('1',32),repeat('a',32))); RAISE EXCEPTION 'damaged receipt accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
