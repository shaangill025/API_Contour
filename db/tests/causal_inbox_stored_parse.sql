-- Run immediately after causal_inbox_basic.sql in the same psql connection,
-- before any other corruption or epoch change. Superuser fault injection on a
-- disposable DB; the positive control proves the current session and retry work.
SET ROLE contour_causal_inbox_writer;
DO $$ DECLARE r record; BEGIN
 SELECT * INTO r FROM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',1,repeat('1',32),repeat('a',32)));
 IF NOT r.duplicate THEN RAISE EXCEPTION 'retry positive control failed'; END IF;
END $$;
-- Incoming errors must keep their ordinary diagnostics, even for an existing ID.
DO $$ DECLARE rejected boolean:=false; msg text; bad bytea; BEGIN
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),decode('ff','hex')); EXCEPTION WHEN character_not_in_repertoire THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'invalid incoming UTF8 diagnostic changed'; END IF;
 rejected:=false;
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),convert_to('{','UTF8')); EXCEPTION WHEN invalid_text_representation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'invalid incoming JSON diagnostic changed'; END IF;
 bad:=convert_to(replace(convert_from(pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',1,repeat('1',32),repeat('a',32)),'UTF8'),'"wire_version":1','"wire_version":2'),'UTF8');
 rejected:=false;
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),bad); EXCEPTION WHEN check_violation THEN GET STACKED DIAGNOSTICS msg=MESSAGE_TEXT; rejected:=(msg='invalid causal envelope'); END;
 IF NOT rejected THEN RAISE EXCEPTION 'invalid incoming semantic diagnostic changed'; END IF;
END $$;
RESET ROLE;
CREATE TEMP TABLE inbox_parse_usage AS SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='f0000000-0000-4000-8000-000000000001';
CREATE TEMP TABLE inbox_original_bytes AS SELECT canonical_batch FROM contour.causal_inbox_batches WHERE batch_id='aa000000-0000-4000-8000-000000000001';
CREATE FUNCTION pg_temp.assert_stored_parse() RETURNS void LANGUAGE plpgsql AS $$
DECLARE payload bytea; msg text; rejected boolean;
BEGIN
 FOREACH payload IN ARRAY ARRAY[
  pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',1,repeat('1',32),repeat('a',32)),
  pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',2,repeat('2',32),repeat('b',32))
 ] LOOP
  rejected:=false;
  BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),payload);
  EXCEPTION WHEN check_violation THEN GET STACKED DIAGNOSTICS msg=MESSAGE_TEXT; rejected:=(msg='stored causal batch corrupted'); END;
  IF NOT rejected THEN RAISE EXCEPTION 'stored parse corruption diagnostic missing'; END IF;
 END LOOP;
END $$;
-- 22021: invalid UTF8 in persisted bytes.
ALTER TABLE contour.causal_inbox_batches DISABLE TRIGGER causal_inbox_batch_immutable;
UPDATE contour.causal_inbox_batches SET canonical_batch=decode('ff','hex') WHERE batch_id='aa000000-0000-4000-8000-000000000001';
ALTER TABLE contour.causal_inbox_batches ENABLE TRIGGER causal_inbox_batch_immutable;
SET ROLE contour_causal_inbox_writer;
SELECT pg_temp.assert_stored_parse();
RESET ROLE;
-- 22P02: malformed JSON in persisted bytes.
ALTER TABLE contour.causal_inbox_batches DISABLE TRIGGER causal_inbox_batch_immutable;
UPDATE contour.causal_inbox_batches SET canonical_batch=convert_to('{','UTF8') WHERE batch_id='aa000000-0000-4000-8000-000000000001';
ALTER TABLE contour.causal_inbox_batches ENABLE TRIGGER causal_inbox_batch_immutable;
SET ROLE contour_causal_inbox_writer;
SELECT pg_temp.assert_stored_parse();
RESET ROLE;
-- Valid canonical envelope with an invalid event sequence (semantic 23514).
ALTER TABLE contour.causal_inbox_batches DISABLE TRIGGER causal_inbox_batch_immutable;
UPDATE contour.causal_inbox_batches SET canonical_batch=convert_to(replace(replace(replace(convert_from((SELECT canonical_batch FROM inbox_original_bytes),'UTF8'),'"seq":1','"seq":0'),'"first_seq":1','"first_seq":0'),'"last_seq":1','"last_seq":0'),'UTF8') WHERE batch_id='aa000000-0000-4000-8000-000000000001';
ALTER TABLE contour.causal_inbox_batches ENABLE TRIGGER causal_inbox_batch_immutable;
SET ROLE contour_causal_inbox_writer;
SELECT pg_temp.assert_stored_parse();
RESET ROLE;
ALTER TABLE contour.causal_inbox_batches DISABLE TRIGGER causal_inbox_batch_immutable;
UPDATE contour.causal_inbox_batches SET canonical_batch=(SELECT canonical_batch FROM inbox_original_bytes) WHERE batch_id='aa000000-0000-4000-8000-000000000001';
ALTER TABLE contour.causal_inbox_batches ENABLE TRIGGER causal_inbox_batch_immutable;
-- Restore control: retry returns its original receipt and remains zero-charge.
SET ROLE contour_causal_inbox_writer;
DO $$ DECLARE r record; BEGIN SELECT * INTO r FROM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',1,repeat('1',32),repeat('a',32))); IF NOT r.duplicate OR NOT EXISTS(SELECT 1 FROM inbox_receipt x WHERE x.receipt_id=r.receipt_id AND x.accepted_at=r.accepted_at) THEN RAISE EXCEPTION 'restored retry control failed'; END IF; END $$;
RESET ROLE;
DO $$ BEGIN IF (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='f0000000-0000-4000-8000-000000000001') IS DISTINCT FROM (SELECT used_bytes FROM inbox_parse_usage) THEN RAISE EXCEPTION 'stored parse retry changed quota'; END IF; END $$;
