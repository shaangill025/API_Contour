-- Run after causal_inbox_basic.sql, before quota/corruption/clock, in one psql
-- session. It exercises actual admissions, not direct seeded event rows.
CREATE FUNCTION pg_temp.history_payload(first_n integer,last_n integer) RETURNS bytea LANGUAGE sql AS $$
 SELECT convert_to(format('{"batch_id":"bb000000-0000-4000-8000-%s","events":[%s],"first_seq":%s,"last_seq":%s,"runtime_id":"fc000000-0000-4000-8000-000000000001","session_epoch":1,"tenant_id":"f0000000-0000-4000-8000-000000000001","wire_version":1}',lpad(to_hex(first_n),12,'0'),string_agg(format('{"event_id":"%s","kind":"root","root":"%s","seq":%s}',lpad(to_hex(n),32,'0'),lpad(to_hex(n),32,'0'),n),',' ORDER BY n),first_n,last_n),'UTF8') FROM generate_series(first_n,last_n) n $$;
-- Nine separate statements avoid reentering the transaction-bound Q operation.
SET ROLE contour_causal_inbox_writer;
SELECT format('SELECT * FROM contour.accept_causal_batch(%L,%L,1,decode(repeat(''33'',32),''hex''),decode(repeat(''ab'',32),''hex''),decode(%L,''hex''));','f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',encode(pg_temp.history_payload(n,least(n+499,4101)),'hex')) FROM generate_series(11,4101,500) n ORDER BY n \gexec
-- At 4,094 entries a LOSS is accepted, including a range with absent sequences.
SELECT * FROM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_event('cc000000-0000-4000-8000-000000005000',format('{"event_id":"%s","first_missing_seq":4998,"kind":"loss","last_missing_seq":4999,"reason":"overflow","seq":5000}',repeat('f',32)),5000));
DO $$ BEGIN
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('cc000000-0000-4000-8000-000000004998',4998,repeat('c',32),repeat('d',32))); RAISE EXCEPTION 'late event entered loss'; EXCEPTION WHEN unique_violation THEN NULL; END;
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_event('cc000000-0000-4000-8000-000000005001',format('{"event_id":"%s","first_missing_seq":4101,"kind":"loss","last_missing_seq":4101,"reason":"overflow","seq":5001}',repeat('c',32)),5001)); RAISE EXCEPTION 'late loss covered event'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
-- 4,096th event is accepted; later fresh admission is explicitly refused.
SELECT * FROM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('cc000000-0000-4000-8000-000000005001',5001,repeat('c',32),repeat('d',32)));
DO $$ DECLARE rejected boolean:=false; cn text; r record; BEGIN
 BEGIN PERFORM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('cc000000-0000-4000-8000-000000005002',5002,repeat('d',32),repeat('e',32))); EXCEPTION WHEN program_limit_exceeded THEN GET STACKED DIAGNOSTICS cn=CONSTRAINT_NAME; rejected:=(cn='causal_session_history_limit'); END;
 IF NOT rejected THEN RAISE EXCEPTION 'history limit diagnostic missing'; END IF;
END $$;
DO $$ DECLARE r record; BEGIN SELECT * INTO r FROM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.inbox_payload('aa000000-0000-4000-8000-000000000001',1,repeat('1',32),repeat('a',32))); IF NOT r.duplicate THEN RAISE EXCEPTION 'retry at cap failed'; END IF; END $$;
RESET ROLE;
SET ROLE contour_owner;
DO $$ BEGIN IF (SELECT count(*) FROM contour.causal_inbox_events WHERE session_epoch=1)<>4096 THEN RAISE EXCEPTION 'history boundary count incorrect'; END IF; END $$;
RESET ROLE;
