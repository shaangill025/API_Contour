-- Run on a fresh database after causal_inbox_basic.sql, in the same psql
-- session. Reports elapsed wall time; no performance threshold is asserted.
CREATE FUNCTION pg_temp.history_payload(first_n integer,last_n integer) RETURNS bytea LANGUAGE sql AS $$
 SELECT convert_to(format('{"batch_id":"bb000000-0000-4000-8000-%s","events":[%s],"first_seq":%s,"last_seq":%s,"runtime_id":"fc000000-0000-4000-8000-000000000001","session_epoch":1,"tenant_id":"f0000000-0000-4000-8000-000000000001","wire_version":1}',lpad(to_hex(first_n),12,'0'),string_agg(format('{"event_id":"%s","kind":"root","root":"%s","seq":%s}',lpad(to_hex(n),32,'0'),lpad(to_hex(n),32,'0'),n),',' ORDER BY n),first_n,last_n),'UTF8') FROM generate_series(first_n,last_n) n $$;
SET ROLE contour_causal_inbox_writer;
SELECT format('SELECT * FROM contour.accept_causal_batch(%L,%L,1,decode(repeat(''33'',32),''hex''),decode(repeat(''ab'',32),''hex''),decode(%L,''hex''));','f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',encode(pg_temp.history_payload(n,least(n+499,3603)),'hex')) FROM generate_series(11,3603,500) n ORDER BY n \gexec
RESET ROLE;
CREATE TEMP TABLE causal_history_timing(started timestamptz);
INSERT INTO causal_history_timing VALUES(clock_timestamp());
SET ROLE contour_causal_inbox_writer;
-- 3,596 prior events times 500 incoming events, then all 4,096 slots filled.
SELECT * FROM contour.accept_causal_batch('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1,decode(repeat('33',32),'hex'),decode(repeat('ab',32),'hex'),pg_temp.history_payload(3604,4103));
RESET ROLE;
SELECT extract(epoch FROM clock_timestamp()-started)*1000 AS elapsed_milliseconds FROM causal_history_timing;
SET ROLE contour_owner;
DO $$ BEGIN IF (SELECT count(*) FROM contour.causal_inbox_events WHERE session_epoch=1)<>4096 THEN RAISE EXCEPTION 'history work boundary incorrect'; END IF; END $$;
RESET ROLE;
