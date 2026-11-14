-- Synthetic-only new session: runtime08 epoch2, independently live product03.
SELECT set_config('apicontour.tenant_id','f0000000-0000-4000-8000-000000000001',false);
SELECT set_config('test.receiver_now',clock_timestamp()::text,false);
CREATE FUNCTION pg_temp.receiver_reader_session() RETURNS contour.causal_session_claim LANGUAGE sql AS $$ SELECT ROW(
 'f0000000-0000-4000-8000-000000000001'::uuid,'fc000000-0000-4000-8000-000000000008'::uuid,
 'f6000000-0000-4000-8000-000000000003'::uuid,'f7000000-0000-4000-8000-000000000003'::uuid,
 'f1000000-0000-4000-8000-000000000001'::uuid,'f2000000-0000-4000-8000-000000000001'::uuid,
 'f3000000-0000-4000-8000-000000000001'::uuid,'f4000000-0000-4000-8000-000000000001'::uuid,
 'f5000000-0000-4000-8000-000000000003'::uuid,'f9000000-0000-4000-8000-000000000003'::uuid,
 decode(repeat('b8',32),'hex'),'nodered_5_0_9_receiver_v1',decode('af3171bdf0ca4bfc70c63aaf998fdfd4cf988b4409e7f7f47e015325608b302d','hex'),
 'fe000000-0000-4000-8000-000000000018'::uuid,1,decode(repeat('ab',32),'hex'),
 current_setting('test.receiver_now')::timestamptz-interval '1 minute',current_setting('test.receiver_now')::timestamptz+interval '10 minutes',
 1,decode('01','hex'),current_setting('test.receiver_now')::timestamptz-interval '1 minute',current_setting('test.receiver_now')::timestamptz+interval '10 minutes',900000000,10,1024,1024,60)::contour.causal_session_claim $$;
SET ROLE contour_causal_issuer;
CREATE TEMP TABLE receiver_reader_epoch AS SELECT * FROM contour.issue_causal_session(pg_temp.receiver_reader_session());
RESET ROLE;
GRANT SELECT ON receiver_reader_epoch TO contour_causal_evidence_provisioner;
DO $$ BEGIN IF (SELECT epoch FROM receiver_reader_epoch)<>2 THEN RAISE EXCEPTION 'unexpected synthetic epoch'; END IF; END $$;
CREATE FUNCTION pg_temp.receiver_reader_claim() RETURNS contour.receiver_enrollment_claim LANGUAGE sql AS $$ SELECT ROW(
 'f0000000-0000-4000-8000-000000000001'::uuid,'fc000000-0000-4000-8000-000000000008'::uuid,(SELECT epoch FROM receiver_reader_epoch),
 'f5000000-0000-4000-8000-000000000003'::uuid,'f9000000-0000-4000-8000-000000000003'::uuid,
 'fa000000-0000-4000-8000-000000000003'::uuid,decode(repeat('03',32),'hex'),decode(repeat('b8',32),'hex'),
 decode(repeat('d1',32),'hex'),decode(repeat('d2',32),'hex'),decode(repeat('d3',32),'hex'),
 current_setting('test.receiver_now')::timestamptz-interval '1 minute',current_setting('test.receiver_now')::timestamptz+interval '10 minutes',
 current_setting('test.receiver_now')::timestamptz-interval '1 minute',current_setting('test.receiver_now')::timestamptz+interval '10 minutes',300000000)::contour.receiver_enrollment_claim $$;
SET ROLE contour_causal_evidence_provisioner;
CREATE TEMP TABLE receiver_reader_result AS SELECT * FROM contour.enroll_causal_receiver(pg_temp.receiver_reader_claim());
RESET ROLE;
SELECT json_build_object('epoch',(SELECT epoch::text FROM receiver_reader_epoch),'generation',generation,'credential_id',credential_id::text,'commitment',encode(commitment,'hex'),'expires_at',to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text FROM receiver_reader_result;
