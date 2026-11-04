-- Regression for stale issuance time. Run on a fresh disposable database after
-- registry pre-fixture, migration 18, causal_session_setup.sql and migration 19.
-- Synthetic claims are not signatures or authentication. This identical test
-- must fail with P0001 "expired issue accepted" against the preserved old 19,
-- and pass on fixed 19. Each statement runs in its own transaction.
SELECT set_config('apicontour.tenant_id','f0000000-0000-4000-8000-000000000001',false);
SELECT set_config('test.session_time',clock_timestamp()::text,false);
CREATE FUNCTION pg_temp.claim(n uuid,rev numeric DEFAULT 1,digest bytea DEFAULT decode(repeat('ab',32),'hex')) RETURNS contour.causal_session_claim
LANGUAGE sql AS $$ SELECT ROW(
 'f0000000-0000-4000-8000-000000000001'::uuid,'fc000000-0000-4000-8000-000000000001'::uuid,
 'f6000000-0000-4000-8000-000000000001'::uuid,'f7000000-0000-4000-8000-000000000001'::uuid,
 'f1000000-0000-4000-8000-000000000001'::uuid,'f2000000-0000-4000-8000-000000000001'::uuid,
 'f3000000-0000-4000-8000-000000000001'::uuid,'f4000000-0000-4000-8000-000000000001'::uuid,
 'f5000000-0000-4000-8000-000000000001'::uuid,'f9000000-0000-4000-8000-000000000001'::uuid,
 decode(repeat('33',32),'hex'),'nodered_5_0_9_v1',decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex'),n,rev,digest,
 current_setting('test.session_time')::timestamptz-interval '1 minute',current_setting('test.session_time')::timestamptz+interval '10 minutes',
 1,decode('01','hex'),current_setting('test.session_time')::timestamptz-interval '1 minute',current_setting('test.session_time')::timestamptz+interval '10 minutes',
 900000000,10,1024,1024,60)::contour.causal_session_claim $$;

-- Establish a live prior lease, then delay only the second insert until after
-- its short TTL, grant expiry, or policy expiry. The trigger runs after the
-- function computed its deadline.
SET ROLE contour_causal_issuer;
DO $$ DECLARE r record; BEGIN
 SELECT * INTO r FROM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000021'));
 IF r.epoch<>1 OR r.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'old session positive control failed'; END IF;
END $$;
RESET ROLE;
CREATE FUNCTION contour.test_session_clock_delay() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.nonce IN ('fe000000-0000-4000-8000-000000000022'::uuid,'fe000000-0000-4000-8000-000000000023'::uuid,'fe000000-0000-4000-8000-000000000024'::uuid) THEN PERFORM pg_catalog.pg_sleep(greatest(0::double precision, extract(epoch FROM NEW.expires_at-pg_catalog.clock_timestamp())::double precision)+0.05); END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER test_session_clock_delay BEFORE INSERT ON contour.causal_sessions FOR EACH ROW EXECUTE FUNCTION contour.test_session_clock_delay();
SET ROLE contour_causal_issuer;
DO $$ DECLARE x contour.causal_session_claim; reason text; n uuid; BEGIN
 FOREACH n IN ARRAY ARRAY['fe000000-0000-4000-8000-000000000022'::uuid,'fe000000-0000-4000-8000-000000000023'::uuid,'fe000000-0000-4000-8000-000000000024'::uuid] LOOP
  x:=pg_temp.claim(n,3,decode(repeat('cd',32),'hex'));
  IF n='fe000000-0000-4000-8000-000000000022'::uuid THEN x.ttl_microseconds:=2000000;
  ELSIF n='fe000000-0000-4000-8000-000000000023'::uuid THEN x.grant_expires:=clock_timestamp()+interval '2 seconds';
  ELSE x.policy_expires:=clock_timestamp()+interval '2 seconds'; END IF;
  BEGIN
   PERFORM contour.issue_causal_session(x);
   RAISE EXCEPTION 'expired issue accepted';
  EXCEPTION WHEN check_violation THEN
   GET STACKED DIAGNOSTICS reason=MESSAGE_TEXT;
   IF reason<>'session unavailable at final lease check' THEN RAISE EXCEPTION 'unexpected check failure: %',reason; END IF;
  END;
 END LOOP;
END $$;
RESET ROLE;
DROP TRIGGER test_session_clock_delay ON contour.causal_sessions;
DROP FUNCTION contour.test_session_clock_delay();
-- The failed insertion must leave the old session live and no new row, nonce,
-- epoch or revision. Each assertion has an independent positive control.
DO $$ BEGIN
 IF (SELECT count(*) FROM contour.causal_sessions)<>1
 OR (SELECT max(epoch) FROM contour.causal_sessions)<>1
 OR EXISTS (SELECT 1 FROM contour.causal_sessions WHERE nonce IN ('fe000000-0000-4000-8000-000000000022','fe000000-0000-4000-8000-000000000023','fe000000-0000-4000-8000-000000000024'))
 THEN RAISE EXCEPTION 'failed issue leaked state'; END IF;
END $$;
SET ROLE contour_causal_issuer;
DO $$ BEGIN
 IF NOT contour.check_causal_session('f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000001',1)
 THEN RAISE EXCEPTION 'prior session was superseded'; END IF;
END $$;
DO $$ DECLARE r record; BEGIN
 -- Same nonce with the prior revision succeeds only if neither the nonce nor
 -- revision 3 survived. Epoch 2 also proves no allocation was consumed.
 SELECT * INTO r FROM contour.issue_causal_session(pg_temp.claim('fe000000-0000-4000-8000-000000000022',1));
 IF r.epoch<>2 THEN RAISE EXCEPTION 'rollback positive control failed'; END IF;
END $$;
RESET ROLE;
