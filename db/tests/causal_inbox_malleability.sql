-- Direct byte-level parser probes. Requires migration 20.
SET ROLE contour_owner;
DO $$ DECLARE valid text := '{"batch_id":"123e4567-e89b-12d3-a456-426614174000","events":[{"event_id":"11111111111111111111111111111111","kind":"root","root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","seq":1}],"first_seq":1,"last_seq":1,"runtime_id":"123e4567-e89b-12d3-a456-426614174002","session_epoch":1,"tenant_id":"123e4567-e89b-12d3-a456-426614174001","wire_version":1}'; candidate text; rejected boolean;
BEGIN
 PERFORM contour.causal_parse(convert_to(valid,'UTF8'));
 FOREACH candidate IN ARRAY ARRAY[
  ' '||valid,
  replace(valid,'"wire_version":1','"wire_version":1.0'),
  replace(valid,'"seq":1','"seq":1.0'),
  replace(valid,'"seq":1','"seq":1,"seq":1'),
  replace(valid,'"seq":1','"seq":1,"unknown":true'),
  replace(valid,'"kind":"root"',E'"kind":"ro\\u006ft"'),
  replace(valid,'"seq":1','"seq":18446744073709551616')
 ] LOOP
  rejected:=false;
  BEGIN PERFORM contour.causal_parse(convert_to(candidate,'UTF8')); EXCEPTION WHEN data_exception OR check_violation THEN rejected:=true; END;
  IF NOT rejected THEN RAISE EXCEPTION 'malleable or invalid encoding accepted'; END IF;
 END LOOP;
END $$;
RESET ROLE;
