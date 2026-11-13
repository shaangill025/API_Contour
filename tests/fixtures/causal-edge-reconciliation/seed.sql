-- Same psql backend as SQL29's receiver fixture, with ON_ERROR_STOP and
-- autocommit. SQL20 admissions below commit independently through its public
-- writer; the origin proof and REQUEST come from the existing ingress fixture.
-- Issuer claims are synthetic assertions, not proof of TLS or peer possession.
DO $$ BEGIN
 IF to_regclass('pg_temp.receiver_pairs') IS NULL OR to_regclass('pg_temp.observer_seed') IS NULL
 OR to_regclass('pg_temp.receiver_claim29') IS NULL
 THEN RAISE EXCEPTION 'SQL29 committed fixture required'; END IF;
END $$;
CREATE TEMP TABLE edge31_batches(name text PRIMARY KEY,tenant uuid,runtime uuid,epoch numeric,peer bytea,grant_digest bytea,body bytea);
GRANT SELECT ON observer_seed,receiver_pairs,receiver_claim29 TO contour_owner;
GRANT INSERT ON edge31_batches TO contour_owner;
SET ROLE contour_owner;
INSERT INTO edge31_batches
 SELECT 'producer',((s.proof).producer_claim).tenant_id,((s.proof).producer_claim).runtime_id,
 (s.proof).producer_epoch,((s.proof).producer_claim).export_leaf,((s.proof).producer_claim).grant_digest,
 convert_to(contour.causal_json_canonical(jsonb_build_object(
 'batch_id','31000000-0000-4000-8000-000000000001'::uuid,
 'tenant_id',((s.proof).producer_claim).tenant_id,'runtime_id',((s.proof).producer_claim).runtime_id,
 'session_epoch',(s.proof).producer_epoch,'wire_version',1,'first_seq',1,'last_seq',1,
 'events',jsonb_build_array(jsonb_build_object('event_id',repeat('31',16),'kind','attempt','seq',1,
 'root',(s.proof).marker_root,'activity',(s.proof).marker_activity,'attempt',(s.proof).marker_attempt,
 'marker_digest',encode((s.proof).marker_wire_digest,'hex'))))),'UTF8')
 FROM observer_seed s;
INSERT INTO edge31_batches
 SELECT 'receiver',(c.claim).tenant_id,(c.claim).runtime_id,c.epoch,(c.claim).export_leaf,(c.claim).grant_digest,
 convert_to(contour.causal_json_canonical(jsonb_build_object(
 'batch_id','31000000-0000-4000-8000-000000000002'::uuid,
 'tenant_id',(c.claim).tenant_id,'runtime_id',(c.claim).runtime_id,
 'session_epoch',c.epoch,'wire_version',1,'first_seq',1,'last_seq',1,
 'events',jsonb_build_array(jsonb_build_object('event_id',repeat('32',16),'kind','root','seq',1,
 'root',convert_from(p.receiver_raw,'UTF8')::jsonb->>'local_root')))),'UTF8')
 FROM receiver_claim29 c CROSS JOIN receiver_pairs p WHERE p.name='observer-first';
RESET ROLE;
CREATE TEMP TABLE edge31_receipts(name text PRIMARY KEY,receipt_id uuid NOT NULL,accepted_at timestamptz NOT NULL,duplicate boolean NOT NULL);
GRANT SELECT ON edge31_batches TO contour_causal_inbox_writer;
GRANT INSERT ON edge31_receipts TO contour_causal_inbox_writer;
SET ROLE contour_causal_inbox_writer;
-- Separate statements commit independently in psql autocommit mode.
INSERT INTO edge31_receipts SELECT b.name,r.* FROM edge31_batches b CROSS JOIN LATERAL contour.accept_causal_batch(b.tenant,b.runtime,b.epoch,b.peer,b.grant_digest,b.body) r WHERE b.name='producer';
INSERT INTO edge31_receipts SELECT b.name,r.* FROM edge31_batches b CROSS JOIN LATERAL contour.accept_causal_batch(b.tenant,b.runtime,b.epoch,b.peer,b.grant_digest,b.body) r WHERE b.name='receiver';
RESET ROLE;
SELECT set_config('apicontour.tenant_id',(SELECT tenant::text FROM edge31_batches WHERE name='producer'),false);
GRANT SELECT ON edge31_batches,edge31_receipts TO contour_owner;
SET ROLE contour_owner;
DO $$ BEGIN
 IF (SELECT count(*) FROM edge31_batches) <> 2 OR (SELECT count(*) FROM edge31_receipts) <> 2
 OR EXISTS (SELECT 1 FROM edge31_receipts WHERE duplicate OR receipt_id IS NULL OR accepted_at IS NULL)
 OR (SELECT count(DISTINCT receipt_id) FROM edge31_receipts) <> 2
 OR EXISTS (
  SELECT 1 FROM edge31_batches input JOIN edge31_receipts r USING(name)
  LEFT JOIN contour.causal_inbox_batches b ON (b.tenant_id,b.runtime_id,b.session_epoch,b.batch_id)=(input.tenant,input.runtime,input.epoch,(convert_from(input.body,'UTF8')::jsonb->>'batch_id')::uuid)
  WHERE b.batch_id IS NULL OR b.canonical_batch IS DISTINCT FROM input.body
   OR b.batch_digest IS DISTINCT FROM sha256(convert_to(E'apicontour/causal-events/1\n','UTF8')||input.body)
   OR b.event_count IS DISTINCT FROM 1 OR b.receipt_id IS DISTINCT FROM r.receipt_id OR b.accepted_at IS DISTINCT FROM r.accepted_at
   OR b.receipt_digest IS DISTINCT FROM contour.causal_receipt_digest(b.tenant_id,b.runtime_id,b.session_epoch,b.batch_id,b.receipt_id,b.accepted_at,b.batch_digest,b.event_count)
   OR (SELECT count(*) FROM contour.causal_inbox_events e WHERE (e.tenant_id,e.runtime_id,e.session_epoch,e.batch_id)=(b.tenant_id,b.runtime_id,b.session_epoch,b.batch_id)) <> 1
   OR EXISTS (SELECT * FROM contour.causal_decoded_events(convert_from(input.body,'UTF8')::jsonb) EXCEPT SELECT e.seq,e.event_id,e.kind,e.root,e.activity,e.parent,e.attempt,e.marker_digest,e.first_missing_seq,e.last_missing_seq,e.reason,e.event_digest FROM contour.causal_inbox_events e WHERE (e.tenant_id,e.runtime_id,e.session_epoch,e.batch_id)=(b.tenant_id,b.runtime_id,b.session_epoch,b.batch_id))
 ) THEN RAISE EXCEPTION 'SQL20 seed readback mismatch'; END IF;
END $$;
RESET ROLE;
