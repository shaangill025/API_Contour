-- Synthetic assertions only, in the same psql backend as observer_seed.
-- The observer's V2 REQUEST/origin proof was produced by the existing ingress
-- and catalog path; no proof or catalog row is inserted here.
GRANT SELECT ON observer_claim TO contour_admin;
BEGIN; SET LOCAL ROLE contour_admin;
SELECT contour.lock_collector((SELECT (claim).tenant_id FROM observer_claim),(SELECT (claim).collector_id FROM observer_claim));
INSERT INTO contour.workload_instances SELECT (claim).tenant_id,(claim).project_id,(claim).service_id,(claim).environment_id,(claim).deployment_id,'00000000-0000-4000-8000-00000000ce0d'::uuid FROM observer_claim;
SELECT contour.register_instance_source((claim).tenant_id,'00000000-0000-4000-8000-00000000ce0f',(claim).collector_id,(claim).project_id,(claim).service_id,(claim).environment_id,(claim).deployment_id,'00000000-0000-4000-8000-00000000ce0f','00000000-0000-4000-8000-00000000ce0d') FROM observer_claim;
INSERT INTO contour.source_authorization SELECT (claim).tenant_id,'00000000-0000-4000-8000-00000000ce0f'::uuid,(claim).collector_id,'runtime',ARRAY['http_json_v1'] FROM observer_claim;
COMMIT;
SET ROLE contour_admin;
SELECT contour.enroll_origin((claim).tenant_id,'00000000-0000-4000-8000-00000000ce0e',(claim).project_id,(claim).service_id,(claim).environment_id,(claim).deployment_id,'00000000-0000-4000-8000-00000000ce0d','trusted_platform_v1',decode(repeat('d5',32),'hex')) FROM observer_claim;
SELECT contour.enroll_origin_credential((claim).tenant_id,'00000000-0000-4000-8000-00000000ce10','00000000-0000-4000-8000-00000000ce0e',decode(repeat('d6',32),'hex')) FROM observer_claim;
RESET ROLE;
SET ROLE contour_causal_provisioner;
SELECT contour.register_causal_profile((SELECT (claim).tenant_id FROM observer_claim),'00000000-0000-4000-8000-000000000504',decode('af3171bdf0ca4bfc70c63aaf998fdfd4cf988b4409e7f7f47e015325608b302d','hex'));
SELECT contour.enroll_causal_runtime((c.claim).tenant_id,'00000000-0000-4000-8000-00000000ce0b',(c.claim).collector_id,'00000000-0000-4000-8000-00000000ce0f',(c.claim).project_id,(c.claim).service_id,(c.claim).environment_id,(c.claim).deployment_id,'00000000-0000-4000-8000-00000000ce0d','00000000-0000-4000-8000-00000000ce0e','00000000-0000-4000-8000-000000000504',decode('af3171bdf0ca4bfc70c63aaf998fdfd4cf988b4409e7f7f47e015325608b302d','hex'),decode(repeat('d7',32),'hex')) FROM observer_claim c;
RESET ROLE;
CREATE TEMP TABLE receiver_claim29 AS SELECT claim,NULL::numeric AS epoch FROM observer_claim;
DO $$ DECLARE x contour.causal_session_claim; BEGIN
 SELECT claim INTO STRICT x FROM receiver_claim29;
 x.runtime_id:='00000000-0000-4000-8000-00000000ce0b'; x.source_id:='00000000-0000-4000-8000-00000000ce0f';
 x.instance_id:='00000000-0000-4000-8000-00000000ce0d'; x.lifecycle_id:='00000000-0000-4000-8000-00000000ce0e'; x.export_leaf:=decode(repeat('d7',32),'hex');
 x.profile_name:='nodered_5_0_9_receiver_v1'; x.profile_hash:=decode('af3171bdf0ca4bfc70c63aaf998fdfd4cf988b4409e7f7f47e015325608b302d','hex');
 x.nonce:='00000000-0000-4000-8000-00000000ce0c';
 UPDATE receiver_claim29 SET claim=x;
END $$;
GRANT SELECT,UPDATE ON receiver_claim29 TO contour_causal_issuer;
SET ROLE contour_causal_issuer;
UPDATE receiver_claim29 SET epoch=(SELECT epoch FROM contour.issue_causal_session(claim));
RESET ROLE;
CREATE TEMP TABLE receiver_product29 AS SELECT '00000000-0000-4000-8000-00000000ce10'::uuid AS product_credential_id,decode(repeat('d6',32),'hex') AS product_leaf_sha256;
CREATE TEMP TABLE receiver_enrollment29(generation text,credential_id uuid,issued_at timestamptz,expires_at timestamptz,commitment bytea);
GRANT SELECT ON receiver_claim29,receiver_product29 TO contour_causal_evidence_provisioner;
GRANT SELECT,INSERT ON receiver_enrollment29 TO contour_causal_evidence_provisioner;
SET ROLE contour_causal_evidence_provisioner;
INSERT INTO receiver_enrollment29 SELECT * FROM contour.enroll_causal_receiver(ROW(
 (c.claim).tenant_id,(c.claim).runtime_id,c.epoch,(c.claim).instance_id,(c.claim).lifecycle_id,
 m.product_credential_id,m.product_leaf_sha256,(c.claim).export_leaf,decode(repeat('d8',32),'hex'),decode(repeat('d9',32),'hex'),decode(repeat('da',32),'hex'),
 (c.claim).grant_issued,(c.claim).grant_expires,(c.claim).policy_issued,(c.claim).policy_expires,60000000)::contour.receiver_enrollment_claim)
 FROM receiver_claim29 c CROSS JOIN receiver_product29 m;
RESET ROLE;
CREATE TEMP TABLE receiver_pairs(name text PRIMARY KEY,receiver_raw bytea NOT NULL,receiver_proof contour.verified_receiver_claim NOT NULL,observer_raw bytea NOT NULL,observer_proof contour.verified_observer_claim NOT NULL);
GRANT SELECT ON observer_seed,receiver_claim29,receiver_enrollment29 TO contour_owner;
GRANT INSERT ON receiver_pairs TO contour_owner;
SET ROLE contour_owner;
WITH variants(name,handle,predecessor,root) AS (VALUES
 ('observer-first',repeat('e1',16),repeat('e',32),repeat('e7',16)),
 ('receiver-first',repeat('e2',16),repeat('e1',16),repeat('e8',16)),
 ('mismatch',repeat('e3',16),repeat('e2',16),repeat('e9',16)),
 ('quota',repeat('e4',16),repeat('e2',16),repeat('ea',16))
), expanded AS (
 SELECT v.*,x.proof,c.epoch,r.generation,r.credential_id,
 jsonb_set(jsonb_set(jsonb_set(jsonb_set(convert_from(x.raw,'UTF8')::jsonb,'{binding,delivery_handle}',to_jsonb(v.handle)),
 '{binding,retry_of}',to_jsonb(v.predecessor)),'{binding,receiver_runtime_id}',to_jsonb('00000000-0000-4000-8000-00000000ce0b'::text)),
 '{binding,receiver_session_epoch}',to_jsonb(c.epoch::text)) AS observer
 FROM observer_seed x CROSS JOIN receiver_claim29 c CROSS JOIN receiver_enrollment29 r CROSS JOIN variants v
)
INSERT INTO receiver_pairs
 SELECT name,convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,
 'tenant_id',observer->'binding'->>'tenant_id','gateway_id',observer->'binding'->>'gateway_id',
 'gateway_generation',observer->'binding'->>'gateway_generation','delivery_handle',handle,
 'receiver_runtime_id','00000000-0000-4000-8000-00000000ce0b','receiver_session_epoch',epoch::text,'local_root',root,
 'binding_digest',CASE WHEN name='mismatch' THEN repeat('f',64) ELSE encode(sha256(convert_to(E'apicontour/causal-evidence/binding/1\n','UTF8')||convert_to(contour.causal_json_canonical(observer->'binding'),'UTF8')),'hex') END)),'UTF8'),
 ROW(decode(repeat('d9',32),'hex'),generation,credential_id)::contour.verified_receiver_claim,
 convert_to(contour.causal_json_canonical(observer),'UTF8'),
 ROW((proof).gateway_peer_leaf,(proof).producer_claim,(proof).producer_epoch,(proof).marker_public,(proof).marker_generation,
 (proof).marker_root,(proof).marker_activity,(proof).marker_attempt,(proof).marker_wire_digest)::contour.verified_observer_claim
 FROM expanded;
RESET ROLE;
